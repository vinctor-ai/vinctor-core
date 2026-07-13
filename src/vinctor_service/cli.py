from __future__ import annotations

import argparse
import importlib.metadata
import json
import os
import sqlite3
import sys
from dataclasses import asdict
from datetime import UTC, datetime
from http.client import HTTPConnection
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Thread
from typing import NoReturn, TextIO
from urllib.parse import urlsplit

from vinctor_core.models import Grant
from vinctor_service.audit_chain import AnchorRecord
from vinctor_service.key_ops import (
    rotate_agent_key,
    rotate_pep_key,
    rotate_workspace_key,
    serialize_key_record,
)
from vinctor_service.keys import SQLiteLocalKeyRepository
from vinctor_service.local_launcher import (
    DEFAULT_SCOPE,
    LocalLaunchConfig,
    prepare_local_service,
    serve_local_service,
)
from vinctor_service.policy_files import (
    apply_policy_file,
    dump_policy_document,
    export_policy_document,
    write_policy_file,
)
from vinctor_service.policy_infer import infer_policy_document
from vinctor_service.service_config import (
    DEFAULT_SUBJECT_TOKEN_TTL_SECONDS,
    LOG_LEVELS,
    SERVICE_MODES,
    load_service_runtime_config,
)
from vinctor_service.service_runtime import serve_service_runtime
from vinctor_service.sqlite import SQLiteV1Service
from vinctor_service.storage_ops import (
    backup_sqlite,
    migrate_sqlite,
    read_schema_versions,
    reset_sqlite,
    restore_sqlite,
)

EXIT_UNEXPECTED = 1
EXIT_USAGE = 2
EXIT_DENIED = 3
EXIT_AUTH = 4
EXIT_SERVICE = 5


class CliError(Exception):
    def __init__(self, message: str, *, code: int = EXIT_USAGE, quiet_json: bool = False):
        super().__init__(message)
        self.code = code
        self.quiet_json = quiet_json


def run_vinctor(
    argv: list[str] | None = None,
    *,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        _dispatch(args, stdout=stdout)
    except CliError as error:
        _emit_error(args, error, stderr=stderr)
        return error.code
    except KeyboardInterrupt:
        print("interrupted", file=stderr)
        return EXIT_UNEXPECTED
    return 0


def main(argv: list[str] | None = None) -> NoReturn:
    raise SystemExit(run_vinctor(argv))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vinctor",
        description="Operate the local Vinctor prototype.",
        allow_abbrev=False,
    )
    # The persistent flags live on the root (with real env defaults) so the
    # historical `vinctor --db X <role> ...` form keeps working, and they are
    # ALSO attached to every leaf subparser (with default=argparse.SUPPRESS) so
    # `vinctor <role> ... --db X` works too. See _add_global_flags.
    _add_global_flags(parser, defaults=True)
    parser.add_argument(
        "--version",
        action="version",
        version=f"vinctor {importlib.metadata.version('vinctor-core')}",
        help="Print the vinctor version and exit.",
    )

    roles = parser.add_subparsers(dest="role", required=True)
    _add_service_commands(roles)
    _add_local_commands(roles)
    _add_agent_commands(roles)
    _add_operator_commands(roles)
    _add_demo_commands(roles)

    # Attach the global flags to every leaf subparser so they may also appear
    # AFTER the subcommand, not only before the role.
    for leaf in _leaf_subparsers(parser):
        _add_global_flags(leaf, defaults=False)
    return parser


def _leaf_subparsers(
    parser: argparse.ArgumentParser,
) -> list[argparse.ArgumentParser]:
    """Return every leaf subparser reachable from ``parser`` (a leaf has no
    further subcommands of its own)."""
    sub_actions = [
        action
        for action in parser._actions
        if isinstance(action, argparse._SubParsersAction)
    ]
    if not sub_actions:
        return [parser]
    leaves: list[argparse.ArgumentParser] = []
    for action in sub_actions:
        for child in action.choices.values():
            leaves.extend(_leaf_subparsers(child))
    return leaves


def _add_global_flags(parser: argparse.ArgumentParser, *, defaults: bool) -> None:
    """Attach the persistent global/output flags to ``parser``.

    On the root parser (``defaults=True``) the real env-backed defaults are
    used. On a leaf subparser (``defaults=False``) every flag uses
    ``default=argparse.SUPPRESS`` so that an OMITTED leaf flag never appears in
    the namespace and therefore cannot clobber the root-provided value (the
    classic argparse parent-parser gotcha). When a leaf flag IS supplied it
    overwrites the root value, so the trailing form wins — which is the intended
    behaviour. Any global flag whose option string a leaf already defines (with
    its own distinct ``dest``/semantics) is skipped so argparse does not raise a
    conflicting-option error.
    """

    def add(option_strings: list[str], **kwargs: object) -> None:
        if not defaults:
            existing = {
                option
                for action in parser._actions
                for option in action.option_strings
            }
            if any(option in existing for option in option_strings):
                return
            kwargs["default"] = argparse.SUPPRESS
        parser.add_argument(*option_strings, **kwargs)

    add(
        ["--endpoint"],
        default=os.environ.get("VINCTOR_ENDPOINT"),
        help="Base URL of the running service, e.g. http://127.0.0.1:8765 "
        "(env: VINCTOR_ENDPOINT).",
    )
    add(
        ["--workspace-key"],
        default=os.environ.get("VINCTOR_WORKSPACE_KEY"),
        help="Operator/workspace API key for operator-side calls "
        "(env: VINCTOR_WORKSPACE_KEY).",
    )
    add(
        ["--agent-key"],
        default=os.environ.get("VINCTOR_AGENT_KEY"),
        help="Agent API key for agent-side calls (env: VINCTOR_AGENT_KEY).",
    )
    add(
        ["--grant-ref"],
        default=os.environ.get("VINCTOR_GRANT_REF"),
        help="Default grant reference to enforce/audit against "
        "(env: VINCTOR_GRANT_REF).",
    )
    add(
        ["--boundary-id"],
        default=os.environ.get("VINCTOR_BOUNDARY_ID"),
        help="Boundary (PEP) id to attach to enforce calls (env: VINCTOR_BOUNDARY_ID).",
    )
    add(
        ["--db"],
        type=Path,
        default=Path(os.environ["VINCTOR_DB"]) if "VINCTOR_DB" in os.environ else None,
        help="SQLite database path for direct-DB operator commands (env: VINCTOR_DB).",
    )
    add(["--workspace-id"], default="ws_local", help="Workspace id (default: ws_local).")
    add(["--agent-id"], default="agent_local", help="Agent id (default: agent_local).")
    add(
        ["--json"],
        action="store_true",
        default=False,
        help="Write JSON to stdout. Alias for `-o json`; --json wins if both are given.",
    )
    add(
        ["-o", "--output"],
        choices=("text", "json"),
        default=None,
        help="Output format (default: text). `--json` is an alias for `-o json` and "
        "takes precedence over --output.",
    )


def _add_service_commands(roles: argparse._SubParsersAction) -> None:
    parser = roles.add_parser("service", help="Run the Vinctor service runtime.")
    commands = parser.add_subparsers(dest="service_command", required=True)

    serve = commands.add_parser("serve", help="Serve an existing SQLite-backed Vinctor service.")
    serve.add_argument("--host")
    serve.add_argument("--port", type=int)
    serve.add_argument("--db", dest="service_db", type=Path)
    serve.add_argument("--mode", choices=SERVICE_MODES, dest="service_mode")
    serve.add_argument("--log-level", choices=LOG_LEVELS)
    serve.add_argument("--metrics", action="store_true", default=None)
    serve.add_argument("--access-log", action="store_true", default=None)


def _add_local_commands(roles: argparse._SubParsersAction) -> None:
    parser = roles.add_parser("local", help="Start and inspect local prototype services.")
    commands = parser.add_subparsers(dest="local_command", required=True)

    start = commands.add_parser("start", help="Start a local SQLite-backed service.")
    _add_local_start_args(start)

    env = commands.add_parser(
        "env",
        help="Print shell exports from provided or existing env values.",
    )
    env.add_argument("--write-file", type=Path)
    env.add_argument("--force", action="store_true")


def _add_local_start_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--db", required=True, type=Path, help="SQLite database path.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default=8765, type=int)
    parser.add_argument("--workspace-id", default="ws_local")
    parser.add_argument("--agent-id", default="agent_local")
    parser.add_argument("--workspace-key")
    parser.add_argument("--agent-key")
    parser.add_argument("--grant-id")
    parser.add_argument("--grant-ref", default="grt_local")
    parser.add_argument("--scope", action="append", dest="scopes")
    parser.add_argument("--grant-ttl-hours", default=8, type=int)
    parser.add_argument("--boundary-name")
    parser.add_argument("--boundary-runtime", default="claude-code")
    parser.add_argument("--boundary-type", default="pretooluse")


def _add_agent_commands(roles: argparse._SubParsersAction) -> None:
    parser = roles.add_parser(
        "agent",
        help="Request and consume scoped grants.",
        description="Agent-side commands: request grants, enforce actions against a "
        "grant, and mint delegated subject tokens.",
    )
    commands = parser.add_subparsers(dest="agent_command", required=True)

    requests = commands.add_parser(
        "requests",
        help="Create grant requests and check their status.",
        description="Create grant requests and check their status.",
    )
    request_commands = requests.add_subparsers(dest="requests_command", required=True)
    create = request_commands.add_parser(
        "create",
        help="Submit a new grant request for the configured agent.",
        description="Submit a new grant request for the configured agent.",
    )
    create.add_argument("--scope", action="append", dest="scopes", required=True)
    create.add_argument("--ttl", required=True)
    create.add_argument("--reason", required=True)
    create.add_argument("--task-id")
    create.add_argument("--session-id")
    create.add_argument("--boundary-id", dest="request_boundary_id")
    create.add_argument("--runtime", dest="requester_runtime")
    create.add_argument("--repo")
    create.add_argument("--worktree")
    status = request_commands.add_parser(
        "status",
        help="Show the current status of one grant request.",
        description="Show the current status of one grant request.",
    )
    status.add_argument("request_id")

    enforce = commands.add_parser(
        "enforce",
        help="Ask the service to permit or deny an action against a grant.",
        description="Ask the service to permit or deny an action/resource against a "
        "grant. Exits non-zero (denied) when the decision is deny.",
    )
    enforce.add_argument("--grant-ref", dest="enforce_grant_ref")
    enforce.add_argument("--action", required=True)
    enforce.add_argument("--resource", required=True)

    token = commands.add_parser(
        "token",
        help="Mint delegated subject tokens.",
        description="Mint delegated subject tokens (proof of the calling agent's "
        "identity) for a downstream resource server.",
    )
    token_commands = token.add_subparsers(dest="token_command", required=True)
    mint = token_commands.add_parser(
        "mint",
        help="Mint a subject token bound to a grant and audience.",
        description="Mint a subject token bound to a grant and audience. The raw "
        "token is printed once and cannot be recovered later.",
    )
    mint.add_argument("--grant-ref", dest="token_grant_ref", required=True)
    mint.add_argument("--audience", required=True)
    mint.add_argument("--ttl")
    mint.add_argument("--action", dest="token_action")
    mint.add_argument("--resource", dest="token_resource")
    mint.add_argument("--pop", action="store_true", dest="token_pop")


def _add_operator_commands(roles: argparse._SubParsersAction) -> None:
    parser = roles.add_parser(
        "operator",
        help="Operate request queues, rules, bounds, mandates, and audit.",
        description="Operator/workspace-side administration: triage and decide grant "
        "requests, manage auto-approval rules, set issuable-scope bounds, toggle "
        "enforcement mandates (require-*), and inspect audit/keys/storage.",
    )
    resources = parser.add_subparsers(dest="operator_resource", required=True)

    requests = resources.add_parser(
        "requests",
        help="Triage and decide grant requests.",
        description="Triage and decide grant requests: list/inbox to review, "
        "view/timeline to inspect, approve/reject/evaluate to decide.",
    )
    request_commands = requests.add_subparsers(dest="requests_command", required=True)
    list_requests = request_commands.add_parser(
        "list",
        help="List all grant requests (optionally filtered by --status).",
        description="List the full grant-request queue, optionally filtered by status. "
        "Use `inbox` for just the pending requests with triage recommendations.",
    )
    list_requests.add_argument(
        "--status",
        choices=("pending", "approved", "rejected", "cancelled", "expired"),
    )
    request_commands.add_parser(
        "inbox",
        help="Show pending requests with risk + triage recommendations.",
        description="Show only the pending requests, each annotated with a risk level "
        "and a recommended action to help triage. Use `list` for the full queue.",
    )
    timeline = request_commands.add_parser(
        "timeline",
        help="Show the chain of audit events for one request.",
        description="Show the ordered chain of audit events tied to one request "
        "(its history). Use `view` for the single request snapshot.",
    )
    timeline.add_argument("request_id")
    view = request_commands.add_parser(
        "view",
        help="Show a single request's current snapshot.",
        description="Show the current snapshot of a single request (status, scopes, "
        "metadata). Use `timeline` for its audit-event history.",
    )
    view.add_argument("request_id")
    approve = request_commands.add_parser(
        "approve",
        help="Manually approve a request and issue its grant.",
        description="Manually approve a request and issue the grant. Use `evaluate` "
        "to apply auto-approval rules instead of deciding by hand.",
    )
    approve.add_argument("request_id")
    approve.add_argument("--reason")
    reject = request_commands.add_parser(
        "reject",
        help="Manually reject a request.",
        description="Manually reject a request, optionally with a decision reason.",
    )
    reject.add_argument("request_id")
    reject.add_argument("--reason")
    evaluate = request_commands.add_parser(
        "evaluate",
        help="Run auto-approval rules against a request.",
        description="Run the workspace auto-approval rules against a request; it is "
        "approved automatically only if a rule matches, otherwise it stays pending "
        "for manual review. Use `approve` for an explicit manual decision.",
    )
    evaluate.add_argument("request_id")

    rules = resources.add_parser(
        "rules",
        help="Manage auto-approval rules.",
        description="Manage auto-approval rules that let matching requests be approved "
        "automatically (see `requests evaluate`).",
    )
    rule_commands = rules.add_subparsers(dest="rules_command", required=True)
    create = rule_commands.add_parser(
        "create",
        help="Create an auto-approval rule.",
        description="Create an auto-approval rule for a target agent, scopes, and "
        "maximum TTL.",
    )
    create.add_argument("--name", required=True)
    create.add_argument("--target-agent-id", required=True)
    create.add_argument("--scope", action="append", dest="scopes", required=True)
    create.add_argument("--max-ttl", required=True)
    rule_commands.add_parser(
        "list",
        help="List auto-approval rules.",
        description="List the workspace's auto-approval rules.",
    )
    disable = rule_commands.add_parser(
        "disable",
        help="Disable an auto-approval rule.",
        description="Disable an auto-approval rule by id.",
    )
    disable.add_argument("rule_id")

    bounds = resources.add_parser(
        "bounds",
        help="Set the ceiling of scopes/TTL an agent may ever be issued.",
        description="Set or show the issuable-scope bounds: the maximum set of scopes "
        "(and optional max TTL) an agent may EVER be granted. This is a ceiling on "
        "what can be issued, not an enforcement mandate -- see `require-boundary` for "
        "the at-enforce-time boundary requirement.",
    )
    bounds_commands = bounds.add_subparsers(dest="bounds_command", required=True)
    set_bounds = bounds_commands.add_parser(
        "set",
        help="Set the issuable-scope ceiling (and optional max TTL) for an agent.",
        description="Set the issuable-scope ceiling (and optional maximum TTL) for an "
        "agent. Requests exceeding these bounds cannot be granted.",
    )
    set_bounds.add_argument("target_agent_id", nargs="?")
    set_bounds.add_argument("--scope", action="append", dest="scopes", required=True)
    set_bounds.add_argument("--max-ttl", dest="max_ttl")
    show_bounds = bounds_commands.add_parser(
        "show",
        help="Show the current issuable-scope ceiling for an agent.",
        description="Show the current issuable-scope bounds (ceiling) for an agent.",
    )
    show_bounds.add_argument("target_agent_id", nargs="?")

    tokens = resources.add_parser(
        "tokens",
        help="List and revoke issued subject tokens.",
        description="List and revoke delegated subject tokens that agents have minted.",
    )
    token_commands = tokens.add_subparsers(dest="tokens_command", required=True)
    token_commands.add_parser(
        "list",
        help="List subject tokens for the workspace.",
        description="List subject tokens for the workspace.",
    )
    revoke_token = token_commands.add_parser(
        "revoke",
        help="Revoke a subject token by id.",
        description="Revoke a subject token by id.",
    )
    revoke_token.add_argument("token_id")

    grants = resources.add_parser(
        "grants",
        help="Manage issued grants.",
        description="Manage issued grants.",
    )
    grant_commands = grants.add_subparsers(dest="grants_command", required=True)
    revoke_grant = grant_commands.add_parser(
        "revoke",
        help="Revoke an issued grant by reference.",
        description="Revoke an issued grant by its grant reference. Calls the running "
        "service at --endpoint (with a workspace key) when an endpoint is configured; "
        "otherwise revokes directly against --db (or VINCTOR_DB).",
    )
    revoke_grant.add_argument("grant_ref")

    require_boundary = resources.add_parser(
        "require-boundary",
        help="Mandate: enforce calls must carry a boundary (PEP) id.",
        description="Enforcement mandate. When enabled, enforce calls for the target "
        "agent (or whole workspace) are denied unless they present a boundary (PEP) "
        "id. Distinct from `bounds`, which caps issuable scopes.",
    )
    rb_commands = require_boundary.add_subparsers(dest="require_boundary_command", required=True)
    rb_enable = rb_commands.add_parser(
        "enable",
        help="Require a boundary id at enforce time.",
        description="Enable the require-boundary mandate for an agent or --workspace.",
    )
    rb_enable.add_argument("target_agent_id", nargs="?")
    rb_enable.add_argument("--workspace", action="store_true")
    rb_disable = rb_commands.add_parser(
        "disable",
        help="Stop requiring a boundary id at enforce time.",
        description="Disable the require-boundary mandate for an agent or --workspace.",
    )
    rb_disable.add_argument("target_agent_id", nargs="?")
    rb_disable.add_argument("--workspace", action="store_true")
    rb_show = rb_commands.add_parser(
        "show",
        help="Show the require-boundary setting.",
        description="Show the require-boundary mandate for an agent or --workspace.",
    )
    rb_show.add_argument("target_agent_id", nargs="?")
    rb_show.add_argument("--workspace", action="store_true")

    require_subject_token = resources.add_parser(
        "require-subject-token",
        help="Mandate: enforce calls must carry a delegated subject token.",
        description="Enforcement mandate. When enabled, enforce calls for the target "
        "agent (or whole workspace) are denied unless they present a valid subject "
        "token proving the calling identity.",
    )
    rst_commands = require_subject_token.add_subparsers(
        dest="require_subject_token_command", required=True
    )
    rst_enable = rst_commands.add_parser(
        "enable",
        help="Require a subject token at enforce time.",
        description="Enable the require-subject-token mandate for an agent or "
        "--workspace.",
    )
    rst_enable.add_argument("target_agent_id", nargs="?")
    rst_enable.add_argument("--workspace", action="store_true")
    rst_disable = rst_commands.add_parser(
        "disable",
        help="Stop requiring a subject token at enforce time.",
        description="Disable the require-subject-token mandate for an agent or "
        "--workspace.",
    )
    rst_disable.add_argument("target_agent_id", nargs="?")
    rst_disable.add_argument("--workspace", action="store_true")
    rst_show = rst_commands.add_parser(
        "show",
        help="Show the require-subject-token setting.",
        description="Show the require-subject-token mandate for an agent or "
        "--workspace.",
    )
    rst_show.add_argument("target_agent_id", nargs="?")
    rst_show.add_argument("--workspace", action="store_true")

    require_pop = resources.add_parser(
        "require-pop",
        help="Mandate: subject tokens must use proof-of-possession (PoP).",
        description="Enforcement mandate. When enabled, the target agent (or whole "
        "workspace) must present a proof-of-possession (PoP) bound subject token; a "
        "missing token or a bearer-only (non-PoP) token is rejected at enforce time.",
    )
    rp_commands = require_pop.add_subparsers(dest="require_pop_command", required=True)
    rp_enable = rp_commands.add_parser(
        "enable",
        help="Require proof-of-possession (PoP) tokens at enforce time.",
        description="Enable the require-pop mandate for an agent or --workspace.",
    )
    rp_enable.add_argument("target_agent_id", nargs="?")
    rp_enable.add_argument("--workspace", action="store_true")
    rp_disable = rp_commands.add_parser(
        "disable",
        help="Stop requiring proof-of-possession (PoP) tokens.",
        description="Disable the require-pop mandate for an agent or --workspace.",
    )
    rp_disable.add_argument("target_agent_id", nargs="?")
    rp_disable.add_argument("--workspace", action="store_true")
    rp_show = rp_commands.add_parser(
        "show",
        help="Show the require-pop setting.",
        description="Show the require-pop mandate for an agent or --workspace.",
    )
    rp_show.add_argument("target_agent_id", nargs="?")
    rp_show.add_argument("--workspace", action="store_true")

    audit = resources.add_parser(
        "audit",
        help="Inspect and export the audit log.",
        description="Inspect and export the workspace audit log.",
    )
    audit_commands = audit.add_subparsers(dest="audit_command", required=True)
    audit_list = audit_commands.add_parser(
        "list",
        help="List recent audit events (filterable).",
        description="List recent audit events, filterable by event type, grant ref, "
        "boundary id, or request id.",
    )
    audit_list.add_argument("--limit", type=int, default=20)
    audit_list.add_argument("--event")
    audit_list.add_argument("--grant-ref")
    audit_list.add_argument("--boundary-id")
    audit_list.add_argument("--request-id")
    audit_export = audit_commands.add_parser(
        "export",
        help="Export the workspace audit log as JSONL.",
        description="Export the workspace audit log as JSONL to stdout or a file.",
    )
    audit_export.add_argument("--format", choices=("jsonl",), default="jsonl")
    audit_export.add_argument("--file", type=Path)
    audit_commands.add_parser(
        "head",
        help="Print the current audit chain head (seq + row_hash) for anchoring.",
        description="Print the tip of the tamper-evidence hash chain. Record it "
        "out-of-band and pass it later to `verify --expected-head`.",
    )
    audit_verify = audit_commands.add_parser(
        "verify",
        help="Verify the audit chain is untampered (tamper-evidence).",
        description="Walk the hash chain and report the first modify/delete/reorder/"
        "column-mismatch. Exit non-zero on any break.",
    )
    audit_verify.add_argument(
        "--expected-head",
        help="Fail if the live chain head hash differs from this value "
        "(catches truncation/rollback that is internally consistent).",
    )
    audit_verify.add_argument(
        "--against-anchor",
        help="Path to a head-log (JSON lines of {seq,row_hash}); '-' for stdin. "
        "Fail if the live chain diverges from any recorded head.",
    )

    policy = resources.add_parser(
        "policy",
        help="Apply or export a workspace policy document.",
        description="Apply or export a declarative workspace policy document "
        "(bounds + auto-approval rules).",
    )
    policy_commands = policy.add_subparsers(dest="policy_command", required=True)
    policy_apply = policy_commands.add_parser(
        "apply",
        help="Apply a policy document to the workspace.",
        description="Apply a policy document (bounds + rules) to the workspace.",
    )
    policy_apply.add_argument("--file", required=True, type=Path)
    policy_export = policy_commands.add_parser(
        "export",
        help="Export the workspace's current policy to a file.",
        description="Export the workspace's current bounds and rules to a policy file.",
    )
    policy_export.add_argument("--file", required=True, type=Path)
    policy_infer = policy_commands.add_parser(
        "infer",
        help="Propose least-privilege scopes from an agent's audit trace.",
        description="Propose (never apply) a least-privilege scope set inferred from "
        "an agent's observed permitted actions in the audit log. Review, tighten, "
        "then apply with `policy apply`.",
    )
    policy_infer.add_argument("--agent", required=True, help="Agent id to infer scopes for.")
    policy_infer.add_argument("--since", help="ISO-8601 lower bound on event time (inclusive).")
    policy_infer.add_argument("--until", help="ISO-8601 upper bound on event time (inclusive).")
    policy_infer.add_argument(
        "--generalize",
        action="store_true",
        help="Collapse deep sibling resources under a terminal wildcard (opt-in).",
    )
    policy_infer.add_argument(
        "--include-denied",
        action="store_true",
        help="Also propose scopes for DENIED attempts, in a separate candidates list.",
    )
    policy_infer.add_argument("--file", type=Path, help="Write the YAML proposal to a file.")

    storage = resources.add_parser(
        "storage",
        help="Back up, restore, reset, or migrate the SQLite database.",
        description="Database maintenance: back up, restore, reset, or migrate the "
        "SQLite database.",
    )
    storage_commands = storage.add_subparsers(dest="storage_command", required=True)
    backup = storage_commands.add_parser(
        "backup",
        help="Back up the database to a file.",
        description="Back up the SQLite database to an output file.",
    )
    backup.add_argument("--output", required=True, type=Path)
    backup.add_argument("--force", action="store_true")
    reset = storage_commands.add_parser(
        "reset",
        help="Wipe and re-initialize the database (requires --yes).",
        description="Wipe and re-initialize the SQLite database. Requires --yes.",
    )
    reset.add_argument("--yes", action="store_true")
    restore = storage_commands.add_parser(
        "restore",
        help="Replace the database from a backup (requires --yes).",
        description="Replace the SQLite database from a backup file. Requires --yes.",
    )
    restore.add_argument("--input", required=True, type=Path)
    restore.add_argument("--yes", action="store_true")
    storage_commands.add_parser(
        "migrate",
        help="Migrate the database to the latest schema.",
        description="Migrate the SQLite database to the latest schema version.",
    )

    service = resources.add_parser(
        "service",
        help="Inspect the configured service/database.",
        description="Inspect the configured service runtime and database.",
    )
    service_commands = service.add_subparsers(dest="service_info_command", required=True)
    service_commands.add_parser(
        "info",
        help="Show service mode, host/port, db path, and schema version.",
        description="Show the service mode, host/port, database path, and schema "
        "version.",
    )

    keys = resources.add_parser(
        "keys",
        help="List, revoke, and rotate API keys.",
        description="Manage API keys: list, revoke, and rotate workspace/agent/PEP "
        "keys.",
    )
    keys_commands = keys.add_subparsers(dest="keys_command", required=True)
    keys_commands.add_parser(
        "list",
        help="List keys for the workspace.",
        description="List API keys for the workspace.",
    )
    keys_revoke = keys_commands.add_parser(
        "revoke",
        help="Revoke a key by id.",
        description="Revoke an API key by id.",
    )
    keys_revoke.add_argument("key_id")
    keys_rotate = keys_commands.add_parser(
        "rotate",
        help="Rotate a workspace, agent, or PEP key.",
        description="Rotate a key, issuing a new secret and revoking the old one. The "
        "raw key is printed once and cannot be recovered later.",
    )
    rotate_targets = keys_rotate.add_subparsers(dest="rotate_target", required=True)
    rotate_targets.add_parser(
        "workspace",
        help="Rotate the workspace key.",
        description="Rotate the workspace key.",
    )
    rotate_agent = rotate_targets.add_parser(
        "agent",
        help="Rotate an agent key.",
        description="Rotate the key for a specific agent.",
    )
    rotate_agent.add_argument("--agent-id", required=True)
    rotate_pep = rotate_targets.add_parser(
        "pep",
        help="Rotate a PEP (resource-server) key.",
        description="Rotate the key for a specific PEP (resource server).",
    )
    rotate_pep.add_argument("--pep-id", required=True)


def _add_demo_commands(roles: argparse._SubParsersAction) -> None:
    parser = roles.add_parser(
        "demo",
        help="Run local demonstration flows.",
        description="Self-contained demos that spin up a throwaway local service: "
        "`check` is a smoke test, `block` is the context-dependent allow/deny "
        "showcase, `service` is the fuller end-to-end walkthrough.",
    )
    commands = parser.add_subparsers(dest="demo_command", required=True)
    commands.add_parser(
        "check",
        help="Smoke test: request -> auto-approve -> enforce -> audit.",
        description="Run a minimal request -> auto-approve -> enforce -> audit smoke "
        "test against a throwaway local service.",
    )
    commands.add_parser(
        "block",
        help="Showcase: the same action allowed or denied by context.",
        description="Hero demo: show the SAME action allowed or denied depending on "
        "context (grant + resource + environment), proving this is not a denylist.",
    )
    service = commands.add_parser(
        "service",
        help="Full end-to-end walkthrough (auto + manual + boundary).",
        description="Fuller end-to-end walkthrough covering auto-approval, manual "
        "review, and repo-boundary scoping against a throwaway local service.",
    )
    service.add_argument("--scenario", default="ci")


def _dispatch(args: argparse.Namespace, *, stdout: TextIO) -> None:
    if args.role == "service":
        _service(args)
        return
    if args.role == "local":
        _local(args, stdout=stdout)
        return
    if args.role == "agent":
        _agent(args, stdout=stdout)
        return
    if args.role == "operator":
        _operator(args, stdout=stdout)
        return
    if args.role == "demo":
        _demo(args, stdout=stdout)
        return
    raise CliError(f"unknown role: {args.role}")


def _service(args: argparse.Namespace) -> None:
    if args.service_command == "serve":
        try:
            config = load_service_runtime_config(
                host=args.host,
                port=args.port,
                sqlite_db_path=args.service_db or args.db,
                log_level=args.log_level,
                service_mode=args.service_mode,
                metrics=args.metrics,
                access_log=args.access_log,
                env=os.environ,
            )
        except ValueError as error:
            raise CliError(str(error)) from error
        serve_service_runtime(config)
        return
    raise CliError(f"unknown service command: {args.service_command}")


def _local(args: argparse.Namespace, *, stdout: TextIO) -> None:
    if args.local_command == "start":
        config = _local_config(args)
        serve_local_service(config)
    if args.local_command == "env":
        body = _local_env_body(args)
        exports = _local_env_exports(body)
        if args.write_file is not None:
            _write_env_file(args.write_file, exports, force=args.force)
            body = {**body, "env_file": str(args.write_file)}
            _emit(args, body, f"wrote Vinctor env file {args.write_file}", stdout=stdout)
            return
        _emit(args, body, exports, stdout=stdout)
        return
    raise CliError(f"unknown local command: {args.local_command}")


def _agent(args: argparse.Namespace, *, stdout: TextIO) -> None:
    if args.agent_command == "requests" and args.requests_command == "create":
        status, body = _request_json(
            args.endpoint,
            "POST",
            "/v1/grant-requests",
            headers={"X-Agent-Key": _required(args.agent_key, "agent key")},
            body=_request_create_body(args),
        )
        _raise_for_status(status, body)
        summary = (
            f"created request {body['request_id']} status={body['status']} "
            f"routing={body.get('routing_hint', '-')} scopes={_scopes(body)}"
        )
        _emit(args, body, summary, stdout=stdout)
        return

    if args.agent_command == "requests" and args.requests_command == "status":
        status, body = _request_json(
            args.endpoint,
            "GET",
            f"/v1/grant-requests/{args.request_id}",
            headers={"X-Agent-Key": _required(args.agent_key, "agent key")},
        )
        _raise_for_status(status, body)
        grant_ref = body.get("issued_grant_ref") or "-"
        summary = (
            f"request {body['request_id']} status={body['status']} "
            f"grant_ref={grant_ref} scopes={_scopes(body)}"
        )
        _emit(args, body, summary, stdout=stdout)
        return

    if args.agent_command == "enforce":
        grant_ref = args.enforce_grant_ref or args.grant_ref or os.environ.get("VINCTOR_GRANT_REF")
        headers = {"X-Agent-Key": _required(args.agent_key, "agent key")}
        if args.boundary_id:
            headers["X-Vinctor-Boundary-Id"] = args.boundary_id
        status, body = _request_json(
            args.endpoint,
            "POST",
            "/v1/enforce",
            headers=headers,
            body={
                "grant_ref": _required(grant_ref, "grant ref"),
                "action": args.action,
                "resource": args.resource,
            },
        )
        if status == 403:
            _emit(
                args,
                body,
                f"{_decision_label('deny', stdout=stdout)}  "
                f"action={args.action} resource={args.resource}",
                stdout=stdout,
            )
            raise CliError(
                str(body.get("reason") or "action_denied"),
                code=EXIT_DENIED,
                quiet_json=True,
            )
        _raise_for_status(status, body)
        summary = (
            f"{_decision_label(str(body['decision']), stdout=stdout)}  "
            f"action={args.action} resource={args.resource} "
            f"audit_event_id={body.get('audit_event_id')}"
        )
        _emit(args, body, summary, stdout=stdout)
        return

    if args.agent_command == "token" and args.token_command == "mint":
        mint_body: dict[str, object] = {
            "grant_ref": _required(args.token_grant_ref, "grant ref"),
            "audience": _required(args.audience, "audience"),
            "ttl_seconds": (
                _parse_duration_seconds(args.ttl)
                if args.ttl
                else DEFAULT_SUBJECT_TOKEN_TTL_SECONDS
            ),
        }
        if args.token_action is not None:
            mint_body["action"] = args.token_action
        if args.token_resource is not None:
            mint_body["resource"] = args.token_resource
        if args.token_pop:
            mint_body["pop"] = True
        status, body = _request_json(
            args.endpoint,
            "POST",
            "/v1/tokens",
            headers={"X-Agent-Key": _required(args.agent_key, "agent key")},
            body=mint_body,
        )
        _raise_for_status(status, body)
        lines = [
            f"minted subject token token_id={body['token_id']} "
            f"expires_at={body['expires_at']}",
            f"token={body['token']}",
            "# Store this raw token now; it cannot be recovered from SQLite.",
        ]
        if "pop_secret" in body:
            lines.append(f"pop_secret={body['pop_secret']}")
            lines.append("# Store this pop_secret now; it cannot be recovered from SQLite.")
        text = "\n".join(lines)
        _emit(args, body, text, stdout=stdout)
        return

    raise CliError("unknown agent command")


def _operator(args: argparse.Namespace, *, stdout: TextIO) -> None:
    resource = args.operator_resource
    if resource == "requests":
        _operator_requests(args, stdout=stdout)
        return
    if resource == "rules":
        _operator_rules(args, stdout=stdout)
        return
    if resource == "bounds":
        _operator_bounds(args, stdout=stdout)
        return
    if resource == "tokens":
        _operator_tokens(args, stdout=stdout)
        return
    if resource == "grants":
        _operator_grants(args, stdout=stdout)
        return
    if resource == "require-boundary":
        _operator_require_boundary(args, stdout=stdout)
        return
    if resource == "require-subject-token":
        _operator_require_subject_token(args, stdout=stdout)
        return
    if resource == "require-pop":
        _operator_require_pop(args, stdout=stdout)
        return
    if resource == "audit":
        _operator_audit(args, stdout=stdout)
        return
    if resource == "policy":
        _operator_policy(args, stdout=stdout)
        return
    if resource == "storage":
        _operator_storage(args, stdout=stdout)
        return
    if resource == "service":
        _operator_service(args, stdout=stdout)
        return
    if resource == "keys":
        _operator_keys(args, stdout=stdout)
        return
    raise CliError(f"unknown operator resource: {resource}")


def _operator_requests(args: argparse.Namespace, *, stdout: TextIO) -> None:
    command = args.requests_command
    if command == "list":
        status, body = _request_json(
            args.endpoint,
            "GET",
            "/v1/grant-requests",
            headers={"X-Workspace-Key": _required(args.workspace_key, "workspace key")},
        )
        _raise_for_status(status, body)
        requests = body["grant_requests"]
        if args.status is not None and isinstance(requests, list):
            requests = [
                request
                for request in requests
                if isinstance(request, dict) and request.get("status") == args.status
            ]
            body = {"grant_requests": requests}
        _emit(args, body, _request_list_text(requests), stdout=stdout)
        return
    if command == "inbox":
        status, body = _request_json(
            args.endpoint,
            "GET",
            "/v1/grant-requests",
            headers={"X-Workspace-Key": _required(args.workspace_key, "workspace key")},
        )
        _raise_for_status(status, body)
        requests = [
            {**request, **_request_recommendation(request)}
            for request in body.get("grant_requests", [])
            if isinstance(request, dict) and request.get("status") == "pending"
        ]
        inbox_body = {"grant_requests": requests}
        _emit(args, inbox_body, _inbox_text(requests), stdout=stdout)
        return
    if command == "timeline":
        status, body = _request_json(
            args.endpoint,
            "GET",
            f"/v1/grant-requests/{args.request_id}",
            headers={"X-Workspace-Key": _required(args.workspace_key, "workspace key")},
        )
        _raise_for_status(status, body)
        events = [
            event
            for event in _sqlite_service(args.db).audit_events
            if _event_matches_request(event, args.request_id, body)
        ]
        timeline_body = {
            "request": body,
            "timeline": [_audit_body(event) for event in events],
        }
        _emit(args, timeline_body, _timeline_text(body, events), stdout=stdout)
        return
    if command == "view":
        status, body = _request_json(
            args.endpoint,
            "GET",
            f"/v1/grant-requests/{args.request_id}",
            headers={"X-Workspace-Key": _required(args.workspace_key, "workspace key")},
        )
        _raise_for_status(status, body)
        _emit(args, body, _request_text(body), stdout=stdout)
        return
    if command in {"approve", "reject"}:
        payload = {"decision_reason": args.reason} if args.reason is not None else None
        status, body = _request_json(
            args.endpoint,
            "POST",
            f"/v1/grant-requests/{args.request_id}/{command}",
            headers={"X-Workspace-Key": _required(args.workspace_key, "workspace key")},
            body=payload,
        )
        _raise_for_status(status, body)
        grant = body.get("grant")
        grant_ref = (
            grant.get("grant_ref") if isinstance(grant, dict) else body.get("issued_grant_ref")
        )
        verb = "approved" if command == "approve" else "rejected"
        _emit(
            args,
            body,
            f"{verb} request {body['request_id']} status={body['status']} "
            f"grant_ref={grant_ref or '-'}",
            stdout=stdout,
        )
        return
    if command == "evaluate":
        status, body = _request_json(
            args.endpoint,
            "POST",
            f"/v1/grant-requests/{args.request_id}/auto-approve",
            headers={"X-Workspace-Key": _required(args.workspace_key, "workspace key")},
        )
        _raise_for_status(status, body)
        auto = body.get("auto_approval")
        if isinstance(auto, dict) and auto.get("decision") == "approved":
            summary = (
                f"approved request {body['request_id']} grant_ref={body['issued_grant_ref']} "
                f"rule={auto.get('rule_id')}"
            )
        else:
            reason = auto.get("reason") if isinstance(auto, dict) else "-"
            summary = (
                f"pending request {body['request_id']} "
                f"routing=manual_review_required reason={reason}"
            )
        _emit(args, body, summary, stdout=stdout)
        return
    raise CliError(f"unknown requests command: {command}")


def _operator_grants(args: argparse.Namespace, *, stdout: TextIO) -> None:
    command = args.grants_command
    if command == "revoke":
        # Transport selection: a configured --endpoint (or VINCTOR_ENDPOINT)
        # takes precedence and uses the running service (preserving the remote-
        # operator path). Otherwise, when --db (or VINCTOR_DB) is set, revoke
        # against the SQLite DB via the same service.revoke_grant the HTTP
        # handler uses — consistent with every other operator mutation
        # (keys/tokens/require-boundary/bounds/policy/storage). The service reads
        # grants per-enforce with no cache, so direct-DB revoke is safe.
        if getattr(args, "endpoint", None) is None and getattr(args, "db", None) is not None:
            revoked = _sqlite_service(args.db).revoke_grant(
                grant_ref=args.grant_ref,
                workspace_id=args.workspace_id,
                now=datetime.now(UTC),
            )
            if revoked is None:
                raise CliError(f"unknown grant: {args.grant_ref}")
            grant, audit_event_id = revoked
            body = {
                "grant_ref": grant.grant_ref,
                "status": grant.status,
                "audit_event_id": audit_event_id,
            }
            _emit(
                args,
                body,
                f"revoked grant {grant.grant_ref} "
                f"status={grant.status} audit_event_id={audit_event_id}",
                stdout=stdout,
            )
            return
        status, body = _request_json(
            args.endpoint,
            "POST",
            f"/v1/grants/{args.grant_ref}/revoke",
            headers={"X-Workspace-Key": _required(args.workspace_key, "workspace key")},
        )
        _raise_for_status(status, body)
        _emit(
            args,
            body,
            f"revoked grant {body.get('grant_ref', args.grant_ref)} "
            f"status={body.get('status', '-')} "
            f"audit_event_id={body.get('audit_event_id', '-')}",
            stdout=stdout,
        )
        return
    raise CliError(f"unknown grants command: {command}")


def _operator_rules(args: argparse.Namespace, *, stdout: TextIO) -> None:
    command = args.rules_command
    if command == "create":
        status, body = _request_json(
            args.endpoint,
            "POST",
            "/v1/auto-approval-rules",
            headers={"X-Workspace-Key": _required(args.workspace_key, "workspace key")},
            body={
                "name": args.name,
                "target_agent_id": args.target_agent_id,
                "allowed_scopes": args.scopes,
                "max_ttl_seconds": _parse_duration_seconds(args.max_ttl),
            },
        )
        _raise_for_status(status, body)
        _emit(
            args,
            body,
            f"created rule {body['rule_id']} status={body['status']} "
            f"scopes={_scopes(body, 'allowed_scopes')}",
            stdout=stdout,
        )
        return
    if command == "list":
        status, body = _request_json(
            args.endpoint,
            "GET",
            "/v1/auto-approval-rules",
            headers={"X-Workspace-Key": _required(args.workspace_key, "workspace key")},
        )
        _raise_for_status(status, body)
        _emit(args, body, _rule_list_text(body["auto_approval_rules"]), stdout=stdout)
        return
    if command == "disable":
        status, body = _request_json(
            args.endpoint,
            "POST",
            f"/v1/auto-approval-rules/{args.rule_id}/disable",
            headers={"X-Workspace-Key": _required(args.workspace_key, "workspace key")},
        )
        _raise_for_status(status, body)
        _emit(args, body, f"disabled rule {body['rule_id']} status={body['status']}", stdout=stdout)
        return
    raise CliError(f"unknown rules command: {command}")


def _operator_bounds(args: argparse.Namespace, *, stdout: TextIO) -> None:
    service = _sqlite_service(args.db)
    agent_id = args.target_agent_id or args.agent_id
    if args.bounds_command == "set":
        max_ttl_seconds = (
            _parse_duration_seconds(args.max_ttl) if args.max_ttl is not None else None
        )
        try:
            service.set_agent_issuable_scope_bounds(
                workspace_id=args.workspace_id,
                agent_id=agent_id,
                scopes=tuple(args.scopes),
                max_ttl_seconds=max_ttl_seconds,
                now=datetime.now(UTC),
            )
        except ValueError as error:
            raise CliError(str(error)) from error
        body = {
            "workspace_id": args.workspace_id,
            "agent_id": agent_id,
            "scopes": args.scopes,
            "max_ttl_seconds": max_ttl_seconds,
        }
        _emit(
            args,
            body,
            f"set bounds workspace={args.workspace_id} agent={agent_id} "
            f"scopes={','.join(args.scopes)} max_ttl={max_ttl_seconds if max_ttl_seconds else '-'}",
            stdout=stdout,
        )
        return
    if args.bounds_command == "show":
        scopes = service.scope_bounds_repository.get_bounds(
            workspace_id=args.workspace_id,
            agent_id=agent_id,
        )
        max_ttl_seconds = service.scope_bounds_repository.get_max_ttl_seconds(
            workspace_id=args.workspace_id,
            agent_id=agent_id,
        )
        body = {
            "workspace_id": args.workspace_id,
            "agent_id": agent_id,
            "scopes": list(scopes or ()),
            "max_ttl_seconds": max_ttl_seconds,
        }
        text = (
            f"bounds workspace={args.workspace_id} agent={agent_id} "
            f"scopes={','.join(scopes)} max_ttl={max_ttl_seconds if max_ttl_seconds else '-'}"
            if scopes
            else f"no bounds workspace={args.workspace_id} agent={agent_id}"
        )
        _emit(args, body, text, stdout=stdout)
        return
    raise CliError(f"unknown bounds command: {args.bounds_command}")


def _operator_require_boundary(args: argparse.Namespace, *, stdout: TextIO) -> None:
    service = _sqlite_service(args.db)
    if args.workspace and args.target_agent_id is not None:
        raise CliError("require-boundary --workspace cannot be combined with an agent id")
    agent_id = "" if args.workspace else (args.target_agent_id or args.agent_id)
    repo = service.agent_enforcement_settings_repository
    if args.require_boundary_command in ("enable", "disable"):
        value = args.require_boundary_command == "enable"
        repo.set_require_boundary(
            workspace_id=args.workspace_id,
            agent_id=agent_id,
            require_boundary=value,
            now=datetime.now(UTC),
        )
    else:  # show
        value = repo.get_require_boundary(workspace_id=args.workspace_id, agent_id=agent_id)
    body = {
        "workspace_id": args.workspace_id,
        "agent_id": agent_id,
        "require_boundary": value,
        "scope": "workspace" if args.workspace else "agent",
    }
    _emit(
        args,
        body,
        f"require_boundary workspace={args.workspace_id} agent={agent_id} value={value}",
        stdout=stdout,
    )


def _operator_require_subject_token(args: argparse.Namespace, *, stdout: TextIO) -> None:
    service = _sqlite_service(args.db)
    if args.workspace and args.target_agent_id is not None:
        raise CliError("require-subject-token --workspace cannot be combined with an agent id")
    agent_id = "" if args.workspace else (args.target_agent_id or args.agent_id)
    repo = service.agent_enforcement_settings_repository
    if args.require_subject_token_command in ("enable", "disable"):
        value = args.require_subject_token_command == "enable"
        repo.set_require_subject_token(
            workspace_id=args.workspace_id,
            agent_id=agent_id,
            require_subject_token=value,
            now=datetime.now(UTC),
        )
    else:  # show
        setting = repo.get_require_subject_token_setting(
            workspace_id=args.workspace_id, agent_id=agent_id
        )
        value = bool(setting)
    body = {
        "workspace_id": args.workspace_id,
        "agent_id": agent_id,
        "require_subject_token": value,
        "scope": "workspace" if args.workspace else "agent",
    }
    _emit(
        args,
        body,
        f"require_subject_token workspace={args.workspace_id} agent={agent_id} value={value}",
        stdout=stdout,
    )


def _operator_require_pop(args: argparse.Namespace, *, stdout: TextIO) -> None:
    service = _sqlite_service(args.db)
    if args.workspace and args.target_agent_id is not None:
        raise CliError("require-pop --workspace cannot be combined with an agent id")
    agent_id = "" if args.workspace else (args.target_agent_id or args.agent_id)
    repo = service.agent_enforcement_settings_repository
    if args.require_pop_command in ("enable", "disable"):
        value = args.require_pop_command == "enable"
        repo.set_require_pop(
            workspace_id=args.workspace_id,
            agent_id=agent_id,
            require_pop=value,
            now=datetime.now(UTC),
        )
    else:  # show
        setting = repo.get_require_pop_setting(
            workspace_id=args.workspace_id, agent_id=agent_id
        )
        value = bool(setting)
    body = {
        "workspace_id": args.workspace_id,
        "agent_id": agent_id,
        "require_pop": value,
        "scope": "workspace" if args.workspace else "agent",
    }
    _emit(
        args,
        body,
        f"require_pop workspace={args.workspace_id} agent={agent_id} value={value}",
        stdout=stdout,
    )


def _operator_tokens(args: argparse.Namespace, *, stdout: TextIO) -> None:
    repository = _sqlite_service(args.db).subject_token_repository
    if args.tokens_command == "list":
        tokens = repository.list_subject_tokens(args.workspace_id)
        body = {"tokens": [_subject_token_row(token) for token in tokens]}
        _emit(args, body, _tokens_list_text(tokens), stdout=stdout)
        return
    if args.tokens_command == "revoke":
        revoked = repository.revoke(args.token_id, now=datetime.now(UTC))
        if not revoked:
            raise CliError(f"unknown subject token: {args.token_id}")
        body = {"token_id": args.token_id, "revoked": True}
        _emit(args, body, f"revoked subject token {args.token_id}", stdout=stdout)
        return
    raise CliError(f"unknown tokens command: {args.tokens_command}")


def _subject_token_row(token: object) -> dict[str, object]:
    return {
        "token_id": token.token_id,
        "agent_id": token.agent_id,
        "grant_ref": token.grant_ref,
        "audience": token.audience,
        "expires_at": token.expires_at.isoformat(),
        "revoked": token.revoked_at is not None,
    }


def _tokens_list_text(tokens: tuple[object, ...]) -> str:
    if not tokens:
        return "no subject tokens"
    lines = []
    for token in tokens:
        lines.append(
            f"{token.token_id} agent={token.agent_id} grant_ref={token.grant_ref} "
            f"audience={token.audience} expires={token.expires_at.isoformat()} "
            f"revoked={token.revoked_at is not None}"
        )
    return "\n".join(lines)


def _operator_audit(args: argparse.Namespace, *, stdout: TextIO) -> None:
    if args.audit_command == "head":
        seq, row_hash = _sqlite_service(args.db).audit_writer.chain_head()
        _emit(
            args,
            {"seq": seq, "row_hash": row_hash},
            f"seq={seq} row_hash={row_hash}",
            stdout=stdout,
        )
        return
    if args.audit_command == "verify":
        writer = _sqlite_service(args.db).audit_writer
        v = writer.verify_chain()
        result = {
            "ok": v.ok, "count": v.count, "head_seq": v.head_seq,
            "head_hash": v.head_hash, "break_seq": v.break_seq,
            "break_event_id": v.break_event_id, "break_kind": v.break_kind,
        }
        ok = v.ok
        if ok and args.expected_head is not None and v.head_hash != args.expected_head:
            ok = False
            result["ok"] = False
            result["expected_head_mismatch"] = True
        if ok and args.against_anchor is not None:
            raw = (
                sys.stdin.read()
                if args.against_anchor == "-"
                else Path(args.against_anchor).read_text(encoding="utf-8")
            )
            # Anchor sinks also carry storage-op trace records (see
            # audit_anchor.storage_op_line), self-identified by a "kind" key;
            # chain-head records never have one. Only chain-head records are
            # assertions about chain rows, so only they are verified.
            records = [
                AnchorRecord(seq=int(d["seq"]), row_hash=str(d["row_hash"]))
                for d in (json.loads(line) for line in raw.splitlines() if line.strip())
                if "kind" not in d
            ]
            av = writer.verify_against_anchor(records)
            result["anchor"] = {
                "ok": av.ok, "checked": av.checked,
                "covered_max_seq": av.covered_max_seq,
                "divergence_seq": av.divergence_seq,
                "divergence_kind": av.divergence_kind,
            }
            ok = ok and av.ok
        _emit(args, result, "audit chain OK" if ok else "audit chain BROKEN", stdout=stdout)
        if not ok:
            raise CliError(
                "audit chain verification failed", code=EXIT_DENIED, quiet_json=True
            )
        return
    if args.audit_command == "export":
        _operator_audit_export(args, stdout=stdout)
        return
    if args.audit_command != "list":
        raise CliError(f"unknown audit command: {args.audit_command}")
    if args.limit <= 0:
        raise CliError("audit --limit must be positive")
    events = [
        event
        for event in _sqlite_service(args.db).audit_events
        if _audit_event_matches(event, args)
    ][-args.limit :]
    body = {"audit_events": [_audit_body(event) for event in events]}
    _emit(args, body, _audit_list_text(events), stdout=stdout)


def _operator_audit_export(args: argparse.Namespace, *, stdout: TextIO) -> None:
    service = _sqlite_service(args.db)
    workspace_key = _required(args.workspace_key, "workspace key")
    identity = SQLiteLocalKeyRepository(service.conn).resolve_workspace_identity(
        workspace_key,
        now=datetime.now(UTC),
    )
    if identity is None:
        raise CliError("valid workspace key is required for audit export", code=EXIT_AUTH)

    events = service.list_filtered(identity.workspace_id)
    payload = "\n".join(json.dumps(_audit_body(event), sort_keys=True) for event in events)
    if args.file is not None:
        args.file.parent.mkdir(parents=True, exist_ok=True)
        args.file.write_text(f"{payload}\n" if payload else "", encoding="utf-8")
        print(
            f"exported audit events count={len(events)} format=jsonl file={args.file}",
            file=stdout,
        )
        return

    if payload:
        stdout.write(payload)
        stdout.write("\n")


def _operator_policy(args: argparse.Namespace, *, stdout: TextIO) -> None:
    service = _sqlite_service(args.db)
    if args.policy_command == "apply":
        try:
            result = apply_policy_file(
                args.file,
                service=service,
                workspace_id=args.workspace_id,
                applied_by=f"workspace:{args.workspace_id}",
                now=datetime.now(UTC),
            )
        except ValueError as error:
            raise CliError(str(error)) from error
        body = asdict(result)
        summary = (
            f"applied policy workspace={result.workspace_id} bounds={result.bounds_set} "
            f"rules_created={result.rules_created} rules_updated={result.rules_updated}"
        )
        _emit(args, body, summary, stdout=stdout)
        return
    if args.policy_command == "export":
        document = export_policy_document(service=service, workspace_id=args.workspace_id)
        try:
            write_policy_file(args.file, document)
        except OSError as error:
            raise CliError(f"could not write policy file: {args.file}") from error
        body = {
            "workspace_id": args.workspace_id,
            "file": str(args.file),
            "agent_bounds": len(document["agent_bounds"]),
            "auto_approval_rules": len(document["auto_approval_rules"]),
        }
        summary = (
            f"exported policy workspace={args.workspace_id} file={args.file} "
            f"bounds={body['agent_bounds']} rules={body['auto_approval_rules']}"
        )
        _emit(args, body, summary, stdout=stdout)
        return
    if args.policy_command == "infer":
        document = infer_policy_document(
            service.audit_events,
            agent_id=args.agent,
            since=args.since,
            until=args.until,
            generalize=args.generalize,
            include_denied=args.include_denied,
        )
        scope_count = len(document["proposed"]["scopes"])  # type: ignore[index]
        if args.file is not None:
            try:
                write_policy_file(args.file, document)
            except OSError as error:
                raise CliError(f"could not write policy file: {args.file}") from error
            _emit(
                args,
                {"agent_id": args.agent, "file": str(args.file), "scopes": scope_count},
                f"inferred proposal agent={args.agent} scopes={scope_count} "
                f"file={args.file} (propose-only — review, then `policy apply`)",
                stdout=stdout,
            )
            return
        if args.json or args.output == "json":
            print(json.dumps(document, sort_keys=True), file=stdout)
            return
        stdout.write(dump_policy_document(document))
        return
    raise CliError(f"unknown policy command: {args.policy_command}")


def _operator_storage(args: argparse.Namespace, *, stdout: TextIO) -> None:
    command = args.storage_command
    if command == "backup":
        db_path = Path(_required(args.db, "db"))
        try:
            result = backup_sqlite(db_path, args.output, force=args.force)
        except (FileNotFoundError, FileExistsError) as error:
            raise CliError(str(error)) from error
        body = {
            "db_path": str(result.db_path),
            "output_path": str(result.output_path),
            "bytes": result.bytes,
            "schema_versions": list(result.schema_versions),
        }
        _emit(
            args,
            body,
            f"backup db={result.db_path} output={result.output_path} bytes={result.bytes}",
            stdout=stdout,
        )
        return
    if command == "reset":
        if not args.yes:
            raise CliError("storage reset requires --yes to confirm wiping the database")
        result = reset_sqlite(Path(_required(args.db, "db")))
        body = {
            "db_path": str(result.db_path),
            "schema_versions": list(result.schema_versions),
            "reset": True,
        }
        versions = ",".join(map(str, result.schema_versions))
        _emit(args, body, f"reset db={result.db_path} schema_versions={versions}", stdout=stdout)
        return
    if command == "restore":
        if not args.yes:
            raise CliError("storage restore requires --yes to confirm replacing the database")
        try:
            result = restore_sqlite(Path(_required(args.db, "db")), args.input)
        except (FileNotFoundError, ValueError) as error:
            raise CliError(str(error)) from error
        body = {
            "db_path": str(result.db_path),
            "input_path": str(result.input_path),
            "schema_versions": list(result.schema_versions),
            "restored": True,
        }
        _emit(
            args,
            body,
            f"restore db={result.db_path} input={result.input_path}",
            stdout=stdout,
        )
        return
    if command == "migrate":
        result = migrate_sqlite(Path(_required(args.db, "db")))
        body = {
            "db_path": str(result.db_path),
            "schema_versions": list(result.schema_versions),
        }
        versions = ",".join(map(str, result.schema_versions))
        _emit(args, body, f"migrate db={result.db_path} schema_versions={versions}", stdout=stdout)
        return
    raise CliError(f"unknown storage command: {command}")


def _operator_service(args: argparse.Namespace, *, stdout: TextIO) -> None:
    if args.service_info_command != "info":
        raise CliError(f"unknown service command: {args.service_info_command}")
    config = load_service_runtime_config(sqlite_db_path=args.db, env=os.environ)
    versions = read_schema_versions(config.sqlite_db_path)
    schema_version = max(versions) if versions else None
    body = {
        "mode": config.service_mode,
        "host": config.host,
        "port": config.port,
        "db_path": str(config.sqlite_db_path),
        "schema_version": schema_version,
        "schema_versions": list(versions or ()),
        "key_storage_mode": config.key_storage_mode,
    }
    text = (
        f"service mode={config.service_mode} host={config.host} port={config.port} "
        f"db={config.sqlite_db_path} "
        f"schema_version={schema_version if schema_version is not None else '-'} "
        f"key_storage={config.key_storage_mode}"
    )
    _emit(args, body, text, stdout=stdout)


def _operator_keys(args: argparse.Namespace, *, stdout: TextIO) -> None:
    repository = SQLiteLocalKeyRepository(_sqlite_service(args.db).conn)
    command = args.keys_command
    now = datetime.now(UTC)
    if command == "list":
        records = repository.list_for_workspace(args.workspace_id)
        body = {"keys": [serialize_key_record(record) for record in records]}
        _emit(args, body, _keys_list_text(records), stdout=stdout)
        return
    if command == "revoke":
        record = repository.revoke_key(args.key_id, now=now)
        if record is None:
            raise CliError(f"unknown key: {args.key_id}")
        body = serialize_key_record(record)
        _emit(args, body, f"revoked key {record.key_id} status={record.status}", stdout=stdout)
        return
    if command == "rotate":
        if args.rotate_target == "workspace":
            result = rotate_workspace_key(repository, workspace_id=args.workspace_id, now=now)
            key_type = "workspace"
            agent_id = None
        elif args.rotate_target == "agent":
            result = rotate_agent_key(
                repository,
                workspace_id=args.workspace_id,
                agent_id=args.agent_id,
                now=now,
            )
            key_type = "agent"
            agent_id = args.agent_id
        elif args.rotate_target == "pep":
            result = rotate_pep_key(
                repository,
                workspace_id=args.workspace_id,
                pep_id=args.pep_id,
                now=now,
            )
            key_type = "resource_server"
            agent_id = args.pep_id
        else:
            raise CliError(f"unknown rotate target: {args.rotate_target}")
        body = {
            "key_id": result.new_key_id,
            "key_type": key_type,
            "agent_id": agent_id,
            "workspace_id": args.workspace_id,
            "raw_key": result.raw_key,
            "revoked_key_ids": list(result.revoked_key_ids),
        }
        revoked = ",".join(result.revoked_key_ids) or "-"
        text = "\n".join(
            [
                f"rotated {key_type} key key_id={result.new_key_id} revoked={revoked}",
                f"raw_key={result.raw_key}",
                "# Store this raw key now; it cannot be recovered from SQLite.",
            ]
        )
        _emit(args, body, text, stdout=stdout)
        return
    raise CliError(f"unknown keys command: {command}")


def _keys_list_text(records: tuple[object, ...]) -> str:
    if not records:
        return "no keys"
    lines = []
    for record in records:
        lines.append(
            f"{record.key_id} type={record.key_type} agent={record.agent_id or '-'} "
            f"status={record.status} created={record.created_at.isoformat()} "
            f"last_used={record.last_used_at.isoformat() if record.last_used_at else '-'} "
            f"revoked={record.revoked_at.isoformat() if record.revoked_at else '-'}"
        )
    return "\n".join(lines)


def _demo(args: argparse.Namespace, *, stdout: TextIO) -> None:
    if args.demo_command == "service":
        _demo_service(args, stdout=stdout)
        return
    if args.demo_command == "block":
        _demo_block(args, stdout=stdout)
        return
    if args.demo_command != "check":
        raise CliError(f"unknown demo command: {args.demo_command}")
    with TemporaryDirectory() as temp_dir:
        handle = prepare_local_service(
            LocalLaunchConfig(
                db_path=Path(temp_dir) / "vinctor.sqlite",
                port=0,
                workspace_id="ws_demo",
                agent_id="agent_runner",
                workspace_key="wsk_demo",
                agent_key="aak_demo",
                grant_ref="grt_bootstrap",
                scopes=("execute:ci/test",),
                boundary_name="claude-code-local",
            ),
            now=datetime.now(UTC),
        )
        thread = Thread(target=handle.server.serve_forever, daemon=True)
        thread.start()
        try:
            common = argparse.Namespace(
                endpoint=handle.endpoint,
                workspace_key=handle.workspace_key,
                agent_key=handle.agent_key,
                grant_ref=handle.grant_ref,
                boundary_id=handle.boundary.boundary_id if handle.boundary else None,
                json=args.json,
                output=args.output,
            )
            _request_json(
                common.endpoint,
                "POST",
                "/v1/auto-approval-rules",
                headers={"X-Workspace-Key": common.workspace_key},
                body={
                    "name": "CI auto approval",
                    "target_agent_id": "agent_runner",
                    "allowed_scopes": ["execute:ci/test"],
                    "max_ttl_seconds": 1800,
                },
            )
            _, created = _request_json(
                common.endpoint,
                "POST",
                "/v1/grant-requests",
                headers={"X-Agent-Key": common.agent_key},
                body={
                    "scopes": ["execute:ci/test"],
                    "ttl_seconds": 900,
                    "reason": "demo check",
                },
            )
            _, approved = _request_json(
                common.endpoint,
                "POST",
                f"/v1/grant-requests/{created['request_id']}/auto-approve",
                headers={"X-Workspace-Key": common.workspace_key},
            )
            _, enforced = _request_json(
                common.endpoint,
                "POST",
                "/v1/enforce",
                headers={
                    "X-Agent-Key": common.agent_key,
                    "X-Vinctor-Boundary-Id": common.boundary_id or "",
                },
                body={
                    "grant_ref": approved["issued_grant_ref"],
                    "action": "execute",
                    "resource": "ci/test",
                },
            )
            body = {
                "ok": True,
                "endpoint": handle.endpoint,
                "request_id": created["request_id"],
                "grant_ref": approved["issued_grant_ref"],
                "decision": enforced["decision"],
                "audit_event_count": len(handle.service.audit_events),
            }
            _emit(args, body, "demo check passed", stdout=stdout)
        finally:
            handle.server.shutdown()
            thread.join(timeout=5)
            handle.close()


def _demo_service(args: argparse.Namespace, *, stdout: TextIO) -> None:
    if args.scenario != "ci":
        raise CliError("only the ci demo service scenario is currently available")
    with TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        handle = prepare_local_service(
            LocalLaunchConfig(
                db_path=temp_path / "vinctor.sqlite",
                port=0,
                workspace_id="ws_demo",
                agent_id="agent_runner",
                workspace_key="wsk_demo",
                agent_key="aak_demo",
                grant_ref="grt_bootstrap",
                scopes=("execute:ci/test",),
                boundary_name="codex-local",
            ),
            now=datetime.now(UTC),
        )
        policy_path = temp_path / "policy.yaml"
        write_policy_file(
            policy_path,
            {
                "version": 1,
                "workspace_id": "ws_demo",
                "agent_bounds": [
                    {
                        "agent_id": "agent_runner",
                        "scopes": [
                            "execute:ci/test",
                            "deploy:npm/package",
                            "write:repo/vinctor-core/*",
                        ],
                    }
                ],
                "auto_approval_rules": [
                    {
                        "rule_id": "apr_ci",
                        "name": "CI auto approval",
                        "target_agent_id": "agent_runner",
                        "allowed_scopes": ["execute:ci/test"],
                        "max_ttl_seconds": 1800,
                        "status": "active",
                    }
                ],
            },
        )
        policy_result = apply_policy_file(
            policy_path,
            service=handle.service,
            workspace_id="ws_demo",
            applied_by="workspace:ws_demo",
            now=datetime.now(UTC),
        )
        thread = Thread(target=handle.server.serve_forever, daemon=True)
        thread.start()
        try:
            boundary_id = handle.boundary.boundary_id if handle.boundary else None
            ci_created = _create_demo_request(
                handle,
                scopes=["execute:ci/test"],
                ttl_seconds=900,
                reason="run CI validation",
                task_id="task-ci",
                session_id="session-demo",
                boundary_id=boundary_id,
            )
            _, ci_approved = _request_json(
                handle.endpoint,
                "POST",
                f"/v1/grant-requests/{ci_created['request_id']}/auto-approve",
                headers={"X-Workspace-Key": handle.workspace_key},
            )
            _, ci_enforced = _request_json(
                handle.endpoint,
                "POST",
                "/v1/enforce",
                headers=_agent_headers(handle, boundary_id),
                body={
                    "grant_ref": ci_approved["issued_grant_ref"],
                    "action": "execute",
                    "resource": "ci/test",
                },
            )

            deploy_created = _create_demo_request(
                handle,
                scopes=["deploy:npm/package"],
                ttl_seconds=1800,
                reason="publish demo package",
                task_id="task-deploy",
                session_id="session-demo",
                boundary_id=boundary_id,
            )
            _, deploy_evaluated = _request_json(
                handle.endpoint,
                "POST",
                f"/v1/grant-requests/{deploy_created['request_id']}/auto-approve",
                headers={"X-Workspace-Key": handle.workspace_key},
            )
            _, deploy_approved = _request_json(
                handle.endpoint,
                "POST",
                f"/v1/grant-requests/{deploy_created['request_id']}/approve",
                headers={"X-Workspace-Key": handle.workspace_key},
                body={"decision_reason": "manual operator review"},
            )
            _, deploy_enforced = _request_json(
                handle.endpoint,
                "POST",
                "/v1/enforce",
                headers=_agent_headers(handle, boundary_id),
                body={
                    "grant_ref": deploy_approved["issued_grant_ref"],
                    "action": "deploy",
                    "resource": "npm/package",
                },
            )

            repo_created = _create_demo_request(
                handle,
                scopes=["write:repo/vinctor-core/*"],
                ttl_seconds=1800,
                reason="edit core repo docs",
                task_id="task-repo-boundary",
                session_id="session-demo",
                boundary_id=boundary_id,
            )
            _, repo_approved = _request_json(
                handle.endpoint,
                "POST",
                f"/v1/grant-requests/{repo_created['request_id']}/approve",
                headers={"X-Workspace-Key": handle.workspace_key},
                body={"decision_reason": "manual repo-boundary review"},
            )
            _, repo_permit = _request_json(
                handle.endpoint,
                "POST",
                "/v1/enforce",
                headers=_agent_headers(handle, boundary_id),
                body={
                    "grant_ref": repo_approved["issued_grant_ref"],
                    "action": "write",
                    "resource": "repo/vinctor-core/README.md",
                },
            )
            sibling_status, sibling_deny = _request_json(
                handle.endpoint,
                "POST",
                "/v1/enforce",
                headers=_agent_headers(handle, boundary_id),
                body={
                    "grant_ref": repo_approved["issued_grant_ref"],
                    "action": "write",
                    "resource": "repo/vinctor-codex-hook/README.md",
                },
            )
            body = {
                "ok": True,
                "endpoint": handle.endpoint,
                "policy": asdict(policy_result),
                "auto_approved_request_id": ci_created["request_id"],
                "manual_review_request_id": deploy_created["request_id"],
                "repo_boundary_request_id": repo_created["request_id"],
                "ci_decision": ci_enforced["decision"],
                "deploy_auto_approval_reason": deploy_evaluated["auto_approval"]["reason"],
                "deploy_decision": deploy_enforced["decision"],
                "repo_core_decision": repo_permit["decision"],
                "sibling_repo_status": sibling_status,
                "sibling_repo_decision": sibling_deny["decision"],
                "audit_event_count": len(handle.service.audit_events),
                "timeline": [
                    event.event_type
                    for event in handle.service.audit_events
                    if event.grant_ref
                    in {
                        ci_created["request_id"],
                        ci_approved["issued_grant_ref"],
                        deploy_created["request_id"],
                        deploy_approved["issued_grant_ref"],
                        repo_created["request_id"],
                        repo_approved["issued_grant_ref"],
                    }
                ],
            }
            _emit(args, body, _demo_service_text(body), stdout=stdout)
        finally:
            handle.server.shutdown()
            thread.join(timeout=5)
            handle.close()


def _create_demo_request(
    handle: object,
    *,
    scopes: list[str],
    ttl_seconds: int,
    reason: str,
    task_id: str,
    session_id: str,
    boundary_id: str | None,
) -> dict[str, object]:
    _, created = _request_json(
        handle.endpoint,
        "POST",
        "/v1/grant-requests",
        headers={"X-Agent-Key": handle.agent_key},
        body={
            "scopes": scopes,
            "ttl_seconds": ttl_seconds,
            "reason": reason,
            "task_id": task_id,
            "session_id": session_id,
            "boundary_id": boundary_id,
            "requester_runtime": "codex",
            "repo": "vinctor-core",
            "worktree": "demo",
        },
    )
    return created


def _agent_headers(handle: object, boundary_id: str | None) -> dict[str, str]:
    headers = {"X-Agent-Key": handle.agent_key}
    if boundary_id is not None:
        headers["X-Vinctor-Boundary-Id"] = boundary_id
    return headers


def _demo_verdict_label(decision: object) -> str:
    text = str(decision)
    if text == "permit":
        return "✅ ALLOW"
    if text == "deny":
        return "🛑 DENY"
    return text


def _demo_service_text(body: dict[str, object]) -> str:
    verdict = _demo_verdict_label
    return "\n".join(
        [
            f"▸ Vinctor demo service running @ {body['endpoint']}",
            "  each request gets a decision — auto-approval, manual review, a boundary check:",
            "",
            (
                f"  {verdict(body['ci_decision'])}   CI test request — auto-approved by rule "
                f"({body['auto_approved_request_id']})"
            ),
            (
                f"  {verdict(body['deploy_decision'])}   deploy request — "
                f"{body['deploy_auto_approval_reason']}, then decided "
                f"({body['manual_review_request_id']})"
            ),
            (
                f"  {verdict(body['repo_core_decision'])}   in-boundary repo edit      "
                f"{verdict(body['sibling_repo_decision'])}   sibling repo, out of boundary "
                f"({body['repo_boundary_request_id']})"
            ),
            "",
            f"  {body['audit_event_count']} audit records — every decision recorded.",
        ]
    )


# Golden-path demo: the same kind of action allowed or denied by context (grant +
# resource + environment), not by a denylist. Packages existing parts
# (prepare_local_service + enforce); adds no new authorization behavior. See
# docs/superpowers/specs/2026-06-25-golden-path-demo-design.md.
_DEMO_BLOCK_GRANT_SCOPES = ("send:net/internal/*", "deploy:staging/*")
_DEMO_BLOCK_BEATS = (
    {
        "action": "send",
        "resource": "net/internal/orders-api",
        "headline": "agent fetches  net/internal/orders-api",
        "note": None,
    },
    {
        "action": "send",
        "resource": "net/external/pastebin.com",
        "headline": "agent fetches  net/external/pastebin.com",
        "note": "same fetch, external destination (exfil)",
    },
    {
        "action": "deploy",
        "resource": "production/web",
        "headline": "agent runs     deploy -> production/web",
        "note": "granted deploy:staging/*, never production",
    },
)


def _demo_block(args: argparse.Namespace, *, stdout: TextIO) -> None:
    with TemporaryDirectory() as temp_dir:
        handle = prepare_local_service(
            LocalLaunchConfig(
                db_path=Path(temp_dir) / "vinctor.sqlite",
                port=0,
                workspace_id="ws_demo",
                agent_id="agent_runner",
                workspace_key="wsk_demo",
                agent_key="aak_demo",
                grant_ref="grt_bootstrap",
                scopes=_DEMO_BLOCK_GRANT_SCOPES,
                boundary_name="claude-code-local",
            ),
            now=datetime.now(UTC),
        )
        thread = Thread(target=handle.server.serve_forever, daemon=True)
        thread.start()
        try:
            boundary_id = handle.boundary.boundary_id if handle.boundary else None
            beats: list[dict[str, object]] = []
            for beat in _DEMO_BLOCK_BEATS:
                _, enforced = _request_json(
                    handle.endpoint,
                    "POST",
                    "/v1/enforce",
                    headers=_agent_headers(handle, boundary_id),
                    body={
                        "grant_ref": "grt_bootstrap",
                        "action": beat["action"],
                        "resource": beat["resource"],
                    },
                )
                event = handle.service.audit_events[-1]
                beats.append(
                    {
                        "action": beat["action"],
                        "resource": beat["resource"],
                        "headline": beat["headline"],
                        "note": beat["note"],
                        "decision": enforced["decision"],
                        "reason": enforced.get("reason"),
                        "audit_event_id": event.event_id,
                    }
                )
            decision_events = [
                event
                for event in handle.service.audit_events
                if event.event_type in ("action_permitted", "action_denied")
            ]
            body = {
                "ok": True,
                "endpoint": handle.endpoint,
                "grant_scopes": list(_DEMO_BLOCK_GRANT_SCOPES),
                "beats": beats,
                "audit_event_count": len(decision_events),
            }
            _emit(args, body, _demo_block_text(body), stdout=stdout)
        finally:
            handle.server.shutdown()
            thread.join(timeout=5)
            handle.close()


def _demo_block_text(body: dict[str, object]) -> str:
    scopes = ",  ".join(body["grant_scopes"])
    lines = [
        f"▸ Vinctor running. this agent's grant:  {scopes}",
        "  the SAME action is allowed or denied by context -- this is not a denylist.",
        "",
    ]
    for beat in body["beats"]:
        scope = f"{beat['action']}:{beat['resource']}"
        lines.append(f"▸ {beat['headline']}")
        if beat["decision"] == "permit":
            lines.append(f"  ✅ ALLOW   {scope} -- within grant")
        else:
            lines.append(
                f"  \U0001f6d1 DENY    {scope} -- outside grant     "
                f"audit ✓ {beat['audit_event_id']}"
            )
            if beat["note"]:
                lines.append(f"            {beat['note']}")
        lines.append("")
    lines.append(
        f"▸ {len(body['beats'])} decisions · {body['audit_event_count']} "
        "audit records · nothing out-of-scope ran."
    )
    lines.append(
        "  Vinctor authorizes mediated tool calls; it is not a sandbox."
    )
    return "\n".join(lines)


def _local_config(args: argparse.Namespace) -> LocalLaunchConfig:
    return LocalLaunchConfig(
        db_path=args.db,
        host=args.host,
        port=args.port,
        workspace_id=args.workspace_id,
        agent_id=args.agent_id,
        workspace_key=args.workspace_key,
        agent_key=args.agent_key,
        grant_id=args.grant_id,
        grant_ref=args.grant_ref,
        scopes=tuple(args.scopes or [DEFAULT_SCOPE]),
        grant_ttl_hours=args.grant_ttl_hours,
        boundary_name=args.boundary_name,
        boundary_runtime=args.boundary_runtime,
        boundary_type=args.boundary_type,
    )


def _request_json(
    endpoint: str | None,
    method: str,
    path: str,
    *,
    headers: dict[str, str],
    body: object | None = None,
) -> tuple[int, dict[str, object]]:
    endpoint_value = _required(endpoint, "endpoint")
    parsed = urlsplit(endpoint_value)
    if parsed.scheme != "http" or parsed.hostname is None or parsed.port is None:
        raise CliError("endpoint must look like http://127.0.0.1:8765")

    request_headers = {"Content-Type": "application/json", **headers}
    conn = HTTPConnection(parsed.hostname, parsed.port, timeout=5)
    try:
        conn.request(
            method,
            path,
            body=None if body is None else json.dumps(body),
            headers=request_headers,
        )
        response = conn.getresponse()
        raw = response.read()
    except ValueError as error:
        # http.client rejects header values that carry control chars / embedded
        # newlines (e.g. a malformed --agent-key/--workspace-key) with a raw
        # ValueError. Surface it as a clean one-line credential error instead of
        # letting the traceback escape.
        raise CliError(
            "invalid credential: contains illegal characters", code=EXIT_AUTH
        ) from error
    except OSError as error:
        raise CliError(f"service unavailable: {error}", code=EXIT_SERVICE) from error
    finally:
        conn.close()
    try:
        parsed_body = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CliError("service returned non-JSON response", code=EXIT_SERVICE) from error
    if not isinstance(parsed_body, dict):
        raise CliError("service returned non-object JSON response", code=EXIT_SERVICE)
    return response.status, parsed_body


def _raise_for_status(status: int, body: dict[str, object]) -> None:
    if 200 <= status < 300:
        return
    error = str(body.get("error") or "error")
    reason = str(body.get("reason") or error)
    if status == 401:
        raise CliError(f"{status} {error}: {reason}", code=EXIT_AUTH)
    if status == 403:
        raise CliError(f"{status} {error}: {reason}", code=EXIT_DENIED)
    if status >= 500:
        raise CliError(f"{status} {error}: {reason}", code=EXIT_SERVICE)
    raise CliError(f"{status} {error}: {reason}")


def _sqlite_service(db_path: Path | None) -> SQLiteV1Service:
    path = _required(db_path, "db")
    conn = sqlite3.connect(path)
    return SQLiteV1Service(conn)


def _required(value: object | None, name: str) -> str:
    if value is None or value == "":
        raise CliError(f"{name} is required")
    return str(value)


def _parse_duration_seconds(raw: str) -> int:
    if raw.isdigit():
        value = int(raw)
    else:
        suffix = raw[-1]
        number = raw[:-1]
        if not number.isdigit() or suffix not in {"s", "m", "h"}:
            raise CliError(f"invalid duration: {raw}")
        multiplier = {"s": 1, "m": 60, "h": 3600}[suffix]
        value = int(number) * multiplier
    if value <= 0:
        raise CliError("duration must be positive")
    return value


def _request_create_body(args: argparse.Namespace) -> dict[str, object]:
    body: dict[str, object] = {
        "scopes": args.scopes,
        "ttl_seconds": _parse_duration_seconds(args.ttl),
        "reason": args.reason,
    }
    metadata = {
        "task_id": args.task_id,
        "session_id": args.session_id,
        "boundary_id": args.request_boundary_id or args.boundary_id,
        "requester_runtime": args.requester_runtime,
        "repo": args.repo,
        "worktree": args.worktree,
    }
    body.update({key: value for key, value in metadata.items() if value is not None})
    return body


def _emit(
    args: argparse.Namespace,
    body: dict[str, object],
    text: str,
    *,
    stdout: TextIO,
) -> None:
    if args.json or args.output == "json":
        print(json.dumps(body, sort_keys=True), file=stdout)
    else:
        print(text, file=stdout)


def _emit_error(args: argparse.Namespace, error: CliError, *, stderr: TextIO) -> None:
    if getattr(args, "json", False) or getattr(args, "output", None) == "json":
        if error.quiet_json:
            # The caller already emitted a structured decision to stdout (e.g. the
            # enforce-deny case); avoid printing a second JSON object to stderr.
            return
        print(json.dumps({"ok": False, "error": str(error), "exit_code": error.code}), file=stderr)
    else:
        print(f"error: {error}", file=stderr)


def _decision_label(decision: str, *, stdout: TextIO) -> str:
    """Human-readable ALLOW/DENY prefix for enforce output.

    Colored only when stdout is a real terminal, so piped/captured output (and
    JSON mode, which never uses this) stays free of escape codes.
    """
    if decision == "permit":
        label, ansi = "✅ ALLOW", "\033[1;32m"
    else:
        label, ansi = "🛑 DENY", "\033[1;31m"
    isatty = getattr(stdout, "isatty", None)
    if callable(isatty) and isatty():
        return f"{ansi}{label}\033[0m"
    return label


def _scopes(body: dict[str, object], key: str = "requested_scopes") -> str:
    value = body.get(key, [])
    if not isinstance(value, list):
        return "-"
    return ",".join(str(scope) for scope in value)


def _request_text(body: dict[str, object]) -> str:
    metadata = _metadata_text(body)
    head = (
        f"{body['request_id']} status={body['status']} requester={body['requester_agent_id']} "
        f"target={body['target_agent_id']} ttl={body['requested_ttl_seconds']} "
        f"scopes={_scopes(body)} issued={body.get('issued_grant_ref') or '-'} "
    )
    # Routing/queue_reason reflect the pending-review intake and are stale once the
    # request is decided; status is authoritative, so omit them for decided requests.
    if body.get("status") == "pending":
        routing = body.get("routing_hint") or "-"
        queue_reason = body.get("queue_reason") or body.get("routing_reason") or "-"
        head += f"routing={routing} queue_reason={queue_reason} "
    return f"{head}{metadata} reason={body['reason']}"


def _request_list_text(requests: object) -> str:
    if not isinstance(requests, list) or not requests:
        return "no grant requests"
    return "\n".join(_request_text(request) for request in requests if isinstance(request, dict))


def _rule_list_text(rules: object) -> str:
    if not isinstance(rules, list) or not rules:
        return "no auto-approval rules"
    lines = []
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        lines.append(
            f"{rule['rule_id']} status={rule['status']} target={rule['target_agent_id']} "
            f"max_ttl={rule['max_ttl_seconds']} scopes={_scopes(rule, 'allowed_scopes')} "
            f"name={rule['name']}"
        )
    return "\n".join(lines)


def _request_recommendation(request: dict[str, object]) -> dict[str, object]:
    scopes = [str(scope) for scope in request.get("requested_scopes", [])]
    ttl = int(request.get("requested_ttl_seconds", 0))
    routing = str(request.get("routing_hint") or "")
    reason = str(request.get("queue_reason") or request.get("routing_reason") or "")
    high_risk_terms = ("deploy:", "delete:", "production", "refund", "migration")
    medium_risk_terms = ("write:", "secret", "credential")
    if any(any(term in scope for term in high_risk_terms) for scope in scopes):
        risk = "high"
        action = "manual_review"
    elif ttl > 3600:
        risk = "medium"
        action = "manual_review"
    elif routing == "auto_approval_available":
        risk = "low"
        action = "evaluate"
    elif any(any(term in scope for term in medium_risk_terms) for scope in scopes):
        risk = "medium"
        action = "manual_review"
    else:
        risk = "medium"
        action = "manual_review" if reason == "no_matching_rule" else "evaluate"
    return {"risk": risk, "recommended_action": action}


def _inbox_text(requests: list[dict[str, object]]) -> str:
    if not requests:
        return "no pending grant requests"
    lines = []
    for request in requests:
        lines.append(
            f"{request['request_id']} risk={request['risk']} "
            f"recommended={request['recommended_action']} ttl={request['requested_ttl_seconds']} "
            f"reason={request.get('queue_reason') or request.get('routing_reason') or '-'} "
            f"scopes={_scopes(request)} {_metadata_text(request)}"
        )
    return "\n".join(lines)


def _timeline_text(request: dict[str, object], events: list[object]) -> str:
    if not events:
        return f"{request['request_id']} has no matching audit events"
    return " -> ".join(event.event_type for event in events)


def _event_matches_request(event: object, request_id: str, request: dict[str, object]) -> bool:
    issued_grant_ref = request.get("issued_grant_ref")
    resource = f"grant_request/{request_id}"
    refs = {request_id}
    if isinstance(issued_grant_ref, str) and issued_grant_ref:
        refs.add(issued_grant_ref)
    return event.grant_ref in refs or event.grant_id in refs or event.resource == resource


def _metadata_text(body: dict[str, object]) -> str:
    parts = []
    for key in ("task_id", "session_id", "boundary_id", "requester_runtime", "repo", "worktree"):
        value = body.get(key)
        if value:
            parts.append(f"{key}={value}")
    return "metadata=-" if not parts else "metadata=" + ",".join(parts)


def _audit_event_matches(event: object, args: argparse.Namespace) -> bool:
    if args.event and event.event_type != args.event:
        return False
    if args.grant_ref and event.grant_ref != args.grant_ref:
        return False
    if args.boundary_id and event.boundary_id != args.boundary_id:
        return False
    if args.request_id:
        request_resource = f"grant_request/{args.request_id}"
        if args.request_id not in {event.grant_id, event.grant_ref} and (
            event.resource != request_resource
        ):
            return False
    return True


def _audit_body(event: object) -> dict[str, object]:
    body = asdict(event)
    created_at = body.get("created_at")
    if isinstance(created_at, datetime):
        body["created_at"] = created_at.isoformat()
    return body


def _audit_list_text(events: list[object]) -> str:
    if not events:
        return "no audit events"
    lines = []
    for event in events:
        lines.append(
            f"{event.created_at.isoformat()} {event.event_type} "
            f"decision={event.decision} reason={event.reason} "
            f"agent={event.agent_id} grant_ref={event.grant_ref} "
            f"action={event.action} resource={event.resource} "
            f"scope={event.scope_matched or '-'} boundary={event.boundary_id or '-'}"
        )
    return "\n".join(lines)


def _local_handle_body(handle: object) -> dict[str, object]:
    boundary = getattr(handle, "boundary", None)
    grant = getattr(handle, "grant", None)
    return {
        "endpoint": handle.endpoint,
        "workspace_key": handle.workspace_key,
        "agent_key": handle.agent_key,
        "grant_ref": grant.grant_ref if isinstance(grant, Grant) else None,
        "boundary_id": boundary.boundary_id if boundary is not None else None,
        "db_path": str(handle.db_path),
    }


def _local_env_body(args: argparse.Namespace) -> dict[str, object]:
    return {
        "endpoint": _required(args.endpoint, "endpoint"),
        "workspace_key": _required(args.workspace_key, "workspace key"),
        "agent_key": _required(args.agent_key, "agent key"),
        "grant_ref": _required(args.grant_ref, "grant ref"),
        "boundary_id": args.boundary_id,
    }


def _local_env_exports(body: dict[str, object]) -> str:
    lines = [
        f'export VINCTOR_ENDPOINT="{body["endpoint"]}"',
        f'export VINCTOR_AGENT_KEY="{body["agent_key"]}"',
        f'export VINCTOR_GRANT_REF="{body["grant_ref"]}"',
        f'export VINCTOR_WORKSPACE_KEY="{body["workspace_key"]}"',
    ]
    if body.get("boundary_id"):
        lines.append(f'export VINCTOR_BOUNDARY_ID="{body["boundary_id"]}"')
    return "\n".join(lines)


def _write_env_file(path: Path, exports: str, *, force: bool) -> None:
    if path.exists() and not force:
        raise CliError(f"env file already exists: {path}; pass --force to overwrite")
    path.parent.mkdir(parents=True, exist_ok=True)
    content = "\n".join(
        [
            "# Vinctor local env file.",
            "# Test/dev only. Keep raw keys out of git.",
            exports,
            "",
        ]
    )
    path.write_text(content, encoding="utf-8")


if __name__ == "__main__":
    main()
