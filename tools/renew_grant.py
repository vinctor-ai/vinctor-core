#!/usr/bin/env python3
"""Renew an agent's grant from an OPERATOR-ONLY shell (PKA-250).

Grants expire. Renewing one requires workspace/operator authority, and the
obvious way to do that — run `vinctor operator ...` in the shell the agent
already runs in — puts the operator key inside the agent's environment. An agent
that can read `VINCTOR_WORKSPACE_KEY` can approve its own grant requests and
widen its own issuable scope bounds, which is the one thing the architecture
exists to prevent. Privilege separation is not a property of the key; it is a
property of which process can read it.

So renewal runs HERE, in a shell the agent has no access to, and the only thing
that crosses back to the agent is the new grant_ref — which is not a credential
and confers nothing on its own.

    # operator shell (has VINCTOR_WORKSPACE_KEY, must NOT have VINCTOR_AGENT_KEY)
    export VINCTOR_WORKSPACE_KEY="wsk_..."
    python tools/renew_grant.py \
      --endpoint https://vinctor.example.com \
      --agent-id agent_release \
      --scope "write:repo/feature/*" \
      --ttl 3600
    export VINCTOR_GRANT_REF="grt_..."      # <- the only line printed

    # agent shell: set VINCTOR_GRANT_REF to that value. Nothing else changes.

The workspace key is never accepted on the command line: argv is world-readable
through `ps` for the life of the process. Use the environment or --key-file.

This is a standalone operator script. It is not part of the installed package
and imports nothing from vinctor.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from typing import TextIO

WORKSPACE_KEY_ENV = "VINCTOR_WORKSPACE_KEY"
AGENT_KEY_ENV = "VINCTOR_AGENT_KEY"

SHARED_SHELL_ERROR = (
    f"refusing to run: {AGENT_KEY_ENV} is set in this environment.\n"
    f"This script carries operator authority, so a shell that also holds the\n"
    f"agent key has already collapsed the separation renewal exists to keep --\n"
    f"anything that can read the agent key can read {WORKSPACE_KEY_ENV} beside\n"
    f"it and issue its own grants.\n"
    f"Run this from an operator-only shell and hand the printed grant_ref to\n"
    f"the agent; the agent never needs {WORKSPACE_KEY_ENV}."
)


class RenewalError(Exception):
    """An operator-facing failure, reported on one line without a traceback."""


def resolve_workspace_key(env: dict[str, str], key_file: str | None) -> str:
    """Read the operator key from the environment or a file -- never from argv.

    Refuses outright when the agent key is present: this script is defined by
    running outside the agent's environment, so both keys in one environment is
    a configuration error, not something to warn about and continue past.
    """
    if AGENT_KEY_ENV in env:
        raise RenewalError(SHARED_SHELL_ERROR)
    if key_file is not None:
        try:
            with open(key_file, encoding="utf-8") as handle:
                key = handle.read().strip()
        except OSError as error:
            raise RenewalError(f"cannot read --key-file: {error}") from error
        if not key:
            raise RenewalError(f"--key-file is empty: {key_file}")
        return key
    key = env.get(WORKSPACE_KEY_ENV, "").strip()
    if not key:
        raise RenewalError(
            f"{WORKSPACE_KEY_ENV} is not set. Export it in this operator-only "
            "shell, or pass --key-file. It is deliberately not accepted as a "
            "command-line argument: argv is readable by every process on the host."
        )
    return key


def issue_grant(
    *,
    endpoint: str,
    workspace_key: str,
    agent_id: str,
    scopes: tuple[str, ...],
    ttl_seconds: int,
    timeout: float = 30.0,
) -> str:
    """POST /v1/grants and return the new grant_ref."""
    payload = json.dumps(
        {"agent_id": agent_id, "scopes": list(scopes), "ttl_seconds": ttl_seconds}
    ).encode("utf-8")
    request = urllib.request.Request(
        endpoint.rstrip("/") + "/v1/grants",
        data=payload,
        headers={
            "Content-Type": "application/json",
            "X-Workspace-Key": workspace_key,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", "replace").strip()
        raise RenewalError(f"grant issuance failed: HTTP {error.code} {detail}") from error
    except urllib.error.URLError as error:
        raise RenewalError(f"cannot reach {endpoint}: {error.reason}") from error
    except json.JSONDecodeError as error:
        raise RenewalError("grant issuance returned a non-JSON body") from error

    grant_ref = body.get("grant_ref")
    if not isinstance(grant_ref, str) or not grant_ref:
        raise RenewalError("grant issuance returned no grant_ref")
    return grant_ref


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Renew an agent's grant from an operator-only shell.",
        epilog=(
            "The workspace key comes from $VINCTOR_WORKSPACE_KEY or --key-file, "
            "never from the command line."
        ),
    )
    parser.add_argument("--endpoint", required=True, help="Vinctor service base URL")
    parser.add_argument("--agent-id", required=True, help="agent the grant is for")
    parser.add_argument(
        "--scope", action="append", required=True, dest="scopes",
        help="scope to grant; repeat for several",
    )
    parser.add_argument(
        "--ttl", type=int, required=True, dest="ttl_seconds",
        help="grant lifetime in seconds",
    )
    parser.add_argument(
        "--key-file",
        help="file holding the workspace key, for shells that do not export it",
    )
    return parser


def main(
    argv: list[str] | None = None,
    *,
    env: dict[str, str] | None = None,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    args = _parser().parse_args(argv)
    try:
        workspace_key = resolve_workspace_key(
            dict(os.environ if env is None else env), args.key_file
        )
        if args.ttl_seconds <= 0:
            raise RenewalError("--ttl must be a positive number of seconds")
        grant_ref = issue_grant(
            endpoint=args.endpoint,
            workspace_key=workspace_key,
            agent_id=args.agent_id,
            scopes=tuple(args.scopes),
            ttl_seconds=args.ttl_seconds,
        )
    except RenewalError as error:
        print(f"error: {error}", file=stderr)
        return 1
    # The ONLY thing that crosses back to the agent's shell. No key is printed.
    print(f'export VINCTOR_GRANT_REF="{grant_ref}"', file=stdout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
