"""The renewal procedure must never place an operator key in the agent's
environment (PKA-250).

The documentation warned operators to keep the workspace key in an operator-only
shell, and then documented a renewal flow that runs `vinctor operator ...` in the
shell the agent already runs in. An agent that can read `VINCTOR_WORKSPACE_KEY`
can approve its own grant requests and widen its own issuable scope bounds.

`tools/renew_grant.py` is the operator-only procedure: it runs outside the
agent's environment and hands back only the new grant_ref.

Everything credential-shaped below is a DECOY string. The service under test is
an in-process loopback server; no external host is contacted.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from http.server import ThreadingHTTPServer
from io import StringIO
from threading import Thread

import pytest

from tools.renew_grant import (
    AGENT_KEY_ENV,
    WORKSPACE_KEY_ENV,
    RenewalError,
    issue_grant,
    main,
    resolve_workspace_key,
)
from vinctor_service import (
    AgentIdentity,
    SQLiteV1Service,
    WorkspaceIdentity,
    create_v1_http_server,
)
from vinctor_service.sqlite_txn import connect_sqlite

NOW = datetime(2026, 8, 5, 12, 0, tzinfo=UTC)
DECOY_WORKSPACE_KEY = "wsk_decoy_not_a_real_key"
DECOY_AGENT_KEY = "aak_decoy_not_a_real_key"


@contextmanager
def _running_service(tmp_path) -> Iterator[str]:
    conn = connect_sqlite(tmp_path / "renew.sqlite", check_same_thread=False)
    service = SQLiteV1Service(conn)
    service.set_agent_issuable_scope_bounds(
        workspace_id="ws_decoy", agent_id="agent_decoy",
        scopes=("write:repo/feature/*",), now=NOW,
    )
    # Fresh 0.6.0 databases require a boundary. This file is about where the
    # operator key lives during renewal, not boundary enforcement, so the
    # mandate is turned off rather than satisfied.
    service.agent_enforcement_settings_repository.set_require_boundary(
        workspace_id="ws_decoy", agent_id="agent_decoy",
        require_boundary=False, now=NOW,
    )
    server: ThreadingHTTPServer = create_v1_http_server(
        ("127.0.0.1", 0),
        service=service,
        agent_identities={
            DECOY_AGENT_KEY: AgentIdentity(
                workspace_id="ws_decoy", agent_id="agent_decoy"
            )
        },
        workspace_identities={
            DECOY_WORKSPACE_KEY: WorkspaceIdentity(workspace_id="ws_decoy")
        },
        clock=lambda: NOW,
    )
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()
        conn.close()


# --- the separation the script exists to keep --------------------------------


def test_refuses_to_run_when_the_agent_key_is_in_the_same_environment() -> None:
    env = {WORKSPACE_KEY_ENV: DECOY_WORKSPACE_KEY, AGENT_KEY_ENV: DECOY_AGENT_KEY}
    with pytest.raises(RenewalError) as caught:
        resolve_workspace_key(env, None)
    message = str(caught.value)
    assert "refusing to run" in message
    assert AGENT_KEY_ENV in message


def test_refusal_is_a_hard_error_not_a_warning(tmp_path) -> None:
    # A collapsed environment must not renew anything, so the exit status is
    # non-zero and stdout carries nothing a shell would eval.
    stdout, stderr = StringIO(), StringIO()
    status = main(
        ["--endpoint", "http://127.0.0.1:1", "--agent-id", "agent_decoy",
         "--scope", "write:repo/feature/*", "--ttl", "3600"],
        env={WORKSPACE_KEY_ENV: DECOY_WORKSPACE_KEY, AGENT_KEY_ENV: DECOY_AGENT_KEY},
        stdout=stdout, stderr=stderr,
    )
    assert status == 1
    assert stdout.getvalue() == ""
    assert "refusing to run" in stderr.getvalue()


def test_the_agent_key_alone_in_the_environment_is_not_enough() -> None:
    with pytest.raises(RenewalError, match=WORKSPACE_KEY_ENV):
        resolve_workspace_key({}, None)


def test_key_file_is_read_only_from_an_operator_only_environment(tmp_path) -> None:
    key_file = tmp_path / "workspace.key"
    key_file.write_text(f"{DECOY_WORKSPACE_KEY}\n", encoding="utf-8")
    assert resolve_workspace_key({}, str(key_file)) == DECOY_WORKSPACE_KEY
    # ...and the refusal still wins over an explicit --key-file.
    with pytest.raises(RenewalError, match="refusing to run"):
        resolve_workspace_key({AGENT_KEY_ENV: DECOY_AGENT_KEY}, str(key_file))


def test_the_workspace_key_is_never_a_command_line_argument() -> None:
    # argv is world-readable via `ps`. Nothing in the parser may accept the key.
    from tools.renew_grant import _parser

    options = {
        option
        for action in _parser()._actions
        for option in action.option_strings
    }
    assert not any("workspace-key" in option for option in options)
    assert "--key-file" in options


# --- it actually renews ------------------------------------------------------


def test_renews_a_grant_and_prints_only_the_grant_ref(tmp_path) -> None:
    with _running_service(tmp_path) as endpoint:
        stdout, stderr = StringIO(), StringIO()
        status = main(
            ["--endpoint", endpoint, "--agent-id", "agent_decoy",
             "--scope", "write:repo/feature/*", "--ttl", "3600"],
            env={WORKSPACE_KEY_ENV: DECOY_WORKSPACE_KEY},
            stdout=stdout, stderr=stderr,
        )

    out = stdout.getvalue()
    assert status == 0, stderr.getvalue()
    assert out.startswith('export VINCTOR_GRANT_REF="grt')
    # The handoff carries the grant_ref and nothing else — no key of any kind.
    assert DECOY_WORKSPACE_KEY not in out
    assert DECOY_AGENT_KEY not in out
    assert len(out.strip().splitlines()) == 1


def test_reports_an_authentication_failure_on_one_line(tmp_path) -> None:
    with _running_service(tmp_path) as endpoint:
        stdout, stderr = StringIO(), StringIO()
        status = main(
            ["--endpoint", endpoint, "--agent-id", "agent_decoy",
             "--scope", "write:repo/feature/*", "--ttl", "3600"],
            env={WORKSPACE_KEY_ENV: "wsk_decoy_wrong"},
            stdout=stdout, stderr=stderr,
        )

    assert status == 1
    assert stdout.getvalue() == ""
    assert stderr.getvalue().startswith("error: grant issuance failed: HTTP 401")


def test_the_renewed_grant_really_authorizes_the_agent(tmp_path) -> None:
    # Positive control: the printed grant_ref is a working grant, so the test
    # above is not passing on a service that issued nothing usable.
    from http.client import HTTPConnection

    with _running_service(tmp_path) as endpoint:
        grant_ref = issue_grant(
            endpoint=endpoint,
            workspace_key=DECOY_WORKSPACE_KEY,
            agent_id="agent_decoy",
            scopes=("write:repo/feature/*",),
            ttl_seconds=3600,
        )
        host_port = endpoint.removeprefix("http://")
        conn = HTTPConnection(host_port, timeout=5)
        conn.request(
            "POST", "/v1/enforce",
            body=json.dumps({
                "grant_ref": grant_ref, "action": "write",
                "resource": "repo/feature/readme",
            }),
            headers={"Content-Type": "application/json",
                     "X-Agent-Key": DECOY_AGENT_KEY},
        )
        response = conn.getresponse()
        decision = json.loads(response.read().decode())
        conn.close()

    assert response.status == 200
    assert decision["decision"] == "permit"


def test_grant_expiry_moves_forward_on_renewal(tmp_path) -> None:
    with _running_service(tmp_path) as endpoint:
        short = issue_grant(
            endpoint=endpoint, workspace_key=DECOY_WORKSPACE_KEY,
            agent_id="agent_decoy", scopes=("write:repo/feature/*",),
            ttl_seconds=60,
        )
        renewed = issue_grant(
            endpoint=endpoint, workspace_key=DECOY_WORKSPACE_KEY,
            agent_id="agent_decoy", scopes=("write:repo/feature/*",),
            ttl_seconds=int(timedelta(hours=8).total_seconds()),
        )
    assert renewed != short
