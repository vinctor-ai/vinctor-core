from __future__ import annotations

import json
import sys
from http.client import HTTPConnection
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.mock_vinctor_service import (
    MOCK_AGENT_KEY,
    MOCK_GRANT_REF,
    MockDecisionConfig,
    create_mock_server,
    run_server_in_thread,
)


def main() -> None:
    server = create_mock_server(
        ("127.0.0.1", 0),
        config=MockDecisionConfig(
            default_decision="deny",
            permit=frozenset({"execute:ci/test"}),
            deny=frozenset({"deploy:npm/package"}),
        ),
    )
    thread = run_server_in_thread(server)
    try:
        permit_status, permit = post_json(
            server,
            {"grant_ref": MOCK_GRANT_REF, "action": "execute", "resource": "ci/test"},
        )
        deny_status, deny = post_json(
            server,
            {"grant_ref": MOCK_GRANT_REF, "action": "deploy", "resource": "npm/package"},
        )
        malformed_status, malformed = post_json(
            server,
            {
                "grant_ref": MOCK_GRANT_REF,
                "action": "execute",
                "resource": "ci/test",
                "boundary_id": "bnd_body",
            },
        )

        assert permit_status == 200
        assert permit["decision"] == "permit"
        assert permit["audit_event_id"].startswith("evt_mock_")
        assert deny_status == 403
        assert deny["decision"] == "deny"
        assert deny["reason"] == "action_denied"
        assert malformed_status == 400
        assert malformed["reason"] == "unexpected field: boundary_id"
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()

    print("ALL MOCK VINCTOR SERVICE STEPS PASSED ✓")


def post_json(server, payload: dict[str, object]) -> tuple[int, dict[str, object]]:
    host, port = server.server_address
    conn = HTTPConnection(host, port, timeout=5)
    conn.request(
        "POST",
        "/v1/enforce",
        body=json.dumps(payload),
        headers={"Content-Type": "application/json", "X-Agent-Key": MOCK_AGENT_KEY},
    )
    response = conn.getresponse()
    response_body = json.loads(response.read().decode("utf-8"))
    conn.close()
    return response.status, response_body


if __name__ == "__main__":
    main()
