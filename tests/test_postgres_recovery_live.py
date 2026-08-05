from __future__ import annotations

import base64
import json
from collections.abc import Iterator
from contextlib import contextmanager
from http.client import HTTPConnection
from threading import Thread

from vinctor_service.idempotency_keyring import load_idempotency_keyring
from vinctor_service.postgres import connect_postgres
from vinctor_service.service_config import ServiceRuntimeConfig
from vinctor_service.service_runtime import ServiceRuntimeHandle, prepare_service_runtime


@contextmanager
def _running_runtime(handle: ServiceRuntimeHandle) -> Iterator[None]:
    thread = Thread(target=handle.server.serve_forever, daemon=True)
    thread.start()
    try:
        yield
    finally:
        handle.server.shutdown()
        thread.join(timeout=5)


def _request(handle: ServiceRuntimeHandle, path: str) -> tuple[int, dict[str, str], str]:
    host, port = handle.server.server_address
    connection = HTTPConnection(host, port, timeout=10)
    try:
        connection.request("GET", path)
        response = connection.getresponse()
        raw = response.read().decode("utf-8")
        return response.status, json.loads(raw), raw
    finally:
        connection.close()


def test_postgres_readyz_recovers_after_backend_termination(
    requires_postgres: str,
) -> None:
    # Given a live PostgreSQL 16 runtime whose process-owned backend is terminated.
    encoded_key = base64.b64encode(b"k" * 32).decode("ascii")
    keyring = load_idempotency_keyring(
        {
            "VINCTOR_IDEMPOTENCY_KEYRING_JSON": f'{{"primary":"{encoded_key}"}}',
            "VINCTOR_IDEMPOTENCY_ACTIVE_KEY_VERSION": "primary",
        }
    )
    handle = prepare_service_runtime(
        ServiceRuntimeConfig(
            storage_backend="postgres",
            postgres_dsn=requires_postgres,
            service_mode="self_hosted",
            port=0,
            idempotency_keyring=keyring,
        )
    )
    try:
        killer = connect_postgres(requires_postgres)
        try:
            with handle.conn.transaction():
                backend_pid = handle.conn.execute("SELECT pg_backend_pid()").fetchone()[0]
            with killer.transaction():
                terminated = killer.execute(
                    "SELECT pg_terminate_backend(%s, 5000)",
                    (backend_pid,),
                ).fetchone()
            assert terminated == (True,)

            # When consecutive readiness probes observe the failed and replacement
            # connections, with a liveness probe against the dead backend in between.
            with _running_runtime(handle):
                unavailable_status, unavailable_body, unavailable_raw = _request(handle, "/readyz")
                live_status, live_body, _ = _request(handle, "/healthz")
                recovered_status, recovered_body, recovered_raw = _request(handle, "/readyz")

                # Asserted HERE, before any cleanup. Run from a finally block
                # instead, a raising handle.close() skips the assertions
                # entirely and reports a teardown failure in place of whatever
                # recovery actually did — which is how a readiness regression
                # reached CI looking like a shutdown bug.
                assert unavailable_status == 503
                assert unavailable_body["status"] == "unavailable"
                assert recovered_status == 200
                assert recovered_body["status"] == "ready"
                assert "postgresql://" not in unavailable_raw
                assert requires_postgres not in unavailable_raw
                assert "postgresql://" not in recovered_raw
                # Liveness never observed the outage: a terminated backend must
                # not restart the process (PKA-117).
                assert live_status == 200
                assert live_body["status"] == "ok"
        finally:
            killer.close()
    finally:
        # And shutdown after an outage must itself succeed: the writer
        # attestation cannot be released to a backend that is gone, and that
        # must not abort teardown. Repeatable, so a second close is a no-op.
        handle.close()
        handle.close()
