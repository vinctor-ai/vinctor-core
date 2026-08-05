from __future__ import annotations

import errno
import sys
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime
from functools import partial
from http.server import ThreadingHTTPServer
from threading import Lock
from time import monotonic
from typing import Any, NoReturn

from vinctor_service.health_checks import resolve_readiness_timeout_seconds
from vinctor_service.idempotency_keyring import IdempotencyKeyring
from vinctor_service.idempotency_readiness import (
    postgres_idempotency_ready,
    require_postgres_idempotency_compatible,
    require_postgres_idempotency_ready,
)
from vinctor_service.keys import SQLiteLocalKeyRepository
from vinctor_service.local_http import create_v1_http_server
from vinctor_service.metrics import Metrics
from vinctor_service.oidc import PyJwtOidcTokenVerifier
from vinctor_service.postgres import (
    PostgresV1Service,
    connect_postgres,
    connect_postgres_readiness,
)
from vinctor_service.postgres_control import PostgresLocalKeyRepository
from vinctor_service.runtime_signals import graceful_sigterm_shutdown
from vinctor_service.service_config import ServiceRuntimeConfig
from vinctor_service.sqlite import SQLiteV1Service
from vinctor_service.sqlite_pool import SQLiteServicePool
from vinctor_service.sqlite_txn import connect_sqlite


@dataclass
class ServiceRuntimeHandle:
    conn: Any
    service: SQLiteV1Service | PostgresV1Service
    key_repository: SQLiteLocalKeyRepository | PostgresLocalKeyRepository
    server: ThreadingHTTPServer
    config: ServiceRuntimeConfig
    endpoint: str
    sqlite_pool: SQLiteServicePool | None = None
    postgres_readiness: PostgresReadinessProbe | None = None

    def close(self) -> None:
        self.server.server_close()
        if self.postgres_readiness is not None:
            # After server_close(), which stops the readiness worker and cancels
            # whatever it was doing. A worker it could not stop still owns this
            # probe's own connection, and close() leaves that one to it.
            self.postgres_readiness.close()
        if self.sqlite_pool is not None:
            self.sqlite_pool.close()
            return
        audit_writer = getattr(self.service, "audit_writer", None)
        close_export = getattr(audit_writer, "close_export", None)
        if callable(close_export):
            _teardown_quietly(close_export, "audit export")
        # The service's own close releases the writer attestation, which talks
        # to the store. Against a store that has already gone the release cannot
        # be performed and cannot matter — the backend dropped the advisory lock
        # when it died — so it must not abort teardown or escape to the caller.
        # It used to, which left the connection open and made shutdown after an
        # outage raise instead of finishing.
        _teardown_quietly(self.service.close, "durable service")
        _teardown_quietly(self.conn.close, "durable connection")


def prepare_service_runtime(
    config: ServiceRuntimeConfig,
    *,
    clock: Callable[[], datetime] | None = None,
) -> ServiceRuntimeHandle:
    sqlite_pool: SQLiteServicePool | None = None
    service: SQLiteV1Service | PostgresV1Service | None = None
    postgres_readiness: PostgresReadinessProbe | None = None
    if config.storage_backend == "postgres":
        assert config.postgres_dsn is not None
        conn = connect_postgres(config.postgres_dsn)
    else:
        db_path = config.sqlite_db_path.expanduser()
        db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = connect_sqlite(db_path, check_same_thread=False)
    try:
        if config.storage_backend == "postgres":
            if config.idempotency_keyring is None:
                service = PostgresV1Service(conn)
            else:
                service = PostgresV1Service(
                    conn,
                    idempotency_keyring=config.idempotency_keyring,
                )
            key_repository = PostgresLocalKeyRepository(conn)
            add_replacement_validator = getattr(conn, "add_replacement_validator", None)
            if callable(add_replacement_validator):
                add_replacement_validator(
                    partial(
                        require_postgres_idempotency_compatible,
                        keyring=config.idempotency_keyring,
                    )
                )
            add_readiness_validator = getattr(conn, "add_readiness_validator", None)
            if callable(add_readiness_validator):
                add_readiness_validator(
                    partial(
                        require_postgres_idempotency_ready,
                        keyring=config.idempotency_keyring,
                    )
                )
            postgres_readiness = PostgresReadinessProbe(
                conn,
                config.postgres_dsn,
                config.idempotency_keyring,
            )
            readiness_check = postgres_readiness
        else:
            if config.idempotency_keyring is None:
                service = SQLiteV1Service(conn)
            else:
                service = SQLiteV1Service(
                    conn,
                    idempotency_keyring=config.idempotency_keyring,
                )
            key_repository = SQLiteLocalKeyRepository(conn)
            sqlite_pool = SQLiteServicePool(
                db_path,
                primary_connection=conn,
                primary_service=service,
                primary_key_repository=key_repository,
            )
            http_service = sqlite_pool.service
            http_key_repository = sqlite_pool.key_repository
            readiness_check = sqlite_pool.readiness_probe
        if config.storage_backend == "postgres":
            http_service = service
            http_key_repository = key_repository
        metrics = Metrics() if config.metrics else None
        oidc_token_verifier = (
            PyJwtOidcTokenVerifier(config.oidc) if config.oidc is not None else None
        )
        server = create_v1_http_server(
            (config.host, config.port),
            service=http_service,
            agent_identities={},
            workspace_identities={},
            agent_identity_resolver=lambda raw_key, used_at: (
                http_key_repository.resolve_agent_identity(raw_key, now=used_at)
            ),
            workspace_identity_resolver=lambda raw_key, used_at: (
                http_key_repository.resolve_workspace_identity(raw_key, now=used_at)
            ),
            auditor_identity_resolver=lambda raw_key, used_at: (
                http_key_repository.resolve_auditor_identity(raw_key, now=used_at)
            ),
            service_operator_resolver=lambda raw_key, used_at: (
                http_key_repository.resolve_service_operator(raw_key, now=used_at)
            ),
            pep_identity_resolver=lambda raw_key, used_at: http_key_repository.resolve_pep_identity(
                raw_key, now=used_at
            ),
            clock=clock,
            service_mode=config.service_mode,
            metrics=metrics,
            access_log=config.access_log,
            readiness_check=readiness_check,
            oidc_token_verifier=oidc_token_verifier,
            request_scope=sqlite_pool.request_scope if sqlite_pool is not None else None,
        )
    except Exception:
        if postgres_readiness is not None:
            postgres_readiness.close()
        if sqlite_pool is not None:
            sqlite_pool.close()
        else:
            if service is not None:
                service.close()
            conn.close()
        raise

    host, port = server.server_address
    return ServiceRuntimeHandle(
        conn=conn,
        service=service,
        key_repository=key_repository,
        server=server,
        config=config,
        endpoint=f"http://{host}:{port}",
        sqlite_pool=sqlite_pool,
        postgres_readiness=postgres_readiness,
    )


@dataclass
class _ReadinessCall:
    """One in-flight readiness call and the connection it is using."""

    started: float
    connection: Any | None = None
    # Set on ATTEMPT and never cleared: the pessimistic reuse guard.
    cancel_attempted: bool = False
    # Set only on a CONFIRMED cancel: what a sweep may skip.
    cancelled: bool = False


class PostgresReadinessProbe:
    """Readiness against PostgreSQL, on a connection the probe owns.

    Probing on the process-wide serialized connection gave the readiness worker
    two problems the caller's deadline could not fix (PKA-146):

    * the backend call outlived the deadline. Nothing bounded the query itself,
      so an expired probe went on holding a session and that connection's lock —
      which every enforce request needs — until the store answered, if it ever
      did. This connection is opened with driver and server side deadlines, and
      an expired call is cancelled and its connection discarded rather than
      reused in an unknown state.
    * shutdown raced it. `close()` cannot join a worker blocked in the driver,
      so the runtime went on to close the connection underneath it. Nothing
      here is shared: whichever of shutdown and the in-flight probe finishes
      last closes the connection, and neither waits for the other.

    Connecting is lazy so a store that is down at startup costs a failed probe
    rather than a failed boot, and so a discarded connection is simply replaced
    by the next probe.
    """

    def __init__(
        self,
        conn: Any,
        dsn: str,
        keyring: IdempotencyKeyring | None = None,
        *,
        timeout_seconds: float | None = None,
    ) -> None:
        self._conn = conn
        self._dsn = dsn
        self._keyring = keyring
        self._timeout_seconds = (
            resolve_readiness_timeout_seconds() if timeout_seconds is None else timeout_seconds
        )
        # Cancelling is bounded separately from, and more tightly than, the
        # readiness deadline: the reclaimer works through the outstanding calls
        # one at a time, so the whole sweep stays inside
        # max_abandoned_workers * this. It is off every request path, so the
        # sweep's latency delays reclamation only, never a response.
        self._cancel_timeout_seconds = min(self._timeout_seconds, 1.0)
        self._lock = Lock()
        self._connection: Any | None = None
        self._active: list[_ReadinessCall] = []
        self._closed = False

    def __call__(self) -> bool:
        # A quarantined runtime connection means this process cannot serve, so
        # readiness is False without asking the store about it.
        if getattr(self._conn, "is_ready", True) is False:
            return False
        # Stamped, and registered, BEFORE connecting. Opening the connection is
        # a TCP (and TLS) handshake plus the session SET round-trips, and a
        # stamp taken after it makes the call look younger than the bound at
        # exactly the moment it is abandoned — so the cancel meant for it would
        # skip it and the session would stay pinned.
        call = _ReadinessCall(started=monotonic())
        with self._lock:
            if self._closed:
                return False
            # Taken OUT of the idle slot rather than borrowed from it: an
            # abandoned probe and the replacement started for it overlap by
            # definition, and must never end up on one connection.
            call.connection = self._connection
            self._connection = None
            self._active.append(call)
        ready = False
        reusable = False
        try:
            if call.connection is None:
                call.connection = connect_postgres_readiness(
                    self._dsn,
                    timeout_seconds=self._timeout_seconds,
                )
            connection = call.connection
            with connection.transaction():
                ready = connection.execute("SELECT 1").fetchone() == (
                    1,
                ) and postgres_idempotency_ready(connection, self._keyring)
            reusable = True
        except Exception:
            # Coarse boundary; readiness fails closed and discloses nothing. A
            # connection that failed or was cancelled is never reused: its
            # session state is unknown.
            ready = False
        finally:
            spent = self._check_in(call, reusable=reusable)
        if spent is not None:
            _close_quietly(spent)
        if not ready:
            return False
        # The store is reachable and schema-ready. Whether THIS process can use
        # it is a second question, and the only thing that answers it is the
        # connection it serves with.
        return self._serving_connection_ready()

    def cancel(self) -> None:
        """Abort probes that have already run past the bound.

        Called from the reclaimer thread, by design — the worker that owns the
        call is the one that cannot act. Only calls older than the bound are
        touched, so aborting a wedged probe cannot abort the replacement started
        for it.

        A cancel travels over a NEW connection, so this is also what makes a
        healthy store recoverable while old sessions hang. It is bounded by the
        driver (libpq 17+ is a startup requirement), so the sweep runs inline:
        worst case `max_abandoned_workers + 1` cancels at
        `_cancel_timeout_seconds` each, on a thread that is on no request path.
        """
        expired = monotonic() - self._timeout_seconds
        with self._lock:
            targets = []
            for call in self._active:
                if call.started > expired or call.connection is None:
                    continue
                # Skipped only once a cancel has been CONFIRMED. Skipping on
                # "we tried" defeats the retry loop this design rests on: a
                # cancel opens a new connection to send the request, so it fails
                # whenever the store is down — the normal case, not an exotic
                # one — and the call would then be passed over for good.
                if call.cancelled:
                    continue
                # Separate, and never cleared: reuse stays pessimistic. A
                # connection a cancel was merely ATTEMPTED against may still
                # have that cancel land later, so it is never handed to another
                # call (see _check_in). Conflating the two was the whole bug.
                call.cancel_attempted = True
                targets.append(call)
        for call in targets:
            connection = call.connection
            if connection is None:
                continue
            if _cancel_quietly(connection, self._cancel_timeout_seconds):
                with self._lock:
                    # "Delivered" means the driver accepted and sent the cancel
                    # request, which psycopg is explicit is not a guarantee the
                    # server acted on it. That is the right thing to record here
                    # anyway: this flag exists to stop re-sending a request that
                    # was sent, and a cancel the server ignored leaves the call
                    # wedged, where the abandoned-worker cap and its report
                    # still cover it. The one silent-success case — cancel_safe
                    # returning immediately on an already-closed connection —
                    # cannot arise, because nothing closes a connection while
                    # its call is still running (see _check_in).
                    call.cancelled = True

    def close(self) -> None:
        with self._lock:
            self._closed = True
            idle = self._connection
            self._connection = None
            active = []
            for call in self._active:
                if call.connection is None:
                    continue
                call.cancel_attempted = True
                active.append(call.connection)
        # Only the idle connection is closed here. A connection still inside a
        # call belongs to that call, which closes it when it returns: closing it
        # from here is the shutdown race this fixes (PKA-146).
        for connection in active:
            _cancel_quietly(connection, self._cancel_timeout_seconds)
        if idle is not None:
            _close_quietly(idle)

    def _serving_connection_ready(self) -> bool:
        """Prove THIS process can serve, on the connection it serves with.

        The `is_ready` flag is not enough on its own: it turns false only once
        something has tried to USE the connection, so between a backend dying
        and the next enforce request it still reads true. Answering from the
        probe's own healthy connection at that point reports `200` while the
        process cannot serve a single request — a fail-open, on the endpoint
        whose whole job is to fail closed.

        Touching it is also what heals it. The serving connection reconnects on
        its next use, and an instance failing readiness is drained, so no
        enforce request arrives to trigger that: without this, one terminated
        backend removes the process from rotation for good even though the
        database is fine.

        This takes that connection's lock, so a wedged enforce transaction parks
        this worker — abandonable, capped and reported like any other. That is
        the honest trade: while a request is wedged on the serving connection
        the process genuinely cannot serve, so failing closed is the right
        answer rather than a symptom to design around.
        """
        try:
            with self._conn.transaction():
                return bool(self._conn.execute("SELECT 1").fetchone() == (1,))
        except Exception:
            return False

    def _check_in(self, call: _ReadinessCall, *, reusable: bool) -> Any | None:
        """Park a healthy connection for the next probe; return one to close."""
        with self._lock:
            self._active = [entry for entry in self._active if entry is not call]
            connection = call.connection
            if (
                connection is not None
                and reusable
                and not call.cancel_attempted
                and not self._closed
                and self._connection is None
            ):
                self._connection = connection
                return None
        return call.connection


def _teardown_quietly(step: Callable[[], Any], what: str) -> None:
    """Run one shutdown step; never let it abort the ones after it.

    Teardown has to be safe and repeatable against a store that is already
    gone. It says nothing about the backend: this reaches logs, and the
    driver's message carries the DSN.
    """
    try:
        step()
    except Exception:  # noqa: BLE001  # noqa: BROAD_EXCEPT_OK - teardown is best effort
        sys.stderr.write(f"vinctor: shutdown could not complete the {what} step\n")


def _close_quietly(connection: Any) -> None:
    with suppress(Exception):
        connection.close()


def _cancel_quietly(connection: Any, timeout_seconds: float) -> bool:
    """Cancel, and report whether it was actually delivered.

    Failure is the NORMAL case during an outage, not an exotic one: psycopg's
    cancel_safe opens a NEW connection to send the request, which is exactly
    what a store that is down refuses, and it raises CancellationTimeout at its
    own bound as well. A caller that cannot tell a failed cancel from a
    delivered one will pass over the call for good and never retry it.

    The timeout is honoured because libpq 17+ is a startup requirement for this
    backend, so there is no unbounded fallback spelling to choose between.
    """
    try:
        connection.cancel_safe(timeout=timeout_seconds)
    except Exception:
        return False
    return True


def render_service_runtime_banner(handle: ServiceRuntimeHandle) -> str:
    return "\n".join(
        [
            "# Vinctor service listening",
            f"# URL: {handle.endpoint}",
            f"# mode: {handle.config.service_mode}",
            f"# database: {_database_label(handle.config)}",
            f"# log_level: {handle.config.log_level}",
            "# Local/self-hostable prototype only; not a hosted production service.",
            "# This command does not print raw keys. Bootstrap keys separately when needed.",
            "# Press Ctrl+C to stop.",
        ]
    )


def _database_label(config: ServiceRuntimeConfig) -> str:
    if config.storage_backend == "postgres":
        return "postgres"
    return str(config.sqlite_db_path)


def serve_service_runtime(config: ServiceRuntimeConfig) -> NoReturn:
    try:
        handle = prepare_service_runtime(config)
    except OSError as error:
        if error.errno == errno.EADDRINUSE:
            from vinctor_service.cli import EXIT_SERVICE, CliError

            raise CliError(
                f"port {config.port} already in use — pass --port <n> "
                "(or --port 0 for any free port)",
                code=EXIT_SERVICE,
            ) from error
        raise
    print(render_service_runtime_banner(handle), flush=True)
    try:
        with graceful_sigterm_shutdown(handle.server):
            handle.server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        handle.close()
    raise SystemExit(0)
