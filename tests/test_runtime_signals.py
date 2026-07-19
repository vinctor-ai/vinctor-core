from __future__ import annotations

import os
import signal
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Event, Thread, get_ident

import pytest

from vinctor_service import local_launcher, service_runtime
from vinctor_service.local_launcher import LocalLaunchConfig
from vinctor_service.runtime_signals import graceful_sigterm_shutdown
from vinctor_service.service_config import ServiceRuntimeConfig


class _NoopHandler(BaseHTTPRequestHandler):
    pass


class _RecordingServer(ThreadingHTTPServer):
    def __init__(self) -> None:
        super().__init__(("127.0.0.1", 0), _NoopHandler)
        self.loop_started = Event()
        self.serve_thread_id: int | None = None
        self.shutdown_thread_id: int | None = None

    def server_bind(self) -> None:
        return None

    def server_activate(self) -> None:
        return None

    def serve_forever(self, poll_interval: float = 0.5) -> None:
        self.serve_thread_id = get_ident()
        return super().serve_forever(poll_interval)

    def service_actions(self) -> None:
        self.loop_started.set()
        return super().service_actions()

    def shutdown(self) -> None:
        self.shutdown_thread_id = get_ident()
        return super().shutdown()


def test_sigterm_stops_serve_loop_from_helper_thread_and_restores_handler() -> None:
    server = _RecordingServer()
    previous_handler = signal.getsignal(signal.SIGTERM)
    sender = Thread(
        target=_send_sigterm_after_loop_starts,
        args=(server.loop_started,),
        daemon=True,
    )

    try:
        with graceful_sigterm_shutdown(server):
            sender.start()
            server.serve_forever(poll_interval=0.01)
    finally:
        sender.join(timeout=5)
        server.server_close()

    assert not sender.is_alive()
    assert server.shutdown_thread_id is not None
    assert server.shutdown_thread_id != server.serve_thread_id
    assert signal.getsignal(signal.SIGTERM) == previous_handler


def _send_sigterm_after_loop_starts(loop_started: Event) -> None:
    loop_started.wait(timeout=5)
    os.kill(os.getpid(), signal.SIGTERM)


class _BlockingServer:
    def __init__(self) -> None:
        self.loop_started = Event()
        self.release = Event()
        self.serve_thread_id: int | None = None
        self.shutdown_thread_id: int | None = None
        self.shutdown_calls = 0
        self.close_calls = 0

    def serve_forever(self) -> None:
        self.serve_thread_id = get_ident()
        self.loop_started.set()
        assert self.release.wait(timeout=5)

    def shutdown(self) -> None:
        self.shutdown_thread_id = get_ident()
        self.shutdown_calls += 1
        self.release.set()

    def server_close(self) -> None:
        self.close_calls += 1


class _KeyboardInterruptServer(_BlockingServer):
    def serve_forever(self) -> None:
        self.serve_thread_id = get_ident()
        raise KeyboardInterrupt


class _ClosableExport:
    def __init__(self) -> None:
        self.close_calls = 0

    def close_export(self) -> None:
        self.close_calls += 1


class _Service:
    def __init__(self, audit_writer: _ClosableExport) -> None:
        self.audit_writer = audit_writer


class _Connection:
    def __init__(self) -> None:
        self.close_calls = 0

    def close(self) -> None:
        self.close_calls += 1


class _ServeHandle:
    def __init__(
        self,
        config: ServiceRuntimeConfig | LocalLaunchConfig,
        server: _BlockingServer,
        export: _ClosableExport,
        connection: _Connection,
    ) -> None:
        self.config = config
        self.endpoint = "http://127.0.0.1:8765"
        self.server = server
        self.service = _Service(export)
        self.conn = connection
        self.close_calls = 0

    def close(self) -> None:
        self.close_calls += 1
        self.server.server_close()
        self.service.audit_writer.close_export()
        self.conn.close()


def test_serve_service_runtime_sigterm_reaches_cleanup_once(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    config = ServiceRuntimeConfig(sqlite_db_path=tmp_path / "vinctor.sqlite", port=0)
    server = _BlockingServer()
    export = _ClosableExport()
    connection = _Connection()
    handle = _ServeHandle(config, server, export, connection)
    monkeypatch.setattr(service_runtime, "prepare_service_runtime", lambda _config: handle)
    previous_handler = signal.getsignal(signal.SIGTERM)
    previous_sigint_handler = signal.getsignal(signal.SIGINT)
    sender = Thread(
        target=_send_sigterm_after_loop_starts,
        args=(server.loop_started,),
        daemon=True,
    )
    sender.start()

    with pytest.raises(SystemExit) as exc_info:
        service_runtime.serve_service_runtime(config)

    sender.join(timeout=5)
    assert exc_info.value.code == 0
    assert not sender.is_alive()
    assert server.shutdown_calls == 1
    assert server.shutdown_thread_id != server.serve_thread_id
    assert handle.close_calls == 1
    assert server.close_calls == 1
    assert export.close_calls == 1
    assert connection.close_calls == 1
    assert signal.getsignal(signal.SIGTERM) == previous_handler
    assert signal.getsignal(signal.SIGINT) == previous_sigint_handler


def test_serve_local_service_sigterm_reaches_cleanup_once(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    config = LocalLaunchConfig(db_path=tmp_path / "vinctor.sqlite", port=0)
    server = _BlockingServer()
    export = _ClosableExport()
    connection = _Connection()
    handle = _ServeHandle(config, server, export, connection)
    monkeypatch.setattr(local_launcher, "prepare_local_service", lambda _config: handle)
    monkeypatch.setattr(local_launcher, "render_env_exports", lambda _handle: "")
    previous_handler = signal.getsignal(signal.SIGTERM)
    sender = Thread(
        target=_send_sigterm_after_loop_starts,
        args=(server.loop_started,),
        daemon=True,
    )
    sender.start()

    with pytest.raises(SystemExit) as exc_info:
        local_launcher.serve_local_service(config)

    sender.join(timeout=5)
    assert exc_info.value.code == 0
    assert not sender.is_alive()
    assert server.shutdown_calls == 1
    assert server.shutdown_thread_id != server.serve_thread_id
    assert handle.close_calls == 1
    assert server.close_calls == 1
    assert export.close_calls == 1
    assert connection.close_calls == 1
    assert signal.getsignal(signal.SIGTERM) == previous_handler


def test_serve_service_runtime_preserves_keyboard_interrupt_cleanup(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    config = ServiceRuntimeConfig(sqlite_db_path=tmp_path / "vinctor.sqlite", port=0)
    server = _KeyboardInterruptServer()
    export = _ClosableExport()
    connection = _Connection()
    handle = _ServeHandle(config, server, export, connection)
    monkeypatch.setattr(service_runtime, "prepare_service_runtime", lambda _config: handle)
    previous_handler = signal.getsignal(signal.SIGTERM)

    with pytest.raises(SystemExit) as exc_info:
        service_runtime.serve_service_runtime(config)

    assert exc_info.value.code == 0
    assert handle.close_calls == 1
    assert server.close_calls == 1
    assert export.close_calls == 1
    assert connection.close_calls == 1
    assert signal.getsignal(signal.SIGTERM) == previous_handler
