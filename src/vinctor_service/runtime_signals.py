from __future__ import annotations

import signal
from collections.abc import Iterator
from contextlib import contextmanager
from socketserver import BaseServer
from threading import Event, Thread, current_thread, main_thread
from types import FrameType


@contextmanager
def graceful_sigterm_shutdown(server: BaseServer) -> Iterator[None]:
    if current_thread() is not main_thread():
        yield
        return

    signal_received = Event()
    serving_done = Event()

    def handle_sigterm(_signum: int, _frame: FrameType | None) -> None:
        signal_received.set()

    def shutdown_server() -> None:
        signal_received.wait()
        if not serving_done.is_set():
            server.shutdown()

    previous_handler = signal.signal(signal.SIGTERM, handle_sigterm)
    shutdown_thread = Thread(
        target=shutdown_server,
        name="vinctor-sigterm-shutdown",
        daemon=True,
    )
    shutdown_thread.start()
    try:
        yield
    finally:
        signal.signal(signal.SIGTERM, previous_handler)
        serving_done.set()
        signal_received.set()
        shutdown_thread.join()
