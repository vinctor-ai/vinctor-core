from __future__ import annotations

import time
from collections import deque
from threading import Condition, RLock
from typing import Generic, TypeVar

Lease = TypeVar("Lease")


class SQLitePoolUnavailable(RuntimeError):
    def __str__(self) -> str:
        return "SQLite service pool unavailable"


class SQLiteLeaseAdmission(Generic[Lease]):
    def __init__(self, lock: RLock, available: deque[Lease]) -> None:
        self.condition = Condition(lock)
        self.available = available
        self.waiters: deque[object] = deque()
        self._closed = False
        self._accepting = True
        self._availability_epoch = 0

    def acquire(self, timeout_seconds: float) -> Lease:
        deadline = time.monotonic() + timeout_seconds
        waiter = object()
        with self.condition:
            epoch = self._availability_epoch
            self.waiters.append(waiter)
            self.condition.notify_all()
            try:
                while True:
                    if self._closed or not self._accepting or epoch != self._availability_epoch:
                        raise SQLitePoolUnavailable
                    if self.waiters[0] is waiter and self.available:
                        self.waiters.popleft()
                        lease = self.available.popleft()
                        self.condition.notify_all()
                        return lease
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise SQLitePoolUnavailable
                    self.condition.wait(remaining)
            finally:
                if waiter in self.waiters:
                    self.waiters.remove(waiter)
                    self.condition.notify_all()

    def release(self, lease: Lease) -> None:
        with self.condition:
            if not self._closed:
                self.available.append(lease)
            self.condition.notify_all()

    def publish(self, lease: Lease) -> None:
        with self.condition:
            if not self._closed:
                self.available.append(lease)
                self._accepting = True
            self.condition.notify_all()

    def invalidate_waiters(self) -> None:
        with self.condition:
            self._accepting = False
            self._availability_epoch += 1
            self.condition.notify_all()

    def close(self) -> None:
        with self.condition:
            self._closed = True
            self._accepting = False
            self._availability_epoch += 1
            self.available.clear()
            self.condition.notify_all()
