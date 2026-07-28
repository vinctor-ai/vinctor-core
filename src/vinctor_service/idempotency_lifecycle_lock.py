from __future__ import annotations

import fcntl
import hashlib
import os
import unicodedata
from pathlib import Path
from types import TracebackType
from typing import BinaryIO

from vinctor_service.idempotency_lifecycle import (
    IdempotencyLifecycleActiveWriters,
    IdempotencyLifecycleUnavailable,
)
from vinctor_service.sqlite_txn import SerializedSQLiteConnection

_IDENTITY_DOMAIN = b"vinctor.idempotency.writer-lock.identity.v1\x00"
_CARRIER_DOMAIN = b"vinctor.idempotency.writer-lock.carrier.v1\x00"


def _version_lock_identity(version: str) -> bytes:
    encoded = unicodedata.normalize("NFC", version).encode("utf-8")
    framed = len(encoded).to_bytes(4, "big") + encoded
    return hashlib.sha256(_IDENTITY_DOMAIN + framed).digest()


def _version_lock_carrier(version: str) -> str:
    return hashlib.sha256(_CARRIER_DOMAIN + _version_lock_identity(version)).hexdigest()


class SQLiteWriterAttestation:
    __slots__ = ("_identity", "_path", "_registry_path", "_writer_file")

    def __init__(self, database: Path, version: str) -> None:
        base = f"{database}.idempotency-writers"
        self._identity = _version_lock_identity(version).hex().encode("ascii")
        self._path = Path(f"{base}.{_version_lock_carrier(version)}.lock")
        self._registry_path = Path(f"{base}.registry.lock")
        self._writer_file: BinaryIO | None = None

    @classmethod
    def registered_for_connection(
        cls,
        connection: SerializedSQLiteConnection,
        version: str,
    ) -> SQLiteWriterAttestation | None:
        rows = connection.execute("PRAGMA database_list").fetchall()
        for row in rows:
            if str(row[1]) != "main":
                continue
            database = str(row[2])
            if not database:
                return None
            attestation = cls(Path(database), version)
            attestation.register()
            return attestation
        raise RuntimeError("SQLite main database is unavailable")

    def register(self) -> None:
        if self._writer_file is not None:
            return
        stream = self._open_verified_carrier()
        try:
            fcntl.flock(stream.fileno(), fcntl.LOCK_SH | fcntl.LOCK_NB)
        except BlockingIOError:
            stream.close()
            raise IdempotencyLifecycleActiveWriters from None
        except OSError:
            stream.close()
            raise IdempotencyLifecycleUnavailable from None
        self._writer_file = stream

    def exclusive_guard(self) -> _SQLiteExclusiveGuard:
        return _SQLiteExclusiveGuard(self)

    def _acquire_exclusive(self) -> BinaryIO:
        if self._writer_file is not None:
            raise IdempotencyLifecycleActiveWriters
        stream = self._open_verified_carrier()
        try:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            stream.close()
            raise IdempotencyLifecycleActiveWriters from None
        except OSError:
            stream.close()
            raise IdempotencyLifecycleUnavailable from None
        return stream

    @staticmethod
    def _release_exclusive(stream: BinaryIO) -> None:
        try:
            stream.close()
        except OSError:
            raise IdempotencyLifecycleUnavailable from None

    def close(self) -> None:
        stream = self._writer_file
        if stream is None:
            return
        self._writer_file = None
        try:
            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
            stream.close()
        except OSError:
            try:
                stream.close()
            finally:
                raise IdempotencyLifecycleUnavailable from None

    def _open_verified_carrier(self) -> BinaryIO:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            registry_fd = os.open(
                self._registry_path,
                os.O_RDWR | os.O_CREAT,
                0o600,
            )
        except OSError:
            raise IdempotencyLifecycleUnavailable from None
        carrier: BinaryIO | None = None
        try:
            fcntl.flock(registry_fd, fcntl.LOCK_EX)
            carrier_fd = os.open(self._path, os.O_RDWR | os.O_CREAT, 0o600)
            carrier = os.fdopen(carrier_fd, "r+b", buffering=0)
            existing = carrier.read()
            if existing and existing != self._identity:
                carrier.close()
                raise IdempotencyLifecycleUnavailable
            if not existing:
                carrier.write(self._identity)
                carrier.flush()
                os.fsync(carrier.fileno())
            return carrier
        except OSError:
            if carrier is not None:
                carrier.close()
            raise IdempotencyLifecycleUnavailable from None
        finally:
            try:
                fcntl.flock(registry_fd, fcntl.LOCK_UN)
                os.close(registry_fd)
            except OSError:
                if carrier is not None:
                    carrier.close()
                raise IdempotencyLifecycleUnavailable from None


class _SQLiteExclusiveGuard:
    __slots__ = ("_attestation", "_stream")

    def __init__(self, attestation: SQLiteWriterAttestation) -> None:
        self._attestation = attestation
        self._stream: BinaryIO | None = None

    def __enter__(self) -> None:
        self._stream = self._attestation._acquire_exclusive()

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_type, exc, traceback
        stream = self._stream
        self._stream = None
        if stream is not None:
            self._attestation._release_exclusive(stream)
