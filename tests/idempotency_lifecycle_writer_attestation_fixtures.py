from __future__ import annotations

import base64
import json
from multiprocessing.connection import Connection
from pathlib import Path

from vinctor_service.idempotency_keyring import (
    IdempotencyKeyring,
    load_idempotency_keyring,
)
from vinctor_service.idempotency_lifecycle import (
    IDEMPOTENCY_REMOVAL_WINDOW_SECONDS,
)
from vinctor_service.sqlite import SQLiteV1Service
from vinctor_service.sqlite_txn import connect_sqlite

_RETIRING = "v" + "1"
_PRIMARY = "v" + "2"


def _keyring(active_version: str) -> IdempotencyKeyring:
    retiring_key = base64.b64encode(b"t" * 32).decode("ascii")
    primary_key = base64.b64encode(b"p" * 32).decode("ascii")
    keyring = load_idempotency_keyring(
        {
            "VINCTOR_IDEMPOTENCY_KEYRING_JSON": json.dumps(
                {_RETIRING: retiring_key, _PRIMARY: primary_key}
            ),
            "VINCTOR_IDEMPOTENCY_ACTIVE_KEY_VERSION": active_version,
        }
    )
    assert keyring is not None
    return keyring


def _lifecycle_env(database: Path) -> dict[str, str]:
    retiring_key = base64.b64encode(b"t" * 32).decode("ascii")
    primary_key = base64.b64encode(b"p" * 32).decode("ascii")
    return {
        "VINCTOR_DB": str(database),
        "VINCTOR_IDEMPOTENCY_KEYRING_JSON": json.dumps(
            {_RETIRING: retiring_key, _PRIMARY: primary_key}
        ),
        "VINCTOR_IDEMPOTENCY_ACTIVE_KEY_VERSION": _PRIMARY,
    }


def _age_drain(database: Path) -> None:
    connection = connect_sqlite(database)
    row = connection.execute("SELECT CAST(strftime('%s', 'now') AS INTEGER)").fetchone()
    assert row is not None
    database_now = int(row[0])
    connection.execute(
        "UPDATE idempotency_cipher_key_versions "
        "SET first_seen_epoch = ?, write_disabled_epoch = ?, "
        "drain_completed_epoch = ? "
        "WHERE version_label = ?",
        (
            database_now - IDEMPOTENCY_REMOVAL_WINDOW_SECONDS - 2,
            database_now - IDEMPOTENCY_REMOVAL_WINDOW_SECONDS - 1,
            database_now - IDEMPOTENCY_REMOVAL_WINDOW_SECONDS,
            _RETIRING,
        ),
    )
    connection.commit()
    connection.close()


def _hold_primary_service(
    database: str,
    ready: Connection,
    release: Connection,
) -> None:
    connection = connect_sqlite(database, check_same_thread=False)
    service = SQLiteV1Service(connection, idempotency_keyring=_keyring(_PRIMARY))
    try:
        ready.send_bytes(b"1")
        release.recv_bytes()
    finally:
        service.close()
        connection.close()
        ready.close()
        release.close()


def _forced_carrier(_: str) -> str:
    return "0" * 64
