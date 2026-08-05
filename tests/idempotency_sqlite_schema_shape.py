from __future__ import annotations

from typing import TYPE_CHECKING, Final

from idempotency_schema_contracts import (
    DECLARED_COLUMN_STORAGE,
    ColumnShape,
    SchemaShape,
)

if TYPE_CHECKING:
    from vinctor_service.sqlite_txn import SerializedSQLiteConnection

_SQLITE_TEXT_COLUMNS: Final = (
    (
        "idempotency_cipher_key_versions",
        ("version_label", "write_disabled_reason"),
    ),
    (
        "idempotency_cipher_nonces",
        ("cipher_key_version", "workspace_id", "principal", "operation"),
    ),
    (
        "idempotency_results",
        ("workspace_id", "principal", "operation", "cipher_key_version"),
    ),
)

def sqlite_idempotency_schema_shape(
    connection: SerializedSQLiteConnection,
) -> SchemaShape:
    tables = tuple(
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type = 'table' AND name LIKE 'idempotency_%' ORDER BY name"
        ).fetchall()
    )
    columns = tuple(
        (
            table,
            tuple(
                ColumnShape(
                    name=str(row[1]),
                    storage=DECLARED_COLUMN_STORAGE[str(row[2]).lower()],
                    nullable=not bool(row[3]),
                    default=None if row[4] is None else str(row[4]),
                )
                for row in connection.execute(f'PRAGMA table_info("{table}")').fetchall()
            ),
        )
        for table in tables
    )
    indexes: list[tuple[str, bool, tuple[str, ...]]] = []
    foreign_keys: list[tuple[str, str, str, str]] = []
    checks: list[tuple[str, str]] = []
    for table in tables:
        for row in connection.execute(f'PRAGMA index_list("{table}")').fetchall():
            index_name = str(row[1])
            index_columns = tuple(
                str(column[2])
                for column in connection.execute(f'PRAGMA index_info("{index_name}")').fetchall()
            )
            indexes.append((table, bool(row[2]), index_columns))
        foreign_keys.extend(
            (
                table,
                str(row[3]),
                str(row[2]),
                str(row[4]),
            )
            for row in connection.execute(f'PRAGMA foreign_key_list("{table}")').fetchall()
        )
        row = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?",
            (table,),
        ).fetchone()
        assert row is not None
        checks.append((table, " ".join(str(row[0]).lower().split())))
    return SchemaShape(
        tables=tables,
        columns=columns,
        indexes=tuple(sorted(indexes)),
        foreign_keys=tuple(sorted(foreign_keys)),
        checks=tuple(checks),
    )
