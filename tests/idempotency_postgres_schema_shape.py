from __future__ import annotations

from typing import TYPE_CHECKING

from idempotency_schema_contracts import (
    DECLARED_COLUMN_STORAGE,
    IDEMPOTENCY_TABLES,
    ColumnShape,
    SchemaShape,
)

if TYPE_CHECKING:
    from vinctor_service.postgres_connection import SerializedPostgresConnection

def postgres_idempotency_schema_shape(
    connection: SerializedPostgresConnection,
) -> SchemaShape:
    tables = tuple(
        str(row[0])
        for row in connection.execute(
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_schema = current_schema() "
            "AND table_name = ANY(%s) ORDER BY table_name",
            (list(IDEMPOTENCY_TABLES),),
        ).fetchall()
    )
    columns = tuple(
        (
            table,
            tuple(
                ColumnShape(
                    name=str(row[0]),
                    storage=DECLARED_COLUMN_STORAGE[str(row[1]).lower()],
                    nullable=str(row[2]) == "YES",
                    default=None if row[3] is None else str(row[3]),
                )
                for row in connection.execute(
                    "SELECT column_name, data_type, is_nullable, column_default "
                    "FROM information_schema.columns "
                    "WHERE table_schema = current_schema() AND table_name = %s "
                    "ORDER BY ordinal_position",
                    (table,),
                ).fetchall()
            ),
        )
        for table in tables
    )
    indexes = tuple(
        sorted(
            (
                str(row[0]),
                bool(row[2]),
                tuple(str(column) for column in row[3]),
            )
            for row in connection.execute(
                "SELECT table_class.relname, index_class.relname, index.indisunique, "
                "array_agg(attribute.attname ORDER BY key.ordinality) "
                "FROM pg_class AS table_class "
                "JOIN pg_namespace AS namespace ON namespace.oid = table_class.relnamespace "
                "JOIN pg_index AS index ON index.indrelid = table_class.oid "
                "JOIN pg_class AS index_class ON index_class.oid = index.indexrelid "
                "JOIN LATERAL unnest(index.indkey) WITH ORDINALITY "
                "AS key(attnum, ordinality) ON TRUE "
                "JOIN pg_attribute AS attribute "
                "ON attribute.attrelid = table_class.oid AND attribute.attnum = key.attnum "
                "WHERE namespace.nspname = current_schema() "
                "AND table_class.relname = ANY(%s) "
                "GROUP BY table_class.relname, index_class.relname, index.indisunique",
                (list(IDEMPOTENCY_TABLES),),
            ).fetchall()
        )
    )
    constraint_rows = connection.execute(
        "SELECT table_class.relname, con.contype, "
        "pg_get_constraintdef(con.oid) "
        "FROM pg_constraint AS con "
        "JOIN pg_class AS table_class ON table_class.oid = con.conrelid "
        "JOIN pg_namespace AS namespace ON namespace.oid = table_class.relnamespace "
        "WHERE namespace.nspname = current_schema() "
        "AND table_class.relname = ANY(%s) ORDER BY table_class.relname, con.conname",
        (list(IDEMPOTENCY_TABLES),),
    ).fetchall()
    foreign_keys = tuple(
        sorted((str(row[0]), str(row[2]), "", "") for row in constraint_rows if str(row[1]) == "f")
    )
    checks = tuple(
        (str(row[0]), str(row[2]).lower()) for row in constraint_rows if str(row[1]) == "c"
    )
    return SchemaShape(tables, columns, indexes, foreign_keys, checks)
