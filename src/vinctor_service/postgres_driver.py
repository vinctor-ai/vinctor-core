"""psycopg exception types that resolve whether or not the extra is installed.

psycopg ships in the optional ``[postgres]`` extra, but ``vinctor_service``
imports its Postgres backend modules eagerly, so a module-scope ``import
psycopg`` in any of them makes a default install unable to import the package
at all -- no CLI, no SQLite backend, nothing (PKA-167).

Those modules need psycopg only for the exception types they catch. The driver
itself is needed solely to open a connection, and ``connect_postgres`` already
gates that with an actionable message naming the extra. So when psycopg is
absent we substitute placeholder exception classes: ``except PostgresError``
stays valid and simply never matches, which is correct, because with no driver
there is no Postgres connection to raise one.

New psycopg exception types must be re-exported here rather than imported from
``psycopg`` at a module's scope. The bare-install CI job enforces this.
"""

from __future__ import annotations


class PostgresDriverUnavailable(RuntimeError):
    """The Postgres backend was selected but psycopg is not installed.

    A ``RuntimeError`` subclass so callers that already catch the historical
    ``RuntimeError`` from ``connect_postgres`` keep working; a distinct type so
    the CLI can report it as the operator configuration error it is, on one
    line, without a traceback exposing internal paths.
    """


try:
    from psycopg import Error as PostgresError
    from psycopg.errors import UniqueViolation

    PSYCOPG_INSTALLED = True
except ModuleNotFoundError:  # pragma: no cover - exercised by the bare-install CI job
    PSYCOPG_INSTALLED = False

    class PostgresError(Exception):  # type: ignore[no-redef]
        """Stand-in for ``psycopg.Error`` when the driver is not installed.

        Nothing can raise it: reaching a Postgres code path requires a
        connection, and no connection can exist without the driver.
        """

    class UniqueViolation(PostgresError):  # type: ignore[no-redef]
        """Stand-in for ``psycopg.errors.UniqueViolation``. Never raised."""


__all__ = [
    "PSYCOPG_INSTALLED",
    "PostgresDriverUnavailable",
    "PostgresError",
    "UniqueViolation",
]
