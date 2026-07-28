"""A default ``pip install vinctor-core`` must be a working install (PKA-167).

psycopg lives in the optional ``[postgres]`` extra, yet ``vinctor_service``
imports its Postgres backend modules eagerly. A module-scope ``import psycopg``
in any of them therefore breaks ``import vinctor_service``, the ``vinctor`` CLI,
and the whole SQLite path -- everything, not just Postgres.

CI installs ``.[dev,postgres]``, so no other test in this suite can observe the
default configuration. These tests re-create it by running a subprocess whose
import system refuses to load psycopg. The wheel-level equivalent is the
``bare-install`` CI job.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import vinctor_service

SRC_ROOT = str(Path(vinctor_service.__file__).resolve().parent.parent)

# A DSN-shaped decoy: no such host, no such credentials. It exists only to prove
# the missing-driver error does not echo it back.
DECOY_DSN = "postgresql://decoy-user:decoy-password@127.0.0.1:1/decoy-db"

_BLOCK_PSYCOPG = """
import sys


class _NoPsycopg:
    def find_spec(self, name, path=None, target=None):
        if name == "psycopg" or name.startswith("psycopg."):
            raise ModuleNotFoundError("No module named 'psycopg'")
        return None


sys.meta_path.insert(0, _NoPsycopg())
"""


def _run_without_psycopg(body: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-c", _BLOCK_PSYCOPG + body],
        capture_output=True,
        text=True,
        env={"PYTHONPATH": SRC_ROOT, "PATH": "/usr/bin:/bin"},
    )


def test_public_modules_import_without_psycopg() -> None:
    result = _run_without_psycopg(
        """
import vinctor_core
import vinctor_service
import vinctor_service.cli
import vinctor_service.postgres
import vinctor_service.sqlite
from vinctor_service.postgres_driver import PSYCOPG_INSTALLED

assert PSYCOPG_INSTALLED is False
print("imported")
"""
    )
    assert result.returncode == 0, result.stderr
    assert "imported" in result.stdout


def test_sqlite_service_works_without_psycopg(tmp_path: Path) -> None:
    result = _run_without_psycopg(
        f"""
from vinctor_service.sqlite import SQLiteV1Service, init_sqlite_schema
from vinctor_service.sqlite_txn import connect_sqlite

conn = connect_sqlite({str(tmp_path / "bare.sqlite3")!r})
init_sqlite_schema(conn)
assert SQLiteV1Service(conn) is not None
print("sqlite ok")
"""
    )
    assert result.returncode == 0, result.stderr
    assert "sqlite ok" in result.stdout


def test_connecting_to_postgres_without_psycopg_names_the_extra() -> None:
    result = _run_without_psycopg(
        f"""
from vinctor_service.postgres_connection import connect_postgres

try:
    connect_postgres({DECOY_DSN!r})
except RuntimeError as exc:
    print("ERROR:", exc)
else:
    raise AssertionError("connect_postgres succeeded without a driver")
"""
    )
    assert result.returncode == 0, result.stderr
    assert "vinctor-core[postgres]" in result.stdout
    # Fail closed without disclosure: no DSN, credentials, or driver internals.
    combined = (result.stdout + result.stderr).lower()
    assert "decoy-password" not in combined
    assert "decoy-user" not in combined
    assert DECOY_DSN not in result.stdout + result.stderr
    assert "traceback" not in combined


def test_cli_serve_on_postgres_without_psycopg_is_one_clean_line() -> None:
    result = _run_without_psycopg(
        f"""
import os

from vinctor_service.cli import run_vinctor

os.environ["VINCTOR_STORAGE_BACKEND"] = "postgres"
os.environ["VINCTOR_POSTGRES_DSN"] = {DECOY_DSN!r}
print("exit:", run_vinctor(["service", "serve"]))
"""
    )
    assert result.returncode == 0, result.stderr
    assert "exit: 5" in result.stdout  # EXIT_SERVICE, not an unhandled crash
    assert result.stderr.strip() == (
        "error: Postgres support requires `pip install vinctor-core[postgres]`"
    )


def test_cli_help_runs_without_psycopg() -> None:
    result = _run_without_psycopg(
        """
import sys

from vinctor_service.cli import main

sys.argv = ["vinctor", "--help"]
try:
    main()
except SystemExit as exc:
    print("exit:", exc.code)
"""
    )
    assert result.returncode == 0, result.stderr
    assert "exit: 0" in result.stdout
