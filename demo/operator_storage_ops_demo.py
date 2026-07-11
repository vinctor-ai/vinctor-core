from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory

from vinctor_service.cli import run_vinctor
from vinctor_service.local_launcher import LocalLaunchConfig, prepare_local_service

NOW = datetime(2026, 6, 10, 12, 0, tzinfo=UTC)


def main() -> None:
    with TemporaryDirectory() as temp_dir:
        db_path = Path(temp_dir) / "vinctor.sqlite"
        backup_path = Path(temp_dir) / "vinctor.backup.sqlite"

        bootstrap = prepare_local_service(
            LocalLaunchConfig(
                db_path=db_path,
                port=0,
                workspace_id="ws_demo",
                agent_id="agent_runner",
                workspace_key="wsk_demo",
                agent_key="aak_demo",
                grant_ref="grt_demo",
                scopes=("execute:ci/test",),
                boundary_name="codex-local",
            ),
            now=NOW,
        )
        bootstrap.close()

        common = ["--json", "--db", str(db_path), "--workspace-id", "ws_demo"]

        # Safe metadata, no secrets.
        info = _run([*common, "operator", "service", "info"])
        assert info["mode"] == "local"
        assert info["schema_version"] == 2
        assert info["key_storage_mode"] == "sqlite_hashes"
        serialized = json.dumps(info)
        assert "wsk_" not in serialized
        assert "aak_" not in serialized

        # Explicit schema migrate is idempotent and preserves data.
        migrate = _run([*common, "operator", "storage", "migrate"])
        assert migrate["schema_versions"] == [1, 2]
        assert _grant_exists(db_path, "grt_demo")

        # Keys list never exposes raw keys or hashes.
        listed = _run([*common, "operator", "keys", "list"])
        assert len(listed["keys"]) == 2
        listed_json = json.dumps(listed)
        assert "wsk_demo" not in listed_json
        assert "aak_demo" not in listed_json
        assert "key_hash" not in listed_json
        agent_key_id = next(
            key["key_id"] for key in listed["keys"] if key["key_type"] == "agent"
        )

        # Rotate the workspace key: new raw key once, old key revoked.
        rotated = _run([*common, "operator", "keys", "rotate", "workspace"])
        assert rotated["raw_key"].startswith("wsk_")
        assert len(rotated["revoked_key_ids"]) == 1

        # Revoke the agent key by id.
        revoked = _run([*common, "operator", "keys", "revoke", agent_key_id])
        assert revoked["status"] == "revoked"

        # Snapshot, wipe, and restore the database.
        backup = _run([*common, "operator", "storage", "backup", "--output", str(backup_path)])
        assert backup["bytes"] > 0
        assert backup["schema_versions"] == [1, 2]
        assert _grant_exists(backup_path, "grt_demo")

        reset = _run([*common, "operator", "storage", "reset", "--yes"])
        assert reset["reset"] is True
        assert not _grant_exists(db_path, "grt_demo")

        restore = _run(
            [*common, "operator", "storage", "restore", "--input", str(backup_path), "--yes"]
        )
        assert restore["restored"] is True
        assert _grant_exists(db_path, "grt_demo")

    print("ALL OPERATOR STORAGE OPS STEPS PASSED ✓")


def _run(argv: list[str]) -> dict[str, object]:
    stdout = StringIO()
    stderr = StringIO()
    status = run_vinctor(argv, stdout=stdout, stderr=stderr)
    assert status == 0, stderr.getvalue()
    return json.loads(stdout.getvalue())


def _grant_exists(db_path: Path, grant_ref: str) -> bool:
    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute(
            "SELECT 1 FROM grants WHERE grant_ref = ?",
            (grant_ref,),
        ).fetchone()
    finally:
        conn.close()
    return row is not None


if __name__ == "__main__":
    main()
