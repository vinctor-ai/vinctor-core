import json

from vinctor_service.audit_anchor import (
    FileAnchor,
    NullAnchor,
    anchor_from_env,
)


def test_null_anchor_is_noop() -> None:
    NullAnchor().emit(1, "a" * 64, "2026-07-12T00:00:00+00:00")  # does not raise


def test_file_anchor_appends_one_json_line_per_head(tmp_path) -> None:
    path = tmp_path / "anchor.log"
    a = FileAnchor(str(path))
    a.emit(1, "h1", "t1")
    a.emit(2, "h2", "t2")
    lines = path.read_text().splitlines()
    assert [json.loads(x) for x in lines] == [
        {"seq": 1, "row_hash": "h1", "created_at": "t1"},
        {"seq": 2, "row_hash": "h2", "created_at": "t2"},
    ]


def test_file_anchor_is_fail_open_on_write_error(tmp_path) -> None:
    # A directory path can't be opened as a file for appending → emit must NOT raise.
    a = FileAnchor(str(tmp_path))  # tmp_path is a directory
    a.emit(1, "h1", "t1")  # swallowed, no exception


def test_anchor_from_env_selects_sink() -> None:
    assert isinstance(anchor_from_env({}), NullAnchor)
    assert isinstance(anchor_from_env({"VINCTOR_AUDIT_ANCHOR": ""}), NullAnchor)
    assert isinstance(
        anchor_from_env({"VINCTOR_AUDIT_ANCHOR": "file:/tmp/x.log"}), FileAnchor
    )
