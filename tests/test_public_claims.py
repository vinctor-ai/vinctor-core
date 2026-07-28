"""Retired coverage claims must not survive anywhere we ship words.

Vinctor decides the calls that are *configured to reach it*. Wording that
promises a verdict on "every tool call" overstates that to exactly the degree
that matters to someone choosing a security control, so each such phrase was
retired deliberately.

The gate is deliberately wide. An earlier version scanned two hand-listed files
and reported a clean run while a retired sentence was still being printed by
`vinctor demo block` and still sitting in `docs/cli-reference.md` — a claim does
not stop being public because it lives in a CLI banner instead of the README.
Paths resolve from this file, never from the working directory, so the gate
cannot quietly narrow to nothing depending on where pytest was invoked.
"""
from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

# Everything shipped or published that carries prose about coverage.
SCAN_GLOBS = ("src/**/*.py", "docs/**/*.md", "docs/**/*.svg")
EXTRA_PATHS = ("README.md",)

# Lowercase; matched case-insensitively against file contents.
SUPERSEDED_CLAIMS = (
    "each tool call",
    "every tool call",
    "checks every action",
    "every action first",
    "verdict on every call",
    "audit record either way",
    "audited either way",
    "enforced before each action",
    "authorizes mediated tool calls",
    # The hero image's alt text. The wheel ships no `docs/`, so this string was
    # for a long time the only hero text a PyPI reader could see, and it carried
    # the retired claim verbatim while the SVG it described had been reworded.
    "each ai-agent action",
    "permits or denies each",
)


def _scanned_files() -> list[Path]:
    paths: set[Path] = set()
    for pattern in SCAN_GLOBS:
        paths.update(
            path
            for path in REPO_ROOT.glob(pattern)
            if path.is_file() and "__pycache__" not in path.parts
        )
    paths.update(REPO_ROOT / name for name in EXTRA_PATHS)
    for path in paths:
        assert path.is_file(), f"scanned path is missing: {path}"
    return sorted(paths)


def test_scan_actually_covers_the_shipped_surface() -> None:
    """A gate that silently matches no files passes forever."""
    scanned = _scanned_files()

    assert REPO_ROOT / "README.md" in scanned
    assert REPO_ROOT / "docs" / "assets" / "vinctor-hero.svg" in scanned
    assert REPO_ROOT / "src" / "vinctor_service" / "cli.py" in scanned
    assert REPO_ROOT / "docs" / "cli-reference.md" in scanned


def test_public_claims_remain_coverage_qualified() -> None:
    violations: dict[str, list[str]] = {}

    for path in _scanned_files():
        content = path.read_text(encoding="utf-8").lower()
        found = [claim for claim in SUPERSEDED_CLAIMS if claim in content]
        if found:
            violations[str(path.relative_to(REPO_ROOT))] = found

    assert violations == {}, f"superseded public claims are still shipped: {violations}"
