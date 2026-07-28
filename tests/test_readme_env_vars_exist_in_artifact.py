"""Every ``VINCTOR_*`` name in the shipped README must exist in the shipped code.

This defect class has now shipped twice: the README named an environment
variable as a control, an operator set it, and nothing in the artifact they
installed ever read it — so it configured nothing, silently, with no error and
no log line. A phantom flag is worse than a missing feature, because the
operator believes the control is on.

The gate is deliberately mechanical. ``README.md`` is shipped (pyproject's
``readme``, rendered into the wheel's METADATA); the wheel's code is exactly the
package roots declared in ``[tool.hatch.build.targets.wheel]``. This test reads
BOTH from ``pyproject.toml`` rather than hardcoding them, so adding or renaming
a shipped package moves the gate with it instead of quietly narrowing it.
"""
from __future__ import annotations

import re
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Whole-identifier matching in both directions: ``\b`` does not fire between a
# letter and ``_``, so ``VINCTOR_AUDIT_EXPORT`` does NOT match inside
# ``VINCTOR_AUDIT_EXPORT_BATCH_SIZE``. Substring matching would report a
# never-implemented flag as present whenever a longer name shared its prefix.
IDENTIFIER = re.compile(r"\bVINCTOR_[A-Z0-9_]+\b")

# Names the README attributes to a DIFFERENT shipped component, which this
# artifact therefore cannot contain. Each entry needs a reason. This is not a
# place to silence a real phantom flag: `test_exemptions_are_still_absent`
# fails once the name does appear here, so an exemption expires by itself.
EXEMPT: dict[str, str] = {
    # README: "driven by the PEP's `VINCTOR_ENFORCEMENT_MODE`" — read by the
    # policy enforcement point (e.g. the vinctor-mcp-pep npm package), not by
    # vinctor-core. The decision service never reads it.
    "VINCTOR_ENFORCEMENT_MODE": "read by the PEP, not by this artifact",
}


def _wheel_source_roots() -> list[Path]:
    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    packages = pyproject["tool"]["hatch"]["build"]["targets"]["wheel"]["packages"]
    roots = [REPO_ROOT / package for package in packages]
    assert roots, "pyproject declares no wheel packages; the gate would check nothing"
    for root in roots:
        assert root.is_dir(), f"declared wheel package is missing: {root}"
    return roots


def _shipped_readme_text() -> str:
    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    return (REPO_ROOT / pyproject["project"]["readme"]).read_text(encoding="utf-8")


def _shipped_sources() -> list[str]:
    contents = []
    for root in _wheel_source_roots():
        for path in sorted(root.rglob("*")):
            if not path.is_file() or "__pycache__" in path.parts:
                continue
            contents.append(path.read_text(encoding="utf-8", errors="replace"))
    return contents


def _names_in_readme() -> set[str]:
    return set(IDENTIFIER.findall(_shipped_readme_text()))


def _absent_from_artifact(names: set[str]) -> set[str]:
    sources = _shipped_sources()
    return {
        name
        for name in names
        if not any(re.search(rf"\b{re.escape(name)}\b", source) for source in sources)
    }


def test_readme_env_vars_all_exist_in_the_shipped_artifact() -> None:
    names = _names_in_readme()
    # Fail loudly if the extraction itself breaks: a regex that matches nothing
    # would make this gate pass forever.
    assert len(names) >= 5, f"suspiciously few VINCTOR_* names found in README: {sorted(names)}"

    missing = sorted(_absent_from_artifact(names) - set(EXEMPT))

    assert not missing, (
        "README documents VINCTOR_* names that do not exist anywhere in the "
        "shipped wheel, so setting them configures nothing:\n  "
        + "\n  ".join(missing)
        + "\n\nEither implement them, remove them from README.md, or — only if "
        "another shipped component owns them — add them to EXEMPT in "
        f"{Path(__file__).name} with a reason."
    )


def test_exemptions_are_still_absent() -> None:
    # A stale exemption is the same failure mode in reverse: it would hide the
    # next phantom flag that happens to reuse the name. Once the artifact
    # implements an exempted name, the exemption must be deleted.
    stale = sorted(set(EXEMPT) - _absent_from_artifact(set(EXEMPT)))

    assert not stale, (
        "these names are now implemented in the shipped artifact; remove them "
        f"from EXEMPT in {Path(__file__).name}:\n  " + "\n  ".join(stale)
    )
