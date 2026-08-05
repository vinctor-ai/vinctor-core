"""The env registry must match what the shipped code actually reads.

PKA-168's defect was a documented control that no shipped code read. A registry
of "known" variables maintained by hand would reintroduce exactly that: it would
drift, and a stale allowlist is another way to claim a control exists when it
does not.

So the registry is checked BOTH ways against the real sources:

  - a name in the code but not the registry would be warned about while working
    perfectly — the warning would cry wolf and get ignored;
  - a name in the registry but not the code is a phantom flag, silenced. That is
    PKA-168 itself.

The scan derives the shipped packages from ``pyproject.toml`` rather than
hardcoding them, so adding or renaming a package moves the gate with it instead
of quietly narrowing it — the same discipline as
``test_readme_env_vars_exist_in_artifact.py``.

It reads those packages as PARSED PYTHON, not as text (PKA-211). A gate that
cannot distinguish a variable the code reads from one a comment merely names
does not check what it claims to check — see
``_names_referenced_in_source``.
"""

from __future__ import annotations

import ast
import re
import tomllib
from pathlib import Path

from vinctor_service.env_registry import (
    _KNOWN,
    _SIBLING_COMPONENTS,
    unrecognized_env_warning,
    unrecognized_vinctor_env_vars,
)

REPO_ROOT = Path(__file__).resolve().parent.parent

# Matched against a COMPLETE string literal, never searched inside one. Anchoring
# is what keeps VINCTOR_AUDIT_EXPORT from matching inside
# VINCTOR_AUDIT_EXPORT_BATCH_SIZE, and it is also what separates a name the code
# USES from a name some prose merely MENTIONS.
NAME = re.compile(r"VINCTOR_[A-Z0-9_]+")


def _wheel_source_roots() -> list[Path]:
    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    packages = pyproject["tool"]["hatch"]["build"]["targets"]["wheel"]["packages"]
    roots = [REPO_ROOT / package for package in packages]
    assert roots, "pyproject declares no wheel packages; the gate would check nothing"
    return roots


def _names_referenced_in_source(source: str) -> set[str]:
    """``VINCTOR_*`` names this source uses as a VALUE, read from its parsed AST.

    PKA-211. This used to be a regex over raw file text, which counted a name
    written in a ``#`` comment as a name the code reads. A phantom in ``_KNOWN``
    plus that same name in a comment anywhere in the shipped packages therefore
    passed this gate, and the live service then silently accepted the phantom —
    PKA-168 reintroduced through the very gate that exists to prevent it, with
    CI green.

    Parsing discards comments before anything is matched. Requiring the name to
    be the ENTIRE literal discards the rest of the prose, which is where the
    remaining mentions live: an error message (``"VINCTOR_MCP_ENDPOINT is
    required"``), an argparse help string (``"(env: VINCTOR_DB)"``), a
    docstring, or an f-string emitting a shell ``export`` line. None of those
    read anything.

    Every shape this codebase actually uses to name a variable it consults
    survives, because all of them pass the bare name as a literal:
    ``os.environ.get(NAME)``, ``os.environ[NAME]``, ``NAME in os.environ``,
    ``.get(NAME)`` on an injected env mapping, a helper called with the name
    (``_env_int(env, NAME, 3)``), a module constant (``KEYRING_ENV: Final =
    NAME``), and a tuple of required names. Measured against the tree, this
    yields exactly the set the old regex did, minus prose.

    The residue is a bare literal that nothing then uses — dead code, which a
    reader can see. Prose is what a reader cannot see, and that is what this
    closes.
    """
    return {
        node.value
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and NAME.fullmatch(node.value)
    }


def _names_in_shipped_sources() -> set[str]:
    names: set[str] = set()
    for root in _wheel_source_roots():
        for path in sorted(root.rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
            # The registry itself LISTS names, it does not read them. Scanning it
            # would make every entry trivially self-justifying — including the
            # sibling-component names, which would then look like variables this
            # artifact reads. That defeats both gates at once.
            if path.name == "env_registry.py":
                continue
            names |= _names_referenced_in_source(path.read_text(encoding="utf-8"))
    return names


def test_every_name_in_the_code_is_registered() -> None:
    """Otherwise the warning fires on a variable that works, and gets ignored."""
    missing = _names_in_shipped_sources() - _KNOWN
    assert not missing, (
        "read by the shipped code but absent from env_registry._KNOWN, so setting "
        f"them would be warned about while configuring the service correctly: {sorted(missing)}"
    )


def test_every_registered_name_is_read_by_the_code() -> None:
    """Otherwise the registry silences a phantom flag — PKA-168's own defect."""
    phantom = _KNOWN - _names_in_shipped_sources()
    assert not phantom, (
        "registered as known but read by nothing in this build, so setting them "
        f"would be silently accepted while configuring nothing: {sorted(phantom)}"
    )


def test_prose_naming_a_variable_does_not_count_as_reading_it() -> None:
    """PKA-211. The two gates above are only worth their claim if the scan can
    tell a READ from a MENTION.

    While it matched raw file text, it could not. Registering a name nothing
    reads and writing that name into a ``#`` comment in any shipped source was
    enough to satisfy `test_every_registered_name_is_read_by_the_code`: the
    phantom was declared "known", the live warning went quiet about it, and CI
    stayed green. That is PKA-168's own defect wearing the gate's uniform, and a
    comment is the ideal place to hide it because nothing about a comment looks
    like code.

    So the shapes below must all be invisible to the scan, and the two real
    reads must both survive it — without the second half, a scan that found
    nothing at all would pass this test.
    """
    source = (
        "# VINCTOR_PHANTOM_IN_COMMENT is honoured here.\n"
        '"""VINCTOR_PHANTOM_IN_DOCSTRING is honoured here too."""\n'
        "import os\n"
        "\n"
        "\n"
        "def load(env, parser):\n"
        '    """Reads VINCTOR_PHANTOM_IN_INNER_DOCSTRING."""\n'
        '    parser.add_argument("--db", help="(env: VINCTOR_PHANTOM_IN_HELP_TEXT)")\n'
        "    print(f'export VINCTOR_PHANTOM_IN_FSTRING=\"{env}\"')\n"
        '    if not env.get("VINCTOR_REALLY_READ"):\n'
        '        raise ValueError("VINCTOR_PHANTOM_IN_ERROR_MESSAGE is required")\n'
        '    return os.environ.get("VINCTOR_ALSO_REALLY_READ")\n'
    )

    assert _names_referenced_in_source(source) == {
        "VINCTOR_REALLY_READ",
        "VINCTOR_ALSO_REALLY_READ",
    }


def test_sibling_names_are_not_also_claimed_as_our_own() -> None:
    """The two sets answer different questions and must not overlap: one means
    'we read this', the other means 'someone else does, stay quiet'."""
    assert not (_KNOWN & _SIBLING_COMPONENTS)


def test_sibling_names_are_not_read_by_this_artifact() -> None:
    """If a sibling's variable ever becomes ours, it belongs in _KNOWN — leaving
    it here would exempt a real variable from the honesty gate above."""
    assert not (_SIBLING_COMPONENTS & _names_in_shipped_sources())


def test_a_recognized_variable_is_silent() -> None:
    env = {"VINCTOR_AUDIT_SINK_REQUIRED": "true", "VINCTOR_PORT": "8765", "PATH": "/bin"}
    assert unrecognized_vinctor_env_vars(env) == []
    assert unrecognized_env_warning(env) is None


def test_a_typo_is_reported() -> None:
    env = {"VINCTOR_AUDIT_SINK_REQUIRE": "true"}
    assert unrecognized_vinctor_env_vars(env) == ["VINCTOR_AUDIT_SINK_REQUIRE"]
    warning = unrecognized_env_warning(env)
    assert warning is not None
    assert "VINCTOR_AUDIT_SINK_REQUIRE" in warning


def test_the_warning_names_the_version_mismatch_cause() -> None:
    """The case that actually happened is NOT a typo: the name is spelled
    correctly and simply is not in the installed build. A warning that only says
    'unknown variable' sends the operator hunting for a misspelling they will
    not find, so it has to name the other cause too."""
    warning = unrecognized_env_warning({"VINCTOR_SOMETHING_NEW": "1"})
    assert warning is not None
    assert "version" in warning.lower()


def test_a_sibling_components_variable_is_silent() -> None:
    """A boundary and its service share one environment all the time. Warning
    here would fire on working deployments and train operators to ignore it."""
    env = {
        "VINCTOR_ENFORCEMENT_MODE": "enforce",
        "VINCTOR_HERMES_UNMAPPED_POLICY": "block",
        "VINCTOR_CLAUDE_CODE_HOOK_CONFIG": "/etc/hook.json",
    }
    assert unrecognized_vinctor_env_vars(env) == []


def test_non_vinctor_variables_are_ignored() -> None:
    assert unrecognized_vinctor_env_vars({"PATH": "/bin", "HOME": "/root"}) == []


def test_multiple_unknowns_are_sorted_and_all_reported() -> None:
    """Stable across restarts, and never truncated — an operator fixing one
    typo must not have to restart to discover the second."""
    env = {"VINCTOR_ZEBRA": "1", "VINCTOR_ALPHA": "1", "VINCTOR_MIKE": "1"}
    assert unrecognized_vinctor_env_vars(env) == [
        "VINCTOR_ALPHA",
        "VINCTOR_MIKE",
        "VINCTOR_ZEBRA",
    ]
    warning = unrecognized_env_warning(env)
    assert warning is not None
    for name in ("VINCTOR_ALPHA", "VINCTOR_MIKE", "VINCTOR_ZEBRA"):
        assert name in warning
