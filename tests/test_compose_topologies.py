from __future__ import annotations

from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
VINCTOR_COMPOSE_PATHS = (
    ROOT / "compose.yaml",
    ROOT / "deploy" / "preview" / "compose.yaml",
    ROOT / "deploy" / "reference" / "compose.yaml",
)


@pytest.mark.parametrize(
    "compose_path",
    VINCTOR_COMPOSE_PATHS,
    ids=lambda compose_path: compose_path.relative_to(ROOT).as_posix(),
)
def test_vinctor_compose_services_enable_pid1_init(compose_path: Path) -> None:
    compose = yaml.safe_load(compose_path.read_text(encoding="utf-8"))
    vinctor = compose["services"]["vinctor"]

    assert vinctor["command"] == ["vinctor", "service", "serve"]
    assert vinctor["init"] is True
