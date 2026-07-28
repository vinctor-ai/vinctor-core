from __future__ import annotations

from pathlib import Path


def _postgres_contract_command() -> str:
    workflow = Path(__file__).parents[1] / ".github" / "workflows" / "ci.yml"
    contents = workflow.read_text(encoding="utf-8")
    marker = "name: Run Postgres storage contract"
    return contents.split(marker, 1)[1]


def test_postgres_job_selects_live_entropy_failure_carrier() -> None:
    command = _postgres_contract_command()
    carrier = "tests/test_idempotency_rng_failure.py"
    assert carrier in command
