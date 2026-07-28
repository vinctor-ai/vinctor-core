from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from vinctor_service.audit_anchor import AuditAnchor
    from vinctor_service.audit_export import AuditExport


@dataclass(slots=True)
class AuditSinkConfigurationError(ValueError):
    """Mutable because Python attaches traceback state while propagating exceptions."""

    variable: str
    reason: str

    def __str__(self) -> str:
        return f"{self.variable}: {self.reason}"


@dataclass(frozen=True, slots=True)
class AuditSinks:
    anchor: AuditAnchor
    export: AuditExport


def audit_sinks_from_env(env: Mapping[str, str]) -> AuditSinks:
    from vinctor_service.audit_anchor import anchor_from_env
    from vinctor_service.audit_export import audit_export_from_env

    values = dict(env)
    required = _parse_required(values.get("VINCTOR_AUDIT_SINK_REQUIRED"))
    anchor = anchor_from_env(values)
    export = audit_export_from_env(values)
    has_sink = bool(
        (values.get("VINCTOR_AUDIT_ANCHOR") or "").strip()
        or (values.get("VINCTOR_AUDIT_EXPORT") or "").strip()
    )
    if required and not has_sink:
        raise AuditSinkConfigurationError(
            "VINCTOR_AUDIT_SINK_REQUIRED",
            "requires VINCTOR_AUDIT_ANCHOR or VINCTOR_AUDIT_EXPORT",
        )
    return AuditSinks(anchor=anchor, export=export)


def _probe_file_destination(path: str, variable: str) -> None:
    if not path:
        raise AuditSinkConfigurationError(variable, "file path must not be empty")
    try:
        with open(path, "a", encoding="utf-8"):
            pass
    except (OSError, ValueError):
        raise AuditSinkConfigurationError(
            variable,
            "file sink destination is not usable",
        ) from None


def _parse_required(value: str | None) -> bool:
    if value is None or not value.strip():
        return False
    normalized = value.strip().lower()
    if normalized in {"1", "true"}:
        return True
    if normalized in {"0", "false"}:
        return False
    raise AuditSinkConfigurationError(
        "VINCTOR_AUDIT_SINK_REQUIRED",
        "must be true/false or 1/0",
    )
