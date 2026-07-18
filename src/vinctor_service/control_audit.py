"""Control-plane audit recording (ADR 0019 / PKA-44).

``ControlPlaneAuditor`` is the single funnel through which control-plane
mutations — mandate toggles, issuable scope bounds, boundary changes,
auto-approval rule changes, policy apply/rollback, and key rotation — reach the
audit chain. The control repositories REQUIRE one at construction, so no
repository can exist without an audit path, and every mutation method calls
:meth:`record` inside its own transaction so the rule change and its audit row
commit as one unit.

Composite operations (policy apply drives the audited bounds/settings
repositories internally) must emit exactly ONE event for the whole operation:
:meth:`composite` suppresses the inner per-mutation records for the duration
and requires the caller to set the operation's single event, which is written
inside the caller's still-open transaction. Finishing a composite without
recording raises — unwinding the enclosing transaction — so a rule change can
never silently commit un-audited. Suppression depth is thread-local and
per-auditor, mirroring the per-connection scope state in ``sqlite_txn``.
"""
from __future__ import annotations

import threading
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime

from vinctor_core.audit import build_control_audit_event
from vinctor_core.models import AuditEvent
from vinctor_service.audit import AuditWriter


class PendingControlEvent:
    """One-shot holder for a composite operation's single control event."""

    def __init__(self) -> None:
        self._event: AuditEvent | None = None

    def set(
        self,
        *,
        event_type: str,
        workspace_id: str,
        action: str,
        resource: str,
        reason: str,
        now: datetime,
        agent_id: str = "",
        scope_attempted: str = "",
        enforcing_principal: str | None = None,
    ) -> None:
        if self._event is not None:
            raise RuntimeError("composite control operation event already recorded")
        self._event = build_control_audit_event(
            event_type=event_type,
            workspace_id=workspace_id,
            action=action,
            resource=resource,
            reason=reason,
            created_at=now,
            agent_id=agent_id,
            scope_attempted=scope_attempted,
            enforcing_principal=enforcing_principal,
        )


class ControlPlaneAuditor:
    def __init__(self, audit_writer: AuditWriter) -> None:
        self._audit_writer = audit_writer
        self._suppression = threading.local()

    def _depth(self) -> int:
        return getattr(self._suppression, "depth", 0)

    def _bound_connection(self) -> object | None:
        """The database connection the durable audit writer writes through.

        ``ExportingAuditWriter`` delegates unknown attributes to its wrapped
        writer, so this reaches the backend writer's connection through any
        decorator. ``None`` means the writer is not connection-backed (e.g.
        the in-memory test writer).
        """
        return getattr(self._audit_writer, "_conn", None)

    def require_bound_to(self, conn: object | None) -> None:
        """Fail closed unless this auditor writes through ``conn``.

        The control repositories and rotation operations claim that a rule
        change and its audit row commit as ONE transaction. That is only true
        when the auditor's durable writer shares the mutation's connection —
        an auditor on another store (or an in-memory writer) would let the
        mutation commit while its audit row lands elsewhere, or nowhere.
        Called at repository construction / rotation / policy entry, BEFORE
        any write. A caller that cannot produce its connection (``None``) is
        refused outright: an identity check that cannot run is a bypass.
        """
        bound = self._bound_connection()
        if bound is None:
            raise ValueError(
                "control auditor must write through the backend's durable "
                "audit writer; a writer without a database connection cannot "
                "commit atomically with the control mutation"
            )
        if conn is None:
            raise ValueError(
                "control mutation store exposes no connection to verify "
                "against; refusing to assume it matches the audit "
                "connection"
            )
        if bound is not conn:
            raise ValueError(
                "control auditor must write through the SAME connection as "
                "the control repository, or the mutation and its audit row "
                "cannot commit as one transaction"
            )

    def _in_open_transaction(self) -> bool | None:
        """Whether the bound connection has an open transaction.

        SQLite exposes ``in_transaction``; psycopg exposes
        ``info.transaction_status`` (libpq: 0 == PQTRANS_IDLE). Returns
        ``None`` when the auditor has no bound connection to inspect.
        """
        conn = self._bound_connection()
        if conn is None:
            return None
        in_transaction = getattr(conn, "in_transaction", None)
        if in_transaction is not None:
            return bool(in_transaction)
        info = getattr(conn, "info", None)
        if info is not None:
            return info.transaction_status != 0
        return None

    def record(
        self,
        *,
        event_type: str,
        workspace_id: str,
        action: str,
        resource: str,
        reason: str,
        now: datetime,
        agent_id: str = "",
        scope_attempted: str = "",
        boundary_id: str | None = None,
        enforcing_principal: str | None = None,
    ) -> None:
        """Write one control event — the caller's open transaction makes the
        mutation and this row atomic. Inside a :meth:`composite`, the enclosing
        operation's single event is the record, so per-mutation records are
        suppressed."""
        if self._depth():
            return
        self._audit_writer.write(
            build_control_audit_event(
                event_type=event_type,
                workspace_id=workspace_id,
                action=action,
                resource=resource,
                reason=reason,
                created_at=now,
                agent_id=agent_id,
                scope_attempted=scope_attempted,
                boundary_id=boundary_id,
                enforcing_principal=enforcing_principal,
            )
        )

    @contextmanager
    def composite(self) -> Iterator[PendingControlEvent]:
        """Bracket a composite control operation (e.g. policy apply).

        Inner :meth:`record` calls are suppressed; the caller MUST set the
        operation's event on the yielded ``PendingControlEvent`` — it is
        written on successful exit, inside the caller's still-open transaction.
        Exiting without one raises (rolling the enclosing transaction back);
        a body exception writes nothing (the transaction rolls back anyway).

        Two fail-closed guards on entry: a composite requires the caller's
        transaction to already be OPEN on the auditor's connection (otherwise
        the suppressed inner mutations would each self-commit while their
        records are swallowed — committed rule changes with no audit trail),
        and composites do not nest (an inner composite would write its event
        while the outer operation is still active, breaking the one-event-
        per-operation contract).
        """
        if self._depth():
            raise RuntimeError(
                "composite control operations do not nest: the enclosing "
                "operation records the ONE control event for everything "
                "inside it"
            )
        if self._in_open_transaction() is False:
            raise RuntimeError(
                "a composite control operation requires an open transaction "
                "on the audit connection; without one, suppressed inner "
                "mutations would commit individually with no audit record"
            )
        pending = PendingControlEvent()
        depth = self._depth()
        self._suppression.depth = depth + 1
        try:
            yield pending
        finally:
            self._suppression.depth = depth
        if pending._event is None:
            raise RuntimeError(
                "composite control operation finished without recording its "
                "control audit event; refusing to commit an un-audited rule change"
            )
        self._audit_writer.write(pending._event)
