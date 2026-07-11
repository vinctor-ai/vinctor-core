"""Propose least-privilege scopes from an agent's observed audit trace (ADR 0010).

Propose-only: this builds a reviewable proposal document; it never applies policy.
Operates on any audit-event objects exposing ``agent_id``, ``decision``, ``action``,
``resource``, and ``created_at`` (e.g. ``vinctor_core.models.AuditEvent``), so the
logic is testable without a database.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime
from typing import Any

from vinctor_core.infer import Observation, ScopeProposal, propose_scopes


def _iso(value: Any) -> str | None:
    if isinstance(value, datetime):
        return value.isoformat()
    return value  # already an ISO string, or None


def _observations_for(
    events: Iterable[Any],
    *,
    agent_id: str,
    decision: str,
    since: str | None,
    until: str | None,
) -> list[Observation]:
    observations: list[Observation] = []
    for event in events:
        if event.agent_id != agent_id or event.decision != decision:
            continue
        last_seen = _iso(event.created_at)
        if since is not None and (last_seen is None or last_seen < since):
            continue
        if until is not None and (last_seen is None or last_seen > until):
            continue
        observations.append(
            Observation(action=event.action, resource=event.resource, count=1, last_seen=last_seen)
        )
    return observations


def _scope_entry(proposal: ScopeProposal) -> dict[str, object]:
    entry: dict[str, object] = {
        "scope": proposal.scope,
        "count": proposal.count,
        "last_seen": proposal.last_seen,
    }
    if proposal.generalized:
        entry["covers"] = list(proposal.covers)
    return entry


def infer_policy_document(
    events: Iterable[Any],
    *,
    agent_id: str,
    since: str | None = None,
    until: str | None = None,
    generalize: bool = False,
    include_denied: bool = False,
) -> dict[str, object]:
    """Build a propose-only scope proposal document for one agent.

    Proposes exact/generalized scopes from the agent's *permitted* actions in the
    window. With ``include_denied``, denied attempts are proposed into a SEPARATE
    ``candidates_from_denied`` list — never merged into ``scopes``.
    """
    events = list(events)
    permitted = _observations_for(
        events, agent_id=agent_id, decision="permit", since=since, until=until
    )
    proposed: dict[str, object] = {
        "apply": False,  # propose-only: this document is for review, not application
        "agent_id": agent_id,
        "generalized": generalize,
        "scopes": [_scope_entry(p) for p in propose_scopes(permitted, generalize=generalize)],
    }
    if include_denied:
        denied = _observations_for(
            events, agent_id=agent_id, decision="deny", since=since, until=until
        )
        proposed["candidates_from_denied"] = [
            _scope_entry(p) for p in propose_scopes(denied, generalize=generalize)
        ]
    return {"proposed": proposed}
