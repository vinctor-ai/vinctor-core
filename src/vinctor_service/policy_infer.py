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

PERMIT_EVENT_SOURCES = {
    "action_permitted": "enforced",
    "action_observed": "observed",
    "action_would_permit": "simulated",
}
DENY_EVENT_TYPES = {"action_denied", "action_would_deny", "access_rejected"}


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
    event_types: set[str],
) -> list[Observation]:
    observations: list[Observation] = []
    for event in events:
        if (
            event.agent_id != agent_id
            or event.decision != decision
            or event.event_type not in event_types
        ):
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


def _scope_entry(
    proposal: ScopeProposal,
    evidence_by_scope: dict[str, dict[str, int]] | None,
) -> dict[str, object]:
    entry: dict[str, object] = {
        "scope": proposal.scope,
        "count": proposal.count,
        "last_seen": proposal.last_seen,
        "generalized": proposal.generalized,
    }
    if evidence_by_scope is not None:
        evidence = {"enforced": 0, "observed": 0, "simulated": 0}
        for covered_scope in proposal.covers:
            for source, count in evidence_by_scope.get(covered_scope, {}).items():
                evidence[source] += count
        entry["evidence"] = evidence
        if (
            evidence["enforced"] == 0
            and evidence["simulated"] == 0
            and evidence["observed"] > 0
        ):
            entry["warning"] = "observed-only evidence; unverified agent self-report"
    if proposal.generalized:
        entry["covers"] = list(proposal.covers)
    return entry


def _in_window(event: Any, *, agent_id: str, since: str | None, until: str | None) -> bool:
    if event.agent_id != agent_id:
        return False
    last_seen = _iso(event.created_at)
    if since is not None and (last_seen is None or last_seen < since):
        return False
    return until is None or (last_seen is not None and last_seen <= until)


def _evidence(
    events: list[Any],
    *,
    agent_id: str,
    since: str | None,
    until: str | None,
) -> tuple[dict[str, dict[str, int]], dict[str, int]]:
    by_scope: dict[str, dict[str, int]] = {}
    summary = {
        "enforced_permit": 0,
        "observed_mapped": 0,
        "observed_unmapped": 0,
        "blocked_unmapped": 0,
        "simulated_permit": 0,
        "simulated_deny": 0,
    }
    summary_key = {
        "action_permitted": "enforced_permit",
        "action_observed": "observed_mapped",
        "action_unmapped": "observed_unmapped",
        # F7 PEPs that block unmapped actions emit action_blocked_unmapped;
        # the rows carry no action/resource, so they are evidence only and
        # never feed scope proposals.
        "action_blocked_unmapped": "blocked_unmapped",
        "action_would_permit": "simulated_permit",
        "action_would_deny": "simulated_deny",
    }
    for event in events:
        if not _in_window(event, agent_id=agent_id, since=since, until=until):
            continue
        key = summary_key.get(event.event_type)
        if key is not None:
            summary[key] += 1
        source = PERMIT_EVENT_SOURCES.get(event.event_type)
        if source is None:
            continue
        scope = f"{event.action}:{event.resource}"
        counts = by_scope.setdefault(
            scope,
            {"enforced": 0, "observed": 0, "simulated": 0},
        )
        counts[source] += 1
    return by_scope, summary


def infer_policy_document(
    events: Iterable[Any],
    *,
    agent_id: str,
    since: str | None = None,
    until: str | None = None,
    generalize: bool = False,
    include_denied: bool = False,
    min_observations: int = 1,
) -> dict[str, object]:
    """Build a propose-only scope proposal document for one agent.

    Proposes exact/generalized scopes from the agent's permitted or explicitly
    observed mapped actions in the window. Unmapped observations carry no
    action/resource pair and are ignored by scope validation. With
    ``include_denied``, denied attempts are proposed into a SEPARATE
    ``candidates_from_denied`` list — never merged into ``scopes``.
    """
    events = list(events)
    permitted = _observations_for(
        events,
        agent_id=agent_id,
        decision="permit",
        since=since,
        until=until,
        event_types=set(PERMIT_EVENT_SOURCES),
    )
    evidence_by_scope, evidence_summary = _evidence(
        events,
        agent_id=agent_id,
        since=since,
        until=until,
    )
    proposals = propose_scopes(
        permitted,
        generalize=generalize,
        min_count=min_observations,
    )
    proposed: dict[str, object] = {
        "apply": False,  # propose-only: this document is for review, not application
        "agent_id": agent_id,
        "generalized": generalize,
        "minimum_observations": min_observations,
        "evidence_summary": evidence_summary,
        "scopes": [_scope_entry(proposal, evidence_by_scope) for proposal in proposals],
    }
    if include_denied:
        denied = _observations_for(
            events,
            agent_id=agent_id,
            decision="deny",
            since=since,
            until=until,
            event_types=DENY_EVENT_TYPES,
        )
        proposed["candidates_from_denied"] = [
            _scope_entry(proposal, None)
            for proposal in propose_scopes(
                denied,
                generalize=generalize,
                min_count=min_observations,
            )
        ]
    return {"proposed": proposed}
