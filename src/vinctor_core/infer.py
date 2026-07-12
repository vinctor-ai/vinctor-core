from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass

from vinctor_core.scope import (
    attempted_scope,
    is_valid_grant_scope,
    is_valid_requested_action,
    is_valid_requested_resource,
)


@dataclass(frozen=True)
class Observation:
    """A single observed (action, resource) access, optionally pre-aggregated.

    `count` is how many times it was seen; `last_seen` is an ISO-8601 timestamp
    string (which sorts chronologically) or None.
    """

    action: str
    resource: str
    count: int = 1
    last_seen: str | None = None


@dataclass(frozen=True)
class ScopeProposal:
    """A proposed grant scope, annotated so an operator can review before applying.

    `covers` lists the concrete `action:resource` scopes this proposal subsumes
    (itself, for an exact scope; all observed siblings, for a generalized wildcard).
    """

    scope: str
    count: int
    last_seen: str | None
    generalized: bool
    covers: tuple[str, ...]


def _latest(a: str | None, b: str | None) -> str | None:
    if a is None:
        return b
    if b is None:
        return a
    return max(a, b)  # ISO-8601 strings sort chronologically


def propose_scopes(
    observations: Iterable[Observation],
    *,
    generalize: bool = False,
) -> tuple[ScopeProposal, ...]:
    """Deterministically propose the narrowest grant scopes covering observations.

    Exact by default (one scope per distinct valid pair). With `generalize`, a group
    of >=2 sibling resources under a parent of >=2 segments collapses to a single
    terminal wildcard `action:parent/*`; shallow parents are deliberately NOT
    widened (avoids top-level `category/*` footguns). Invalid actions/resources are
    dropped. Propose-only — this never applies policy.
    """
    # Aggregate valid (action, resource) observations.
    agg: dict[tuple[str, str], tuple[int, str | None]] = {}
    for obs in observations:
        if not is_valid_requested_action(obs.action):
            continue
        if not is_valid_requested_resource(obs.resource):
            continue
        key = (obs.action, obs.resource)
        count, last_seen = agg.get(key, (0, None))
        agg[key] = (count + obs.count, _latest(last_seen, obs.last_seen))

    def _exact(action: str, resource: str, count: int, last_seen: str | None) -> ScopeProposal:
        scope = attempted_scope(action, resource)
        return ScopeProposal(
            scope=scope,
            count=count,
            last_seen=last_seen,
            generalized=False,
            covers=(scope,),
        )

    if not generalize:
        proposals = [
            _exact(action, resource, count, last_seen)
            for (action, resource), (count, last_seen) in agg.items()
        ]
        return tuple(sorted(proposals, key=lambda p: p.scope))

    # Group by (action, parent) for generalization.
    groups: dict[tuple[str, str], list[tuple[str, int, str | None]]] = defaultdict(list)
    for (action, resource), (count, last_seen) in agg.items():
        parent = resource.rsplit("/", 1)[0]
        groups[(action, parent)].append((resource, count, last_seen))

    proposals = []
    for (action, parent), members in groups.items():
        wildcard = f"{action}:{parent}/*"
        deep_enough = len(parent.split("/")) >= 2
        if len(members) >= 2 and deep_enough and is_valid_grant_scope(wildcard):
            total = sum(count for _, count, _ in members)
            latest: str | None = None
            for _, _, last_seen in members:
                latest = _latest(latest, last_seen)
            covers = tuple(sorted(attempted_scope(action, resource) for resource, _, _ in members))
            proposals.append(
                ScopeProposal(
                    scope=wildcard,
                    count=total,
                    last_seen=latest,
                    generalized=True,
                    covers=covers,
                )
            )
        else:
            proposals.extend(
                _exact(action, resource, count, last_seen)
                for resource, count, last_seen in members
            )

    return tuple(sorted(proposals, key=lambda p: p.scope))
