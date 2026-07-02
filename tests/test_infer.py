from __future__ import annotations

from vinctor_core.infer import Observation, ScopeProposal, propose_scopes


def _scopes(proposals):
    return [p.scope for p in proposals]


def test_empty_observations_yield_no_proposals():
    assert propose_scopes([]) == ()


def test_single_pair_yields_one_exact_scope():
    out = propose_scopes(
        [Observation("read", "repo/feature/readme", count=1, last_seen="2026-07-01T00:00:00+00:00")]
    )
    assert out == (
        ScopeProposal(
            scope="read:repo/feature/readme",
            count=1,
            last_seen="2026-07-01T00:00:00+00:00",
            generalized=False,
            covers=("read:repo/feature/readme",),
        ),
    )


def test_duplicates_aggregate_count_and_latest_last_seen():
    out = propose_scopes(
        [
            Observation("read", "repo/feature/a", count=2, last_seen="2026-07-01T00:00:00+00:00"),
            Observation("read", "repo/feature/a", count=3, last_seen="2026-07-02T00:00:00+00:00"),
        ]
    )
    assert [(p.scope, p.count, p.last_seen) for p in out] == [
        ("read:repo/feature/a", 5, "2026-07-02T00:00:00+00:00"),
    ]


def test_invalid_action_or_resource_is_dropped():
    out = propose_scopes(
        [
            Observation("frobnicate", "repo/feature/a"),  # bad action
            Observation("read", "singleseg"),  # bad resource (<2 segments)
            Observation("read", "repo/../secrets"),  # traversal → invalid
            Observation("read", "repo/feature/a"),  # valid, kept
        ]
    )
    assert _scopes(out) == ["read:repo/feature/a"]


def test_exact_mode_never_emits_wildcards_even_with_siblings():
    out = propose_scopes(
        [
            Observation("read", "repo/feature/a"),
            Observation("read", "repo/feature/b"),
        ]
    )
    assert _scopes(out) == ["read:repo/feature/a", "read:repo/feature/b"]
    assert all(not p.generalized for p in out)


def test_generalize_collapses_deep_siblings():
    out = propose_scopes(
        [
            Observation("read", "repo/feature/a", count=1, last_seen="2026-07-01T00:00:00+00:00"),
            Observation("read", "repo/feature/b", count=2, last_seen="2026-07-03T00:00:00+00:00"),
        ],
        generalize=True,
    )
    assert out == (
        ScopeProposal(
            scope="read:repo/feature/*",
            count=3,
            last_seen="2026-07-03T00:00:00+00:00",
            generalized=True,
            covers=("read:repo/feature/a", "read:repo/feature/b"),
        ),
    )


def test_generalize_refuses_shallow_siblings_exfil_footgun():
    # parent "net" has only 1 segment → do NOT widen to send:net/* .
    out = propose_scopes(
        [
            Observation("send", "net/internal"),
            Observation("send", "net/external"),
        ],
        generalize=True,
    )
    assert _scopes(out) == ["send:net/external", "send:net/internal"]
    assert all(not p.generalized for p in out)


def test_generalize_leaves_singletons_exact():
    out = propose_scopes([Observation("read", "repo/feature/a")], generalize=True)
    assert _scopes(out) == ["read:repo/feature/a"]
    assert out[0].generalized is False


def test_output_is_sorted_by_scope_deterministically():
    out = propose_scopes(
        [
            Observation("write", "repo/x/z"),
            Observation("read", "repo/x/a"),
        ]
    )
    assert _scopes(out) == ["read:repo/x/a", "write:repo/x/z"]
