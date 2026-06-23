from __future__ import annotations

from datetime import UTC, datetime, timedelta

from vinctor_core import Grant
from vinctor_core.audit import REASON_SUBJECT_TOKEN_INVALID
from vinctor_service import (
    InMemoryAuditWriter,
    InMemoryGrantRepository,
    InMemoryV1Service,
    V1DelegatedEnforceRequest,
)
from vinctor_service.pop import PopReplayCache, pop_canonical, pop_mac, verify_pop
from vinctor_service.v1_enforce import delegated_enforce_v1_contract

NOW = datetime(2026, 6, 10, 12, 0, tzinfo=UTC)
SKEW = 30


def _grant() -> Grant:
    return Grant(
        grant_id="grnt_main",
        grant_ref="grt_main",
        workspace_id="ws_main",
        agent_id="agent_release",
        scopes=("write:repo/feature/*",),
        status="active",
        expires_at=NOW + timedelta(hours=1),
    )


def _request(
    *, subject_token: str | None, subject_token_proof: str | None = None,
    action: str = "write", resource: str = "repo/feature/readme",
) -> V1DelegatedEnforceRequest:
    return V1DelegatedEnforceRequest(
        pep_id="pep_git_host",
        workspace_id="ws_main",
        agent_id="agent_release",
        grant_ref="grt_main",
        action=action,
        resource=resource,
        pep_workspace_id="ws_main",
        subject_token=subject_token,
        subject_token_proof=subject_token_proof,
    )


def make_proof(
    pop_secret: str,
    *,
    action: str,
    resource: str,
    ts: int,
    nonce: str,
    token_id: str,
) -> str:
    """Test-side proof builder. MUST mirror verify_pop's construction exactly."""
    mac = pop_mac(pop_secret, pop_canonical(action, resource, ts, nonce, token_id))
    return f"{ts}.{nonce}.{mac}"


def _pop_svc() -> tuple[InMemoryV1Service, str, str, str]:
    """Service with a single pop-required token. Returns (svc, raw_token, pop_secret, token_id)."""
    svc = InMemoryV1Service(grants=(_grant(),))
    result = svc.mint_subject_token(
        workspace_id="ws_main",
        agent_id="agent_release",
        grant_ref="grt_main",
        audience="pep_git_host",
        ttl_seconds=300,
        now=NOW,
        pop=True,
    )
    assert result.pop_secret is not None
    return svc, result.token, result.pop_secret, result.token_id


def _now_unix() -> int:
    return int(NOW.timestamp())


# ---- helper / canonical unit tests ----------------------------------------


def test_verify_pop_valid_returns_true() -> None:
    secret = "s3cr3t"
    ts = _now_unix()
    proof = make_proof(secret, action="write", resource="r", ts=ts, nonce="n1",
                       token_id="vtk_x")
    assert verify_pop(
        proof=proof, pop_secret=secret, token_id="vtk_x", action="write",
        resource="r", now=NOW, skew=SKEW, replay_cache=PopReplayCache(),
    ) is True


def test_verify_pop_non_ascii_mac_returns_false_no_crash() -> None:
    # A non-ASCII mac segment would make hmac.compare_digest raise TypeError;
    # verify_pop must reject it cleanly (False), not crash. ts is fresh so that,
    # absent the guard, this would reach compare_digest.
    ts = _now_unix()
    proof = f"{ts}.n1.énot-ascii"
    assert verify_pop(
        proof=proof, pop_secret="s3cr3t", token_id="vtk_x", action="write",
        resource="r", now=NOW, skew=SKEW, replay_cache=PopReplayCache(),
    ) is False


# ---- delegated path tests --------------------------------------------------


def test_pop_non_ascii_mac_denies_without_exception() -> None:
    # Regression: a non-ASCII mac on the enforce path must return the generic
    # fail-closed 403, never an unhandled TypeError.
    svc, raw, _secret, _tid = _pop_svc()
    proof = f"{_now_unix()}.n-1.ébad-mac"
    r = svc.delegated_enforce(
        _request(subject_token=raw, subject_token_proof=proof), now=NOW
    )
    assert r.status_code == 403
    assert r.decision is None


def test_pop_valid_proof_permits_and_proves_identity() -> None:
    svc, raw, secret, token_id = _pop_svc()
    proof = make_proof(secret, action="write", resource="repo/feature/readme",
                       ts=_now_unix(), nonce="n-1", token_id=token_id)
    r = svc.delegated_enforce(
        _request(subject_token=raw, subject_token_proof=proof), now=NOW
    )
    assert r.decision == "permit"
    assert svc.audit_events[-1].identity_proven is True


def test_pop_token_without_proof_denies() -> None:
    svc, raw, _secret, _tid = _pop_svc()
    audit = InMemoryAuditWriter()
    r = delegated_enforce_v1_contract(
        _request(subject_token=raw, subject_token_proof=None),
        grant_repository=svc.grant_repository,
        now=NOW,
        audit_writer=audit,
        subject_token_repository=svc.subject_token_repository,
        pop_replay_cache=PopReplayCache(),
        pop_skew_seconds=SKEW,
    )
    assert r.status_code == 403
    assert r.error == "forbidden"
    assert audit.events[-1].reason_code == REASON_SUBJECT_TOKEN_INVALID


def test_pop_token_with_blank_proof_denies() -> None:
    svc, raw, _secret, _tid = _pop_svc()
    r = svc.delegated_enforce(
        _request(subject_token=raw, subject_token_proof="   "), now=NOW
    )
    assert r.status_code == 403
    assert r.decision is None


def test_pop_wrong_secret_denies() -> None:
    svc, raw, _secret, token_id = _pop_svc()
    proof = make_proof("wrong-secret", action="write",
                       resource="repo/feature/readme", ts=_now_unix(),
                       nonce="n-1", token_id=token_id)
    r = svc.delegated_enforce(
        _request(subject_token=raw, subject_token_proof=proof), now=NOW
    )
    assert r.status_code == 403
    assert r.decision is None


def test_pop_stale_ts_denies() -> None:
    svc, raw, secret, token_id = _pop_svc()
    stale_ts = _now_unix() - (SKEW + 5)
    proof = make_proof(secret, action="write", resource="repo/feature/readme",
                       ts=stale_ts, nonce="n-1", token_id=token_id)
    r = svc.delegated_enforce(
        _request(subject_token=raw, subject_token_proof=proof), now=NOW
    )
    assert r.status_code == 403


def test_pop_far_future_ts_denies() -> None:
    svc, raw, secret, token_id = _pop_svc()
    future_ts = _now_unix() + (SKEW + 5)
    proof = make_proof(secret, action="write", resource="repo/feature/readme",
                       ts=future_ts, nonce="n-1", token_id=token_id)
    r = svc.delegated_enforce(
        _request(subject_token=raw, subject_token_proof=proof), now=NOW
    )
    assert r.status_code == 403


def test_pop_bound_to_different_action_denies() -> None:
    svc, raw, secret, token_id = _pop_svc()
    # proof computed for action "read" but request asks "write"
    proof = make_proof(secret, action="read", resource="repo/feature/readme",
                       ts=_now_unix(), nonce="n-1", token_id=token_id)
    r = svc.delegated_enforce(
        _request(subject_token=raw, subject_token_proof=proof, action="write"),
        now=NOW,
    )
    assert r.status_code == 403


def test_pop_bound_to_different_resource_denies() -> None:
    svc, raw, secret, token_id = _pop_svc()
    proof = make_proof(secret, action="write", resource="repo/feature/other",
                       ts=_now_unix(), nonce="n-1", token_id=token_id)
    r = svc.delegated_enforce(
        _request(subject_token=raw, subject_token_proof=proof,
                 resource="repo/feature/readme"),
        now=NOW,
    )
    assert r.status_code == 403


def test_pop_replay_same_nonce_denies_second_then_new_nonce_permits() -> None:
    svc, raw, secret, token_id = _pop_svc()
    proof = make_proof(secret, action="write", resource="repo/feature/readme",
                       ts=_now_unix(), nonce="n-replay", token_id=token_id)
    first = svc.delegated_enforce(
        _request(subject_token=raw, subject_token_proof=proof), now=NOW
    )
    assert first.decision == "permit"
    # exact same proof (same nonce) -> replay -> denied
    second = svc.delegated_enforce(
        _request(subject_token=raw, subject_token_proof=proof), now=NOW
    )
    assert second.status_code == 403
    # a fresh nonce -> permitted again
    proof2 = make_proof(secret, action="write", resource="repo/feature/readme",
                        ts=_now_unix(), nonce="n-fresh", token_id=token_id)
    third = svc.delegated_enforce(
        _request(subject_token=raw, subject_token_proof=proof2), now=NOW
    )
    assert third.decision == "permit"


def test_pop_malformed_two_parts_denies() -> None:
    svc, raw, _secret, _tid = _pop_svc()
    r = svc.delegated_enforce(
        _request(subject_token=raw, subject_token_proof="123.onlytwo"), now=NOW
    )
    assert r.status_code == 403


def test_pop_malformed_non_int_ts_denies() -> None:
    svc, raw, secret, token_id = _pop_svc()
    # well-formed 3-part shape but ts is not an int
    mac = pop_mac(secret, pop_canonical("write", "repo/feature/readme", 0, "n", token_id))
    proof = f"notanint.n.{mac}"
    r = svc.delegated_enforce(
        _request(subject_token=raw, subject_token_proof=proof), now=NOW
    )
    assert r.status_code == 403


def test_non_pop_token_ignores_present_proof() -> None:
    # A token minted without pop ignores any proof header and behaves as today.
    svc = InMemoryV1Service(grants=(_grant(),))
    result = svc.mint_subject_token(
        workspace_id="ws_main", agent_id="agent_release", grant_ref="grt_main",
        audience="pep_git_host", ttl_seconds=300, now=NOW,
    )
    assert result.pop_secret is None
    r = svc.delegated_enforce(
        _request(subject_token=result.token, subject_token_proof="garbage.proof.here"),
        now=NOW,
    )
    assert r.decision == "permit"


def test_pop_canonical_injection_is_locked_by_length_prefix() -> None:
    # A '\n' (or any byte) inside resource cannot let a proof for one
    # (action, resource) validate for a different split. The length prefix locks
    # the field boundaries.
    secret = "s3cr3t"
    ts = _now_unix()
    nonce = "n1"
    token_id = "vtk_x"
    # Proof bound to action="a", resource="b\nc"
    proof = make_proof(secret, action="a", resource="b\nc", ts=ts, nonce=nonce,
                       token_id=token_id)
    # The same proof must NOT verify for a different field split, e.g.
    # action="a\nb", resource="c" (a naive newline-join would collide here).
    assert verify_pop(
        proof=proof, pop_secret=secret, token_id=token_id, action="a\nb",
        resource="c", now=NOW, skew=SKEW, replay_cache=PopReplayCache(),
    ) is False
    # And the canonical bytes for the two splits differ.
    assert pop_canonical("a", "b\nc", ts, nonce, token_id) != pop_canonical(
        "a\nb", "c", ts, nonce, token_id
    )


def test_pop_cache_full_of_fresh_entries_rejects() -> None:
    cache = PopReplayCache(max_entries=1)
    now_unix = _now_unix()
    assert cache.check_and_record(
        token_id="t", nonce="n1", ts=now_unix, now_unix=now_unix, skew=SKEW
    ) is True
    # a second distinct, fresh nonce -> rejected (fail closed), never evicting
    # the fresh entry already held.
    assert cache.check_and_record(
        token_id="t", nonce="n2", ts=now_unix, now_unix=now_unix, skew=SKEW
    ) is False


def test_pop_token_without_cache_wired_fails_closed() -> None:
    svc, raw, secret, token_id = _pop_svc()
    proof = make_proof(secret, action="write", resource="repo/feature/readme",
                       ts=_now_unix(), nonce="n-1", token_id=token_id)
    audit = InMemoryAuditWriter()
    r = delegated_enforce_v1_contract(
        _request(subject_token=raw, subject_token_proof=proof),
        grant_repository=InMemoryGrantRepository((_grant(),)),
        now=NOW,
        audit_writer=audit,
        subject_token_repository=svc.subject_token_repository,
        pop_replay_cache=None,  # not wired
        pop_skew_seconds=SKEW,
    )
    assert r.status_code == 403
    assert audit.events[-1].reason_code == REASON_SUBJECT_TOKEN_INVALID
