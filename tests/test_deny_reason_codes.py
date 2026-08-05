"""Operator-facing subject-token deny reason codes (PKA-254).

An operator who sees a deny has exactly three questions: do I widen a grant, do
I edit a rule, or do I stop? Six distinct subject-token failure causes — with
genuinely different answers to that question — all wrote the single
`subject_token_invalid` reason_code, so the operator audit could not tell "I
revoked that token" from "the PEP is configured with the wrong audience" from
"the PoP proof failed".

The AGENT-facing side must not gain that detail: a fine-grained deny reason in a
response is a policy-probing side channel (ADR 0008). This refines the
`reason_code` on a rejection row that already existed — no new rows, no volume
change, caller-facing bytes identical — which is ADR 0008's own pattern.

Every test asserts BOTH sides: the operator record gains the specific cause AND
the agent-facing response stays byte-identical. The second half is what stops a
later change from quietly widening the side channel.
"""

from dataclasses import asdict
from datetime import UTC, datetime, timedelta

from vinctor_core import Grant
from vinctor_service import (
    InMemoryAuditWriter,
    InMemoryGrantRepository,
    V1DelegatedEnforceRequest,
    delegated_enforce_v1_contract,
)
from vinctor_service.keys import _hash_key
from vinctor_service.models import SubjectToken
from vinctor_service.pop import PopReplayCache
from vinctor_service.repositories import InMemorySubjectTokenRepository

NOW = datetime(2026, 8, 4, 12, 0, tzinfo=UTC)
WS = "ws_main"
AGENT = "agent_release"
PEP = "pep_git"
RAW_TOKEN = "vat_decoy_not_a_real_token"

GRANT = Grant(
    grant_id="grnt_main",
    grant_ref="grt_main",
    workspace_id=WS,
    agent_id=AGENT,
    scopes=("read:repo/docs/*",),
    status="active",
    expires_at=NOW + timedelta(hours=1),
)


def _token(**over) -> SubjectToken:
    base = dict(
        token_id="vtk_probe",
        token_hash=_hash_key(RAW_TOKEN),
        workspace_id=WS,
        agent_id=AGENT,
        grant_ref=GRANT.grant_ref,
        audience=PEP,
        issued_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=10),
        created_by=AGENT,
    )
    base.update(over)
    return SubjectToken(**base)


def _delegated(token: SubjectToken | None, audit: InMemoryAuditWriter):
    repository = InMemorySubjectTokenRepository()
    if token is not None:
        repository.insert(token)
    return delegated_enforce_v1_contract(
        V1DelegatedEnforceRequest(
            workspace_id=WS,
            agent_id=AGENT,
            grant_ref=GRANT.grant_ref,
            action="read",
            resource="repo/docs/readme",
            pep_id=PEP,
            subject_token=RAW_TOKEN,
        ),
        grant_repository=InMemoryGrantRepository((GRANT,)),
        now=NOW,
        audit_writer=audit,
        pep_workspace_id=WS,
        subject_token_repository=repository,
        pop_replay_cache=PopReplayCache(),
    )


TOKEN_CAUSES = {
    # cause -> (token, expected operator-only reason_code)
    "not_found": (None, "subject_token_not_found"),
    "revoked": (
        _token(revoked_at=NOW - timedelta(minutes=1)),
        "subject_token_revoked",
    ),
    "expired": (
        _token(expires_at=NOW - timedelta(minutes=1)),
        "subject_token_expired",
    ),
    "wrong_audience": (_token(audience="pep_other"), "subject_token_mismatch"),
    "bound_elsewhere": (_token(bound_action="write"), "subject_token_mismatch"),
    "pop_proof_failed": (_token(pop_secret="decoy-pop-secret"), "pop_proof_invalid"),
}


def test_each_subject_token_cause_has_its_own_operator_reason_code() -> None:
    seen = {}
    for cause, (token, expected) in TOKEN_CAUSES.items():
        audit = InMemoryAuditWriter()
        _delegated(token, audit)
        assert len(audit.events) == 1, cause
        seen[cause] = audit.events[0].reason_code
        assert seen[cause] == expected, cause

    # The remedies differ, so the codes must too: a revoked token is an operator
    # decision, an audience mismatch is a PEP misconfiguration, and a failed PoP
    # proof is a clock/secret/replay problem.
    assert seen["revoked"] != seen["expired"] != seen["not_found"]
    assert seen["wrong_audience"] != seen["revoked"]
    assert seen["pop_proof_failed"] != seen["wrong_audience"]


def test_subject_token_audit_row_count_is_unchanged() -> None:
    """Refinement, not new volume: still exactly one rejection row per deny.

    ADR 0008 rejected "audit every rejection" partly over log-flooding risk, so
    a change to the reason codes must not become a change to how much is
    written. It also must not weaken the row's redaction invariants.
    """
    for cause, (token, _) in TOKEN_CAUSES.items():
        audit = InMemoryAuditWriter()
        _delegated(token, audit)
        assert len(audit.events) == 1, cause
        assert audit.events[0].event_type == "access_rejected", cause
        assert audit.events[0].grant_id == "", cause
        assert audit.events[0].grant_ref == "", cause


def test_subject_token_denials_stay_indistinguishable_to_the_agent() -> None:
    """The side-channel pin: no specific cause may reach the agent.

    Every subject-token deny must return the SAME response. If a later change
    plumbs a specific reason code into the response, an agent can probe the
    token/PEP configuration by reading it back, and this test fails.
    """
    responses = []
    specific_codes = {expected for _, expected in TOKEN_CAUSES.values()}

    for cause, (token, _) in TOKEN_CAUSES.items():
        response = _delegated(token, InMemoryAuditWriter())
        body = asdict(response)
        body.pop("audit_event_id", None)
        responses.append((cause, body))

    first_cause, first_body = responses[0]
    assert first_body == {
        "status_code": 403,
        "decision": None,
        "error": "forbidden",
        "reason": "subject token is not valid",
    }
    for cause, body in responses[1:]:
        assert body == first_body, f"{cause} is distinguishable from {first_cause}"

    text = str([body for _, body in responses])
    for code in specific_codes:
        assert code not in text, f"agent-facing response leaks {code!r}"
