# ADR 0021: Asymmetric sender-constrained proof of possession

Date: 2026-07-19

## Status

Accepted. This resolves PKA-19.

This decision supersedes only the proof-of-possession HMAC-redesign dimension
of PKA-17. Audit authenticity (including the audit hash chain and any future
external signing or anchoring) remains a separate decision and is not changed
here. It also removes only `pop_secret` from the PKA-36 KMS scope; PKA-36
remains applicable to future audit/other-secret custody decisions.

## Context

ADR 0007 selected grant-bound subject tokens as the identity-proof mechanism.
Its HMAC-PoP hardening is implemented today: an agent receives a per-token
`pop_secret` once, signs a fresh proof over the action, resource, timestamp,
nonce, and token id, and the delegated-enforce service verifies it with a
30-second freshness window and a bounded replay cache. The PEP relays the raw
token and `X-Subject-Token-Proof`; the PEP does not learn the secret. Invalid,
stale, mismatched, or replayed proofs fail closed with the existing generic
subject-token-invalid response and rejection audit event.

That mechanism still makes the service a holder of a signing secret. A
read-only compromise of the token store exposes `pop_secret`; combined with a
captured raw token, that permits forged proofs until expiry or revocation. The
sender constraint should instead be anchored in a key that only the agent can
use.

## Decision

### Asymmetric PoP is the forward contract

Use an asymmetric sender-constrained subject-token proof. The agent generates
and retains the private signing key. Vinctor stores and uses only the
corresponding public verification key (identified by a token-bound key id).
The private key is never sent to Vinctor, the PEP, or stored in the Vinctor
database. The initial profile is an Ed25519 key pair and signature; the
wire-level profile is versioned so a future algorithm can be added without
silently accepting an ambiguous proof.

An asymmetric subject token is bound to the agent's public-key id. Each
delegated enforce carries a fresh signature from that private key over the
same authorization binding as the current PoP path (token id, action,
resource, timestamp, and nonce), plus the proof-profile version. Vinctor
checks the signature with the stored public key, enforces the existing
freshness and replay rules, and keeps the existing generic failure/no-disclosure
and audit behavior. A PEP remains a relay; possession of the token alone is
not sufficient.

The asymmetric verifier is the only accepted PoP mechanism after migration.
It does not alter grant evaluation, tenant isolation, audit-chain ordering, or
the distinction between the enforcing PEP and the asserted subject in ADR
0007.

### Finite HMAC migration and expiry contract

The current HMAC contract remains unchanged until the first release that can
mint and verify asymmetric credentials. Rollout must not begin until the
agents in scope can generate, retain, and use their asymmetric keys.

At that migration release:

1. The release stops issuing new HMAC-PoP tokens immediately. Newly issued
   **PoP-bound** tokens must use the asymmetric profile; this is not a period
   in which both PoP profiles are issued by default. Bearer-only subject tokens
   and the existing optional/default-off posture are unchanged. This decision
   does not mandate presenting a subject token or PoP unless a separate
   enforcement-mandate decision requires it.
2. The operator records `migration_started_at` for the deployment. Existing
   HMAC-PoP tokens are grandfathered only until
   `min(token.expires_at, migration_started_at + 30 days)`. Their existing
   expiry and revocation checks still apply.
3. Any configured HMAC cutoff later than `migration_started_at + 30 days` is
   invalid and must be rejected at configuration/startup. Operators may use a
   shorter cutoff, but never extend the 30-day hard maximum.
4. At the effective cutoff, HMAC proofs and HMAC-bound tokens fail closed with
   the same generic subject-token-invalid response and operator-only rejection
   audit signal. There is no fallback or indefinite dual-verifier mode.

The next cleanup release removes the HMAC verifier and the `pop_secret` schema
and secret-handling path after the cutoff. Public verification keys remain
non-secret. This staged removal lets the finite grandfather window drain while
making the end state unambiguous and auditable.

## Alternatives considered

- **Keep HMAC-PoP indefinitely:** rejected. It leaves Vinctor holding a
  per-token signing secret and preserves the compromise path this decision
  closes.
- **Keep both HMAC and asymmetric PoP without an expiry:** rejected. It makes
  the weaker mechanism permanent and gives operators no meaningful cutover.
- **Bearer subject tokens or PEP assertion alone:** rejected. They do not
  constrain the sender and regress the identity-proof guarantee of ADR 0007.
- **mTLS or an external federation/DPoP provider:** not selected for this
  contract. Those are deployment/integration choices that can wrap the same
  asymmetric key proof later; they do not justify retaining a service-held
  HMAC secret during this migration.

## Consequences

- The service no longer needs a secret signing value for each PoP token, so
  `pop_secret` is removed from the PKA-36 KMS scope. PKA-36 remains applicable
  to any future audit MAC/signing key and other service secrets that require
  managed key custody. The current audit chain is unkeyed SHA-256; this ADR
  makes no claim of present KMS-backed audit authenticity.
- A stolen token or read-only copy of the token database cannot create a new
  valid asymmetric proof without the agent's private key. Revocation,
  expiration, freshness, and replay checks remain necessary and unchanged.
- Agents and provisioning tooling need asymmetric key generation, secure
  private-key retention, public-key registration/binding, and key rotation.
  The public key is safe to store and to expose as metadata; the private key
  is an agent-side secret.
- Migration has a bounded operational cost: at most 30 days of legacy HMAC
  acceptance, followed by one verifier and schema cleanup. Audit authenticity
  work proceeds independently.

## References

- [ADR 0007 — delegated enforce and PEP identity](0007-delegated-enforce-and-pep-identity.md)
- [HMAC-PoP implementation design](../superpowers/specs/2026-06-23-0007-hmac-pop-design.md)
- [Subject-token API contract](../api-contract.md#subject-tokens)
- [Threat model — Phase 1.8](../threat-model.md#phase-18-resource-side-pdppep)
