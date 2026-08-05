# ADR 0022: Encrypted idempotency results

Date: 2026-07-20

## Status

Accepted. This records the encryption and key-custody contract for PKA-62.

## Context

Seven credential and control-plane mutation APIs need exact retry semantics. A completed
retry must return the original serialized response without repeating the mutation or its
audit effects. Some responses contain bearer tokens and proof-of-possession secrets, so
their exact bytes cannot be persisted as plaintext. Hash-only credential storage also
cannot reconstruct the response.

The service therefore needs reversible encryption for completed idempotency results.
Nonce reuse under AES-GCM would be catastrophic, including when a business transaction
rolls back after encryption. Rotation must retain old decrypt capability until every
unexpired result has drained, while preventing lifetime nonce accounting from resetting.

## Decision

### Cipher and key custody

Use AES-256-GCM from the direct runtime dependency `cryptography>=49,<50`. The service
accepts only 32-byte AES keys and will use a fresh 12-byte cryptographically secure nonce
for every durable encryption reservation. Stored ciphertext includes the full 16-byte
authentication tag produced by `AESGCM`.

Operators supply a versioned keyring through exactly:

- `VINCTOR_IDEMPOTENCY_KEYRING_JSON`
- `VINCTOR_IDEMPOTENCY_ACTIVE_KEY_VERSION`

The JSON value is an object from immutable version labels to standard base64-encoded
32-byte keys. Labels match `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`. Exactly one configured
version is active for new encryption; every configured version remains available for
decryption. Historical keys are decrypt-only.

Only both variables being truly absent represents an absent keyring. Empty, one-sided,
malformed, duplicate-member, invalid-label, whitespace-bearing base64, invalid base64,
wrong-length, missing-active, or duplicate-key configurations fail before server bind.
They use one typed, coarse configuration error.

Key material and the original JSON are excluded from representations, errors, and logs.
The PostgreSQL DSN remains representation-redacted. Storage services never read the
process environment; construction boundaries parse once and inject the immutable typed
configuration.

Each key has a non-secret SHA-256 commitment over:

```text
"vinctor.idempotency.key-commitment.v1\0" || key_bytes
```

Version labels and commitments become immutable tombstones once registered. Neither a
label nor key commitment can be reused to reset lifecycle or nonce accounting.

### Persistence and transaction boundary

Completed results persist only authenticated ciphertext and the version needed for
decryption. Fingerprints, associated data, schema, and the durable reservation protocol
are versioned separately. Idempotency persistence stores no raw idempotency key, bearer
token, exact serialized response, proof-of-possession material, or AES key. Those values
must not appear in idempotency tables, their WAL/journal representation, logical dump
rows, logs, or errors.

PKA-19 predates this decision and keeps one authoritative plaintext copy of a minted PoP
secret in `subject_tokens.pop_secret`. PKA-62 neither duplicates nor migrates that
column. Its acceptance boundary is therefore exact: the bearer token and serialized
response remain absent globally; the PoP secret may occur only in that authoritative
column (and the database/WAL/dump bytes representing that row), never in idempotency
rows, ciphertext plaintext, or logs. Removing the authoritative copy depends on the
separate PKA-19 migration.

Before encryption or business mutation, a separate committed phase permanently reserves
one encryption slot and nonce. A rollback, loser, or crash may burn a reservation but
never reclaims it. The soft rotation signal is `2^23` reservations and the hard limit is
`2^24` per key version.

Unknown versions, missing historical keys, commitment mismatch, malformed envelopes, or
authentication failure retain the row and fail closed with the same external
`503 idempotency_unavailable`; they never fall back to repeating the mutation.

### HTTP retry contract

`Idempotency-Key` is optional and changes behavior on exactly these seven mutation
routes:

1. `POST /v1/grants`
2. `POST /v1/tokens`
3. `POST /v1/boundaries`
4. `POST /v1/auto-approval-rules`
5. `POST /v1/grant-requests/{request_id}/approve`
6. `POST /v1/grant-requests/{request_id}/reject`
7. `POST /v1/grant-requests/{request_id}/auto-approve`

Callers generate the value; a UUIDv4 or an independently generated identifier with at
least 128 bits of entropy is recommended. Vinctor does not generate or propagate retry
keys for clients. One ASCII value matching `[A-Za-z0-9._~-]{1,128}` is accepted.
Duplicate, combined, malformed, non-ASCII, or overlong values receive
`400 invalid_idempotency_key`; reuse with a different effective request receives
`409 idempotency_key_conflict`; unavailable or unverifiable replay state receives
`503 idempotency_unavailable`.

The header is checked only after authentication and request parsing. With no header,
the existing unkeyed route behavior is unchanged. With a header but no configured
keyring, the mutation fails closed. Durable business state, its authoritative audit row,
and the encrypted result commit atomically. Optional external audit anchor/export sinks
remain post-commit and fail open; their failure cannot roll back or repeat the mutation.

### Rotation and deployment

Rotation first deploys a keyring containing both the old and new keys through the
external secret-injection system, then selects the new version for encryption in
`VINCTOR_IDEMPOTENCY_ACTIVE_KEY_VERSION`. The lifecycle surface has exactly four
commands: `status`, `write-disable`, `drain-complete`, and `retire`. It never accepts,
generates, switches, or prints AES key material.

`write-disable` accepts one explicit historical immutable label and the fixed reason
`rotation`; it rejects the locally active label. `drain-complete` also requires the
operator's explicit `--confirm-no-active-writers` attestation. Every keyed service
automatically owns the backend attestation lock for its active key version for its
full lifetime, including SQLite pool generations and PostgreSQL replacement
connections. Drain and retirement take the exclusive lock for only their historical
target: an old-version writer blocks them, while a replacement-only writer does not.
`retire` requires an explicit removal window confirmation, prior disable and drain
barriers, a decrypt-capable active replacement, zero unexpired results for the
historical version, and database time at least
`86,400 + 300` seconds after the recorded drain epoch. Host time, caller time, and a
caller-supplied result count do not authorize removal. All barriers are idempotent and
fail closed on ambiguous authority. Version/commitment tombstones, final lifetime
reservation counts, and nonce rows remain after retirement.

Startup performs an exact reservation-count compatibility check. Runtime readiness uses
the registry's bounded counter snapshot and fails closed for an absent required
historical key, commitment mismatch, unknown unexpired result version, or a disabled or
retired active version. Expired-result garbage collection uses database time, deletes
only result rows with `expires_at_epoch <= now`, and processes at most 100 rows per
batch; it never deletes or decrements nonce reservations or key-version tombstones.

The authoritative encrypted-result schema is SQLite migration 18 and PostgreSQL
migration 8. Rollout from SQLite 17 or PostgreSQL 7 uses a maintenance window:
stop every writer, take and verify a complete pre-migration snapshot, run the
migration with one new binary, verify the contiguous version sequence, and then
start only new binaries. Mixed old/new binaries are not supported.

Downgrade is restore-only from that verified pre-migration snapshot. Deleting the
new migration row, dropping the idempotency tables, or otherwise editing the
schema in place is not a rollback and can break the audit chain or encrypted replay
state.

This decision does not add a KMS/provider abstraction, key generation, ordinary
client/CLI key propagation, or migration of the separate PKA-19 `pop_secret` debt.

## Alternatives considered

- **Persist exact response bytes as plaintext:** rejected because successful token
  responses contain reusable credentials.
- **Persist only a response hash:** rejected because exact replay requires reconstructing
  the original bytes.
- **Retry encryption with a nonce after rollback:** rejected because ambiguous execution
  can reuse a nonce and violate AES-GCM safety.
- **Keep one unversioned key:** rejected because safe rotation and historical decryption
  require explicit immutable versions.
- **Add a generic KMS/provider layer now:** rejected as PKA-36 scope. External secret
  injection is sufficient for this contract.

## Consequences

- Operators must inject, retain, rotate, and back up every key needed by unexpired
  results.
- A malformed or incomplete configured keyring prevents startup instead of silently
  disabling keyed safety.
- Fully absent configuration preserves legacy unkeyed behavior; a keyed request cannot
  execute without an available compatible keyring.
- Permanent reservation accounting intentionally overcounts abandoned and losing work
  to preserve the cryptographic limit.
- Later PKA-62 implementation stages must add versioned envelopes, backend schemas,
  durable reservations, lifecycle checks, and exact HTTP replay without weakening this
  boundary.

## References

- [ADR 0021 — asymmetric sender-constrained proof of possession](0021-asymmetric-sender-constrained-pop.md)
- [Self-hosting deployment](../deployment/self-hosting.md)
- [Threat model](../threat-model.md)
