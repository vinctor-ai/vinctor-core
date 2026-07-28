# Durable local key storage

- status: accepted
- date: 2026-06-10

## Context

`vinctor_service` now has local HTTP adapters for:

- `POST /v1/enforce`, authenticated with `X-Agent-Key`
- workspace-scoped boundary admin routes, authenticated with `X-Workspace-Key`

The first local launcher bootstrapped keys in memory and printed them as
environment exports. That is enough for a single local process, but it is not
durable across restart and does not give the service a revocable key record.

We compared similar local/developer token systems:

- GitHub CLI stores authentication tokens in the system credential store when
  available and falls back to a plaintext file only when necessary.
  Source: https://cli.github.com/manual/gh_auth_login
- npm exposes full access token values at creation/view time and supports
  explicit token revocation.
  Sources:
  https://docs.npmjs.com/creating-and-viewing-access-tokens/
  https://docs.npmjs.com/revoking-access-tokens/
- Stripe documents secret key prefixes and key rolling, with live secret keys
  revealed only in constrained circumstances.
  Source: https://docs.stripe.com/keys
- Docker documents external credential stores for local CLI credentials.
  Source: https://docs.docker.com/reference/cli/docker/login/#credential-stores
- OWASP's secrets management guidance describes creation, rotation,
  revocation, expiration, least privilege, and masking/plaintext logging
  controls as part of the secret lifecycle.
  Source:
  https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html

The shared pattern is that bearer secrets are opaque capabilities. Durable
systems should store metadata and verification material, not treat raw tokens as
recoverable service state.

## Decision

Add SQLite-backed durable local key records for workspace/admin keys and agent
keys.

Use two key types:

- `workspace`: sent as `X-Workspace-Key` for workspace-scoped local/admin
  routes.
- `agent`: sent as `X-Agent-Key` for `/v1/enforce`.

Use these raw key prefixes:

- `wsk_` for workspace/admin keys.
- `aak_` for agent keys.

Store only:

- `key_id`
- `workspace_id`
- `agent_id` for agent keys
- `key_hash`
- `key_prefix`
- `status`
- `created_at`
- `last_used_at`
- `revoked_at`

Do not store raw key values in SQLite.

Hash local keys with SHA-256 for this prototype. Keys are high-entropy random
bearer tokens, so a fast digest is sufficient for local lookup in this slice.
If copied-DB resistance becomes a requirement, move to HMAC-SHA-256 with a
machine-local secret stored outside SQLite.

Supported statuses:

- `active`
- `revoked`

Unknown and revoked keys both resolve as unauthenticated. HTTP adapters should
continue returning the existing generic `401 authentication_required` response
for missing, unknown, or revoked keys. Authentication failures should not write
audit events.

Add repository/helper functions for key creation, lookup, and revocation, but
do not add key management HTTP endpoints in this slice.

Integrate the local launcher with durable key storage:

- If `--workspace-key` or `--agent-key` is supplied, register or reuse the
  matching hashed key record.
- Explicitly seeded workspace, agent, and PEP keys must keep at least 32
  characters of secret material after their type prefix. Operators should
  generate those values with a CSPRNG; the length check preserves the
  high-entropy assumption required by unsalted SHA-256 storage.
- If no raw key is supplied, generate a new key, store only its hash, and print
  the raw value once in the launcher exports.
- Re-running the launcher without supplying previously generated raw keys may
  create additional active keys. That is acceptable for this slice because
  local config/keychain persistence is intentionally deferred.

Use explicit-key reuse for the current local prototype:

- Operators should pass restart-stable raw keys back through `--workspace-key`
  and `--agent-key`, or equivalent environment/config wiring that already
  exists outside this repository.
- Do not add plaintext raw key storage in SQLite.
- Do not add a local config file containing raw keys.
- Do not add OS keychain integration or automatic key recovery in this slice.
- If a future local config option is considered, it should store references or
  metadata rather than raw secrets.
- OS keychain integration remains the preferred future direction for local
  developer UX, but it needs a separate ADR-backed slice after dogfooding the
  explicit bootstrap flow.

## Consequences

- Raw keys cannot be recovered from SQLite. Lost keys must be rotated or
  regenerated.
- The local launcher remains useful without repository-managed raw secret
  storage, but restart-stable raw key reuse requires explicit
  `--workspace-key`/`--agent-key` input for now.
- Key revocation can be tested and used by service code before public key
  management endpoints exist.
- `X-Agent-Key` remains separate from `X-Workspace-Key`; neither key type is
  accepted on the other's route family.
- This does not add hosted service behavior, production deployment, official
  runtime integrations, approval workflow, sandboxing, raw interception, or
  provider integration.
