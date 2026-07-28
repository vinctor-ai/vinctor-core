# Mock Vinctor Service

`tools/mock_vinctor_service.py` is a small stdlib HTTP fixture for Claude,
Codex, Hermes, and other runtime-boundary repositories.

It exposes only:

```text
POST /v1/enforce
```

Use it when a hook/plugin repo needs deterministic integration smoke tests for:

- permit
- deny
- fail-closed behavior when Vinctor is unavailable
- strict `/v1/enforce` request body validation
- `X-Agent-Key` handling
- optional `X-Vinctor-Boundary-Id` forwarding

## What It Is Not

The mock does not implement:

- real grant issuance
- grant lookup or revocation
- audit persistence
- boundary registry
- policy evaluation
- SQLite
- hosted service behavior
- production readiness
- credential brokering
- approval workflow
- raw tool interception

It should not receive raw tool input, prompts, raw commands, or hook-specific
payloads. Runtime hook repos should translate their own tool events into the
strict Vinctor action/resource request before calling this mock.

## Run It

Create `mock-vinctor.json`:

```json
{
  "default_decision": "deny",
  "permit": [
    "execute:ci/test",
    "read:secret/env"
  ],
  "deny": [
    "deploy:npm/package"
  ]
}
```

Start the mock:

```bash
python tools/mock_vinctor_service.py --port 8765 --config mock-vinctor.json
```

It prints test-only exports:

```bash
export VINCTOR_ENDPOINT="http://127.0.0.1:8765"
export VINCTOR_AGENT_KEY="aak_mock"
export VINCTOR_GRANT_REF="grt_mock"
```

Hook repos should run their own CLI/plugin smoke tests against that endpoint.

## Config Format

```json
{
  "default_decision": "permit",
  "permit": ["execute:ci/test"],
  "deny": ["deploy:npm/package"],
  "mode": "normal",
  "status": 503,
  "agent_key": "aak_mock",
  "grant_ref": "grt_mock"
}
```

Fields:

| Field | Meaning |
| --- | --- |
| `default_decision` | `permit` or `deny`; used when no explicit rule matches. |
| `permit` | List of `action:resource` pairs to permit. |
| `deny` | List of `action:resource` pairs to deny. |
| `mode` | `normal` or `unavailable`. |
| `status` | HTTP error status for unavailable mode. Defaults to `503`. |
| `agent_key` | Expected `X-Agent-Key`. Defaults to `aak_mock`. |
| `grant_ref` | Exported mock grant ref. Defaults to `grt_mock`. |

Decision precedence:

1. explicit deny wins over permit
2. explicit permit wins over default
3. otherwise use `default_decision`

CLI flags can also add behavior:

```bash
python tools/mock_vinctor_service.py \
  --default-decision deny \
  --permit execute:ci/test \
  --deny deploy:npm/package
```

## Permit Request

```bash
curl -sS "$VINCTOR_ENDPOINT/v1/enforce" \
  -H "Content-Type: application/json" \
  -H "X-Agent-Key: $VINCTOR_AGENT_KEY" \
  -H "X-Vinctor-Boundary-Id: bnd_mock" \
  -d "{\"grant_ref\":\"$VINCTOR_GRANT_REF\",\"action\":\"execute\",\"resource\":\"ci/test\"}"
```

Permit response:

```json
{
  "decision": "permit"
}
```

## Deny Request

```bash
curl -sS "$VINCTOR_ENDPOINT/v1/enforce" \
  -H "Content-Type: application/json" \
  -H "X-Agent-Key: $VINCTOR_AGENT_KEY" \
  -d "{\"grant_ref\":\"$VINCTOR_GRANT_REF\",\"action\":\"deploy\",\"resource\":\"npm/package\"}"
```

Deny response:

```json
{
  "decision": "deny",
  "error": "action_denied",
  "reason": "action_denied"
}
```

## Strict Body Behavior

The mock accepts exactly:

```json
{
  "grant_ref": "grt_mock",
  "action": "execute",
  "resource": "ci/test"
}
```

It rejects:

- missing required fields
- extra fields such as `boundary_id`
- invalid JSON
- non-string values
- empty strings

Boundary context belongs in the `X-Vinctor-Boundary-Id` header, not the JSON
body.

## Simulate Unavailable Service

Use either:

```bash
python tools/mock_vinctor_service.py --fail-all
```

or:

```bash
python tools/mock_vinctor_service.py --status 503
```

or config:

```json
{
  "mode": "unavailable",
  "status": 503
}
```

Unavailable response:

```json
{
  "error": "service_unavailable",
  "reason": "mock service unavailable"
}
```

Hook repos should assert that mapped calls fail closed when this response is
returned or when the mock process is not reachable.

## What Hook Repos Should Assert

Hook/plugin smoke tests should verify:

- mapped permit calls continue
- mapped deny calls are blocked
- mapped calls fail closed when the mock is unavailable
- `X-Agent-Key` is sent
- `X-Vinctor-Boundary-Id` is forwarded when configured
- the request body contains only `grant_ref`, `action`, and `resource`
- hook-specific raw payloads are not sent to Vinctor

This mock is a deterministic contract fixture. It is not a substitute for
testing against the local Vinctor service when grant lifecycle behavior matters.
