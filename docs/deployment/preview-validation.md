# Preview Deployment Validation

Use this checklist before handing a single-node preview deployment to a design
partner. Record the command outputs or screenshots in the partner deployment
notes. Do not record raw keys in shared artifacts.

> FOUNDER-GATED: the build/CI environment has no Docker, so the real
> `docker compose up` plus full end-to-end smoke against a live container stack
> CANNOT be run or verified here. The steps below that require Docker (stack
> start, restart persistence, backup/restore, audit export) are documented for a
> founder-operated host and must be executed and recorded there. The non-Docker
> assertions in this repo's test suite (compose wiring, `.env` hygiene, the smoke
> check against an in-process service, and fail-closed-when-unreachable) are what
> CI actually proves.

## Required Evidence

| Check | Evidence to record |
| --- | --- |
| Stack starts | `docker compose ps` showing `vinctor` healthy and `caddy` running |
| HTTPS health | `GET /healthz` response over the preview endpoint |
| Partner grant issued | `/v1/grants` response with `grant_ref` and expected scopes |
| Permit smoke | smoke script reports `permit_decision=permit` |
| Deny smoke | smoke script reports `deny_decision=deny` |
| Fail-closed | smoke script exits non-zero against a down endpoint |
| Audit smoke | smoke script reports both audit event ids |
| Restart persistence | smoke script still passes after `docker compose restart vinctor` |
| Backup/restore | smoke script still passes after backup and restore |
| Audit export | JSONL file contains the preview enforce events |

## 1. Stack And Health

```bash
cd deploy/preview
docker compose --env-file .env up -d --build
docker compose ps
curl -sS "$VINCTOR_ENDPOINT/healthz"
```

Expected health body:

```json
{"status":"ok","service":"vinctor-service","mode":"self_hosted"}
```

## 2. Provisioning

Provision with operator commands as described in
[preview-runbook.md](preview-runbook.md). Confirm:

- workspace key is stored securely by the operator
- agent key is stored only for the partner runtime
- partner grant is issued through `POST /v1/grants`
- `VINCTOR_GRANT_REF` comes from the service response
- no raw key is written to `.env`, Compose, Dockerfile, GitHub, or logs

## 3. Smoke Check

Run from the repository root:

```bash
python deploy/preview/smoke.py \
  --endpoint "$VINCTOR_ENDPOINT" \
  --agent-key "$VINCTOR_AGENT_KEY" \
  --workspace-key "$VINCTOR_WORKSPACE_KEY" \
  --grant-ref "$VINCTOR_GRANT_REF" \
  --permit-action write \
  --permit-resource repo/preview/README.md \
  --deny-action write \
  --deny-resource repo/other/README.md
```

Expected final line:

```text
ALL SINGLE-NODE PREVIEW SMOKE STEPS PASSED
```

Use `--insecure-tls` only for localhost or internal-CA certificates. Do not use
it for a public design-partner endpoint.

## 3a. Fail-Closed When Unreachable

Confirm the smoke check denies-by-failure when Vinctor is unreachable, so a down
service can never be mistaken for a healthy one:

```bash
python deploy/preview/smoke.py \
  --endpoint http://127.0.0.1:1 \
  --agent-key unused --workspace-key unused --grant-ref unused
echo "exit=$?"
```

Expected: a `preview smoke failed:` line on stderr and `exit=1`. Record the
non-zero exit. See "Fail-Closed When Vinctor Is Unreachable" in
[preview-runbook.md](preview-runbook.md).

## 4. Restart Persistence

```bash
cd deploy/preview
docker compose restart vinctor
cd ../..
python deploy/preview/smoke.py \
  --endpoint "$VINCTOR_ENDPOINT" \
  --agent-key "$VINCTOR_AGENT_KEY" \
  --workspace-key "$VINCTOR_WORKSPACE_KEY" \
  --grant-ref "$VINCTOR_GRANT_REF" \
  --permit-action write \
  --permit-resource repo/preview/README.md \
  --deny-action write \
  --deny-resource repo/other/README.md
```

The same raw keys should still authenticate because SQLite stores durable key
hash records in the `vinctor-data` volume.

## 5. Backup And Restore

```bash
cd deploy/preview
docker compose exec vinctor \
  vinctor --db /data/vinctor.sqlite \
  operator storage backup --output /data/backups/validation.sqlite --force
docker compose cp vinctor:/data/backups/validation.sqlite ./validation.sqlite

docker compose stop vinctor
docker compose cp ./validation.sqlite vinctor:/data/restore-source.sqlite
docker compose run --rm --no-deps vinctor \
  vinctor --db /data/vinctor.sqlite \
  operator storage restore --input /data/restore-source.sqlite --yes
docker compose start vinctor
```

Run the smoke check again and record the pass.

## 6. Audit Export

```bash
cd deploy/preview
docker compose exec vinctor \
  vinctor --db /data/vinctor.sqlite \
  --workspace-key "$VINCTOR_WORKSPACE_KEY" \
  operator audit export --format jsonl --file /data/validation-audit.jsonl
docker compose cp vinctor:/data/validation-audit.jsonl ./validation-audit.jsonl
```

Confirm the JSONL includes permit and deny enforce events. It must not contain:

- raw tool input
- raw command text
- prompts
- model-facing reason strings

## Known Limits

This validation proves only a preview-grade single-node deployment. It does not
prove production readiness, hosted service behavior, high availability,
operator role separation, managed credential delivery, or official runtime
integration support.

The Docker-dependent steps (stack start, restart persistence, backup/restore,
audit export) are FOUNDER-GATED: there is no Docker in the build/CI environment,
so they are not exercised here. Only the in-repo tests are automatically proven:
compose wiring, `.env` raw-key hygiene, the smoke check against an in-process
service, and the fail-closed-when-unreachable behavior.
