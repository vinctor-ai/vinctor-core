# Operational Runbooks

Practical guidance for running the **single-node self-hostable Vinctor
prototype** on a machine you control. These runbooks complement
[self-hosting.md](self-hosting.md), which covers configuration and the
`vinctor service serve` runtime.

## Status And Scope

This is prototype infrastructure, not a production-ready or managed deployment.
There is no high availability, replication, managed auth, or hardened release
process. The recipes below are starting points you must review and adapt for
your environment, not turnkey production recipes.

As an operator you remain responsible for:

- network exposure and firewall rules
- TLS termination
- workspace and agent key distribution and rotation
- host patching and process supervision
- access control around the SQLite database file
- backup and restore of that database

Vinctor keys are **bearer tokens**. Anyone who can reach the service and present
a valid `X-Workspace-Key` or `X-Agent-Key` is treated as that identity. Protect
both the network path and the keys accordingly.

## First-Time Setup

Do these steps in order the first time on a fresh host. The later sections (TLS,
firewall, supervision, backups) build on the install path and the `vinctor`
service user created here.

> CLI note: `--db`, `--json`, and `--workspace-id` are **global** flags and must
> come before the role — `vinctor --db <path> operator audit list`, not
> `vinctor operator audit list --db <path>`.

### 1. Install the released package

Install `vinctor-core` from PyPI into a dedicated virtualenv. Requires Python
3.11+. Pin an explicit version for reproducible deploys — check the
[releases](https://github.com/vinctor-ai/vinctor-core/releases) for the current
one (`x.y.z` below is a placeholder).

```bash
sudo mkdir -p /opt/vinctor
sudo python3.11 -m venv /opt/vinctor/.venv
sudo /opt/vinctor/.venv/bin/pip install "vinctor-core==x.y.z"   # e.g. 0.2.1
/opt/vinctor/.venv/bin/vinctor --help   # confirm the console script exists
```

This produces `/opt/vinctor/.venv/bin/vinctor`, the path the systemd unit and
cron job below rely on.

### 2. Create the service user and data directory

```bash
sudo useradd --system --home /var/lib/vinctor --shell /usr/sbin/nologin vinctor
sudo mkdir -p /var/lib/vinctor
sudo chown vinctor:vinctor /var/lib/vinctor
sudo chmod 750 /var/lib/vinctor
```

The database lives at `/var/lib/vinctor/vinctor.sqlite`. After it is created in
the next step, restrict it so only the service user can read it:

```bash
sudo chown vinctor:vinctor /var/lib/vinctor/vinctor.sqlite
sudo chmod 600 /var/lib/vinctor/vinctor.sqlite
```

That lockdown sets the ground rule for the rest of this guide: run every
`vinctor` command that touches this database **as the `vinctor` user** —
`sudo -u vinctor /opt/vinctor/.venv/bin/vinctor …`. An ordinary admin account
cannot open the `0600` file. Plain `sudo` (root) can — but any file root
creates next to the live database (a restored database, a WAL sidecar) is a
file the `User=vinctor` service cannot open later.

### 3. Bootstrap keys into the database

`vinctor service serve` opens existing state but does **not** mint authority, so
you must bootstrap once. `vinctor local start` creates the workspace key, agent
key, a bootstrap grant, and an optional boundary, prints them, and then **keeps
running as a foreground server** — it does not return on its own.

Run it once against the real database path, copy the printed `VINCTOR_*` values,
then stop it with Ctrl+C:

```bash
sudo -u vinctor /opt/vinctor/.venv/bin/vinctor local start \
  --db /var/lib/vinctor/vinctor.sqlite \
  --boundary-name codex-local
# Copy the printed export lines, then press Ctrl+C to stop this process.
```

Store the raw keys securely now — SQLite keeps only their hashes and they cannot
be recovered:

- `VINCTOR_WORKSPACE_KEY` — operator/admin routes and the operator audit/storage
  commands in this guide. Keep it on the operator side.
- `VINCTOR_AGENT_KEY`, `VINCTOR_GRANT_REF`, `VINCTOR_BOUNDARY_ID` — distribute to
  the calling runtime/hook that sends `/v1/enforce` requests.

You can replace any of these later with `vinctor operator keys rotate` (see
[Key Rotation And Compromise](#key-rotation-and-compromise)).

### 4. Serve persistently

The persistent service is `vinctor service serve` against the same database, run
under systemd ([Process Supervision](#process-supervision-systemd)). After it is
up, put TLS in front, restrict the firewall, and schedule backups using the
sections below.

## Network Exposure And Binding

`vinctor service serve` binds `127.0.0.1:8765` by default, reachable only from
the local host. The bundled Docker image sets `VINCTOR_HOST=0.0.0.0` so the
container port can be published.

| Goal | Setting |
| --- | --- |
| Local-only (default) | `--host 127.0.0.1` (or `VINCTOR_HOST=127.0.0.1`) |
| Reachable from other hosts | `--host 0.0.0.0` **plus** a firewall and TLS in front |

Do not expose `0.0.0.0` without a firewall and TLS. The service speaks plain
HTTP and does not terminate TLS itself.

Check liveness without secrets:

```bash
curl -sS http://127.0.0.1:8765/healthz
# {"status": "ok", "service": "vinctor-service", "mode": "self_hosted"}
```

The health response intentionally omits keys, grant refs, database paths, and
internal configuration.

The bundled `compose.yaml` publishes the port as `127.0.0.1:8765:8765`, so the
raw server stays host-local; put a reverse proxy in front for any network
exposure (see TLS / Reverse Proxy below).

## Container Hardening

The image runs as an unprivileged system user (`vinctor`, uid `10001`), not
root, and the build `chown`s `/data` to that user. A fresh `vinctor-data`
volume inherits the correct ownership automatically.

If you attach a **pre-existing** named volume (or a host bind mount) created by
an older root-running image, its files may still be owned by root and the
non-root process will fail to write. Fix ownership once with a one-off root
container before starting the service:

```bash
# Re-own a pre-existing volume to the non-root container user (uid 10001).
docker compose run --rm --user 0 vinctor chown -R 10001:10001 /data
```

## TLS / Reverse Proxy

Run Vinctor bound to localhost and put a reverse proxy in front for TLS. Keep
Vinctor itself on `127.0.0.1` so the only network entry point is the proxy.

nginx:

```nginx
server {
    listen 443 ssl;
    server_name vinctor.example.internal;

    ssl_certificate     /etc/ssl/vinctor/fullchain.pem;
    ssl_certificate_key /etc/ssl/vinctor/privkey.pem;

    # Cap request bodies at the proxy. Legitimate Vinctor bodies are tiny JSON;
    # this matches the server-side body cap (64 KiB) as defense-in-depth.
    client_max_body_size 64k;

    location / {
        proxy_pass http://127.0.0.1:8765;
        proxy_set_header Host $host;
        # Vinctor reads X-Workspace-Key / X-Agent-Key / X-Vinctor-Boundary-Id.
        # Forward those request headers unchanged (proxy_pass does by default).
        #
        # X-Forwarded-For is the one header that must NOT be forwarded
        # unchanged. nginx adds nothing to it on its own, so without this line
        # the client controls the entire header. $proxy_add_x_forwarded_for
        # appends the address nginx accepted this connection from, so the
        # header always ends in an address the socket proved. Required if you
        # enable rate limiting with VINCTOR_TRUSTED_PROXIES (note below).
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

Caddy (automatic certificates):

```caddy
vinctor.example.internal {
    # Match the server-side body cap (64 KiB) at the proxy.
    request_body {
        max_size 64KB
    }
    reverse_proxy 127.0.0.1:8765
}
```

Notes:

- Terminate TLS at the proxy; forward to Vinctor over loopback.
- Do not strip or rewrite the `X-Workspace-Key`, `X-Agent-Key`, or
  `X-Vinctor-Boundary-Id` headers.
- If you enable per-source rate limiting behind the proxy
  (`VINCTOR_RATE_LIMIT_PER_MINUTE` plus, for this loopback proxy,
  `VINCTOR_TRUSTED_PROXIES=127.0.0.1/32` — see
  [cli-reference.md](../cli-reference.md)), Vinctor resolves the client by
  walking `X-Forwarded-For` right to left and taking the rightmost entry that
  is not itself a trusted proxy. That walk is sound only if every proxy you
  list as trusted **appends the peer address it accepted the connection from**
  to `X-Forwarded-For` (or replaces the header with that address): the header
  then ends in a socket-proved suffix, and anything the client fabricated sits
  further left, beyond the first non-trusted entry where the walk stops. The
  `$proxy_add_x_forwarded_for` line above is what provides that property in
  nginx. Without it, nginx forwards the client's own header untouched, every
  request can claim a fresh source address, and listing the proxy as trusted
  *disables* the limiter instead of sharpening it. Preserve the same property
  when adapting this config: Caddy (2.5+, including the block above) and most
  cloud load balancers append or replace by default; nginx's `realip` module
  does **not** — it rewrites nginx's own idea of the peer for when nginx sits
  behind yet another proxy, and is not a substitute for appending here.
- Certificates are your responsibility. For a public hostname, obtain them with
  an ACME client (certbot, or Caddy's automatic issuance shown above). For an
  internal-only name like `vinctor.example.internal`, public ACME cannot
  validate it — use your internal CA or a self-signed certificate trusted by the
  callers.
- This does not make Vinctor a production service; it only protects the
  transport for a single-node prototype.

## Firewall

If you bind beyond loopback, restrict who can reach the port. Example with
`ufw`, allowing only an internal subnet to reach the proxy and blocking direct
access to Vinctor's port:

```bash
# Allow HTTPS to the reverse proxy from a trusted subnet only.
ufw allow from 10.0.0.0/24 to any port 443 proto tcp

# Do not expose Vinctor's own port (8765) off-host; it stays on loopback.
ufw deny 8765/tcp
```

Prefer keeping `8765` on `127.0.0.1` entirely and exposing only the proxy.

## Process Supervision (systemd)

Run the service under a supervisor so it restarts on failure and starts at boot.
Use absolute paths and a dedicated unprivileged user that owns the database
directory.

```ini
# /etc/systemd/system/vinctor.service
[Unit]
Description=Vinctor self-hostable service (single-node prototype)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=vinctor
Group=vinctor
# Use the absolute path to the installed console script (e.g. a venv bin dir).
ExecStart=/opt/vinctor/.venv/bin/vinctor service serve
Environment=VINCTOR_HOST=127.0.0.1
Environment=VINCTOR_PORT=8765
Environment=VINCTOR_DB=/var/lib/vinctor/vinctor.sqlite
Environment=VINCTOR_SERVICE_MODE=self_hosted
Environment=VINCTOR_LOG_LEVEL=info
Restart=on-failure
# The service needs to read and write only its database directory.
ReadWritePaths=/var/lib/vinctor

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now vinctor.service
sudo systemctl status vinctor.service
```

The service does not print raw keys on startup; bootstrap keys separately (see
[self-hosting.md](self-hosting.md#bootstrap-and-hook-environment)).

## Logs And Observability

What the prototype emits today:

- **Startup banner** to stdout: listening URL, mode, database path, configured
  log level, and a prototype warning. It contains no raw keys.
- **Per-request HTTP access logging is suppressed by default.** Enable an opt-in,
  leak-free structured access log with `VINCTOR_ACCESS_LOG=1` or
  `vinctor service serve --access-log` — one JSON line per request to stderr with
  `{ts, method, path, status, latency_ms, decision?, error?}` and no keys, tokens,
  grant refs, ids, or request bodies.
- **Metrics:** `VINCTOR_METRICS=1` or `vinctor service serve --metrics` exposes an
  opt-in `/metrics` Prometheus endpoint (in-process counters
  `vinctor_http_requests_total` and `vinctor_enforce_decisions_total`;
  low-cardinality, leak-free labels). Off by default; counters are per-process.
- **`VINCTOR_LOG_LEVEL` / `--log-level`** sets the configured level shown in the
  banner.

The authoritative operational signal is the **audit record**, not process logs.
Authorization decisions and lifecycle events are recorded in SQLite and read
through the operator audit commands:

```bash
vinctor --db /var/lib/vinctor/vinctor.sqlite operator audit list --limit 50
vinctor --db /var/lib/vinctor/vinctor.sqlite \
  --workspace-key "$VINCTOR_WORKSPACE_KEY" \
  operator audit export --format jsonl --file audit.jsonl
```

Audit records intentionally exclude raw tool input, raw command text, prompts,
and model-facing reason strings.

To stream a best-effort copy to an OpenTelemetry Collector without putting the
collector on the enforcement path:

```bash
VINCTOR_AUDIT_EXPORT=otlp-http:http://otel-collector:4318/v1/logs \
  vinctor service serve
```

The local database remains authoritative. The exporter batches up to 32 events
per request and retries network, `408`, `429`, and `5xx` failures up to three
times with exponential backoff. Configure those bounds with
`VINCTOR_AUDIT_EXPORT_BATCH_SIZE`, `VINCTOR_AUDIT_EXPORT_MAX_ATTEMPTS`, and
`VINCTOR_AUDIT_EXPORT_RETRY_BACKOFF_SECONDS`. Collector failures and queue or
shutdown-flush timeouts are fail-open and reported on stderr; use `operator
audit export` to reconcile missed events.

Capture the service's stdout/stderr through your supervisor:

```bash
journalctl -u vinctor.service -f      # systemd
docker compose logs -f vinctor        # Docker Compose
```

## SQLite Backup And Restore

Use the operator storage commands (see
[self-hosting.md](self-hosting.md#operator-storage-and-service-info)) for
consistent snapshots. They produce a database file that holds only key hashes
and metadata — no raw secrets.

### Why the command, and not `cp`

Since 0.5.0 Vinctor opens every database connection with
`PRAGMA journal_mode = WAL`, and WAL — unlike the other journal modes — is a
property of the *database file*: once a database has been converted, later
connections and processes come up in WAL as well. Neither half of that is a
guarantee. If WAL cannot be enabled (some network filesystems cannot support
it), the service does not fail: it warns on stderr and continues on whatever
journal mode it got. And the setting persists in the file rather than being
permanent — a later connection can switch the database to a different journal
mode.

While a WAL database is in use, it is more than one file on disk: committed
transactions can be resident in a `vinctor.sqlite-wal` sidecar next to the main
file, with a `vinctor.sqlite-shm` index beside it. The sidecars come and go —
a cleanly closed database is typically a single file again — which is exactly
why they are easy to forget.

That makes copying the database file **silently lossy**. Committed transactions
can still be resident in the `-wal` sidecar while the main file looks untouched,
so a `cp` of the main file alone produces a database that opens cleanly, queries
cleanly, and is quietly missing rows. There is no error at copy time or at read
time. We watched a dogfood run lose committed rows exactly this way, without a
single warning.

`operator storage backup` reads through the SQLite backup API, so it captures
WAL-resident data and writes a single self-contained file. Use it — including
inside containers, where the instinct to snapshot the volume is strongest; it is
safe while the service runs. If you must copy files instead, stop (or otherwise
quiesce) the service first and checkpoint with
`PRAGMA wal_checkpoint(TRUNCATE)`, so the main file is complete before you copy
it. Never copy the files of a live database.

Scheduled backup with cron (consistent snapshot; safe while the service runs).
Create the backup directory once, owned by the service user, and run the cron
entry as that same user — the snapshots then stay readable for a later
`sudo -u vinctor … restore`, and no root-owned file is ever created next to
the live database:

```bash
sudo install -d -o vinctor -g vinctor -m 750 /var/backups/vinctor
```

```cron
# /etc/cron.d/vinctor-backup — daily snapshot at 02:00, kept by date, run as
# the vinctor service user (the sixth field; crontab entries are single lines).
0 2 * * * vinctor /opt/vinctor/.venv/bin/vinctor --db /var/lib/vinctor/vinctor.sqlite operator storage backup --output /var/backups/vinctor/vinctor-$(date +\%Y\%m\%d).sqlite
```

Restore from a snapshot (validates the input before replacing the live DB):

```bash
sudo systemctl stop vinctor.service
sudo -u vinctor /opt/vinctor/.venv/bin/vinctor \
  --db /var/lib/vinctor/vinctor.sqlite operator storage restore \
  --input /var/backups/vinctor/vinctor-20260611.sqlite --yes
sudo systemctl start vinctor.service
```

> **Run the restore as the service user — `sudo -u vinctor`, not plain
> `sudo`.** `restore` builds the replacement database as a temp file next to
> the live one and atomically renames it into place, and the swapped-in file
> keeps its creator's ownership and `0600` mode. As `vinctor`, that is exactly
> the `vinctor:vinctor` `0600` state step 2 established. As root, the swap
> also succeeds — but the live database is now root-owned, the `User=vinctor`
> service can no longer open it, and the next start fails. As an ordinary
> admin, it fails outright (the `vinctor`-owned `0750` data directory refuses
> the temp file). `storage reset` swaps the database the same way; the step 2
> ground rule — every command that touches this database runs as `vinctor` —
> covers the rest.

> **Stop the service first — this is not a formality.** `restore` swaps the
> database file atomically, but a service that is still running holds its own
> open handle to the *replaced* file. It keeps answering `permit` and writing
> audit events into an inode nothing will ever read again, and when it exits
> those records are gone for good. Worse, the restored database's own chain
> cannot reveal the rewind: `operator audit verify` reports **"chain OK"**,
> because the snapshot's chain is internally consistent. Only out-of-band
> records can expose it — every storage op (this restore included) first emits
> a trace with the pre-op chain head to stderr and to the configured anchor
> (`VINCTOR_AUDIT_ANCHOR`), and `verify --expected-head` / `--against-anchor`
> check the live chain against heads recorded outside the database. There is
> no runtime guard for this today beyond `--yes`; the ordering above *is* the
> control.

The backup → restore path is covered by drill tests
(`tests/test_cli.py::test_dr_drill_*`) that run these same commands and assert
the restored audit chain verifies with the backed-up head hash — not merely that
it verifies, since an empty chain verifies too.

### Docker volume backup

The Compose file stores SQLite at `/data/vinctor.sqlite` in the `vinctor-data`
volume. Snapshot it with the operator command inside the running container, then
copy the artifact out:

```bash
# Consistent snapshot inside the container.
docker compose exec vinctor \
  vinctor --db /data/vinctor.sqlite operator storage backup --output /data/backup.sqlite

# Copy the snapshot to the host.
docker compose cp vinctor:/data/backup.sqlite ./vinctor-backup.sqlite
```

To restore into the volume, do it with the service stopped (so nothing holds the
database open), using a one-off container that shares the same volume:

```bash
# 1. Stop the running service container.
docker compose stop vinctor

# 2. Copy a host snapshot into the volume, into a staging path (cp works on
#    the stopped container). docker cp always writes it root-owned with the
#    host file's mode. This file holds plaintext pop_secret values and auth
#    state — it must stay 0600, never chmod'd world-readable to work around
#    the ownership mismatch.
docker compose cp ./vinctor-backup.sqlite vinctor:/data/restore-staging.sqlite

# 3. Re-stage it at the ownership and mode the restore needs, with a
#    narrowly-scoped root helper: this one-off invocation's only job is
#    `install`, never the application or the restore itself.
docker compose run --rm --user 0 vinctor \
  install -o 10001 -g 10001 -m 0600 \
  /data/restore-staging.sqlite /data/restore-source.sqlite
docker compose run --rm --user 0 vinctor rm -f /data/restore-staging.sqlite

# 4. Validate-and-replace the database with a one-off container. It runs as
#    the image's non-root user (uid 10001), which is what keeps the replaced
#    database owned by the service user. Do NOT add --user 0 here (the
#    Container Hardening idiom): a root-run restore succeeds and leaves a
#    root-owned database the service container can no longer open.
docker compose run --rm vinctor \
  vinctor --db /data/vinctor.sqlite operator storage restore \
  --input /data/restore-source.sqlite --yes

# 5. Start the service again.
docker compose start vinctor
```

## Upgrades

Upgrades are explicit and operator-controlled. Always back up first.

```bash
# 1. Snapshot the current database (see SQLite Backup And Restore).
sudo -u vinctor /opt/vinctor/.venv/bin/vinctor \
  --db /var/lib/vinctor/vinctor.sqlite \
  operator storage backup --output /var/backups/vinctor/pre-upgrade.sqlite

# 2. Stop and install the target package version.
sudo systemctl stop vinctor.service
sudo /opt/vinctor/.venv/bin/pip install --upgrade "vinctor-core==<target-version>"

# 3. Confirm the on-disk schema is current (idempotent, data-safe).
sudo -u vinctor /opt/vinctor/.venv/bin/vinctor \
  --db /var/lib/vinctor/vinctor.sqlite operator storage migrate

# 4. Start the service.
sudo systemctl start vinctor.service
```

## Key Rotation And Compromise

Workspace and agent keys are bearer tokens; rotate them periodically and revoke
any key you believe is exposed. These commands act on the same database the
service uses and never print existing raw keys or hashes (full reference:
[self-hosting.md](self-hosting.md#operator-keys-list)).

```bash
# List local keys as masked metadata (find the key_id).
vinctor --db /var/lib/vinctor/vinctor.sqlite --workspace-id ws_local operator keys list

# Revoke a compromised key immediately (it then fails authentication).
vinctor --db /var/lib/vinctor/vinctor.sqlite operator keys revoke <key_id>

# Rotate the workspace/admin key (prints the new raw key once).
vinctor --db /var/lib/vinctor/vinctor.sqlite --workspace-id ws_local operator keys rotate workspace

# Rotate a specific agent's key.
vinctor --db /var/lib/vinctor/vinctor.sqlite --workspace-id ws_local operator keys rotate agent \
  --agent-id agent_local
```

After rotating, distribute the new raw key to the affected caller and update its
`VINCTOR_*` environment. The new key is shown only once at rotation time.

## What Is Still Deferred

These remain intentionally out of scope for the single-node prototype:

- production auth/session/user management and managed identity
- high availability, replication, and multi-tenant control plane
- automated fleet rollout, rollback, and registry-promotion policy beyond the
  published single-node package/image artifacts

Opt-in structured access logging and a `/metrics` Prometheus endpoint shipped
(off by default); see "What the prototype emits today" above.

Until those exist, describe deployments as a "single-node self-hostable
prototype", not a production-ready service.
