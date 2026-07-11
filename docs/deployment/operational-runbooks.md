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

### 1. Install from source

There is no published package or image yet (see
[What Is Still Deferred](#what-is-still-deferred)), so install from a git
checkout into a dedicated virtualenv. Requires Python 3.11+.

```bash
sudo mkdir -p /opt/vinctor
sudo git clone https://github.com/vinctor-ai/vinctor-core.git /opt/vinctor/src
sudo python3.11 -m venv /opt/vinctor/.venv
sudo /opt/vinctor/.venv/bin/pip install /opt/vinctor/src
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
        # Make sure the proxy forwards request headers unchanged.
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

Scheduled backup with cron (consistent snapshot; safe while the service runs):

```cron
# Daily snapshot at 02:00, kept by date.
0 2 * * * /opt/vinctor/.venv/bin/vinctor --db /var/lib/vinctor/vinctor.sqlite \
  operator storage backup --output /var/backups/vinctor/vinctor-$(date +\%Y\%m\%d).sqlite
```

Restore from a snapshot (validates the input before replacing the live DB):

```bash
sudo systemctl stop vinctor.service
vinctor --db /var/lib/vinctor/vinctor.sqlite operator storage restore \
  --input /var/backups/vinctor/vinctor-20260611.sqlite --yes
sudo systemctl start vinctor.service
```

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

# 2. Copy a host snapshot into the volume (cp works on the stopped container).
docker compose cp ./vinctor-backup.sqlite vinctor:/data/restore-source.sqlite

# 3. Validate-and-replace the database with a one-off container.
docker compose run --rm vinctor \
  vinctor --db /data/vinctor.sqlite operator storage restore \
  --input /data/restore-source.sqlite --yes

# 4. Start the service again.
docker compose start vinctor
```

## Upgrades

This is a from-source install, so upgrades are manual. Always back up first.

```bash
# 1. Snapshot the current database (see SQLite Backup And Restore).
sudo -u vinctor /opt/vinctor/.venv/bin/vinctor \
  --db /var/lib/vinctor/vinctor.sqlite \
  operator storage backup --output /var/backups/vinctor/pre-upgrade.sqlite

# 2. Stop, pull, reinstall.
sudo systemctl stop vinctor.service
sudo git -C /opt/vinctor/src pull
sudo /opt/vinctor/.venv/bin/pip install --upgrade /opt/vinctor/src

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
- Docker image publishing and tagged release artifacts (the CI workflow and
  registry/PyPI credentials are still required)

Opt-in structured access logging and a `/metrics` Prometheus endpoint shipped
(off by default); see "What the prototype emits today" above.

Until those exist, describe deployments as a "single-node self-hostable
prototype", not a production-ready service.
