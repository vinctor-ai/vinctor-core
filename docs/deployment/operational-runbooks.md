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
    reverse_proxy 127.0.0.1:8765
}
```

Notes:

- Terminate TLS at the proxy; forward to Vinctor over loopback.
- Do not strip or rewrite the `X-Workspace-Key`, `X-Agent-Key`, or
  `X-Vinctor-Boundary-Id` headers.
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
- **Per-request HTTP access logging is intentionally suppressed**, so request
  details are not written to stderr.
- **`VINCTOR_LOG_LEVEL` / `--log-level`** sets the configured level shown in the
  banner. Structured operational logging is not yet implemented in this
  prototype; do not rely on log volume changing with the level.

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

To restore, stop the service, replace the volume's database from a snapshot
(e.g. `operator storage restore --input ... --yes` against `/data/vinctor.sqlite`
inside the container), then start it again.

## What Is Still Deferred

These remain intentionally out of scope for the single-node prototype:

- production auth/session/user management and managed identity
- high availability, replication, and multi-tenant control plane
- structured/exportable operational logging and metrics
- Docker image publishing and tagged release artifacts

Until those exist, describe deployments as a "single-node self-hostable
prototype", not a production-ready service.
