# Base image pinned by digest for reproducible builds (PKA-24). This is the
# multi-arch index digest of python:3.11-slim; refresh it when bumping the tag:
#   docker buildx imagetools inspect python:3.11-slim
FROM python:3.11-slim@sha256:db3ff2e1800a8581e2c48a27c3995339d47bdf046da21c7627accd3d51053a93

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src

# Include the postgres + oidc extras so the published image can run the
# TIER-3 features (Postgres storage backend, OIDC identity) without a rebuild.
RUN python -m pip install --no-cache-dir ".[postgres,oidc]"

# Run as an unprivileged system user; own the data directory it writes to.
RUN useradd --system --uid 10001 vinctor \
    && mkdir -p /data \
    && chown vinctor:vinctor /data

ENV VINCTOR_HOST=0.0.0.0
ENV VINCTOR_PORT=8765
ENV VINCTOR_DB=/data/vinctor.sqlite
ENV VINCTOR_SERVICE_MODE=self_hosted
ENV VINCTOR_LOG_LEVEL=info

EXPOSE 8765

# Probe the readiness endpoint with the stdlib (no curl in python-slim).
# /readyz, not /healthz: a container healthcheck is a traffic and dependency
# gate (`depends_on: condition: service_healthy`, orchestrator health checks),
# and /healthz reports process liveness only — it stays 200 through a total
# store outage, so gating on it would keep routing to an instance that cannot
# serve. --timeout exceeds the endpoint's own 2s probe bound so a slow store
# reports "unavailable" rather than timing out indistinguishably.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s CMD \
    python -c "import urllib.request,os;urllib.request.urlopen('http://127.0.0.1:'+os.environ.get('VINCTOR_PORT','8765')+'/readyz').read()"

USER vinctor

CMD ["vinctor", "service", "serve"]
