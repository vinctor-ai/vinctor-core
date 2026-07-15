# TODO: pin by digest (FROM python:3.11-slim@sha256:<digest>  # 3.11-slim) once
# a digest can be resolved in CI (e.g. `docker buildx imagetools inspect`).
FROM python:3.11-slim

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

# Probe the service health endpoint with the stdlib (no curl in python-slim).
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s CMD \
    python -c "import urllib.request,os;urllib.request.urlopen('http://127.0.0.1:'+os.environ.get('VINCTOR_PORT','8765')+'/healthz').read()"

USER vinctor

CMD ["vinctor", "service", "serve"]
