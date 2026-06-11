FROM python:3.11-slim

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src

RUN python -m pip install --no-cache-dir .

RUN mkdir -p /data

ENV VINCTOR_HOST=0.0.0.0
ENV VINCTOR_PORT=8765
ENV VINCTOR_DB=/data/vinctor.sqlite
ENV VINCTOR_SERVICE_MODE=self_hosted
ENV VINCTOR_LOG_LEVEL=info

EXPOSE 8765

CMD ["vinctor", "service", "serve"]
