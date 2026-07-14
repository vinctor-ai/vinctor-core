# ADR 0012: Best-effort OTLP/HTTP audit export

## Status

Accepted.

## Context

Enterprise operators need Vinctor audit events in their existing SIEM and
OpenTelemetry pipelines. The enforce path must not depend on collector health,
and Vinctor's durable audit store remains the system of record.

## Decision

- `VINCTOR_AUDIT_EXPORT=otlp-http:<http(s)-url>` enables OTLP/HTTP JSON logs.
- The configured URL is the complete logs endpoint, normally `/v1/logs`.
- Each durable `AuditEvent` becomes one OTLP `LogRecord`. Its complete sorted
  JSON is the body; stable Vinctor identifiers are also searchable attributes.
- Persistence happens before export. Network work runs on one daemon thread
  behind a bounded 1,024-item queue with a one-second request timeout.
- Collector errors and queue overflow are reported to stderr and fail open.
- The existing `stdout` and `file:` sinks keep their behavior.

## Consequences

Collector latency cannot add latency to the enforce caller. The first slice is
best-effort: it does not persist the outbound queue, batch, or retry, so a
collector outage or process exit can leave an export gap. Operators can detect
and repair that gap from the durable, workspace-key-gated JSONL audit export.
OTLP/gRPC and durable delivery are separate follow-ups if customer demand
justifies their operational cost.
