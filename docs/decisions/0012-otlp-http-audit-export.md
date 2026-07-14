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
- The worker coalesces up to 32 records for at most 50 milliseconds into one
  OTLP request. The batch size is configurable.
- Network errors and HTTP `408`, `429`, and `5xx` responses are retried up to
  three total attempts with bounded exponential backoff. Other HTTP `4xx`
  responses are not retried. Attempts and initial backoff are configurable.
- Service shutdown requests a bounded background-queue flush before the
  database connection closes.
- Collector errors and queue overflow are reported to stderr and fail open.
- The existing `stdout` and `file:` sinks keep their behavior.

## Consequences

Collector latency and retry backoff cannot add latency to the enforce caller.
Delivery remains best effort because the outbound queue is memory-only and a
bounded shutdown cannot guarantee delivery during a prolonged outage or hard
process termination. Operators can detect and repair that gap from the durable,
workspace-key-gated JSONL audit export. OTLP/gRPC and durable outbound delivery
are separate follow-ups if customer demand justifies their operational cost.
