# Decisions

This directory is for durable design decisions that future agents and
maintainers should not rediscover from chat history.

Use a new file only when a decision is hard to reverse or changes the public
contract.

Suggested filename format:

```text
0001-short-decision-title.md
```

Each decision should include:

- status
- date
- context
- decision
- consequences

Do not use this directory for speculative architecture notes that are not tied
to implemented behavior.

Current decisions:

- `0001-service-package-in-repository.md`
- `0002-durable-local-key-storage.md`
- `0003-grant-lifecycle-jit-semantics.md`
- `0004-approval-authority-and-auto-approval-rules.md`
- `0005-grant-request-routing-and-approval-modes.md`
- `0006-local-bootstrap-ux-and-key-reuse.md`
- `0007-delegated-enforce-and-pep-identity.md`
- `0008-auditing-pre-grant-evaluation-rejections.md`
- `0009-mandatory-boundary-enforcement.md`
- `0010-infer-scope-proposals-from-audit.md`
- `0011-mcp-resource-side-pep.md`
- `0013-versioned-policy-rollback.md`
- `0017-storage-readiness-probe.md`
- `0018-postgres-full-control-plane.md`
