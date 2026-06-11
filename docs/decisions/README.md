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
