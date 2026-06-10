# AGENTS.md

Guidance for AI coding agents working in this repository.

## Project Shape

`vinctor-core` starts with the deterministic authorization core for mediated
AI-agent actions. It evaluates explicit authorization inputs and returns
deterministic decision/audit data.

Service-layer packages may live here as the implementation matures, but must
remain layered above the core. Keep core behavior small, deterministic, and
runtime-agnostic.

## Hard Boundaries

Do not add runtime-specific code to `vinctor_core`.

Layering rule:

- `vinctor_core` must not import `vinctor_service`.
- `vinctor_service` may import `vinctor_core`.
- `vinctor_core` remains DB/HTTP/runtime-agnostic.
- `vinctor_service` owns HTTP APIs, auth headers, persistence, and
  workspace/agent/grant/boundary/audit storage.

Do not implement:

- Claude Code, Codex, Hermes, LangGraph, or MCP hooks
- HTTP service endpoints unless a task explicitly asks for a service package
- durable database persistence unless a task explicitly asks for it
- prompt/content safety logic
- raw tool interception
- sandboxing or OS/process isolation
- provider integrations
- approval workflows
- hosted service behavior
- UI/dashboard behavior

Runtime adapters translate tool calls into action/resource pairs. Service
layers handle authentication and persistence. This core evaluates explicit
authorization inputs.

## Development Workflow

Use a small, test-first loop:

1. Define the behavior with tests.
2. Implement the minimum code needed to pass.
3. Run the relevant tests.
4. Simplify the diff.
5. Update docs only when public behavior or agent workflow changes.

Prefer pure functions and small typed dataclasses. Avoid heavy class hierarchies
or speculative extension points.

## Validation

Use:

```bash
/opt/homebrew/bin/python3.11 -m venv .venv
.venv/bin/python -m pip install -e ".[dev]"
.venv/bin/python -m pytest -q
.venv/bin/python demo/boundary_registry_core_e2e.py
.venv/bin/ruff check .
git diff --check
```

When using the local venv created for this repo:

```bash
.venv/bin/python -m pytest -q
.venv/bin/python demo/boundary_registry_core_e2e.py
.venv/bin/ruff check .
git diff --check
```

## Documentation

Keep docs small and current.

- `README.md` explains the public package boundary.
- `docs/next-actions.md` tracks current work and the next useful tasks.
- `docs/decisions/` records durable decisions only when needed.

Do not create architecture-only documents as a substitute for implemented,
tested behavior.
