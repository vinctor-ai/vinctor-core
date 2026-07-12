# Git Boundary Demo Scenario

This demo scenario shows why repository-scoped grants matter for agent work.

## Product Point

An agent may have authority to edit or push in `vinctor-core` without having
authority to modify sibling hook repositories. Even when a sibling change seems
useful, the agent should request or propose that change through the owner of the
sibling repo rather than pushing directly.

## Scope Shape

Example grant:

```text
write:repo/vinctor-core/*
```

Permitted request:

```text
write:repo/vinctor-core/README.md
```

Denied request:

```text
write:repo/vinctor-codex-hook/README.md
```

## Demo

Run:

```bash
.venv/bin/python demo/git_repo_boundary_demo.py
```

The demo creates one grant for `write:repo/vinctor-core/*`, then proves:

- a core repo write is permitted
- a sibling repo write is denied
- both decisions are auditable

## Intended Follow-up Behavior

If a sibling repo change is needed, the agent should create an issue, open a PR
from an approved branch, or request a new scoped grant. It should not treat
nearby filesystem access as authority.
