# Contributing

`vinctor-core` is the deterministic authorization core for mediated AI-agent
actions, plus a thin `vinctor_service` application layer above it. Contributions
are welcome — the goal is to keep the core small, explicit, and reviewable.

## Dev setup

Python >= 3.11. Editable install with dev tools:

```bash
python3.11 -m venv .venv
.venv/bin/python -m pip install -e ".[dev]"
```

## Quality gates

Before committing (CI runs the same on every PR):

```bash
make test     # python -m pytest -q
make lint     # python -m ruff check .
make demo     # the demo scripts, which CI also executes
```

PRs must be green on the full suite, `ruff check`, and the demo scripts.

## Conventions

- **stdlib + PyYAML only.** No new runtime dependencies without discussion — the
  dependency surface is deliberately tiny. Lint is `ruff check` only (not `ruff format`).
- **Test-first.** New behavior or a bug fix lands with a test that fails before the
  change and passes after.
- **Fail closed.** No change may turn a deny — or an error — into a permit. This is
  the core invariant, and tests pin it.
- **No disclosure in deny reasons or audit.** Deny reasons and audit events must not
  leak secrets, raw keys, or even grant existence (an unknown grant and a foreign
  grant return the same generic 403). Resources are hierarchical path-prefixes, so
  `.` / `..` traversal segments are rejected. Don't interpolate caller input into
  reasons — the no-disclosure tests enforce this.
- **Schema changes are additive and versioned** (`schema_migrations`); bump every
  schema-version assertion across the tests when you add a version.
- **Surgical diffs.** Match the surrounding style; don't refactor unrelated code.

## Branch / PR model

`main` is human-merged only — work on a feature branch and open a PR. Architecture
and design decisions live in `docs/decisions/` (ADRs) and elsewhere under `docs/`.

## Security

Found a vulnerability? See [SECURITY.md](SECURITY.md) — please don't use public issues.
