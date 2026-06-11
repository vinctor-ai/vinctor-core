# 0006 Local Bootstrap UX And Key Reuse

Date: 2026-06-11

## Status

Accepted for the local prototype.

## Context

The local launcher currently prints raw `VINCTOR_*` values:

- endpoint
- workspace/admin key
- agent key
- bootstrap grant ref
- optional boundary id

This is usable, but repeated demos require copying exports. The tempting fix is
to auto-save everything into a local config file and reuse it automatically.

Raw keys are sensitive. The SQLite database intentionally stores only key
hashes and metadata. Storing raw keys in a repo-local file would weaken that
boundary and make accidental commits more likely.

## Decision

For now, Vinctor keeps raw key handling explicit:

- `vinctor local start` prints raw keys only to the operator's terminal.
- `vinctor local env` formats already-provided or already-exported values.
- `vinctor local env --write-file .vinctor.env` may explicitly write a
  test/dev env file when the operator asks for it.
- SQLite stores key hashes, not raw keys.
- `vinctor operator storage info` exposes local storage metadata without
  exposing raw secrets.
- Policy import/export may write non-secret operator policy to files.

Vinctor will not silently persist raw workspace or agent keys to repository
files.

`.vinctor.env` and `.vinctor-*.env` are ignored by git. Operators remain
responsible for keeping raw keys out of committed files.

## Future Options

Future local UX can consider:

- OS keychain-backed raw key reuse
- an explicit config file containing only non-secret metadata
- per-demo ephemeral key regeneration

Those options should be implemented only after a separate design slice.

## Consequences

Repeated demos can use exported environment variables, explicit key arguments,
or an explicitly written local env file. This preserves the no-silent-secret
storage posture while the service contract is still changing.
