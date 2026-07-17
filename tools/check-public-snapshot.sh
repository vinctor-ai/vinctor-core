#!/usr/bin/env bash
# Release pre-flight: is the public snapshot a verbatim copy of what we're releasing?
#
# The public repo is published as a fresh single orphan commit whose tree is
# copied from this repo's main, and releases are tagged there — so whatever that
# snapshot contains is what ships to PyPI and GHCR. Between releases it is
# deliberately BEHIND main; that is the normal state, which is why this is a
# pre-flight rather than a scheduled check. A continuous "snapshot != main" alarm
# would fire constantly and teach everyone to ignore it.
#
# Run it after re-syncing the snapshot and before pushing the tag, so the one
# manual step in the release is verified rather than remembered.
#
#   tools/check-public-snapshot.sh          # compare against HEAD
#   tools/check-public-snapshot.sh <ref>    # or any other ref
#
# The default is HEAD — the commit you are about to tag — and the public side
# is always fetched fresh. Do not default to a remote-tracking ref like
# origin/main: it is only as new as your last fetch, so a stale local ref that
# happens to match the snapshot reports "in sync" while the commit actually
# being tagged does not. If you compare against origin/main explicitly, fetch
# first.
#
# Override the public remote with VINCTOR_PUBLIC_REMOTE.
set -euo pipefail

remote="${VINCTOR_PUBLIC_REMOTE:-https://github.com/vinctor-ai/vinctor-core.git}"
ref="${1:-HEAD}"

git fetch --quiet "$remote" main
snapshot_commit="$(git rev-parse FETCH_HEAD)"
snapshot_tree="$(git rev-parse FETCH_HEAD^{tree})"
local_commit="$(git rev-parse "${ref}^{commit}")"
local_tree="$(git rev-parse "${ref}^{tree}")"

if [ "$snapshot_tree" = "$local_tree" ]; then
  echo "in sync — the public snapshot's tree matches ${ref} (commit ${local_commit}, tree ${local_tree})"
  exit 0
fi

{
  echo "DRIFT — the public snapshot is not a copy of ${ref}."
  echo "  public snapshot: commit ${snapshot_commit}, tree ${snapshot_tree}"
  echo "  ${ref}: commit ${local_commit}, tree ${local_tree}"
  echo
  echo "Paths that differ:"
  git diff --stat FETCH_HEAD "$ref" || true
  echo
  echo "Re-sync the snapshot before tagging, or you will publish something other"
  echo "than what you just reviewed."
} >&2
exit 1
