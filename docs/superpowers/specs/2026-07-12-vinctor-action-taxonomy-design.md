# Vinctor Action Taxonomy — Design

**Status:** Approved (brainstorming) — ready for writing-plans.
**Date:** 2026-07-12
**Context:** Three independent reviews (a 5-persona adoption panel, a Codex red-team, and a Codex product review) converged on the same #1 moat: **"the same tool call must mean the same thing on every runtime."** Today it doesn't — `merge_pull_request` maps to `deploy` in the Claude/Codex hooks but `execute` in the Hermes plugin, and the MCP proxy uses a different resource-path shape. Each adapter re-derives its own mapping, so a grant written once does not enforce identically across runtimes. This spec defines a **principled Action Taxonomy** — a rubric plus a canonical `(tool → action, resource)` mapping — so that classification is derived from a stated rule, not from whatever each adapter happened to do.

This is **[1] of two slices.** [1] = the taxonomy (this spec: the rubric + canonical mapping). [2] (a separate follow-up) = the conformance mechanism that enforces it (a `vinctor-conformance` repo with language-neutral fixtures + a per-adapter conformance test + reconciliation of the current divergences + a coverage matrix). This spec designs [1] and specifies the [2] interface it must feed.

## Goal

A single, rubric-derived source of truth for how any agent tool call becomes a Vinctor `(action, resource)` — so all adapters (Claude Code hook, Codex hook, Hermes plugin, MCP PEP) can be held to it, and "same call → same meaning anywhere" becomes a testable fact.

## The rubric

### Verbs (the fixed 6, defined by effect)

| verb | effect it names |
| --- | --- |
| `read` | observes state; no mutation |
| `write` | mutates state within a bounded, owned resource (a file, a record, repo contents) |
| `delete` | destroys/removes a resource (irreversible removal) |
| `deploy` | causes a change to become **externally effective** — crosses into a shipping / production / shared environment (release, publish, merge to the default branch, run a deployment) |
| `execute` | runs **arbitrary computation or commands** whose effects are not statically known (shell, CI/workflow run, code execution) |
| `send` | **network egress / communication** to an external or other party (email, chat message, HTTP to an external host) |

### Classification rule

1. **Determine the operation's effect set** from the **operation type alone** — context-free. We deliberately do NOT branch on hard-to-extract runtime context (e.g. which git branch a merge targets), because (a) each adapter would extract it differently and re-introduce divergence, and (b) context-free rules are trivially conformant. When an operation *could* be more or less consequential depending on unextractable context, we classify it at its **more consequential** effect (fail toward the stricter verb). An operator who wants to allow the benign case grants the stricter scope deliberately.
2. **Among the effects it has, the highest-precedence verb wins.** Precedence, ordered by irreversibility + blast-radius (most consequential first):

   ```
   delete  >  deploy  >  execute  >  send  >  write  >  read
   ```

   So a `merge_pull_request` has `{write (repo contents), deploy (becomes the shipping baseline)}` → **deploy**. A `run_workflow` runs arbitrary CI → **execute**. `npm publish` ships a package externally → **deploy**.

This rule — *effect set by operation type (context-free, fail-stricter), then highest-precedence verb* — is the universal disambiguator. Every contested case is resolved by it, not by adapter lineage.

### Resource path grammar (domain-keyed)

Resources are hierarchical, `/`-separated path prefixes (Vinctor scopes are prefix wildcards; `.`/`..` segments are rejected — existing PDP invariant). Each domain has one canonical shape:

| domain | canonical resource template |
| --- | --- |
| GitHub | `github/<owner>/<repo>/<kind>` — kind ∈ `pr` `issue` `workflow` `release` `contents` `secret` |
| filesystem | `fs/<path…>` |
| CI/CD | `ci/<system>/<pipeline>` |
| network | `net/<scope>/<host>` — scope ∈ `internal` `external` |
| chat | `chat/<platform>/<channel>` |
| package registry | `pkg/<registry>/<name>` |
| container | `container/<registry>/<image>` |
| secrets | `secret/<kind>` |
| shell (opaque) | `shell/<first-token>` |

This closes the second divergence axis (the MCP proxy's `github/<owner>/<repo>/issue` and the hooks' shapes both normalize to `github/<owner>/<repo>/<kind>`).

## Canonical mapping (v1 families)

Re-derived from the rubric. Representative per family; the exhaustive machine-readable table is the [2] canon artifact. `<o>/<r>` = owner/repo.

**GitHub** — `github/<o>/<r>/<kind>`
- `get_*`, `list_*`, `search_*`, `get_file_contents` → **read**
- `create_issue`, `update_issue`, `add_issue_comment` → **write** · `…/issue`
- `create_pull_request`, `update_pull_request` → **write** · `…/pr`
- **`merge_pull_request` → deploy · `…/pr`** (write + becomes shipping baseline → precedence)
- `create_or_update_file`, `push_files` → **write** · `…/contents`
- `delete_file` → **delete** · `…/contents`
- `create_release`, `publish_release` → **deploy** · `…/release`
- `run_workflow`, `dispatch_workflow` → **execute** · `…/workflow` (arbitrary CI)
- secret-scanning / manage-secret tools → **read**/**write** · `…/secret`

**Filesystem** — `fs/<path>`
- `read_text_file`, `read_file`, `list_directory`, `directory_tree` → **read**
- `write_file`, `edit_file`, `create_directory`, `move_file` → **write**
- `delete_file`, `remove_directory` → **delete**
- sensitive targets (`.env`, `~/.ssh`, cloud-cred files) → same verb over `secret/<kind>` (existing shared sensitive-path module)

**Shell / git / npm / docker** — `shell/<first-token>` unless a more specific domain applies
- `git status|log|diff|show` → **read** · `shell/git`
- `git add|commit|stash` → **write** · `shell/git`
- `git push`, `push_files` → **write** · `github/<o>/<r>/contents` (uploads commits to a branch — the same logical effect via CLI or API, so classified identically. The **deploy moment is the explicit integration** — `merge_pull_request` / `create_release` / a deploy workflow — not the push. A direct push to a protected branch is an edge case for GitHub branch-protection to prevent, not one the taxonomy over-restricts *every* push for.)
- `npm test`, `npm run <script>` → **execute** · `shell/npm`
- `npm install`, `npm ci` → **execute** · `shell/npm` (runs arbitrary install scripts)
- `npm publish` → **deploy** · `pkg/npm/<name>`
- `docker build` → **execute** · `container/<registry>/<image>`
- `docker push` → **deploy** · `container/<registry>/<image>`
- `docker run` → **execute** · `container/<registry>/<image>`
- `rm`, `rmdir` → **delete** · `fs/<path>`
- `curl … | sh`, piped/subshell exec → **execute** · `shell/<first-token>` (the hooks already document that shell matching is literal, not a full parser — obfuscated commands are the operator's/authorization service's job, not the taxonomy's)

**Slack / chat** — `chat/slack/<channel>`
- `list_channels`, `get_messages`, `conversations_history` → **read**
- `post_message`, `send_message`, `reply` → **send**

## Reconciling the current divergences

- `merge_pull_request`: Hermes `execute` → **`deploy`** (rule-derived, not "the hooks win"). Claude/Codex already `deploy` — unchanged.
- GitHub resource shape: the MCP proxy's `github/<o>/<r>/issue` already fits `github/<o>/<r>/<kind>` — keep; the hooks normalize to the same grammar where they differ.
- Any other adapter mapping that the rubric now assigns differently is corrected in [2] (that's where each adapter is made conformant); this spec is the reference they conform to.

## The [2] interface this spec feeds

[1] emits, and [2] consumes:
1. **A machine-readable canon** — a language-neutral file (JSON) of `{tool_family, operation, params-shape} → {action, resource_template}` entries, plus this rubric doc. Lives in the `vinctor-conformance` repo (founder creates it when [2] starts; until then it can stage in this repo's `docs/`).
2. **Language-neutral fixtures** derived from the canon: `{id, family, operation, params, expected: {action, resource}}` — each adapter's conformance test constructs its own native tool-call input for `(family, operation, params)`, runs its real mapper, and asserts the output equals `expected`.
3. **A coverage matrix** generated from adapter results: per operation × adapter → `agrees` / `disagrees` / `unmapped`. This is the honest "what is protected where" artifact (and a public benchmark candidate).

## Non-goals

- **Unmapped-tool fallback is NOT part of the canon.** Adapters legitimately differ: hooks abstain (`ask`), the MCP proxy denies. This is documented, not forced equal — the canon governs *mapped* classification only.
- **Runtime hook coverage** (whether a runtime even fires for a given tool) is a different axis; the matrix surfaces it but the taxonomy doesn't fix it.
- **Exhaustive tool coverage** — v1 covers the families that actually overlap today (GitHub, filesystem, shell/git/npm/docker, Slack). New tools are classified by the rubric as they arise.
- **No change to the 6-verb set** or the scope grammar; this spec defines how tools *map into* them, consistently.

## Testing / validation (for [1])

- The rubric is validated by a **worked-examples table**: for each family above, assert the canonical mapping is what the rubric produces (a reviewer can re-derive each row from the rule). The contested cases (`merge_pull_request`, `git push`, `run_workflow`, `npm publish`) each carry a one-line derivation.
- The machine-readable canon file is validated by a schema check (well-formed entries; every `action` ∈ the 6 verbs; every `resource_template` matches the grammar).
- Full behavioral conformance (each adapter agrees) is [2], not [1].
