# Gradual rollout: observe → simulate → enforce

Vinctor is meant to be adopted incrementally. Instead of turning on blocking
enforcement on day one — and risking breaking an agent's real workflow — you
can run it in two **non-blocking** modes first, learn what the agent actually
does, propose a policy from that evidence, and cut over to enforcement one tool
at a time.

The mode is selected on the **PEP** — the adapter that sits in front of the
agent (for example the Claude Code hook) — not on the Vinctor service. The
service exposes three intake endpoints (`/v1/observe`, `/v1/simulate`,
`/v1/enforce`); the PEP calls the one that matches its configured mode. The
same endpoints work on both the SQLite and Postgres backends.

## The four stages

### 1. Observe — record, never block

Set the PEP to observe mode:

```
VINCTOR_ENFORCEMENT_MODE=observe
```

Every mapped tool call is sent to `/v1/observe` and recorded as an
`action_observed` audit event; unmapped calls are recorded as `action_unmapped`.
The agent is **never blocked** — observe mode always allows the tool to run, and
a service/telemetry failure fails open (the agent keeps working).

After the agent has run a representative workload, see which scopes it actually
used:

```
vinctor operator policy infer --agent <agent_id> --min-observations 2
```

`policy infer` is **propose-only** — it never grants anything. It reports the
scopes the agent exercised (separating enforced / observed / simulated
evidence), and `--min-observations` drops one-off pairs before optional wildcard
generalization. Use the proposal to author a grant/policy that matches reality.

### 2. Simulate — compute the decision, still never block

Once a candidate policy is in place, switch the PEP to simulate mode:

```
VINCTOR_ENFORCEMENT_MODE=simulate
VINCTOR_GRANT_REF=<grant_ref>        # the grant to simulate against
```

Now each mapped call goes to `/v1/simulate`: Vinctor computes the **real**
enforce decision (`would_permit` / `would_deny`) and records it as an
`action_would_permit` / `action_would_deny` audit event — but the agent is
**still never blocked**, and a would-deny reason is **never shown to the agent**
(it is operator-only). Review the would-denies before you flip enforcement on —
they are exactly the calls that would break once you enforce:

```
vinctor operator audit list --event action_would_deny
```

Tighten the policy until the simulated denies are only the ones you intend.

### 3. Selective enforcement — promote one tool at a time

To de-risk the cutover you can enforce a **subset** of tools for real while the
rest keep simulating. Stay in simulate mode and list the promoted tools:

```
VINCTOR_ENFORCEMENT_MODE=simulate
VINCTOR_GRANT_REF=<grant_ref>
VINCTOR_ENFORCE_TOOLS=Bash,Write     # these enforce for real; everything else simulates
```

A promoted tool gets a real `/v1/enforce` decision (and can be blocked); every
other tool still simulates and allows. Promote tools one at a time as you gain
confidence.

### 4. Enforce — the default

```
VINCTOR_ENFORCEMENT_MODE=enforce     # also the default when unset or unrecognized
```

Every mapped call is enforced through `/v1/enforce` and denied if the active
grant does not cover it. Unmapped calls follow the PEP's own fallback (the
Claude Code hook abstains / asks; the MCP PEP denies).

## Invariants (hold in every mode)

- **Observe and simulate never block** the agent, and a telemetry/service
  failure in those two modes fails open — they cannot break a workflow.
- **No disclosure to the agent**: a `would_deny` (simulate) or a real deny
  (enforce) never reveals the classified action/resource or grant details to the
  agent; the reason is recorded operator-side only.
- **Inference is propose-only**: `policy infer` reads observed / simulated /
  enforced evidence and proposes scopes; it never auto-grants.

## Where the modes are configured

`VINCTOR_ENFORCEMENT_MODE`, `VINCTOR_ENFORCE_TOOLS`, and `VINCTOR_GRANT_REF` are
read by the **PEP adapter** (e.g. the Claude Code hook), not by the Vinctor
service — see the adapter's own README for exactly how to set them. The service
side is mode-agnostic: it simply answers whichever of `/v1/observe`,
`/v1/simulate`, `/v1/enforce` the PEP calls.

Related: [`self-hosting.md`](self-hosting.md) (service configuration),
[`../operator-policy-authoring/README.md`](../operator-policy-authoring/README.md)
(authoring the policy you roll out).
