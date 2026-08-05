"""Which ``VINCTOR_*`` environment variables this artifact actually reads.

PKA-168. The README promised ``VINCTOR_AUDIT_SINK_REQUIRED=true`` would refuse
startup without a sink. On the published 0.5.0 the variable did not exist at
all, so an operator set it, the service started normally, and nothing anywhere
said otherwise. For an audit-trail product a control that silently does nothing
is worse than one that is absent: it manufactures confidence in exactly the
property being sold.

Shipping the missing feature fixes that one variable. This module fixes the
CLASS, which is the part that generalises — an unrecognised ``VINCTOR_*`` name
is now reported at startup, so the next phantom flag announces itself instead of
being discovered by an auditor. It catches both causes at once:

  - a TYPO (``VINCTOR_AUDIT_SINK_REQUIRE``), and
  - a VERSION MISMATCH, where the operator is reading documentation for a build
    they do not have. That is the case that actually happened, and it is
    invisible from the outside: the name is spelled correctly, it is simply not
    in this artifact.

This is a WARNING, never a refusal. Startup must not begin failing on an
environment that worked before — an unknown name is usually harmless, the
service cannot know what else shares its environment, and an upgrade that
crashes on a leftover variable is a worse failure than the one being fixed.

`_KNOWN` is the single runtime source of truth;
``tests/test_env_registry_matches_sources.py`` re-derives the same set from the
shipped packages and fails if the two disagree, in either direction. So adding a
variable without registering it fails CI, and so does registering one nothing
reads — the registry cannot rot into a stale allowlist.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

#: Every ``VINCTOR_*`` name read by this artifact's shipped packages.
_KNOWN: frozenset[str] = frozenset(
    {
        "VINCTOR_ACCESS_LOG",
        "VINCTOR_AGENT_KEY",
        "VINCTOR_AUDITOR_KEY",
        "VINCTOR_AUDIT_ANCHOR",
        "VINCTOR_AUDIT_EXPORT",
        "VINCTOR_AUDIT_EXPORT_BATCH_SIZE",
        "VINCTOR_AUDIT_EXPORT_MAX_ATTEMPTS",
        "VINCTOR_AUDIT_EXPORT_RETRY_BACKOFF_SECONDS",
        "VINCTOR_AUDIT_SINK_REQUIRED",
        "VINCTOR_BOUNDARY_ID",
        "VINCTOR_DB",
        "VINCTOR_ENDPOINT",
        "VINCTOR_GRANT_REF",
        "VINCTOR_HOST",
        "VINCTOR_IDEMPOTENCY_ACTIVE_KEY_VERSION",
        "VINCTOR_IDEMPOTENCY_KEYRING_JSON",
        "VINCTOR_LOG_LEVEL",
        "VINCTOR_MCP_ENDPOINT",
        "VINCTOR_MCP_OUTPUT_MODE",
        "VINCTOR_MCP_SERVICE_OPERATOR_KEY",
        "VINCTOR_MCP_TIMEOUT",
        "VINCTOR_MCP_WORKSPACE_KEY",
        "VINCTOR_MCP_WRITE",
        "VINCTOR_METRICS",
        "VINCTOR_OIDC_ALGORITHMS",
        "VINCTOR_OIDC_ALLOWED_WORKSPACE_IDS",
        "VINCTOR_OIDC_AUDIENCE",
        "VINCTOR_OIDC_AUDITOR_GROUP",
        "VINCTOR_OIDC_GROUPS_CLAIM",
        "VINCTOR_OIDC_ISSUER",
        "VINCTOR_OIDC_JWKS_URL",
        "VINCTOR_OIDC_OPERATOR_GROUP",
        "VINCTOR_OIDC_SERVICE_OPERATOR_GROUP",
        "VINCTOR_OIDC_WORKSPACE_CLAIM",
        "VINCTOR_POP_REPLAY_MAX_ENTRIES",
        "VINCTOR_POP_REPLAY_MAX_PER_TOKEN",
        "VINCTOR_PORT",
        "VINCTOR_POSTGRES_DSN",
        "VINCTOR_RATE_LIMIT_PER_MINUTE",
        "VINCTOR_READINESS_PROBE_TIMEOUT_SECONDS",
        "VINCTOR_SERVICE_MODE",
        "VINCTOR_SERVICE_OPERATOR_KEY",
        "VINCTOR_STORAGE_BACKEND",
        "VINCTOR_SUBJECT_TOKEN_MAX_TTL_SECONDS",
        "VINCTOR_SUBJECT_TOKEN_POP_SKEW_SECONDS",
        "VINCTOR_TRUSTED_PROXIES",
        "VINCTOR_WORKSPACE_KEY",
    }
)

#: Names belonging to a DIFFERENT Vinctor component, which this service does not
#: read and must not warn about.
#:
#: A boundary and the service it calls routinely share one environment — a
#: compose file, a pod spec, a developer's shell. Warning on a neighbour's
#: correctly-spelled variable would fire on ordinary working deployments, and a
#: warning that fires when nothing is wrong is one operators learn to skip past.
#: That would cost exactly the signal this module exists to add.
#:
#: Measured 2026-07-29 from the shipped sources of each sibling, so this is the
#: real surface rather than a guess.
_SIBLING_COMPONENTS: frozenset[str] = frozenset(
    {
        # Policy enforcement points (vinctor-mcp-pep).
        "VINCTOR_AGENT_ID",
        "VINCTOR_ENFORCEMENT_MODE",
        "VINCTOR_PEP_KEY",
        "VINCTOR_SUBJECT_TOKEN",
        "VINCTOR_SUBJECT_TOKEN_ID",
        "VINCTOR_SUBJECT_TOKEN_POP_SECRET",
        "VINCTOR_WORKSPACE_ID",
        # Claude Code / Codex hooks.
        "VINCTOR_CLAUDE_CODE_HOOK_CONFIG",
        "VINCTOR_CODEX_HOOK_CONFIG",
        "VINCTOR_ENFORCE_TOOLS",
        "VINCTOR_HOOK_DEBUG",
        "VINCTOR_NET_HOSTNAME_POLICY",
        # Hermes plugin.
        "VINCTOR_HERMES_ALLOW_MCP_REGISTRY_RUNTIME_RULES",
        "VINCTOR_HERMES_COVERAGE_LOG",
        "VINCTOR_HERMES_COVERAGE_LOG_INCLUDE_ARGS",
        "VINCTOR_HERMES_DEBUG",
        "VINCTOR_HERMES_DECISION_LOG",
        "VINCTOR_HERMES_MCP_REGISTRY",
        "VINCTOR_HERMES_PLUGIN_CONFIG",
        "VINCTOR_HERMES_TIMEOUT_MS",
        "VINCTOR_HERMES_UNMAPPED_POLICY",
    }
)


def unrecognized_vinctor_env_vars(env: Mapping[str, str]) -> list[str]:
    """``VINCTOR_*`` names present in ``env`` that nothing in this build reads.

    Sorted, so the warning is stable and diffable across restarts.
    """
    return sorted(
        name
        for name in env
        if name.startswith("VINCTOR_")
        and name not in _KNOWN
        and name not in _SIBLING_COMPONENTS
    )


def unrecognized_env_warning(env: Mapping[str, str]) -> str | None:
    """The startup warning, or ``None`` when every ``VINCTOR_*`` name is known."""
    unknown = unrecognized_vinctor_env_vars(env)
    if not unknown:
        return None
    return _render(unknown)


def _render(unknown: Sequence[str]) -> str:
    names = ", ".join(unknown)
    plural = "variables are" if len(unknown) > 1 else "variable is"
    return (
        f"vinctor: {plural} set but not read by this build: {names}. "
        "They configure NOTHING here. Check the spelling, and check that this "
        "version of vinctor-core is the one whose documentation you are reading "
        "— a control named in newer docs does nothing in an older artifact."
    )
