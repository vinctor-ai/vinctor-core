# Security Policy

Vinctor is a runtime authorization layer for AI agents, so we take security reports
seriously. This repository is `vinctor-core` — the deterministic authorization
engine plus the thin local/self-hostable `vinctor_service` layer above it.

## Reporting a Vulnerability

**Please do not open a public issue for a security vulnerability.**

Report it privately through GitHub's
[**Report a vulnerability**](../../security/advisories/new) flow (the repository's
*Security* tab -> *Advisories*). We aim to acknowledge a report within 5 business
days and will keep you updated on remediation.

When you can, include: the affected version/commit, the impact, and a minimal
reproduction.

## Scope and Maturity

This is an **early preview** (single-node) and is labelled as such. Vinctor scopes
what an agent is *allowed* to do; it does not strip the ambient credentials an agent
already holds, and the agent-side hook is *cooperative* (a resource-side enforcement
point is the stronger control). For the full picture of what Vinctor does and does
not defend against, read the [threat model](docs/threat-model.md).

We hunt our own gaps adversarially and fix them in the open — see the dogfooding
record and the ADRs under `docs/`.

## Supported Versions

During the preview period, only the latest released version is supported.
