from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal, Protocol

OidcRole = Literal["operator", "auditor", "service_operator"]

_ASYMMETRIC_ALGORITHMS = frozenset(
    {"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"}
)


@dataclass(frozen=True)
class OidcConfig:
    issuer: str
    audience: str
    jwks_url: str
    groups_claim: str = "groups"
    workspace_claim: str = "vinctor_workspace_id"
    operator_group: str = "vinctor-operator"
    auditor_group: str = "vinctor-auditor"
    service_operator_group: str = "vinctor-service-operator"
    algorithms: tuple[str, ...] = ("RS256",)
    allowed_workspace_ids: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        required = {
            "issuer": self.issuer,
            "audience": self.audience,
            "jwks_url": self.jwks_url,
            "groups_claim": self.groups_claim,
            "workspace_claim": self.workspace_claim,
            "operator_group": self.operator_group,
            "auditor_group": self.auditor_group,
            "service_operator_group": self.service_operator_group,
        }
        for name, value in required.items():
            if not value.strip():
                raise ValueError(f"OIDC {name} is required")
        if not self.algorithms or any(
            algorithm not in _ASYMMETRIC_ALGORITHMS for algorithm in self.algorithms
        ):
            raise ValueError("OIDC algorithms must be supported asymmetric algorithms")
        if any(
            not workspace_id or workspace_id.strip() != workspace_id
            for workspace_id in self.allowed_workspace_ids
        ):
            raise ValueError("OIDC allowed workspace ids must be non-empty and trimmed")


@dataclass(frozen=True)
class OidcPrincipal:
    subject: str
    workspace_id: str | None
    roles: frozenset[OidcRole]


class OidcTokenVerifier(Protocol):
    def verify(self, token: str) -> OidcPrincipal | None: ...


class PyJwtOidcTokenVerifier:
    def __init__(self, config: OidcConfig) -> None:
        try:
            import jwt
        except ModuleNotFoundError as error:
            raise RuntimeError(
                "OIDC is configured but PyJWT is unavailable; install vinctor-core[oidc]"
            ) from error
        self._config = config
        self._jwt = jwt
        self._jwks_client = jwt.PyJWKClient(config.jwks_url)

    def verify(self, token: str) -> OidcPrincipal | None:
        try:
            signing_key = self._jwks_client.get_signing_key_from_jwt(token)
            claims = self._jwt.decode(
                token,
                signing_key.key,
                algorithms=list(self._config.algorithms),
                audience=self._config.audience,
                issuer=self._config.issuer,
                options={"require": ["exp", "iss", "aud", "sub"]},
            )
        except self._jwt.PyJWTError:
            return None
        return principal_from_claims(self._config, claims)


def load_oidc_config(env: Mapping[str, str]) -> OidcConfig | None:
    core_names = (
        "VINCTOR_OIDC_ISSUER",
        "VINCTOR_OIDC_AUDIENCE",
        "VINCTOR_OIDC_JWKS_URL",
    )
    configured = [name for name in core_names if env.get(name)]
    if not configured:
        return None
    missing = [name for name in core_names if not env.get(name)]
    if missing:
        raise ValueError(f"OIDC configuration requires {', '.join(missing)}")

    algorithms = tuple(
        value.strip()
        for value in env.get("VINCTOR_OIDC_ALGORITHMS", "RS256").split(",")
        if value.strip()
    )
    allowed_workspace_ids = frozenset(
        value.strip()
        for value in env.get("VINCTOR_OIDC_ALLOWED_WORKSPACE_IDS", "").split(",")
        if value.strip()
    )
    return OidcConfig(
        issuer=env["VINCTOR_OIDC_ISSUER"],
        audience=env["VINCTOR_OIDC_AUDIENCE"],
        jwks_url=env["VINCTOR_OIDC_JWKS_URL"],
        groups_claim=env.get("VINCTOR_OIDC_GROUPS_CLAIM", "groups"),
        workspace_claim=env.get("VINCTOR_OIDC_WORKSPACE_CLAIM", "vinctor_workspace_id"),
        operator_group=env.get("VINCTOR_OIDC_OPERATOR_GROUP", "vinctor-operator"),
        auditor_group=env.get("VINCTOR_OIDC_AUDITOR_GROUP", "vinctor-auditor"),
        service_operator_group=env.get(
            "VINCTOR_OIDC_SERVICE_OPERATOR_GROUP", "vinctor-service-operator"
        ),
        algorithms=algorithms,
        allowed_workspace_ids=allowed_workspace_ids,
    )


def principal_from_claims(
    config: OidcConfig,
    claims: Mapping[str, object],
) -> OidcPrincipal | None:
    subject = claims.get("sub")
    groups = claims.get(config.groups_claim, [])
    workspace_id = claims.get(config.workspace_claim)
    if not isinstance(subject, str) or not subject:
        return None
    if not isinstance(groups, list) or not all(isinstance(group, str) for group in groups):
        return None
    if workspace_id is not None and (not isinstance(workspace_id, str) or not workspace_id):
        return None
    workspace_role_requested = (
        config.operator_group in groups or config.auditor_group in groups
    )
    if workspace_role_requested:
        if workspace_id is None or workspace_id not in config.allowed_workspace_ids:
            return None
    else:
        workspace_id = None

    roles: set[OidcRole] = set()
    if workspace_id is not None and config.operator_group in groups:
        roles.add("operator")
    if workspace_id is not None and config.auditor_group in groups:
        roles.add("auditor")
    if config.service_operator_group in groups:
        roles.add("service_operator")
    return OidcPrincipal(
        subject=subject,
        workspace_id=workspace_id,
        roles=frozenset(roles),
    )
