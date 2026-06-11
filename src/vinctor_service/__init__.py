"""Vinctor service-layer application helpers."""

from vinctor_service.audit import AuditWriter, InMemoryAuditWriter
from vinctor_service.authorize import authorize_action
from vinctor_service.auto_approval import (
    auto_approve_grant_request,
    create_auto_approval_rule,
    disable_auto_approval_rule,
    evaluate_auto_approval,
    list_auto_approval_rules,
)
from vinctor_service.auto_approval_http import handle_v1_auto_approval_rules_http
from vinctor_service.boundary_http import WorkspaceIdentity, handle_v1_boundaries_http
from vinctor_service.grant_http import handle_v1_grants_http
from vinctor_service.grant_request_http import handle_v1_grant_requests_http
from vinctor_service.grant_requests import (
    approve_grant_request,
    create_grant_request,
    list_grant_requests,
    lookup_grant_request,
    reject_grant_request,
)
from vinctor_service.grants import (
    AgentIssuableScopeBoundsRepository,
    InMemoryAgentIssuableScopeBoundsRepository,
    issue_grant,
    lookup_grant,
    revoke_grant,
    validate_issuable_scope_bounds,
)
from vinctor_service.in_memory import InMemoryV1Service
from vinctor_service.keys import (
    AGENT_KEY_PREFIX,
    WORKSPACE_KEY_PREFIX,
    CreatedLocalKey,
    LocalKeyRecord,
    SQLiteLocalKeyRepository,
    mask_key,
)
from vinctor_service.local_http import create_v1_http_handler, create_v1_http_server
from vinctor_service.models import (
    AuthorizationRequest,
    AuthorizationResponse,
    AutoApprovalEvaluationResult,
    AutoApprovalRule,
    GrantIssueRequest,
    GrantIssueResult,
    GrantRequest,
    GrantRequestCreateRequest,
    GrantRequestCreateResult,
    GrantRequestDecisionResult,
    V1EnforceRequest,
    V1EnforceResponse,
)
from vinctor_service.repositories import (
    AutoApprovalRuleRepository,
    GrantLifecycleRepository,
    GrantRepository,
    GrantRequestRepository,
    InMemoryAutoApprovalRuleRepository,
    InMemoryGrantRepository,
    InMemoryGrantRequestRepository,
)
from vinctor_service.sqlite import (
    SQLiteAgentIssuableScopeBoundsRepository,
    SQLiteAuditWriter,
    SQLiteAutoApprovalRuleRepository,
    SQLiteBoundaryRegistry,
    SQLiteGrantRepository,
    SQLiteGrantRequestRepository,
    SQLiteV1Service,
    init_sqlite_schema,
    insert_grant,
)
from vinctor_service.v1_enforce import enforce_v1_contract
from vinctor_service.v1_http import AgentIdentity, V1HttpResponse, handle_v1_enforce_http

__all__ = [
    "AgentIdentity",
    "AuthorizationRequest",
    "AuthorizationResponse",
    "AutoApprovalEvaluationResult",
    "AutoApprovalRule",
    "AutoApprovalRuleRepository",
    "AuditWriter",
    "AGENT_KEY_PREFIX",
    "CreatedLocalKey",
    "AgentIssuableScopeBoundsRepository",
    "GrantIssueRequest",
    "GrantIssueResult",
    "GrantLifecycleRepository",
    "GrantRequest",
    "GrantRequestCreateRequest",
    "GrantRequestCreateResult",
    "GrantRequestDecisionResult",
    "GrantRequestRepository",
    "GrantRepository",
    "InMemoryAgentIssuableScopeBoundsRepository",
    "InMemoryAutoApprovalRuleRepository",
    "InMemoryAuditWriter",
    "InMemoryGrantRepository",
    "InMemoryGrantRequestRepository",
    "InMemoryV1Service",
    "LocalKeyRecord",
    "SQLiteAgentIssuableScopeBoundsRepository",
    "SQLiteAuditWriter",
    "SQLiteAutoApprovalRuleRepository",
    "SQLiteBoundaryRegistry",
    "SQLiteGrantRepository",
    "SQLiteGrantRequestRepository",
    "SQLiteLocalKeyRepository",
    "SQLiteV1Service",
    "V1EnforceRequest",
    "V1EnforceResponse",
    "V1HttpResponse",
    "WORKSPACE_KEY_PREFIX",
    "WorkspaceIdentity",
    "approve_grant_request",
    "auto_approve_grant_request",
    "authorize_action",
    "create_auto_approval_rule",
    "create_grant_request",
    "create_v1_http_handler",
    "create_v1_http_server",
    "enforce_v1_contract",
    "evaluate_auto_approval",
    "handle_v1_boundaries_http",
    "handle_v1_auto_approval_rules_http",
    "handle_v1_enforce_http",
    "handle_v1_grant_requests_http",
    "handle_v1_grants_http",
    "init_sqlite_schema",
    "insert_grant",
    "issue_grant",
    "list_auto_approval_rules",
    "list_grant_requests",
    "lookup_grant_request",
    "lookup_grant",
    "mask_key",
    "reject_grant_request",
    "revoke_grant",
    "disable_auto_approval_rule",
    "validate_issuable_scope_bounds",
]
