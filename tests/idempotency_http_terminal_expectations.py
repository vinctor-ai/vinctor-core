from idempotency_http_terminal_boundary_rule import BOUNDARY_RULE_RESPONSES
from idempotency_http_terminal_grant_requests import GRANT_REQUEST_RESPONSES
from idempotency_http_terminal_grant_token import GRANT_TOKEN_RESPONSES
from idempotency_http_terminal_models import (
    ExpectedTerminalResponse,
    assert_expected_terminal_response,
)

EXPECTED_TERMINAL_RESPONSES = {
    **GRANT_TOKEN_RESPONSES,
    **BOUNDARY_RULE_RESPONSES,
    **GRANT_REQUEST_RESPONSES,
}

__all__ = (
    "EXPECTED_TERMINAL_RESPONSES",
    "ExpectedTerminalResponse",
    "assert_expected_terminal_response",
)
