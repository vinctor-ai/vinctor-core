from idempotency_postgres_fixtures import outcome

from vinctor_service.idempotency_models import CacheableTerminalOutcome


class MutationProbe:
    def __init__(self) -> None:
        self.calls = 0

    def __call__(self) -> CacheableTerminalOutcome:
        self.calls += 1
        return outcome()
