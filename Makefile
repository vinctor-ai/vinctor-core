PYTHON ?= .venv/bin/python
VINCTOR ?= .venv/bin/vinctor

.PHONY: install-dev test lint demo demo-self-host demo-mock build check-public-snapshot

install-dev:
	$(PYTHON) -m pip install -e ".[dev]"

test:
	$(PYTHON) -m pytest -q

lint:
	$(VINCTOR) --help >/dev/null
	$(PYTHON) -m ruff check .

demo:
	$(VINCTOR) demo service

demo-self-host:
	$(PYTHON) demo/self_hostable_service_demo.py

demo-mock:
	$(PYTHON) demo/mock_vinctor_service_demo.py

build:
	$(PYTHON) -m build

# Release pre-flight: the public snapshot must be a verbatim copy of what we
# tag. Compares the snapshot against HEAD — the commit being tagged. Run after
# re-syncing the snapshot, before pushing the tag.
check-public-snapshot:
	tools/check-public-snapshot.sh
