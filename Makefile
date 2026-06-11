PYTHON ?= .venv/bin/python
VINCTOR ?= .venv/bin/vinctor

.PHONY: install-dev test lint demo demo-self-host demo-mock build

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
