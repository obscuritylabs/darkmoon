# Copyright (C) 2022 Obscurity Labs LLC. <admin@obscuritylabs.com> - All Rights Reserved
# Unauthorized copying of this file, via any medium is strictly prohibited.
# All rights reserved. No warranty, explicit or implicit, provided.
# Proprietary and confidential.

# ================================================
# Main
# ================================================

# COLORS
GREEN  := $(shell tput -Txterm setaf 2)
WHITE  := $(shell tput -Txterm setaf 7)
YELLOW := $(shell tput -Txterm setaf 3)
RESET  := $(shell tput -Txterm sgr0)

HELP_FUN = \
    %help; \
    while(<>) { push @{$$help{$$2 // 'main'}}, [$$1, $$3] if /^([a-zA-Z\-]+)\s*:.*\#\#(?:@([a-zA-Z\-]+))?\s(.*)$$/ }; \
    print "usage: make [target]\n\n"; \
    for (sort keys %help) { \
    print "${WHITE}$$_:${RESET}\n"; \
    for (@{$$help{$$_}}) { \
    $$sep = " " x (32 - length $$_->[0]); \
    print "  ${YELLOW}$$_->[0]${RESET}$$sep${GREEN}$$_->[1]${RESET}\n"; \
    }; \
    print "\n"; }

.PHONY: help
help: ## Show all make targets.
	@perl -e '$(HELP_FUN)' $(MAKEFILE_LIST)

.PHONY: clean
clean: ## Clean all development artifacts.
	-find . -name "__pycache__" -type d -exec rm -rf {} \;
	rm -rf .coverage .pytest_cache/ .venv/ coverage* .mypy_cache/


# ================================================
# Install
# ================================================

.PHONY: install
install: ##@install Install all dependencies.
	@poetry install --no-interaction

.PHONY: install-dev
install-dev: ##@install Install only dev dependencies.
	@poetry install


# ================================================
# Check
# ================================================

.PHONY: check
check: | check-lint check-format check-types check-imports ##@check Run all checks.

.PHONY: check-lint
check-lint: ##@check Check code linting (pylint, flake8).
	@poetry run flake8

.PHONY: check-format
check-format: ##@check Check code formating (black).
	@poetry run black --check .
	@poetry run autoflake --check .

.PHONY: check-types
check-types: ##@check Check code typing (mypy).
	@poetry run mypy .

.PHONY: check-imports
check-imports: ##@check Check code imports (isort).
	@poetry run isort --check-only .


# ================================================
# Format
# ================================================

.PHONY: format
format: ##@format Run auto-formatters against your code.
	@poetry run black .
	@poetry run isort .
	@poetry run autoflake --in-place --recursive .


# ================================================
# Test
# ================================================

.PHONY: test
test: ##@test Run unit tests.
	@poetry run pytest -m unit --cov=darkmoon --cov-report=xml


# ================================================
# Run
# ================================================

.PHONY: run
run: ##@run Run uvicorn application.
	poetry run uvicorn darkmoon.app:app --reload --port 8000
