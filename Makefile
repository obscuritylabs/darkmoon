# Copyright (C) 2023 Obscurity Labs LLC. <admin@obscuritylabs.com> - All Rights Reserved
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

.PHONY: docker-clean
docker-clean: ## clean all docker cache and containers
	@docker rm -f $(docker ps -a -q) && \
	docker volume rm $(docker volume ls -q) && \
	docker rmi -f $(docker images -aq)

# ================================================
# Install
# ================================================

.PHONY: install
install: ##@install Install all dependencies.
	@poetry install --no-interaction && \
	poetry run pre-commit install --install-hooks -t commit-msg  -t pre-commit

.PHONY: install-dev
install-dev: ##@install Install only dev dependencies.
	@poetry install


# ================================================
# Check
# ================================================

.PHONY: check
check: | check-lint check-format check-types ##@check Run all checks.

.PHONY: check-lint
check-lint: ##@check Check code linting (ruff).
	@poetry run ruff .

.PHONY: check-format
check-format: ##@check Check code formatting (black).
	@poetry run black --check .

.PHONY: check-types
check-types: ##@check Check code typing (mypy).
	@poetry run mypy .


# ================================================
# Format
# ================================================

.PHONY: format
format: ##@format Run auto-formatters against your code.
	@poetry run ruff .


# ================================================
# Pre-commit
# ================================================

.PHONY: pre-commit
pre-commit: ##@pre-commit Run pre-commit hooks on all files.
	@poetry run pre-commit run --all-files


# ================================================
# Test
# ================================================

.PHONY: test
test: ##@test Run all tests.
	@poetry run pytest


# ================================================
# Run
# ================================================

.PHONY: run
run: ##@run Run uvicorn application.
	poetry run uvicorn --factory darkmoon.app:get_app --reload --port 8000
