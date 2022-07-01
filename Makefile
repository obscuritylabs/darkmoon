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


# ================================================
# Install
# ================================================

.PHONY: install
install: ##@install Install all dependencies for both projects and setup pre-commit.
	@cd darkmoon && \
		$(MAKE) install && \
		poetry run pre-commit install --install-hooks -t commit-msg  -t pre-commit
	@cd darkmoon-cli && $(MAKE) install-dev

.PHONY: install-dev
install-dev: ##@install Install only dev dependencies for both projects and setup pre-commit.
	@cd darkmoon && \
		$(MAKE) install-dev && \
		poetry run pre-commit install --install-hooks -t commit-msg  -t pre-commit
	@cd darkmoon-cli && $(MAKE) install-dev

# ================================================
# Pre-commit
# ================================================

.PHONY: pre-commit
pre-commit: ##@pre-commit Run pre-commit hooks on all files.
	@cd darkmoon && poetry run pre-commit run --all-files
	@cd darkmoon-cli && poetry run pre-commit run --all-files
