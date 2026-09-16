SHELL := /bin/sh
.DEFAULT_GOAL := release-artifacts
# The Python entrypoint owns stage ordering, including under inherited MAKEFLAGS.
.NOTPARALLEL:

UV ?= uv
PYTHON ?= python3
RELEASE_ARGS ?=

.PHONY: release-artifacts sync completions dist helper helper-archive formula

release-artifacts:
	$(PYTHON) scripts/release_artifacts.py --uv "$(UV)" $(RELEASE_ARGS)

sync:
	$(UV) sync --locked --extra test --group dev

completions:
	$(UV) run --locked python scripts/generate_completions.py

dist:
	$(PYTHON) scripts/release_artifacts.py --uv "$(UV)" --python-only $(RELEASE_ARGS)

helper-archive: helper

helper:
	$(PYTHON) scripts/release_artifacts.py --uv "$(UV)" --helper-only $(RELEASE_ARGS)

formula:
	$(PYTHON) scripts/release_artifacts.py --formula-only $(RELEASE_ARGS)
