SHELL := /bin/sh
.DEFAULT_GOAL := release-artifacts
# The Python entrypoint owns stage ordering, including under inherited MAKEFLAGS.
.NOTPARALLEL:

UV ?= uv
PYTHON ?= .venv/bin/python
RELEASE_ARGS ?=

.PHONY: release-artifacts release-preflight release-check candidate sync completions dist helper helper-archive formula

release-artifacts:
	$(PYTHON) scripts/release_artifacts.py --uv "$(UV)" $(RELEASE_ARGS)

release-preflight:
	$(PYTHON) scripts/release_artifacts.py --preflight $(RELEASE_ARGS)

release-check:
	$(PYTHON) scripts/release_artifacts.py --verify-release

candidate:
	$(PYTHON) scripts/release_artifacts.py --uv "$(UV)" --candidate $(RELEASE_ARGS)

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
