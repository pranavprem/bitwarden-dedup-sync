# bwsync — guided consolidation of Apple Passwords + Chrome into Bitwarden.
#
# Run these in order:
#
#   make setup    install prerequisites, create a work dir, walk the exports
#   make dedup    plan -> review -> dry run -> apply
#   make verify   re-export and confirm the vault is clean
#   make shred    securely destroy the plaintext exports
#
# The interactive logic lives in scripts/guided.sh: macOS ships GNU Make 3.81,
# which has no .ONESHELL, so each recipe line would otherwise be its own shell.

SHELL := /bin/bash
GUIDED := scripts/guided.sh

.PHONY: help setup dedup verify shred plan test install clean

help:
	@echo ""
	@echo "  bwsync — make Bitwarden your single source of truth"
	@echo ""
	@echo "  Run in order:"
	@echo "    make setup     Check prerequisites and walk you through each export"
	@echo "    make dedup     Plan, review conflicts, dry run, then apply"
	@echo "    make verify    Re-export your vault and confirm no duplicates remain"
	@echo "    make shred     Securely delete the plaintext export files"
	@echo ""
	@echo "  Also available:"
	@echo "    make plan      Re-run planning only, without the guided prompts"
	@echo "    make test      Run the test suite"
	@echo "    make install   Install the 'bwsync' command into your environment"
	@echo "    make clean     Remove build artefacts and caches (never your exports)"
	@echo ""
	@echo "  Nothing before 'make dedup' touches your vault, and 'make dedup'"
	@echo "  shows a full dry run and asks for confirmation before it does."
	@echo ""

setup:
	@bash $(GUIDED) setup

dedup:
	@bash $(GUIDED) dedup

verify:
	@bash $(GUIDED) verify

shred:
	@bash $(GUIDED) shred

# Escape hatch for re-planning with custom flags:
#   make plan ARGS="--vault ~/w/vault.json --chrome ~/w/chrome.csv --out ~/w/out"
plan:
	@python3 -m bwsync plan $(ARGS)

test:
	@python3 -m unittest discover -s tests -t .

install:
	@python3 -m pip install -e .

clean:
	@rm -rf build dist *.egg-info .pytest_cache
	@find . -name __pycache__ -type d -prune -exec rm -rf {} + 2>/dev/null || true
	@echo "Cleaned build artefacts. Your exports and work directory are untouched."
