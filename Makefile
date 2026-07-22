# Publishing fenceline to crates.io.
#
# Secret safety: CARGO_REGISTRY_TOKEN lives only in .env.publish (gitignored).
# It is sourced inside a recipe's own shell subprocess with `. ./.env.publish`
# and never assigned to a Make variable. A Make variable like
# `TOKEN := $(shell cat .env.publish)` would get expanded by Make itself —
# and printed — even under `make -n`, since that substitution happens at
# parse time before the shell ever runs. Keeping it shell-side means `make -n`
# and `make publish` (without CONFIRM=yes) never touch or print it.

.PHONY: help test dry-run publish check-env check-not-tracked check-clean

help:
	@echo "make test         - run the test suite"
	@echo "make dry-run      - cargo publish --dry-run"
	@echo "make publish CONFIRM=yes - test, dry-run, then publish for real"

check-env:
	@test -f .env.publish || { echo ".env.publish not found (needs CARGO_REGISTRY_TOKEN=...)"; exit 1; }

check-not-tracked:
	@if git ls-files --error-unmatch .env.publish >/dev/null 2>&1; then \
		echo "REFUSING: .env.publish is tracked by git — untrack it and rotate the token before publishing"; \
		exit 1; \
	fi

check-clean:
	@test -z "$$(git status --porcelain)" || { echo "Working tree not clean; commit or stash first"; exit 1; }

test:
	cargo test

dry-run: check-env check-not-tracked
	@set -a; . ./.env.publish; set +a; cargo publish --dry-run

publish: check-env check-not-tracked check-clean test
	@set -a; . ./.env.publish; set +a; cargo publish --dry-run
	@if [ "$(CONFIRM)" != "yes" ]; then \
		echo "Dry run above looked fine. Re-run as 'make publish CONFIRM=yes' to publish for real (this cannot be undone)."; \
		exit 1; \
	fi
	@set -a; . ./.env.publish; set +a; cargo publish
