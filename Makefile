.PHONY: test lint check

test:
	./tests/run.sh
	@command -v pwsh >/dev/null 2>&1 && pwsh -NoProfile -File tests/run.ps1 || echo "pwsh not installed, skipped PowerShell tests"

lint:
	shellcheck -x patchcheck.sh tests/run.sh

check: lint test
