# RatSweepr Free build tooling (bash-only).
# No compilation - RatSweepr Free is a single self-contained bash script.
# Public repo: https://github.com/alltrad3s/ratsweepr-free

VERSION ?= $(shell grep '^RS_VERSION=' ratsweepr.sh | cut -d'"' -f2)

.PHONY: test lint yara-sync safety sign-sigs version

## test: syntax check, yara sync check, and rule-compile check if yara-x is present
test: lint yara-sync
	@command -v yr >/dev/null 2>&1 && yr scan ratsweepr.yar /dev/null >/dev/null 2>&1 \
		&& echo "yara rules compile OK" \
		|| echo "yara engine not present - skipping rule-compile check"

## lint: bash syntax check
lint:
	bash -n ratsweepr.sh && echo "ratsweepr.sh: syntax OK"

## yara-sync: ratsweepr.yar must be identical to the write_bundled_yara() heredoc
yara-sync:
	@sed -n '/^    cat >> "$$1" << .RSYARA.$$/,/^RSYARA$$/p' ratsweepr.sh | sed '1d;$$d' \
		| diff - ratsweepr.yar >/dev/null && echo "ratsweepr.yar == bundled heredoc" \
		|| { echo "ratsweepr.yar and the bundled heredoc differ - resync and bump RS_VERSION"; exit 1; }

## safety: list every line that could write/move/delete, for human review
safety:
	@grep -nE 'quarantine|restore|clean|salts|baseline|mv |rm |UPDATE |DELETE |INSERT |ALTER ' ratsweepr.sh || true

## sign-sigs: sign the distributable pattern file (needs priv.pem, keep it OFF servers and out of git)
sign-sigs:
	openssl dgst -sha256 -sign priv.pem -out ratsweepr-sigs.conf.sig ratsweepr-sigs.conf
	@echo "signed ratsweepr-sigs.conf - commit both files"

## version: print the current version
version:
	@echo "$(VERSION)"
