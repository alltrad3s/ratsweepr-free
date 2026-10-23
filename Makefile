# RatSweepr Free build tooling (bash-only).
# No compilation - RatSweepr Free is a single self-contained bash script.
# Public repo: https://github.com/alltrad3s/ratsweepr-free

VERSION ?= $(shell grep '^RS_VERSION=' ratsweepr.sh | cut -d'"' -f2)

.PHONY: test lint check-nofd yara-sync safety sign-sigs version

## test: syntax check, yara sync check, and rule-compile check if yara-x is present
test: lint check-nofd yara-sync
	@command -v yr >/dev/null 2>&1 && yr scan ratsweepr.yar /dev/null >/dev/null 2>&1 \
		&& echo "yara rules compile OK" \
		|| echo "yara engine not present - skipping rule-compile check"

## lint: bash syntax check
lint:
	bash -n ratsweepr.sh && echo "ratsweepr.sh: syntax OK"

## check-nofd: guard against regressing to process substitution. Bash's
##             <( ... ) is implemented via /dev/fd/NN, which does not exist
##             on CageFS-jailed cPanel accounts (common shared hosting) -
##             it fails silently there while the check it was feeding still
##             prints "[ OK ]" (RATSWEEPR-006). Every "<(" site in this repo
##             was replaced with a plain temp file under $RS_CACHE; this
##             keeps a new one from creeping back in. Checked code only -
##             strips from the first "#" on each line before matching, so
##             comments (including this script's own explanation of the
##             bug) never trip it.
check-nofd:
	@bad=0; \
	while IFS= read -r line; do \
		code="$${line%%#*}"; \
		case "$$code" in *'<('*) echo "check-nofd: process substitution: $$line" >&2; bad=1;; esac; \
		case "$$code" in *'/dev/fd'*|*'/dev/stdin'*|*'/dev/stdout'*) echo "check-nofd: /dev/fd or /dev/stdin/stdout reference: $$line" >&2; bad=1;; esac; \
	done < ratsweepr.sh; \
	if [ "$$bad" = "1" ]; then \
		echo "check-nofd: FAILED - process substitution or /dev/fd dependence found (breaks on CageFS-jailed hosts)" >&2; \
		exit 1; \
	fi; \
	echo "check-nofd: OK - no process substitution or /dev/fd dependence"

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
