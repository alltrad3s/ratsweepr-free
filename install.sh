#!/usr/bin/env bash
# RatSweepr Free installer - downloads the read-only scanner into the current
# directory. No root, nothing to build. RatSweepr Free is a single bash script.
#
# Usage (from your WordPress root, where wp-config.php lives):
#   bash install.sh [TAG] [SHA256]
#   ./ratsweepr.sh scan
#
# TAG defaults to the current release tag. Pass the SHA256 from the release's
# SHA256SUMS file to verify the download (recommended).

set -euo pipefail

# GitHub release-asset base URL. Override with RS_REPO_URL to point at a
# fork or a different release host.
REPO_URL="${RS_REPO_URL:-https://github.com/alltrad3s/ratsweepr-free/releases/download}"
REF="${1:-v2.9.17-free}"               # tag (recommended) or commit
WANT_SHA="${2:-}"

case "$REPO_URL" in
    http*://*) ;;
    *) echo "FAIL: REPO_URL is not a URL. Set RS_REPO_URL or edit install.sh."; exit 1;;
esac
command -v curl >/dev/null 2>&1 || { echo "FAIL: curl required"; exit 1; }

RAW="$REPO_URL/$REF/ratsweepr.sh"
echo ".. downloading ratsweepr.sh ($REF)"
curl -fsSL -o ratsweepr.sh.tmp "$RAW"

# If no SHA was passed, try to fetch the release's own SHA256SUMS and look
# up the expected hash there, so verification happens by default.
if [ -z "$WANT_SHA" ]; then
    if sums="$(curl -fsSL "$REPO_URL/$REF/SHA256SUMS" 2>/dev/null)"; then
        WANT_SHA="$(printf '%s\n' "$sums" | awk '$2=="ratsweepr.sh"{print $1; exit}')"
    fi
fi

# sanity: make sure we got a shell script, not an error page
if ! head -1 ratsweepr.sh.tmp | grep -q '^#!/'; then
    rm -f ratsweepr.sh.tmp
    echo "FAIL: downloaded file is not a script (bad ref '$REF'?)"; exit 1
fi
if ! bash -n ratsweepr.sh.tmp 2>/dev/null; then
    rm -f ratsweepr.sh.tmp
    echo "FAIL: downloaded script failed syntax check - refusing to install"; exit 1
fi
if [ -n "$WANT_SHA" ]; then
    got="$(sha256sum ratsweepr.sh.tmp | awk '{print $1}')"
    if [ "$got" != "$WANT_SHA" ]; then
        rm -f ratsweepr.sh.tmp
        echo "FAIL: SHA256 mismatch (got $got) - refusing to install"; exit 1
    fi
    echo "OK  SHA256 verified"
else
    echo "NOTE: no SHA256 given - the download was not checksum-verified."
fi

mv ratsweepr.sh.tmp ratsweepr.sh
chmod +x ratsweepr.sh
ver="$(grep -m1 '^RS_VERSION=' ratsweepr.sh | cut -d'"' -f2)"
echo "OK  installed ./ratsweepr.sh (v${ver:-?}) - read-only scanner"
echo "    run:  ./ratsweepr.sh scan"
