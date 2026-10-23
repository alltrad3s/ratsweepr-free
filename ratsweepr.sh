#!/usr/bin/env bash
#
# ======================= RATSWEEPR FREE ===================================
#  RatSweepr Free - read-only WordPress malware scanner
#  For shared hosting (no root). This edition only REPORTS: it never changes,
#  moves, quarantines, restores or deletes files or database rows on the site.
#
#  Design principles:
#    * READ-ONLY     - scanning never deletes or modifies anything on the site.
#                      The only files written are the scan report (in the WP
#                      root, mode 600) and the signature cache (~/.ratsweepr).
#    * VERIFY        - integrity checks against wordpress.org checksum APIs
#                      are the primary detector; signatures are secondary.
#    * FREE FEEDS    - wordpress.org checksums API (free), rfxn/maldet MD5
#                      malware DB (free, updated ~daily), plus a local
#                      heuristic pattern file you can host & sign yourself.
#
#  Requirements (all standard on shared hosts, none need root):
#    bash 4+, coreutils (md5sum, sort, comm), grep, awk, sed, find,
#    curl or wget, and ideally: php-cli (JSON parsing, WP-CLI),
#    mysql client (DB scan), openssl (signature verification).
#
#  Usage:
#    ./ratsweepr.sh                  interactive menu
#    ./ratsweepr.sh scan             full read-only scan -> report
#    ./ratsweepr.sh scan --since 2026-07-01   also list DB content
#                                     modified since a date
#    ./ratsweepr.sh update-sigs      refresh rfxn hash DB + pattern file
#    ./ratsweepr.sh share-report     make a REDACTED copy of the latest
#                                     report to share for research (opt-in,
#                                     nothing is uploaded)
#    ./ratsweepr.sh help-report      what to do if the report looks empty
#                                     or you don't understand it
#
# ==============================================================================

set -u
umask 077

RS_VERSION="2.9.24-free"

# ------------------------------ configuration --------------------------------
# Everything lives under the invoking user's home; nothing touches system dirs.
RS_HOME="${RS_HOME:-$HOME/.ratsweepr}"
RS_SIG_DIR="$RS_HOME/signatures"
RS_BIN="$RS_HOME/bin"
RS_CACHE="$RS_HOME/cache"

# Free maldet/rfxn MD5 malware hash database (format md5:size:name).
# Updated by the maintainer roughly daily. See rfxn.com / linux-malware-detect.
RFXN_HDB_URL="${RS_RFXN_URL:-https://www.rfxn.com/downloads/rfxn.hdb}"

# Your own heuristic pattern file (host the sample ratsweepr-sigs.conf on e.g.
# a GitHub repo and point this at the raw URL). Leave empty to use only the
# local/bundled copy.
PATTERN_URL="${RS_PATTERN_URL:-}"
# Optional: URL of the openssl signature for the pattern file (PATTERN_URL.sig)
# and the local path to your public key. If the pubkey exists, downloaded
# pattern files MUST verify or they are rejected.
PATTERN_PUBKEY="$RS_HOME/ratsweepr-pub.pem"

# Optional Wordfence Intelligence API key (free, from your own account) for
# the live vulnerability-feed check:  export WORDFENCE_API_KEY=xxxx
# or add a "WORDFENCE_API_KEY=xxxx" line to $RS_HOME/config. Never required -
# the scan runs and the hand-picked VULNPLUGIN list + outdated-plugin check
# still work without one. Get a free key: https://www.wordfence.com/account/integrations
WORDFENCE_API_KEY="${WORDFENCE_API_KEY:-}"

# ------------------------------ tiny toolbox ---------------------------------
C_RED=$'\033[0;31m'; C_GRN=$'\033[0;32m'; C_YEL=$'\033[0;33m'
C_CYN=$'\033[0;36m'; C_OFF=$'\033[0m'
say()  { printf '%s\n' "$*"; }
ok()   { printf '%s[ OK ]%s %s\n'   "$C_GRN" "$C_OFF" "$*"; }
warn() { printf '%s[WARN]%s %s\n'   "$C_YEL" "$C_OFF" "$*"; }
bad()  { printf '%s[FIND]%s %s\n'   "$C_RED" "$C_OFF" "$*"; }
info() { printf '%s[ .. ]%s %s\n'   "$C_CYN" "$C_OFF" "$*"; }
notice() { printf '%s[NOTE ]%s %s\n' "$C_CYN" "$C_OFF" "$*"; }   # advisory text, never written to $REPORT
die()  { printf '%s[FAIL]%s %s\n'   "$C_RED" "$C_OFF" "$*" >&2; exit 1; }

# ------------------------------ temp files -----------------------------------
# Every mktemp in this script goes through rs_tmp(): one place that (a) always
# lands under $RS_CACHE - never /tmp, which is shared across accounts on some
# hosts - and (b) is cleaned up on exit/interrupt via the trap below, so a
# Ctrl+C mid-scan or mid-share-report never leaves a stray file behind (some
# of these briefly hold a DB password/salts in plaintext). Also replaces every
# `<( ... )` process substitution in this script - process substitution is
# implemented via /dev/fd/NN, which does not exist on CageFS-jailed cPanel
# accounts (common on shared hosting), silently failing every "<(cmd)" use
# while still printing "[ OK ]" for the check that depended on it. Plain files
# work identically everywhere: CageFS, other cPanel hosts, Ubuntu, macOS.
#
# Registration is a FILE (one path per line), not a shell array: every call
# site uses `var="$(rs_tmp name)"`, and command substitution always runs the
# function in a subshell - an array append inside rs_tmp would mutate only
# that subshell's copy and vanish the instant it exits, silently never
# registering anything. Appending to a file has a real, persistent effect
# regardless of which subshell does the writing.
RS_TMPREG="$RS_CACHE/.rs-tmpfiles-$$"
rs_tmp() { # rs_tmp NAME -> path to a new empty temp file under $RS_CACHE
    local name="$1" f
    f="$(mktemp "$RS_CACHE/${name}.XXXXXX" 2>/dev/null)" || f="$RS_CACHE/${name}.$$.$RANDOM"
    : > "$f" 2>/dev/null
    printf '%s\n' "$f" >> "$RS_TMPREG" 2>/dev/null
    printf '%s\n' "$f"
}
rs_cleanup() {
    [ -f "$RS_TMPREG" ] || return 0
    local f
    while IFS= read -r f; do
        [ -n "$f" ] && rm -f "$f" 2>/dev/null
    done < "$RS_TMPREG"
    rm -f "$RS_TMPREG"
}
# A trap registered on INT/TERM/HUP runs the handler and then RESUMES the
# script where it left off - it does not stop execution on its own. Only the
# EXIT trap needs just rs_cleanup; INT/TERM/HUP must explicitly exit so
# Ctrl+C (or a host-imposed timeout sending SIGTERM) actually stops the scan
# instead of cleaning up mid-file and continuing. exit always re-triggers the
# EXIT trap, so cleanup still happens exactly once either way.
trap 'rs_cleanup' EXIT
trap 'exit 130' INT TERM HUP

# report(): append a finding line to the machine-readable report.
# Format:  SEVERITY <TAB> CATEGORY <TAB> PATH-OR-ITEM <TAB> DETAIL
report() { printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" >> "$REPORT"; }

# check_incomplete NAME REASON -> a required check's input was missing, empty,
# or its producer command failed. Warns, records a MED check-incomplete
# finding (counted by run_scan's summary into "scan INCOMPLETE"), and returns
# - the caller must NOT print its own "... done."/ok() after this, and any
# file this check would have populated (e.g. $VERIFIED) is left exactly as
# it was, so downstream scanners correctly treat its files as unverified
# rather than silently reading a failed check as "nothing to report."
check_incomplete() {
    warn "$1: $2 - treating as UNVERIFIED, not clean"
    report "MED" "check-incomplete" "$1" "$2"
}

# rs_timed FUNCNAME -> runs it; under RS_DEBUG=1 also prints elapsed seconds,
# so a future "the scan looks stuck" report can say which scanner it's in
# instead of guessing (this is exactly what would have pinpointed the
# CageFS VERIFIED-empty slowdown immediately instead of reading as a hang).
rs_timed() {
    if [ "${RS_DEBUG:-0}" = "1" ]; then
        local name="$1" start end
        start="$(date +%s)"
        "$@"
        end="$(date +%s)"
        info "[debug] $name took $((end-start))s"
    else
        "$@"
    fi
}

fetch() { # fetch URL OUTFILE  (curl or wget, whichever exists)
    local url="$1" out="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fsL --connect-timeout 15 -o "$out" "$url"
    elif command -v wget >/dev/null 2>&1; then
        wget -q -T 15 -O "$out" "$url"
    else
        return 1
    fi
}

have() { command -v "$1" >/dev/null 2>&1; }

php_json() { # php_json 'php-expression-using-$d' < file.json
    # Parses JSON on stdin into $d and runs the given expression. Requires php.
    php -r '$d=json_decode(stream_get_contents(STDIN),true); if(!is_array($d)){exit(2);} '"$1"
}

# ------------------------------ preflight ------------------------------------
preflight() {
    mkdir -p "$RS_HOME" "$RS_SIG_DIR" "$RS_BIN" "$RS_CACHE"

    for t in grep awk find sort comm md5sum sha256sum; do
        have "$t" || die "'$t' is required but not available."
    done
    have curl || have wget || die "Need 'curl' or 'wget'."

    HAVE_PHP=0;     have php     && HAVE_PHP=1
    HAVE_MYSQL=0;   have mysql   && HAVE_MYSQL=1
    HAVE_OPENSSL=0; have openssl && HAVE_OPENSSL=1

    JSON_PARSER=""
    if have jq; then JSON_PARSER="jq"
    elif [ "$HAVE_PHP" = "1" ]; then JSON_PARSER="php"
    fi

    # Refuse to run as root: on shared hosting you never should be, and a bug
    # as root is catastrophic. (Override only if you truly know why.)
    if [ "$(id -u)" = "0" ] && [ "${RS_ALLOW_ROOT:-0}" != "1" ]; then
        die "Refusing to run as root. Run as the site user (RS_ALLOW_ROOT=1 to override)."
    fi

    # Must be executed from a WordPress root.
    WPROOT="$(pwd)"
    [ -f "$WPROOT/wp-config.php" ] || die "No wp-config.php here. cd into the WordPress root first."
    [ -f "$WPROOT/wp-includes/version.php" ] || die "wp-includes/version.php missing. Not a WordPress root?"

    WPVER="$(grep -E "\\\$wp_version\s*=" "$WPROOT/wp-includes/version.php" \
             | grep -Eo "([0-9]+\.)+[0-9]+" | head -1)"
    [ -n "$WPVER" ] || die "Could not determine the WordPress version."

    # Locate WP-CLI (optional but recommended). We never auto-install silently.
    WPCLI=""
    if have wp; then WPCLI="wp"
    elif [ -f "$RS_BIN/wp-cli.phar" ] && [ "$HAVE_PHP" = "1" ]; then
        WPCLI="php $RS_BIN/wp-cli.phar"
    fi

    RUNSTAMP="$(date +%Y-%m-%d_%H%M%S)"
    EXPLOIT_WINDOW_START=""
    EXPLOIT_LABEL=""
    MANIFEST_OK=0
    DBPREFIX=""
    REPORT="$WPROOT/ratsweepr-$RUNSTAMP.report"
}

banner() {
    say ""
    say "  RatSweepr Free - read-only WordPress malware scanner   v$RS_VERSION"
    say "  Site: $WPROOT"
    say "  WordPress: $WPVER    WP-CLI: ${WPCLI:-not found}    php: $HAVE_PHP  mysql: $HAVE_MYSQL"
    say ""
}

# ========================== SIGNATURE MANAGEMENT ==============================
# Two feeds, both free:
#   1. rfxn.hdb        - MD5 hash DB from Linux Malware Detect (~10k sigs)
#   2. patterns.conf   - heuristic grep patterns + piracy domains + bad
#                        wp_options keys. Bundled defaults below; you can host
#                        an updated copy (PATTERN_URL) and sign it with openssl.

write_default_patterns() {
    # Bundled fallback so the scanner works offline out of the box.
    printf '# RatSweepr bundled patterns [bundled-version: %s]\n' "$RS_VERSION" \
        > "$RS_SIG_DIR/patterns.conf"
    cat >> "$RS_SIG_DIR/patterns.conf" << 'EOSIG'
# RatSweepr heuristic signature file
# Lines:  TYPE|NAME|VALUE          (TYPE: GREP, FNAME, DOMAIN, OPTION)
# GREP   = POSIX-extended regex applied to php/ico/suspected files (review!)
# FNAME  = suspicious file name glob for `find -name`
# DOMAIN = nulled/piracy or malware distribution domain to grep for
# OPTION = wp_options keys left behind by nulled plugins
# VULNPLUGIN = hand-picked outdated-plugin-with-a-CVE entries; see the
#              README's "Vulnerable plugin versions" section for the full
#              field format and what each column means
#
# --- generic webshell / injection constructs (high signal, still REVIEW) ---
GREP|eval_base64|eval[[:space:]]*\(([[:space:]]*@)?[[:space:]]*base64_decode
GREP|eval_gzinflate|eval[[:space:]]*\(([[:space:]]*@)?[[:space:]]*gz(inflate|uncompress)
GREP|eval_request|\b(eval|assert)[[:space:]]*\([[:space:]]*(stripslashes[[:space:]]*\()?[[:space:]]*\$_(POST|GET|REQUEST|COOKIE)
GREP|preg_replace_e_modifier|preg_replace[[:space:]]*\([[:space:]]*['\"][^'\"]*/[a-zA-Z]*e[a-zA-Z]*['\"]
GREP|create_function_request|create_function[[:space:]]*\([^)]*\$_(POST|GET|REQUEST)
GREP|str_rot13_base64|str_rot13[[:space:]]*\([[:space:]]*base64_decode
GREP|globals_hex_obfuscation|\$\{["']\\x47L?\\x4[fF]
GREP|filesman_shell|FilesMan|Files[[:space:]]*Man
GREP|wso_shell|wso_version|WSOsetcookie
GREP|b374k_marker|b374k
GREP|c99_marker|c99sh_|c99shell
GREP|leaf_mailer|leafmailer|Leaf[[:space:]]PHP[[:space:]]Mailer
GREP|move_uploaded_generic|copy[[:space:]]*\([[:space:]]*\$_FILES\[[^]]+\]\[.tmp_name.\]
GREP|gif_header_in_php_file|^GIF89a
#
# --- nulled-plugin behaviors (CaptainCore drift findings) ---
GREP|pre_http_request_hook|add_filter[[:space:]]*\([[:space:]]*['\"]pre_http_request
GREP|update_hook_priority_abuse|add_filter[[:space:]]*\([^,]*update_plugins[^,]*,[^,]*,[[:space:]]*9{6,}
GREP|sslverify_disabled|['\"]sslverify['\"][[:space:]]*=>[[:space:]]*false
#
#
#
# --- self-concealment & fake-plugin behaviors (GREPHIGH = HIGH severity) ---
# No legitimate plugin hides itself from the plugin list or hides admin users.
GREPHIGH|hides_self_unset_php|unset[[:space:]]*\([[:space:]]*\$[a-zA-Z_]+\[['"][^]]*/[^]]*\.php['"]
GREPHIGH|hides_admin_users_prequery|add_(action|filter)[[:space:]]*\([[:space:]]*['"]pre_user_query['"]
GREPHIGH|hides_admin_users_views|add_filter[[:space:]]*\([[:space:]]*['"]views_users['"]
GREPHIGH|variable_function_eval|\$[a-zA-Z_][a-zA-Z0-9_]*[[:space:]]*\([[:space:]]*gzinflate[[:space:]]*\([[:space:]]*base64_decode
#
# --- suspicious file names ---
FNAME|hidden_ico|.*.ico
FNAME|suspected_ext|*.suspected
FNAME|input_dropper|_input_*
FNAME|vuln_probe|vuln.php
#
# --- piracy / nulled distribution domains (extend as you find more) ---
DOMAIN|gpltimes|gpltimes.com
DOMAIN|gplvault|gplvault.com
DOMAIN|festinger|festingervault.com
DOMAIN|worldpressit|worldpressit.com
DOMAIN|gpldl|gpldl.com
DOMAIN|srmehranclub|srmehranclub.com
DOMAIN|weadown|weadown.com
DOMAIN|babiato|babiato.co
#
# --- wp_options residue from nulled plugins ---
OPTION|gplstatus
OPTION|gpltokenid
OPTION|rg_gforms_key
OPTION|fusion_registration_data
OPTION|monsterinsights_license
#
# --- known-vulnerable WordPress core versions (CORE_VULN|label|min|max|fixed|note) ---
# max is INCLUSIVE. Version compare is dotted-numeric. Update via signed feed.
CORE_VULN|wp2shell (CVE-2026-63030+60137, unauth RCE)|6.9.0|6.9.4|6.9.5|REST API batch-route RCE chain; block /wp-json/batch/v1 if you cannot upgrade|2026-07-17
CORE_VULN|wp2shell (CVE-2026-63030+60137, unauth RCE)|7.0.0|7.0.1|7.0.2|REST API batch-route RCE chain; block /wp-json/batch/v1 if you cannot upgrade|2026-07-17
CORE_VULN|CVE-2026-60137 (SQLi, author__not_in)|6.8.0|6.8.5|6.8.6|WP_Query SQL injection; upgrade to 6.8.6+|2026-07-17
CORE_VULN|CVE-2026-87902 (unauth path-traversal LFI->RCE, CVSS 9.2)|4.7.0|7.1.1|7.1.2|get_page_template() includes attacker-chosen local .php via the pagename query var (RCE via PEAR pearcmd.php when register_argc_argv is on - default in official PHP Docker images and pre-8.5 cPanel). Upgrade to 7.1.2. If you cannot upgrade, block requests with double-encoded traversal (%252e%252e) in the pagename parameter at the WAF|2026-09-22
#
# --- external-request allowlist (ALLOWHOST|host) ---
# Hosts here are treated as unremarkable destinations (suffix match, so
# "elementor.com" also covers "my.elementor.com"). Add vendors you trust after
# confirming them, to keep the external-request report focused on unknowns.
ALLOWHOST|elementor.com
ALLOWHOST|automattic.com
ALLOWHOST|akismet.com
ALLOWHOST|wordfence.com
ALLOWHOST|woocommerce.com
ALLOWHOST|kinsta.com
ALLOWHOST|kinsta.cloud
#
# --- trusted vendor paths (ALLOWPATH|prefix|reinstall-url-or-dash) ---
ALLOWPATH|wp-content/mu-plugins/kinsta-mu-plugins|https://kinsta.com/kinsta-tools/kinsta-mu-plugins.zip
#
# --- known-vulnerable plugin versions (hand-picked from public advisories,
#     NOT a full vulnerability database - see README) ---
# VULNPLUGIN|slug|fixed_version|CVE|exploited(yes/no)|source_url[|EXTRA...]
VULNPLUGIN|ninja-forms|3.15.4|CVE-2026-94504|yes|https://patchstack.com/articles/four-ways-back-in-the-wordpress-xss-campaign-that-hides-its-own-admin-account/
VULNPLUGIN|woo-product-bundle|8.6.7|CVE-2026-93836|yes|https://patchstack.com/articles/four-ways-back-in-the-wordpress-xss-campaign-that-hides-its-own-admin-account/
VULNPLUGIN|bricksforge|3.1.8.10|CVE-2026-85097|yes|https://patchstack.com/articles/critical-unauthenticated-arbitrary-file-upload-vulnerability-exploited-in-bricksforge-plugin/|EXACT=4.0.0:unusual version jump not covered by the advisory - verify with the vendor that this build is genuinely past the fix
VULNPLUGIN|elementor-pro|4.2.2|CVE-2026-32475|yes|https://thehackernews.com/2026/09/over-440000-exploit-attempts-target.html
VULNPLUGIN|super-forms|6.3.314|CVE-2026-14894|yes|https://thehackernews.com/2026/09/over-440000-exploit-attempts-target.html
VULNPLUGIN|updraftplus|1.26.5|CVE-2026-10795|yes|https://patchstack.com/articles/updraftcentral-key-compromise-wordpress-backdoors/|ALTFIXED=2.26.5
VULNPLUGIN|rank-math-pro|3.0.124|CVE-2026-111862|yes|https://rankmath.com/kb/pro-3-0-123-security-incident/|EXACT=3.0.123:Rank Math SEO PRO 3.0.123: some packages of this version were compromised (supply chain). Version alone doesn't prove infection; check the findings below and Rank Math's guide. Delete the rank-math-pro folder (deactivating isn't enough) and install 3.0.124.
EOSIG
    ok "Wrote bundled heuristic patterns -> $RS_SIG_DIR/patterns.conf"
}

update_signatures() {
    info "Updating rfxn/maldet MD5 hash database..."
    local tmp="$RS_CACHE/rfxn.hdb.$$"
    if fetch "$RFXN_HDB_URL" "$tmp" && [ -s "$tmp" ] \
       && head -1 "$tmp" | grep -Eq '^[0-9a-f]{32}:'; then
        mv "$tmp" "$RS_SIG_DIR/rfxn.hdb"
        ok "rfxn.hdb updated: $(wc -l < "$RS_SIG_DIR/rfxn.hdb") MD5 signatures."
    else
        rm -f "$tmp"
        warn "Could not fetch/validate rfxn.hdb (offline or URL changed). Keeping existing copy."
    fi

    if [ -n "$PATTERN_URL" ]; then
        info "Updating heuristic pattern file from $PATTERN_URL ..."
        local ptmp="$RS_CACHE/patterns.conf.$$"
        if fetch "$PATTERN_URL" "$ptmp" && [ -s "$ptmp" ]; then
            if [ -f "$PATTERN_PUBKEY" ]; then
                if [ "$HAVE_OPENSSL" != "1" ]; then
                    warn "openssl missing; cannot verify signed patterns. Rejecting download."
                    rm -f "$ptmp"; return
                fi
                local stmp="$RS_CACHE/patterns.sig.$$"
                if fetch "${PATTERN_URL}.sig" "$stmp" \
                   && openssl dgst -sha256 -verify "$PATTERN_PUBKEY" \
                        -signature "$stmp" "$ptmp" >/dev/null 2>&1; then
                    mv "$ptmp" "$RS_SIG_DIR/patterns.conf"
                    ok "Pattern file updated (openssl signature VERIFIED)."
                else
                    warn "Pattern file signature FAILED verification. Rejected."
                    rm -f "$ptmp"
                fi
                rm -f "$stmp"
            else
                warn "No public key at $PATTERN_PUBKEY - installing UNVERIFIED pattern file."
                warn "Strongly consider signing (see README)."
                mv "$ptmp" "$RS_SIG_DIR/patterns.conf"
            fi
        else
            rm -f "$ptmp"; warn "Could not fetch pattern file."
        fi
    fi
    [ -f "$RS_SIG_DIR/patterns.conf" ] || write_default_patterns
}

load_signatures() {
    # Refresh bundled patterns if missing or stamped with an older version, so
    # `curl | bash` picks up new signatures on every script update. A signed
    # remote pattern file (PATTERN_URL) is never clobbered.
    local bundled_ver=""
    [ -f "$RS_SIG_DIR/patterns.conf" ] && \
        bundled_ver="$(sed -n 's/.*\[bundled-version: \([^]]*\)\].*/\1/p' "$RS_SIG_DIR/patterns.conf" | head -1)"
    if [ ! -s "$RS_SIG_DIR/patterns.conf" ] || \
       { [ -z "${PATTERN_URL:-}" ] && [ "$bundled_ver" != "$RS_VERSION" ]; }; then
        write_default_patterns
    fi
    PATTERNS_FILE="$RS_SIG_DIR/patterns.conf"
    HDB_FILE="$RS_SIG_DIR/rfxn.hdb"
}

# =============================== SCANNERS =====================================
# Every scanner is strictly read-only: findings go to $REPORT, nothing else.

# List of PHP-ish files once, reused by several scanners. Skips wp-content/cache.
# NUL-safe.
build_php_filelist() {
    PHPLIST="$RS_CACHE/philist.$$"
    find "$WPROOT" \( -path "$WPROOT/wp-content/cache" -prune \) -o \
         -type f \( -name '*.php' -o -name '*.php[0-9]' -o -name '*.phtml' \
                    -o -name '*.suspected' -o -name '.*.ico' \) -print0 \
         > "$PHPLIST" 2>/dev/null
}

# ver_le A B  -> returns 0 (true) if dotted-numeric A <= B
ver_le() {
    [ "$1" = "$2" ] && return 0
    local lo
    lo="$(printf '%s\n%s\n' "$1" "$2" | sort -t. -k1,1n -k2,2n -k3,3n -k4,4n | head -1)"
    [ "$lo" = "$1" ]
}

scan_core_vulns() {
    info "Checking WordPress $WPVER against known core vulnerabilities..."
    local label lo hi fixed note disclosed hit=0
    while IFS='|' read -r type label lo hi fixed note disclosed; do
        [ "$type" = "CORE_VULN" ] || continue
        if ver_le "$lo" "$WPVER" && ver_le "$WPVER" "$hi"; then
            hit=1
            # Record the earliest disclosure date among matched CVEs so the
            # compromise-indicator scan knows to run and from when.
            if [ -n "$disclosed" ]; then
                if [ -z "$EXPLOIT_WINDOW_START" ] || [[ "$disclosed" < "$EXPLOIT_WINDOW_START" ]]; then
                    EXPLOIT_WINDOW_START="$disclosed"
                fi
                EXPLOIT_LABEL="$label"
            fi
            report "HIGH" "core-vulnerable" "WordPress $WPVER" \
                "$label — fixed in $fixed. $note"
            warn "VULNERABLE CORE: $label"
            warn "  Your version : $WPVER"
            warn "  Fixed in     : $fixed"
            warn "  ACTION: upgrade now ->  wp core update"
            case "$label" in
              *batch-route*|*wp2shell*|*63030*)
                warn "  If you cannot upgrade immediately, block the batch endpoint at the"
                warn "  server/WAF layer. BOTH forms must be blocked (permalink AND query):"
                warn "    Apache (.htaccess, before WP rules):"
                warn "      RewriteEngine On"
                warn "      RewriteRule ^wp-json/batch/v1 - [F,L]"
                warn "      RewriteCond %{QUERY_STRING} (^|&)rest_route=/?batch/v1 [NC]"
                warn "      RewriteRule .* - [F,L]"
                warn "    Nginx (server block):"
                warn "      location ~* ^/wp-json/batch/v1 { return 403; }"
                warn "      if (\$args ~* \"(^|&)rest_route=/?batch/v1\") { return 403; }"
                warn "  NOTE: this is a stopgap; some plugins use the batch API. Upgrading is the real fix.";;
            esac
        fi
    done < "$PATTERNS_FILE"
    if [ "$hit" = "0" ]; then
        ok "No known core vulnerabilities for $WPVER (core is patched)."
        info "Running post-exploitation trace sweep anyway (a patched site can still carry prior-breach traces)..."
    fi
}

# scan_core_orphans: defense-in-depth. Flags PHP files in wp-admin/wp-includes and
# the webroot top level that are NOT part of a stock WordPress install, using a
# built-in name allowlist. Runs even when the checksum manifest is unavailable
# (new version, API blocked) - the case where scan_core_checksums bails early and
# unknown-file detection would otherwise be lost. This is how a renamed file manager
# like wp-admin/user-lust.php gets caught even with no manifest.
scan_core_orphans() {
    # Only a FALLBACK: when the checksum manifest was available, core-unknown-file
    # already found dropped files precisely. Running here too would flag hundreds of
    # legit core files (our name-allowlist can never be complete). So skip if manifest ran.
    [ "${MANIFEST_OK:-0}" = "1" ] && return
    [ -d "$WPROOT/wp-admin" ] || return
    # Known stock top-level PHP (webroot). Anything else *.php at root is suspect.
    local root_ok="|index.php|wp-activate.php|wp-blog-header.php|wp-comments-post.php|wp-config.php|wp-config-sample.php|wp-cron.php|wp-links-opml.php|wp-load.php|wp-login.php|wp-mail.php|wp-settings.php|wp-signup.php|wp-trackback.php|xmlrpc.php|"
    local f rel base
    local root_list; root_list="$(rs_tmp core-orphan-root)"
    if ! find "$WPROOT" -maxdepth 1 -type f -name '*.php' -print0 > "$root_list" 2>/dev/null; then
        check_incomplete "core-orphans" "find failed listing webroot top-level PHP"
    fi
    # webroot top-level php
    while IFS= read -r -d '' f; do
        base="$(basename "$f")"
        case "$root_ok" in *"|$base|"*) : ;; *)
            rel="${f#"$WPROOT"/}"
            grep -Fq $'\tcore-unknown-file\t'"$rel"$'\t' "$REPORT" 2>/dev/null && continue
            grep -Fq $'\t'"$rel"$'\t' "$REPORT" 2>/dev/null && continue
            report "HIGH" "core-orphan-file" "$rel" "unexpected PHP at WordPress root (not a stock core file) - verify manually (cleanup: RatSweepr Cleanup Kit / Done-For-You at ratsweepr.com)"
        ;; esac
    done < "$root_list"
    # wp-admin / wp-includes: only flag files whose NAME looks out-of-place for core
    # (core uses wp-*/class-*/ms-* plus a known set of bare names). To avoid noise we
    # exempt the common bare core filenames and only surface genuinely odd names.
    local core_bare="|version.php|functions.php|general-template.php|link-template.php|option.php|options.php|plugin.php|theme.php|user.php|post.php|comment.php|category.php|feed.php|cron.php|load.php|media.php|meta.php|nav-menu.php|pluggable.php|rewrite.php|shortcodes.php|taxonomy.php|template.php|update.php|widgets.php|index.php|admin.php|menu.php|about.php|nav-menus.php|upgrade.php|install.php|"
    local core_list; core_list="$(rs_tmp core-orphan-coredirs)"
    if ! find "$WPROOT/wp-admin" "$WPROOT/wp-includes" -maxdepth 1 -type f -name '*.php' -print0 > "$core_list" 2>/dev/null; then
        check_incomplete "core-orphans" "find failed listing wp-admin/wp-includes top-level PHP"
    fi
    while IFS= read -r -d '' f; do
        base="$(basename "$f")"
        case "$base" in
            wp-*|class-*|ms-*) continue;;
        esac
        case "$core_bare" in *"|$base|"*) continue;; esac
        rel="${f#"$WPROOT"/}"
        grep -Fq $'\tcore-unknown-file\t'"$rel"$'\t' "$REPORT" 2>/dev/null && continue
        grep -Fq $'\t'"$rel"$'\t' "$REPORT" 2>/dev/null && continue
        report "MED" "core-orphan-file" "$rel" "unusually-named PHP in a core directory - review (core files are wp-*/class-*/ms-*)"
    done < "$core_list"
}

scan_core_checksums() {
    info "Verifying WordPress $WPVER core files against api.wordpress.org checksums..."
    if [ "$HAVE_PHP" != "1" ]; then
        warn "php-cli not found: skipping core checksum verification."
        report "WARN" "core" "-" "php missing, core checksums skipped"
        return
    fi
    local js="$RS_CACHE/core-$WPVER.json"
    if [ ! -s "$js" ]; then
        fetch "https://api.wordpress.org/core/checksums/1.0/?version=$WPVER&locale=en_US" "$js" \
            || { check_incomplete "core-checksums" "could not download the checksum API response for $WPVER"; return; }
    fi
    [ -s "$js" ] || { check_incomplete "core-checksums" "checksum API response for $WPVER is missing or empty"; return; }
    local manifest="$RS_CACHE/core-$WPVER.md5"
    php_json 'foreach($d["checksums"] as $f=>$m) echo $m."  ".$f."\n";' \
        < "$js" > "$manifest" 2>/dev/null
    if [ ! -s "$manifest" ]; then
        check_incomplete "core-checksums" "checksum API returned no usable data for $WPVER"
        return
    fi

    local fails=0 faillist="$RS_CACHE/core-fails.$$" bundled_missing="$RS_CACHE/core-bundled-missing.$$"
    : > "$faillist"; : > "$bundled_missing"
    # md5sum -c reports FAILED / missing files; --quiet hides the OKs. Its own
    # exit status isn't checked - nonzero just means "something differed",
    # which is the normal case on an infected or lightly-customized site.
    local md5out; md5out="$(rs_tmp core-md5out)"
    ( cd "$WPROOT" && md5sum -c --quiet "$manifest" 2>/dev/null ) > "$md5out"
    while IFS= read -r line; do
        local f="${line%%:*}"
        printf '%s\n' "$f" >> "$faillist"
        case "$line" in
            *": FAILED open or read")
                case "$f" in
                    wp-config-sample.php) report "INFO" "core-sample-missing" "$f" \
                        "wp-config-sample.php absent - commonly removed as hardening, not an infection sign";;
                    # Collapsed below into one INFO line per component (theme/plugin
                    # dir) instead of one per missing file - a theme with its whole
                    # unused language/template tree absent would otherwise flood
                    # the report with dozens of near-identical lines.
                    wp-content/*) printf '%s\n' "$f" >> "$bundled_missing";;
                    *) report "HIGH" "core-missing" "$f" "core file missing or unreadable";;
                esac;;
            *": FAILED"*)
                report "HIGH" "core-modified" "$f" "does not match official $WPVER checksum";;
        esac
        fails=$((fails+1))
    done < "$md5out"
    if [ -s "$bundled_missing" ]; then
        local bmcomp; bmcomp="$(rs_tmp core-bmcomp)"
        awk -F'/' '{
            if (NF>=3 && ($2=="themes" || $2=="plugins" || $2=="mu-plugins")) comp=$2"/"$3
            else comp=$2
            cnt[comp]++
        } END { for (c in cnt) printf "%s\t%d\n", c, cnt[c] }' "$bundled_missing" | sort > "$bmcomp"
        while IFS=$'\t' read -r comp bcnt; do
            report "INFO" "core-bundled-missing" "wp-content/$comp" "$bcnt bundled file(s) absent (often intentional)"
        done < "$bmcomp"
    fi
    rm -f "$bundled_missing"

    # Every manifest file that did NOT fail is integrity-verified: heuristics
    # must never flag a file that is byte-identical to the official release.
    # comm needs real files (not <(...)/dev-fd process substitution, which
    # doesn't exist on CageFS-jailed cPanel accounts and fails silently,
    # leaving $VERIFIED empty while this still looked like it worked).
    local manifest_sorted; manifest_sorted="$(rs_tmp core-manifest-sorted)"
    local faillist_sorted; faillist_sorted="$(rs_tmp core-faillist-sorted)"
    local verified_add; verified_add="$(rs_tmp core-verified-add)"
    awk '{print $2}' "$manifest" | sort > "$manifest_sorted"
    sort -u "$faillist" > "$faillist_sorted"
    if ! comm -23 "$manifest_sorted" "$faillist_sorted" > "$verified_add" 2>/dev/null; then
        check_incomplete "core-checksums" "comm failed computing the verified-file list - core files are UNVERIFIED this run"
        return
    fi
    cat "$verified_add" >> "$VERIFIED"

    # Files present on disk in core dirs but NOT in the manifest = dropped files.
    local expected="$RS_CACHE/core-expected.$$" actual="$RS_CACHE/core-actual.$$"
    awk '{print $2}' "$manifest" | grep -Ev '^wp-content/' | sort > "$expected"
    ( cd "$WPROOT" && find wp-admin wp-includes -type f 2>/dev/null ; \
      find . -maxdepth 1 -type f -name '*.php' ! -name 'wp-config.php' \
           -printf '%P\n' 2>/dev/null || \
      find . -maxdepth 1 -type f -name '*.php' ! -name 'wp-config.php' \
           | sed 's|^\./||' ) | sort -u > "$actual"
    if [ ! -s "$expected" ] || [ ! -s "$actual" ]; then
        check_incomplete "core-checksums" "expected/actual core file list came back empty - unknown-file detection skipped this run"
        rm -f "$expected" "$actual"
        return
    fi
    local extra_list; extra_list="$(rs_tmp core-extra-list)"
    if ! comm -13 "$expected" "$actual" > "$extra_list" 2>/dev/null; then
        check_incomplete "core-checksums" "comm failed diffing expected vs. actual core files - unknown-file detection skipped this run"
        rm -f "$expected" "$actual"
        return
    fi
    while IFS= read -r extra; do
        case "$extra" in
            *.php|*.php[0-9]|*.phtml|*.phar)
                report "HIGH" "core-unknown-file" "$extra" "unexpected executable PHP in core area, not in official $WPVER manifest";;
            */.htaccess|.htaccess)
                # An unexpected .htaccess in a core dir warrants inspection. Two malware
                # tells make it HIGH: (a) the 'suspected' extension token (blocks access
                # to host-quarantined .suspected files), and (b) a Deny-all + Allow-specific
                # -.php carve-out (locks everyone out EXCEPT the attacker's own shells).
                # Otherwise it's active config worth a MED review; plain/empty is silent.
                local hcontent; hcontent="$(cat "$WPROOT/$extra" 2>/dev/null)"
                if printf '%s' "$hcontent" | grep -qiE '\|suspected\)' \
                   || { printf '%s' "$hcontent" | grep -qi 'Deny from all' \
                        && printf '%s' "$hcontent" | grep -qiE 'Allow from all' \
                        && printf '%s' "$hcontent" | grep -qiE 'FilesMatch.*\.php'; }; then
                    report "HIGH" "malicious-htaccess" "$extra" "access-control malware: .htaccess locking out cleanup while whitelisting attacker shells (deny-all + allow-specific-php / 'suspected' token)"
                elif printf '%s' "$hcontent" | grep -qiE 'RewriteRule|php_value|SetHandler|AddType|auto_prepend|auto_append'; then
                    report "MED" "core-extra-htaccess" "$extra" "unexpected .htaccess with active rules in core area - review"
                fi
                ;;
            *)
                report "MED" "core-extra-file" "$extra" "unexpected non-core file in core area, not in official $WPVER manifest - review";;
        esac
    done < "$extra_list"
    rm -f "$expected" "$actual"
    MANIFEST_OK=1   # unknown-file detection ran against a real manifest; orphan fallback not needed
    ok "Core verification done."
}

scan_fake_plugins() {
    # Fake-plugin NAME/payload heuristics - pure filename checks, no php/checksums needed
    # (runs even where plugin checksum verification is skipped). Legit plugins are never
    # named word-<random hex> (native-database-checker-c975, content-delivery-helper-fd9196),
    # and a plugin shipping a bare payload.php is almost always a malware dropper. Flagged
    # HIGH by name/path; the files are still content-scanned by YARA independently.
    [ -d "$WPROOT/wp-content/plugins" ] || return
    local plugdir slug
    for plugdir in "$WPROOT"/wp-content/plugins/*/; do
        [ -d "$plugdir" ] || continue
        slug="$(basename "$plugdir")"
        if printf '%s' "$slug" | grep -qE '\-[0-9a-f]{4,8}$' \
           && ! printf '%s' "$slug" | grep -qiE '^(woocommerce|wordpress|wp-)'; then
            report "HIGH" "fake-plugin-name" "wp-content/plugins/$slug" \
                "plugin directory has a random hex suffix (word-<hex>) - a near-unique fake-plugin/malware naming pattern; verify manually (cleanup: RatSweepr Cleanup Kit / Done-For-You at ratsweepr.com)"
        fi
        if [ -f "${plugdir}includes/payload.php" ] || [ -f "${plugdir}payload.php" ]; then
            report "HIGH" "fake-plugin-payload" "wp-content/plugins/$slug" \
                "plugin ships a file literally named payload.php - almost always a malware dropper; verify manually (cleanup: RatSweepr Cleanup Kit / Done-For-You at ratsweepr.com)"
        fi
    done
}

# scan_plugin_header_mismatch: a plugin's own declared header metadata can out a
# fake/dropped plugin before any code pattern fires - a Text Domain unrelated to
# its Plugin Name, a Text Domain with the same random-hex-suffix disguise
# fake-plugin directory names use (here on the header field instead), or an
# Author claiming to be WordPress.org/WordPress/Automattic on a plugin that
# genuinely isn't theirs. Any ONE hit is MED (could be sloppy but real); two or
# more on the SAME plugin is HIGH. Pure header-text checks, no php needed.
scan_plugin_header_mismatch() {
    [ -d "$WPROOT/wp-content/plugins" ] || return
    local plugdir slug mainfile f line name textdomain author hits detail
    # Automattic/core plugins that legitimately use these generic author strings.
    local known_automattic="|akismet|jetpack|woocommerce|classic-editor|classic-widgets|wordpress-importer|wp-super-cache|vaultpress|polldaddy|"
    for plugdir in "$WPROOT"/wp-content/plugins/*/; do
        [ -d "$plugdir" ] || continue
        slug="$(basename "$plugdir")"
        mainfile=""
        for f in "$plugdir"*.php; do
            [ -f "$f" ] || continue
            grep -qiE '^[[:space:]*/]*Plugin Name:' "$f" 2>/dev/null || continue
            mainfile="$f"; break
        done
        [ -n "$mainfile" ] || continue

        line="$(grep -iE '^[[:space:]*/]*Plugin Name:' "$mainfile" | head -1)"
        name="$(printf '%s' "${line#*:}" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')"
        line="$(grep -iE '^[[:space:]*/]*Text Domain:' "$mainfile" | head -1)"
        textdomain="$(printf '%s' "${line#*:}" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')"
        line="$(grep -iE '^[[:space:]*/]*Author:' "$mainfile" | head -1)"
        author="$(printf '%s' "${line#*:}" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')"

        hits=0; detail=""

        if [ -n "$textdomain" ]; then
            if printf '%s' "$textdomain" | grep -qE '\-[0-9a-f]{4,8}$'; then
                hits=$((hits+1)); detail="${detail}Text Domain '$textdomain' has a random-hex suffix; "
            fi
            if [ -n "$name" ]; then
                local namenorm tdnorm
                namenorm="$(printf '%s' "$name" | tr '[:upper:]' '[:lower:]' | tr -cd '[:alnum:]')"
                tdnorm="$(printf '%s' "$textdomain" | tr '[:upper:]' '[:lower:]' | tr -cd '[:alnum:]')"
                if [ -n "$namenorm" ] && [ -n "$tdnorm" ]; then
                    case "$namenorm" in
                        *"$tdnorm"*) : ;;
                        *) case "$tdnorm" in
                               *"$namenorm"*) : ;;
                               *) hits=$((hits+1))
                                  detail="${detail}Text Domain '$textdomain' doesn't resemble Plugin Name '$name'; " ;;
                           esac ;;
                    esac
                fi
            fi
        fi

        if [ -n "$author" ]; then
            case "$author" in
                "WordPress.org Community"|"WordPress"|"Automattic")
                    case "$known_automattic" in
                        *"|$slug|"*) : ;;
                        *) hits=$((hits+1))
                           detail="${detail}Author claims '$author' but '$slug' isn't a known Automattic/core plugin; " ;;
                    esac ;;
            esac
        fi

        [ "$hits" -gt 0 ] || continue
        local sev="MED"; [ "$hits" -ge 2 ] && sev="HIGH"
        report "$sev" "plugin-header-mismatch" "wp-content/plugins/$slug" "${detail% }"
    done
}

scan_plugin_checksums() {
    info "Verifying plugins against downloads.wordpress.org plugin-checksums..."
    [ -d "$WPROOT/wp-content/plugins" ] || return
    if [ "$HAVE_PHP" != "1" ]; then
        warn "php-cli not found: skipping plugin checksum verification."
        return
    fi
    local plugdir slug ver mainfile js manifest
    for plugdir in "$WPROOT"/wp-content/plugins/*/; do
        [ -d "$plugdir" ] || continue
        slug="$(basename "$plugdir")"
        # find plugin version from its headers
        ver=""
        for mainfile in "$plugdir$slug.php" "$plugdir"*.php; do
            [ -f "$mainfile" ] || continue
            ver="$(grep -iE '^[[:space:]*/]*Version:' "$mainfile" 2>/dev/null \
                   | head -1 | grep -Eo '([0-9]+\.)+[0-9]+' | head -1)"
            [ -n "$ver" ] && break
        done
        if [ -z "$ver" ]; then
            report "INFO" "plugin-noversion" "wp-content/plugins/$slug" "could not read version header"
            continue
        fi
        js="$RS_CACHE/plugin-$slug-$ver.json"
        if [ ! -s "$js" ]; then
            fetch "https://downloads.wordpress.org/plugin-checksums/$slug/$ver.json" "$js" \
                || { report "INFO" "plugin-premium" "wp-content/plugins/$slug ($ver)" \
                     "not on wordpress.org - verify manually (cleanup: RatSweepr Cleanup Kit / Done-For-You at ratsweepr.com)"; rm -f "$js"; continue; }
        fi
        [ -s "$js" ] || { report "INFO" "plugin-premium" "wp-content/plugins/$slug ($ver)" \
                          "checksum data download produced an empty file"; rm -f "$js"; continue; }
        manifest="$RS_CACHE/plugin-$slug-$ver.list"
        # Emits: relpath <TAB> md5a,md5b  (the API may list several valid md5s)
        php_json 'if(!isset($d["files"])) exit(2);
            foreach($d["files"] as $f=>$i){ $m=$i["md5"];
              if(is_array($m)) $m=implode(",",$m);
              echo $f."\t".$m."\n"; }' < "$js" > "$manifest" 2>/dev/null
        [ -s "$manifest" ] || { report "INFO" "plugin-premium" "wp-content/plugins/$slug ($ver)" \
                                "no checksum data on wordpress.org"; continue; }

        local rel md5s cur missing=0 modified=0
        while IFS=$'\t' read -r rel md5s; do
            if [ ! -f "$plugdir$rel" ]; then missing=$((missing+1)); continue; fi
            cur="$(md5sum "$plugdir$rel" | awk '{print $1}')"
            case ",$md5s," in
                *",$cur,"*) printf '%s\n' "wp-content/plugins/$slug/$rel" >> "$VERIFIED" ;;
                *) modified=$((modified+1))
                   report "HIGH" "plugin-modified" "wp-content/plugins/$slug/$rel" \
                          "does not match official $slug $ver checksums";;
            esac
        done < "$manifest"
        # extra files inside the plugin dir not in the manifest
        local expected="$RS_CACHE/pl-exp.$$" actual="$RS_CACHE/pl-act.$$"
        cut -f1 "$manifest" | sort > "$expected"
        if ! ( cd "$plugdir" && find . -type f | sed 's|^\./||' ) | sort > "$actual"; then
            check_incomplete "plugin-checksums:$slug" "could not list plugin directory contents - extra-file detection skipped for this plugin"
            rm -f "$expected" "$actual"
            continue
        fi
        local pl_extra; pl_extra="$(rs_tmp pl-extra)"
        if comm -13 "$expected" "$actual" > "$pl_extra" 2>/dev/null; then
            while IFS= read -r extra; do
                report "MED" "plugin-unknown-file" "wp-content/plugins/$slug/$extra" \
                       "file not in official $slug $ver package"
            done < "$pl_extra"
        else
            check_incomplete "plugin-checksums:$slug" "comm failed diffing expected vs. actual plugin files - extra-file detection skipped for this plugin"
        fi
        rm -f "$expected" "$actual"
        [ "$modified" = "0" ] || bad "$slug: $modified modified file(s)"
    done
    ok "Plugin verification done."
}

scan_mu_plugins() {
    # mu-plugins auto-load on every request with no UI and no activation - a top-tier
    # persistence/backdoor spot. Flag any PHP here that isn't a known host MU plugin.
    # Files still go through YARA/heuristics too; this catches by LOCATION so an
    # unknown mu-plugin is surfaced even if no content rule matches it.
    local mud="$WPROOT/wp-content/mu-plugins"
    [ -d "$mud" ] || return
    # Known-legitimate mu-plugin entries (host loaders). Extend via ALLOWPATH if needed.
    # Known-legit host/vendor mu-plugins. These are real files from managed hosts
    # and reputable tools that auto-load by design; flagging them is noise. Any file
    # here still goes through the YARA/heuristic content scan, so a tampered copy is
    # caught by content even though its name is allowlisted.
    local known="|kinsta-mu-plugins.php|index.php|wp-migrate-db-pro-compatibility.php|0-worker.php|wpengine-common.php|wpe-wp-sign-on-plugin.php|mu-plugin.php|slt-force-strong-passwords.php|"
    local f base rel
    for f in "$mud"/*.php; do
        [ -f "$f" ] || continue
        base="$(basename "$f")"
        rel="${f#"$WPROOT"/}"
        case "$known" in *"|$base|"*) continue;; esac
        # allow anything already covered by an ALLOWPATH trusted-vendor prefix
        if allowpath_check "$rel"; then continue; fi
        # WP Engine's per-install helper mu-plugins are named wpe_<hash>_private_ips.php
        # (legit IP-whitelist helpers). Exempt that exact shape ONLY if the file does
        # not trip a content red flag - a backdoor named to mimic it still fires.
        if printf '%s' "$base" | grep -qE '^wpe_[a-z0-9]+_private_ips\.php$' \
           && ! grep -qiE 'eval|base64_decode|system|passthru|\$_(GET|POST|REQUEST|COOKIE)|assert|gzinflate' "$f" 2>/dev/null; then
            continue
        fi
        report "HIGH" "mu-plugin-unexpected" "$rel" \
            "unexpected must-use plugin - mu-plugins auto-load invisibly on every request and are a common backdoor location; verify manually (cleanup: RatSweepr Cleanup Kit / Done-For-You at ratsweepr.com)"
    done
}

mask_wpconfig_secrets() { # stdin -> stdout, redacts DB_PASSWORD/*_KEY/*_SALT define() values
    sed -E "s/(define\([[:space:]]*['\"](DB_PASSWORD|[A-Z_]+_KEY|[A-Z_]+_SALT)['\"][[:space:]]*,[[:space:]]*['\"])[^'\"]*(['\"])/\1***MASKED***\3/g"
}

wpconfig_flagged_lines() { # emits CATEGORY<TAB>LINENO<TAB>CODE for every flagged wp-config.php line (LINENO 0 = unknown)
    local wc="$WPROOT/wp-config.php"
    [ -f "$wc" ] || return 0
    local raw lnum lcontent
    # rogue require/include of anything that isn't the normal wp-settings/ABSPATH bootstrap
    local wcrogue; wcrogue="$(rs_tmp wpconfig-rogue)"
    grep -nE "^[[:space:]]*(require|include)(_once)?[[:space:]]*[('\"]" "$wc" 2>/dev/null \
        | grep -viE 'wp-settings\.php|ABSPATH|dirname\(__FILE__\)|__DIR__' > "$wcrogue"
    while IFS= read -r raw; do
        [ -n "$raw" ] || continue
        lnum="${raw%%:*}"; lcontent="${raw#*:}"
        case "$lnum" in ''|*[!0-9]*) lnum="0" ;; esac
        printf 'wp-config-rogue-include\t%s\t%s\n' "$lnum" "$lcontent"
    done < "$wcrogue"
    # injected eval/base64/exec constructs in wp-config
    local wcinject; wcinject="$(rs_tmp wpconfig-inject)"
    grep -nE 'eval\s*\(|base64_decode\s*\(|gzinflate\s*\(|\$_(GET|POST|REQUEST|COOKIE)\[|assert\s*\(|create_function\s*\(' "$wc" 2>/dev/null > "$wcinject"
    while IFS= read -r raw; do
        [ -n "$raw" ] || continue
        lnum="${raw%%:*}"; lcontent="${raw#*:}"
        case "$lnum" in ''|*[!0-9]*) lnum="0" ;; esac
        printf 'wp-config-injected-code\t%s\t%s\n' "$lnum" "$lcontent"
    done < "$wcinject"
}

scan_wpconfig_content() {
    # wp-config.php is excluded from checksum verification (it's site-specific), which
    # makes it a favored injection target precisely because scanners skip it. Scan its
    # CONTENT for rogue includes and injected code, active or commented-out.
    [ -f "$WPROOT/wp-config.php" ] || return
    local cat lnum content label
    local flagged; flagged="$(rs_tmp wpconfig-flagged)"
    wpconfig_flagged_lines > "$flagged"
    while IFS=$'\t' read -r cat lnum content; do
        [ -n "$cat" ] || continue
        if [ "$lnum" = "0" ]; then label="line unknown, review the whole file"; else label="L$lnum"; fi
        report "HIGH" "$cat" "wp-config.php" \
            "$label: $(printf '%s' "$content" | sed 's/^[[:space:]]*//' | mask_wpconfig_secrets | cut -c1-80)"
    done < "$flagged"
}

wp_config_review() { # read-only: show flagged wp-config.php lines with context, secrets masked
    [ -f "$WPROOT/wp-config.php" ] || die "No wp-config.php here."
    local matches; matches="$(wpconfig_flagged_lines)"
    if [ -z "$matches" ]; then
        ok "No rogue includes or injected code found in wp-config.php."
        return
    fi
    say ""
    say "Flagged lines in wp-config.php (2 lines of context each, secrets masked):"
    say "=========================================================================="
    local cat lnum content start end
    while IFS=$'\t' read -r cat lnum content; do
        [ -n "$cat" ] || continue
        say ""
        if [ "$lnum" = "0" ]; then
            warn "[$cat] line unknown, review the whole file"
            continue
        fi
        warn "[$cat] line $lnum:"
        start=$((lnum - 2)); [ "$start" -lt 1 ] && start=1
        end=$((lnum + 2))
        sed -n "${start},${end}p" "$WPROOT/wp-config.php" \
            | mask_wpconfig_secrets | cut -c1-160 \
            | awk -v s="$start" '{printf "    %4d| %s\n", s+NR-1, $0}'
    done <<EOF
$matches
EOF
    say "=========================================================================="
    say "Edit wp-config.php by hand and remove only the flagged line(s) above."
    say "Then re-run: ratsweepr.sh scan"
}

scan_uploads_php() {
    info "Scanning wp-content/uploads for PHP files (should contain none)..."
    [ -d "$WPROOT/wp-content/uploads" ] || return
    local uplist; uplist="$(rs_tmp uploads-php)"
    find "$WPROOT/wp-content/uploads" -type f \
         \( -name '*.php' -o -name '*.php[0-9]' -o -name '*.phtml' \) -print0 > "$uplist"
    while IFS= read -r -d '' f; do
        rel="${f#"$WPROOT"/}"
        # Many legit plugins drop an empty "Silence is golden" index.php guard.
        # Treat a small index.php with no real code as INFO, not HIGH.
        local base; base="$(basename "$f")"
        local sz; sz="$(wc -c < "$f" 2>/dev/null || echo 999)"
        if [ "$base" = "index.php" ] && [ "$sz" -lt 200 ] \
           && ! grep -qiE '\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)|eval|base64|system|exec|passthru|assert|include|require|fopen|file_put|curl' "$f" 2>/dev/null; then
            report "INFO" "php-in-uploads" "$rel" "empty index.php silence-guard (benign) - no executable code"
        else
            report "HIGH" "php-in-uploads" "$rel" "executable PHP inside uploads - almost always malicious"
        fi
    done < "$uplist"
    ok "Uploads scan done."
}

scan_asset_tampering() {
    # D1/D2: SEO-cloaker payloads hidden under asset-looking names. Two
    # independent tells on the same file set, checked in one pass:
    #   D1 - magic bytes don't match the extension (gzip/zip payload stored
    #        as a .png/.js/.css/etc so casual review and extension-based
    #        tooling skip right over it)
    #   D2 - a PHP open tag (or a strong eval+decode combo) inside a file
    #        whose extension isn't .php/.phtml/.phar
    # Neither is covered by build_php_filelist/scan_yara - those only ever
    # look at PHP-shaped filenames, which is exactly the blind spot this
    # pattern exploits.
    info "Checking static assets for magic-byte mismatches and embedded PHP..."
    local exts=(png gif jpg jpeg webp svg css scss sass less js mjs map woff woff2 ttf eot ico mp3 mp4 pdf)
    local nameargs=() e
    for e in "${exts[@]}"; do
        [ "${#nameargs[@]}" -gt 0 ] && nameargs+=(-o)
        nameargs+=(-iname "*.$e")
    done
    local f rel sz magic head
    local assetlist; assetlist="$(rs_tmp asset-tampering)"
    find "$WPROOT" \( -path "$WPROOT/wp-content/cache" -prune \) -o \
         -type f \( "${nameargs[@]}" \) -print0 2>/dev/null > "$assetlist"
    while IFS= read -r -d '' f; do
        rel="${f#"$WPROOT"/}"
        case "$rel" in *.gz) continue;; esac   # legitimate pre-compressed assets
        grep -Fxq "$rel" "$VERIFIED" 2>/dev/null && continue
        if allowpath_check "$rel"; then continue; fi

        # --- D1: first 4 bytes vs. the extension's expected magic ---
        # `dd bs=1 count=N` + `od -An -tx1` reads/renders identically under
        # GNU coreutils (CI/shared hosting) and BSD/macOS (Jorge's Mac) -
        # unlike `head -c`, which some stripped-down hosts lack entirely.
        # Streams only the head of the file; never slurps whole binaries.
        magic="$(dd if="$f" bs=1 count=4 2>/dev/null | od -An -tx1 | tr -d ' \n')"
        case "$magic" in
            1f8b*)
                report "HIGH" "gzip-masquerading-as-asset" "$rel" \
                    "file starts with gzip magic (1f 8b) but has a static-asset extension - classic SEO-cloaker payload-storage trick";;
            504b0304*)
                report "MED" "zip-masquerading-as-asset" "$rel" \
                    "file starts with zip magic (50 4b 03 04) but has a static-asset extension - review";;
        esac

        # --- D2: PHP content under a non-PHP extension ---
        # Skip multi-MB files outright - a legitimate font/video/PDF this big
        # is never a PHP dropper, and there's no reason to grep it whole.
        sz="$(wc -c < "$f" 2>/dev/null || echo 0)"
        [ "$sz" -gt 5000000 ] 2>/dev/null && continue
        # First ~200 bytes, NUL-stripped, for the open-tag check - mirrors the
        # mktemp-file decode pattern used elsewhere in this script rather than
        # capturing raw (possibly binary) bytes into a variable.
        head="$(dd if="$f" bs=1 count=200 2>/dev/null | LC_ALL=C tr -d '\000')"
        if printf '%s' "$head" | LC_ALL=C grep -aqE '^[[:space:]]*<\?(php|=)'; then
            report "HIGH" "php-in-nonphp-extension" "$rel" \
                "PHP open tag at the start of a file with a non-PHP extension - almost certainly a disguised payload"
        elif LC_ALL=C grep -aqE '<\?php|<\?=' "$f" 2>/dev/null \
             && LC_ALL=C grep -aqiE 'eval[[:space:]]*\(' "$f" 2>/dev/null \
             && LC_ALL=C grep -aqiE 'base64_decode|gzinflate|gzuncompress|compress\.zlib://' "$f" 2>/dev/null; then
            # A real open tag ANYWHERE (not just the head) combined with an
            # eval+decode combo - looser than the head-only check above, so
            # require the stronger multi-signal combo to hold the FP rate
            # down (ordinary minified JS/CSS can contain the bare word "eval").
            report "HIGH" "php-in-nonphp-extension" "$rel" \
                "PHP open tag + eval/decode combo inside a file with a non-PHP extension - review"
        fi
    done < "$assetlist"
    ok "Asset tampering check done."
}

scan_hashdb() {
    if [ ! -s "${HDB_FILE:-}" ]; then
        warn "rfxn.hdb not present - run 'update-sigs' first to enable hash scanning."
        return
    fi
    info "Scanning against rfxn/maldet MD5 database ($(wc -l < "$HDB_FILE") signatures)..."
    local hashes="$RS_CACHE/site-hashes.$$"
    xargs -0 md5sum < "$PHPLIST" 2>/dev/null > "$hashes" || true
    # join site hashes against hdb (md5:size:name). md5sum output is
    # "32-char-hash<2 chars>path", so the path starts at column 35.
    awk 'NR==FNR { split($0, a, ":"); sig[a[1]] = a[3]; next }
         { h = substr($0, 1, 32); p = substr($0, 35);
           if (h in sig) printf "%s\t%s\n", p, sig[h] }' \
        "$HDB_FILE" "$hashes" | while IFS=$'\t' read -r f name; do
            report "HIGH" "known-malware" "${f#"$WPROOT"/}" "matches maldet signature: $name"
        done
    rm -f "$hashes"
    ok "Hash database scan done."
}

# allowpath_check REL -> returns 0 if REL is under a trusted vendor prefix,
# and sets ALLOWPATH_URL to its reinstall URL (or empty).
allowpath_check() {
    local rel="$1" pfx url
    ALLOWPATH_URL=""
    while IFS='|' read -r type pfx url; do
        [ "$type" = "ALLOWPATH" ] || continue
        case "$rel" in "$pfx"/*|"$pfx") ALLOWPATH_URL="$url"; return 0;; esac
    done < "$PATTERNS_FILE"
    return 1
}

write_bundled_yara() {
    printf '// bundled-version: %s\n' "$RS_VERSION" > "$1"
    cat >> "$1" << 'RSYARA'
/*
   RatSweepr bundled YARA rules — WordPress webshell & backdoor detection.
   Self-contained (no includes). Operators can supplement with maintained
   rulesets (php-malware-finder, signature-base) via RS_YARA_RULES=/path.
*/

rule RS_eval_user_input {
    meta:
        description = "eval/assert of user-controlled input"
        severity = "HIGH"
    strings:
        // \b anchors avoid matching a plain function call like doubleval(...) or
        // retrieval(...), both of which contain "eval(" as a bare substring -
        // confirmed against a clean Gravity Forms copy, see VERIFY.md
        $a = /\b(eval|assert)\s*\(\s*(stripslashes\s*\()?\s*\$_(POST|GET|REQUEST|COOKIE)/ nocase
        $b = /\b(eval|assert)\s*\(\s*\$[a-zA-Z_]+\s*\)/ nocase
    condition:
        any of them
}

rule RS_command_exec_user_input {
    meta:
        description = "OS command execution with user input"
        severity = "HIGH"
    strings:
        $a = /(system|passthru|shell_exec|proc_open)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[/ nocase
        $b = /(system|passthru|shell_exec)\s*\(\s*["']?\s*\$_(GET|POST|REQUEST)/ nocase
    condition:
        any of them
}

rule RS_obfuscated_eval_chain {
    meta:
        description = "eval of decoded/inflated payload"
        severity = "HIGH"
    strings:
        $a = /eval\s*\(\s*(gzinflate|gzuncompress|str_rot13|base64_decode)\s*\(/ nocase
        $b = /\$[a-zA-Z_][a-zA-Z0-9_]*\s*\(\s*(gzinflate|gzuncompress)\s*\(\s*base64_decode/ nocase
    condition:
        any of them
}

rule RS_hex_obfuscated_hooks {
    meta:
        description = "WordPress hook names hex-escaped to evade grep (nulled/backdoor)"
        severity = "HIGH"
    strings:
        $a = /add_(action|filter)\s*\(\s*["'](\\x[0-9a-fA-F]{2}|\\[0-9]{2,3}){4,}/ nocase
    condition:
        $a
}

rule RS_fake_wordpress_plugin {
    meta:
        description = "Plugin falsely attributed to WordPress.org"
        severity = "HIGH"
    strings:
        $a = /Author URI:\s*https?:\/\/wordpress\.org\/#/ nocase
        $b = "Official WordPress plugin" nocase
    condition:
        any of them
}

rule RS_self_hiding_plugin {
    meta:
        description = "Plugin hides itself from the admin plugin list (wp_list_table items, or all_plugins filter unsetting own basename)"
        severity = "HIGH"
    strings:
        $items = /unset\s*\([^)]*wp_list_table->items/ nocase
        $str   = /unset\s*\(\s*\$[a-zA-Z_]+\[['"][^]]*\.php['"]\s*\]\s*\)/
        $hook  = /add_filter\s*\(\s*['"]all_plugins['"]/ nocase
        $self  = /unset\s*\(\s*\$[a-zA-Z_]+\s*\[\s*plugin_basename\s*\(\s*__FILE__/ nocase
    condition:
        $items or $str or ($hook and $self)
}

rule RS_php_in_disguise {
    meta:
        description = "PHP code with image/asset header (fake image shell)"
        severity = "HIGH"
    strings:
        $gif = /^GIF8[79]a/
        $php = "<?php"
    condition:
        $gif at 0 and $php
}

rule RS_hmac_authed_backdoor {
    meta:
        description = "HMAC-authenticated request handler feeding eval (RAT)"
        severity = "HIGH"
    strings:
        $h = /hash_hmac\s*\(\s*["']sha256["'][^)]*\$_(POST|GET|SERVER|REQUEST)/ nocase
        $e = /eval\s*\(\s*base64_decode/ nocase
    condition:
        $h and $e
}

rule RS_uploader_shell {
    meta:
        description = "File uploader (potential webshell dropper)"
        severity = "MEDIUM"
    strings:
        $a = /move_uploaded_file\s*\([^)]*\$_FILES/ nocase
        $b = /\$_FILES\[[^]]+\]\[['"]tmp_name/ nocase
    condition:
        all of them
}

rule RS_large_base64_payload {
    meta:
        description = "Large base64 blob decoded (packed payload)"
        severity = "HIGH"
    strings:
        $a = /base64_decode\s*\(\s*["'][A-Za-z0-9+\/]{200,}/ nocase
    condition:
        $a
}

rule RS_command_exec_fallback_chain {
    meta:
        description = "Command-exec webshell probing disable_functions with multiple exec fallbacks (wp2shell family)"
        severity = "HIGH"
    strings:
        $df = "disable_functions" nocase
        $a = /shell_exec\s*\(\s*\$/ nocase
        $b = /\bexec\s*\(\s*\$/ nocase
        $c = /\bsystem\s*\(\s*\$/ nocase
        $d = /passthru\s*\(\s*\$/ nocase
    condition:
        $df and 2 of ($a,$b,$c,$d)
}

rule RS_hardcoded_secret_gated_exec {
    meta:
        description = "Hardcoded-secret gated command-exec backdoor (hash_equals against fixed value then runs request-derived command), or the same hash_equals gate paired with a disable_functions= probe as a bonus tell"
        severity = "HIGH"
    strings:
        $h = /hash_equals\s*\(\s*["'][^"']{6,}["']\s*,\s*\$_(GET|POST|REQUEST|SERVER)/ nocase
        $e = /(system|passthru|shell_exec|exec|popen|proc_open)\s*\(\s*\$_(GET|POST|REQUEST)/ nocase
        $df = "disable_functions=" nocase
    condition:
        ($h and $e) or ($h and $df)
}

rule RS_globals_flood_backdoor {
    meta:
        description = "Backdoor obfuscated with 50+ $GLOBALS[] variable references feeding eval"
        severity = "HIGH"
    strings:
        $g = /\$GLOBALS\s*\[/
        $e = /eval\s*\(/ nocase
    condition:
        #g > 50 and $e
}

rule RS_remote_content_obfuscated {
    meta:
        description = "Obfuscated malware fetching remote content (file_get_contents/curl) and decoding/executing it"
        severity = "HIGH"
    strings:
        $fetch1 = "file_get_contents" nocase
        $fetch2 = "curl_exec" nocase
        $dec = /(gzinflate|gzuncompress|str_rot13)\s*\(\s*base64_decode/ nocase
        $b64url = /base64_decode\s*\(\s*["'][A-Za-z0-9+\/]{16,}["']\s*\)/ nocase
    condition:
        (any of ($fetch1,$fetch2)) and ($dec or $b64url)
}

rule RS_header_dynamic_call_backdoor {
    meta:
        description = "Backdoor invoking functions from HTTP header values (getallheaders + variable-variable call)"
        severity = "HIGH"
    strings:
        $gah = "getallheaders" nocase
        $hdr = "$_HEADERS"
        $call = /\$_HEADERS\s*\[[^\]]+\]\s*\(/
    condition:
        $gah and $hdr and $call
}

rule RS_cookie_dynamic_include_backdoor {
    meta:
        description = "Backdoor assembling function names from $_COOKIE and calling include/dynamic function"
        severity = "HIGH"
    strings:
        $cook = "$_COOKIE"
        $dyncall = /\$[a-zA-Z_][a-zA-Z0-9_]*\s*\[\s*[0-9]+\s*\]\s*\(/
        $inc = /\b(include|require|require_once|include_once)\s*\(\s*\$/
    condition:
        $cook and $dyncall and $inc
}

rule RS_cookie_rot13_base64_dropper {
    meta:
        description = "Cookie-fed dropper: base64_decode(str_rot13($_COOKIE)) written to temp file and executed"
        severity = "HIGH"
    strings:
        $chain = /base64_decode\s*\(\s*str_rot13/ nocase
        $cook = "$_COOKIE"
        $exec = /\b(require_once|require|include|include_once|fputs|file_put_contents)\b/ nocase
    condition:
        $chain and $cook and $exec
}

rule RS_header_file_dropper {
    meta:
        description = "Dropper writing PHP to a temp file then include+unlink (header/request triggered)"
        severity = "HIGH"
    strings:
        $trig1 = "getallheaders" nocase
        $trig2 = "$_HEADERS"
        $write = /file_put_contents\s*\(/ nocase
        $inc = /\b(include|require|require_once|include_once)\s*\(/ nocase
        $del = "unlink" nocase
    condition:
        ($trig1 or $trig2) and $write and $inc and $del
}

rule RS_pack_obfuscated_shell {
    meta:
        description = "Obfuscated shell using pack('H*') to build function names, invoked dynamically from request data"
        severity = "HIGH"
    strings:
        $packh = /pack\s*\(\s*['"]H\*['"]/ nocase
        $dyncall = /\$[a-zA-Z_][a-zA-Z0-9_]*\s*\(\s*\$[a-zA-Z_]/
        $req = /\$_(POST|GET|REQUEST|COOKIE)\s*\[/
        $evalfam = /\b(eval|assert|create_function)\s*\(/ nocase
    condition:
        ($packh and $evalfam) or (#packh >= 2 and $dyncall and $req)
}

rule RS_php_file_manager {
    meta:
        description = "Standalone PHP file manager (Tiny File Manager / CCP) - legit tool, but on a WordPress site it is a webshell"
        severity = "HIGH"
    strings:
        $a = "Tiny File Manager" nocase
        $b = "CCP Programmers" nocase
        $c = "tinyfilemanager" nocase
        $d = "H3K"
        $e = "filemanager.php" nocase
        $f1 = "$_FILES"
        $f2 = /function\s+(list_dir|scan_dir|fm_get_file_path|fm_rename|fm_download)/ nocase
    condition:
        any of ($a,$b,$c,$d,$e) or (2 of ($f1,$f2))
}

rule RS_injected_js_executor {
    meta:
        description = "Obfuscated client-side JS injection: atob/TextDecoder + new Function()/eval executor (drainer/spam/redirect)"
        severity = "HIGH"
    strings:
        $script = "<script" nocase
        $newfn = /new\s+Function\s*\(/ nocase
        $atob = "atob(" nocase
        $td = "TextDecoder" nocase
        $charcode = "charCodeAt" nocase
        $jseval = /\beval\s*\(\s*(atob|unescape|decodeURIComponent)/ nocase
    condition:
        $script and (
            ($newfn and ($atob or $td)) or
            $jseval or
            ($atob and $charcode and $newfn)
        )
}

rule RS_injected_html_comment_marker {
    meta:
        description = "Paired random HTML comment markers wrapping an injected <script> (mass-injection signature)"
        severity = "MED"
    strings:
        $openmark = /<!--\s*[a-z]{6,12}\s*-->\s*(<\?php\s*\?>)?\s*<script/ nocase
    condition:
        $openmark
}

rule RS_malicious_htaccess_lockout {
    meta:
        description = "Access-control malware: .htaccess denying PHP execution while whitelisting attacker shells, or blocking host-quarantined .suspected files"
        severity = "HIGH"
    strings:
        $fm = "FilesMatch" nocase
        $suspected = /\|\s*suspected\s*\)/ nocase
        $deny = /Deny\s+from\s+all/ nocase
        $allow = /Allow\s+from\s+all/ nocase
        $phpmatch = /FilesMatch[^>]*\.php/ nocase
    condition:
        $fm and ( $suspected or ($deny and $allow and $phpmatch) )
}


rule RS_url_key_admin_login_backdoor {
    meta:
        description = "Unauthenticated admin-login backdoor: a hardcoded URL/GET key gates wp_insert_user/wp_set_auth_cookie to log the attacker in as administrator"
        severity = "HIGH"
    strings:
        $getkey = /\$_(GET|POST|REQUEST)\s*\[\s*['"][a-z]{1,6}['"]\s*\][^;]{0,12}[!=]==?\s*['"][A-Za-z0-9]{12,}['"]/
        $setcookie = "wp_set_auth_cookie" nocase
        $role = /['"]administrator['"]/
        $insert = /wp_insert_user|wp_create_user/ nocase
    condition:
        $getkey and $setcookie and ($role or $insert)
}

rule RS_fake_cache_proxy_gateway {
    meta:
        description = "Fake cache plugin acting as a same-origin reverse-proxy to a remote C2 (extensionless wp_head script + remote config fetch, often self-hiding)"
        severity = "HIGH"
    strings:
        $head = /add_action\s*\(\s*['"]wp_head['"]/ nocase
        $fetch = /(curl_exec|wp_remote_get|file_get_contents)\s*\(/ nocase
        $remote = /(gateway|proxy|cfx|c2)/ nocase
        $scripttag = /<script[^>]+src=['"]\/[a-z-]+\/[a-z]{2,4}['"]/ nocase
        $hidefilter = /add_filter\s*\(\s*['"]all_plugins['"]/ nocase
    condition:
        $head and $fetch and ($scripttag or ($remote and $hidefilter))
}

rule RS_goto_obfuscated_malware {
    meta:
        description = "goto-obfuscated malware: scrambled hex-label goto control flow with base64/eval payload (near-zero FP; legit PHP does not use scrambled-label goto)"
        severity = "HIGH"
    strings:
        $goto1 = /goto [A-Fa-f0-9]{10,}/
        $goto2 = /goto [a-z0-9]{4,}[0-9]+;/
        $label = /[A-Fa-f0-9]{10,}:/
        $payload = /(eval|base64_decode|\\x[0-9a-f]{2})/ nocase
    condition:
        (#goto1 >= 2 or ($goto1 and $label) or (#goto2 >= 3)) and $payload
}

rule RS_self_bootstrapping_backdoor {
    meta:
        description = "Self-bootstrapping standalone backdoor: climbs dirs to find wp-load.php then command-handles via request + system/eval (wp-mails/mu-functions-apsm family)"
        severity = "HIGH"
    strings:
        $boot = /while\s*\(\s*\$[a-z_]+\s*!==\s*dirname\s*\(\s*\$[a-z_]+\s*\)\s*\)/ nocase
        $wpload = "wp-load.php"
        $define = /define\s*\(\s*['"]_[A-Z_]+['"]\s*,\s*\$[a-z_]+/
        $exec = /@?(system|passthru|shell_exec|eval)\s*\(\s*.{0,30}\$_(GET|POST|REQUEST)/ nocase
        $jsonout = /json_encode[^;]*exit/ nocase
        $errsup = "error_reporting(0)"
    condition:
        ($boot and $wpload) and ($exec or ($define and ($jsonout or $errsup)))
}

rule RS_cookie_reassembled_superglobal_eval {
    meta:
        description = "Backdoor reassembling _COOKIE/superglobal name from string fragments feeding eval(base64_decode) - string-splitting scanner evasion"
        severity = "HIGH"
    strings:
        $reassemble = /\$\{\s*['"]_(CO|PO|GE|RE|SE|SER)['"]\s*\./ nocase
        $implode_fn = /implode\s*\(\s*['"]{2}\s*,\s*array\s*\(\s*['"](file|sys|exec|eval|base)/ nocase
        $cookeval = /eval\s*\(\s*(base64_decode|str_rot13|gzinflate)/ nocase
    condition:
        ($reassemble or $implode_fn) and $cookeval
}

rule RS_plaintext_external_script_injection {
    meta:
        description = "Plaintext external <script src> injection to a typosquat CDN or spam TLD in a theme/plugin file (coredelivr/quickdelivr family) - caught by technique, not domain blocklist"
        severity = "HIGH"
    strings:
        // typosquats of real CDNs (jsdelivr is the real one - these mimic it)
        $fake1 = /cdn\.(quickdelivr|coredelivr|fastdelivr|speeddelivr|jsdelivrs|jsdeliver)\./ nocase
        // the family's payload filename pattern on ANY external host
        $pkg = /<script[^>]{0,40}src\s*=\s*["']https?:\/\/[a-z0-9.-]+\/(sm|m)package\.js/ nocase
        // script src pointing at a spam/throwaway TLD
        $spamtld = /<script[^>]{0,40}src\s*=\s*["']https?:\/\/[a-z0-9.-]+\.(top|icu|sbs|xyz|cc|fun|click|rest)\// nocase
    condition:
        $fake1 or $pkg or $spamtld
}

rule RS_updraftcentral_oct2026_backdoor {
    meta:
        description = "UpdraftCentral key-compromise backdoor plugin (Oct 2026 campaign): a fake maintenance-toolkit plugin deployed via a stolen UpdraftCentral signing key, creating a hidden admin via wp_set_auth_cookie gated by a hash_equals token check against an option ending in _sync_token"
        severity = "HIGH"
    strings:
        $desc = "Small maintenance toolkit: keeps option storage tidy."
        $t = "_sync_token'"
        $c = "wp_set_auth_cookie"
        $h = "hash_equals"
    condition:
        $desc or ($t and $c and $h)
}

rule RS_xss_hidden_admin_backdoor {
    meta:
        description = "Hidden-admin-account backdoor from the Oct 2026 plugin-XSS-chain campaign (wp-smart-thumbnails dropper + class-wp-query-*/class-wp-token-validate.php mu-plugins): fires on the dropper's own revealing code comment"
        severity = "HIGH"
    strings:
        $comment = "WP plugin load: do not run shell (keeps wp-admin normal)"
    condition:
        $comment
}

rule RS_rankmath_pro_supplychain_oct2026 {
    meta:
        description = "Rank Math SEO PRO supply-chain compromise (Oct 2026, CVE-2026-111862): backdoored packages of PRO 3.0.123 contain a C2 domain, randomized option/key markers and a disguised cron tag - matches on any one published IOC in a PHP file"
        severity = "HIGH"
    strings:
        $php = "<?php"
        $i1 = "rank1cdn.com"
        $i2 = "xmmqhn"
        $i3 = "_uf6qdn2hmm"
        $i4 = "t8krdk990phb"
        $i5 = "_np5pvf754c"
        $i6 = "#ms6v46"
        $i7 = "@wp-mail.net"
    condition:
        $php and 1 of ($i*)
}

rule RS_updraftcentral_variant2_oct2026_backdoor {
    meta:
        description = "UpdraftCentral key-compromise backdoor, second variant (Oct 2026 campaign): hides its planted editor account from the admin-list query/count (pre_user_query + pre_count_users) in addition to the hash_equals-gated wp_set_auth_cookie takeover"
        severity = "HIGH"
    strings:
        $d1 = "keep service accounts out of the main user list"
        $d2 = "Improves cron tasks efficiency for content sites with minimal overhead"
        $hook1 = "pre_user_query"
        $hook2 = "pre_count_users"
        $c = "wp_set_auth_cookie"
        $h = "hash_equals"
    condition:
        $d1 or $d2 or ($hook1 and $hook2 and $c and $h)
}

rule RS_option_js_injector_wp_head {
    meta:
        description = "wp_head-hooked PHP that echoes a <script> block built from a get_option() value and an obfuscated-call marker ([].constructor.constructor(atob( or Function(atob(), without the current_user_can('manage_options') gate a legitimate admin-notice script would have"
        severity = "HIGH"
    strings:
        $hook = /add_action\s*\(\s*['"]wp_head['"]/ nocase
        $script = "<script" nocase
        $opt = /get_option\s*\(/ nocase
        $cap = /current_user_can\s*\(\s*['"]manage_options['"]/ nocase
        $m1 = "[].constructor.constructor(atob("
        $m2 = "Function(atob("
    condition:
        $hook and $script and $opt and ($m1 or $m2) and not $cap
}

rule RS_rest_backdoor_keyed_open_route {
    meta:
        description = "Unauthenticated REST backdoor: register_rest_route() with permission_callback '__return_true', a GET-param key compared to a hardcoded literal, gating update_option/delete_option or WP_Filesystem->delete"
        severity = "HIGH"
    strings:
        $route = /register_rest_route\s*\(/ nocase
        $perm  = /permission_callback['"]?\s*=>\s*['"]__return_true['"]/ nocase
        $key   = /get_param\s*\(\s*['"]key['"]\s*\)/ nocase
        $cmp   = /(==|===)\s*['"][A-Za-z0-9_\-]{6,}['"]/
        $opt1  = /update_option\s*\(/ nocase
        $opt2  = /delete_option\s*\(/ nocase
        $fsdel = /WP_Filesystem[^;]{0,60}->\s*delete\s*\(/ nocase
    condition:
        $route and $perm and $key and $cmp and ($opt1 or $opt2 or $fsdel)
}

rule RS_split_string_include {
    meta:
        description = "include/require of a filename reassembled from 2+ concatenated string fragments (e.g. __DIR__ . \"x\" . \"y.ph\" . \"p\") - evades static .php-extension grep; no legitimate reason to split a short filename like this"
        severity = "HIGH"
    strings:
        // {0,80} not {0,80}?: yara-x and classic yara both reject mixing
        // greedy and non-greedy quantifiers in one regex (E015 / "greedy
        // and ungreedy quantifiers can't be mixed"). A bounded quantifier
        // backtracks to the same match/no-match result either way, so this
        // doesn't change which files the rule fires on.
        $a = /\b(include|require|require_once|include_once)\s*\([^;{}]{0,80}['"][^'"]{0,40}['"]\s*\.\s*['"][^'"]{0,40}['"]\s*\.\s*['"][^'"]{0,40}['"]/ nocase
    condition:
        $a
}

rule RS_compress_zlib_stream_include {
    meta:
        description = "compress.zlib:// stream-wrapper paired with an include/eval/fetch call - how SEO cloakers load a gzip-compressed payload off disk without leaving plain-text PHP in the payload file itself"
        severity = "HIGH"
    strings:
        $wrap = "compress.zlib://" nocase
        $inc1 = /\b(include|include_once|require|require_once)\b/ nocase
        $inc2 = /\beval\s*\(/ nocase
        $inc3 = /\b(file_get_contents|readfile)\s*\(/ nocase
    condition:
        // Written as three ANDed pairs (logically $wrap and ($inc1 or $inc2
        // or $inc3)) on purpose: this trips native_yara()'s skip-regex (two+
        // "and"s), because its string-presence fallback can't distinguish
        // "wrap AND an include/eval nearby" from "wrap alone" - and
        // include(/require(/eval( are far too common to ever treat as an
        // OR-fallback trigger on their own. See scan_compress_zlib_grep_fallback.
        ($wrap and $inc1) or ($wrap and $inc2) or ($wrap and $inc3)
}

rule RS_compress_zlib_stream_bare_MED {
    meta:
        description = "compress.zlib:// stream wrapper referenced with no include/eval/fetch call in the same file - weaker signal (rare legitimate use exists), review manually"
        severity = "MEDIUM"
    strings:
        $wrap = "compress.zlib://" nocase
        $inc1 = /\b(include|include_once|require|require_once)\b/ nocase
        $inc2 = /\beval\s*\(/ nocase
        $inc3 = /\b(file_get_contents|readfile)\s*\(/ nocase
    condition:
        // "not" always trips native_yara()'s skip-regex; see
        // scan_compress_zlib_grep_fallback for the unconditional equivalent.
        $wrap and not ($inc1 or $inc2 or $inc3)
}

rule RS_cloaker_token_marker_MED {
    meta:
        description = "campaign-specific cloaker trigger/C2 token seen in Japanese spam-SEO loader kits - context marker only, not a standalone compromise indicator"
        severity = "MEDIUM"
    strings:
        $t1 = "cf1988" nocase
        $t2 = "ys001" nocase
    condition:
        any of them
}
RSYARA
}

scan_yara() {
    local rulesdir="$RS_SIG_DIR/yara"
    mkdir -p "$rulesdir"

    # --- rules: bundled (stale-refreshed) + operator dir + online feed (Path B) ---
    local bver=""
    [ -f "$rulesdir/ratsweepr.yar" ] && bver="$(sed -n 's#.*bundled-version: \([0-9A-Za-z.-]*\).*#\1#p' "$rulesdir/ratsweepr.yar" | head -1)"
    [ "$bver" = "$RS_VERSION" ] || write_bundled_yara "$rulesdir/ratsweepr.yar"

    # Path B: pull an updatable rule feed over HTTPS (no engine needed to fetch).
    if [ -n "${RS_RULES_URL:-}" ]; then
        local rtmp="$RS_CACHE/remote.yar.$$"
        if fetch "$RS_RULES_URL" "$rtmp" && grep -q '^rule ' "$rtmp" 2>/dev/null; then
            if [ -f "$PATTERN_PUBKEY" ] && [ "$HAVE_OPENSSL" = "1" ]; then
                local rsig="$RS_CACHE/remote.yar.sig.$$"
                if fetch "${RS_RULES_URL}.sig" "$rsig" \
                   && openssl dgst -sha256 -verify "$PATTERN_PUBKEY" -signature "$rsig" "$rtmp" >/dev/null 2>&1; then
                    mv "$rtmp" "$rulesdir/remote.yar"; ok "Pulled online YARA rules (signature VERIFIED)."
                else
                    warn "Online YARA rules failed signature check - rejected."; rm -f "$rtmp"
                fi
                rm -f "$rsig"
            else
                mv "$rtmp" "$rulesdir/remote.yar"; info "Pulled online YARA rules (UNVERIFIED - set a public key to require signing)."
            fi
        else
            rm -f "$rtmp"
        fi
    fi

    # collect all rule files
    local rulefiles=(); rulefiles+=("$rulesdir/ratsweepr.yar")
    [ -f "$rulesdir/remote.yar" ] && rulefiles+=("$rulesdir/remote.yar")
    if [ -n "${RS_YARA_RULES:-}" ] && [ -d "$RS_YARA_RULES" ]; then
        local extra_rules; extra_rules="$(rs_tmp yara-extra-rules)"
        find "$RS_YARA_RULES" \( -name '*.yar' -o -name '*.yara' \) 2>/dev/null > "$extra_rules"
        while IFS= read -r rf; do rulefiles+=("$rf"); done < "$extra_rules"
    fi

    # --- engine: system yara, else Path A (auto-download static yara-x), else native ---
    ensure_yara_engine
    local engine_desc="built-in matcher (no engine needed)"
    if [ -n "$YARA_ENGINE" ]; then
        if [ "$YARA_ENGINE_KIND" = "yara-x" ]; then
            engine_desc="yara-x ($("$YARA_ENGINE" --version 2>/dev/null | awk '{print $2}'))"
        else
            engine_desc="$("$YARA_ENGINE" --version 2>/dev/null | head -1 || echo yara)"
        fi
    fi

    local total_rules=0 rf
    for rf in "${rulefiles[@]}"; do
        total_rules=$((total_rules + $(grep -c '^rule ' "$rf" 2>/dev/null || echo 0)))
    done
    info "Running YARA scan: $total_rules rules via $engine_desc ..."

    local nmatch=0 rel
    while IFS= read -r -d '' f; do
        rel="${f#"$WPROOT"/}"
        grep -Fxq "$rel" "$VERIFIED" 2>/dev/null && continue
        for rf in "${rulefiles[@]}"; do
            local rulehits
            if [ -n "$YARA_ENGINE" ]; then
                if [ "$YARA_ENGINE_KIND" = "yara-x" ]; then
                    rulehits="$("$YARA_ENGINE" scan "$rf" "$f" 2>/dev/null | awk '{print $1}')"
                else
                    rulehits="$("$YARA_ENGINE" "$rf" "$f" 2>/dev/null | awk '{print $1}')"
                fi
            else
                rulehits="$(native_yara "$rf" "$f")"
            fi
            local rule
            while IFS= read -r rule; do
                [ -n "$rule" ] || continue
                local sev="HIGH"; case "$rule" in *uploader*|*_MEDIUM*|*_MED*) sev="MED";; esac
                allowpath_check "$rel" && sev="INFO"
                # Backdoor rules are never suppressed by allowlists - a planted backdoor
                # inside a trusted-looking vendor path (e.g. a host's own mu-plugins
                # folder) is exactly the scenario ALLOWPATH must not hide. Force HIGH
                # back for any rule with "backdoor" in its name, undoing the downgrade
                # above (covers future backdoor-named rules automatically), plus named
                # exceptions for backdoor-class rules whose name doesn't say so.
                case "$rule" in
                    *backdoor*|RS_rankmath_pro_supplychain_oct2026) sev="HIGH";;
                esac
                # A few rules (eval/pack) legitimately fire inside well-known vendored
                # libraries that USE eval/pack by design (dompdf's template engine, the
                # portable-utf8 encoder, Less/SCSS compilers, apimatic). Downgrade ONLY
                # those rules in those paths to INFO. Backdoor/injection rules are never
                # downgraded - they must fire even inside vendor dirs.
                case "$rule" in
                    RS_eval_user_input|RS_pack_obfuscated_shell|RS_obfuscated_eval_chain)
                        case "$rel" in
                            */vendor/*dompdf/*|*/dompdf/*|*/portable-utf8/*|*/voku/*|\
                            */Less/*|*/scssphp/*|*/wikimedia/*|*/apimatic/*|\
                            */vendor/*/sabberworm/*|*/php-css-parser/*)
                                sev="INFO" ;;
                        esac ;;
                esac
                report "$sev" "yara:$rule" "$rel" "matched YARA rule $rule"
                nmatch=$((nmatch+1))
            done <<< "$rulehits"
        done
    done < "$PHPLIST"
    ok "YARA scan done ($nmatch match(es))."
}

# ensure_yara_engine: sets YARA_ENGINE (path) and YARA_ENGINE_KIND (yara|yara-x),
# or leaves YARA_ENGINE empty to use the built-in matcher.
ensure_yara_engine() {
    YARA_ENGINE=""; YARA_ENGINE_KIND=""
    if have yara; then YARA_ENGINE="yara"; YARA_ENGINE_KIND="yara"; return; fi
    if [ -x "$RS_BIN/yr" ]; then YARA_ENGINE="$RS_BIN/yr"; YARA_ENGINE_KIND="yara-x"; return; fi
    # Path A: one-time download of the static yara-x CLI (opt out: RS_NO_ENGINE_DL=1).
    # Note: the built-in matcher already runs the same rules; the engine is a bonus
    # (full YARA condition support), never a requirement for detection.
    if [ "${RS_NO_ENGINE_DL:-0}" != "1" ]; then
        local arch=""; case "$(uname -m)" in
            x86_64|amd64)  arch="x86_64-unknown-linux-gnu";;
            aarch64|arm64) arch="aarch64-unknown-linux-gnu";;
        esac
        if [ -n "$arch" ]; then
            local ver="${RS_YARAX_VER:-v1.19.0}"
            local url="${RS_YARAX_URL:-https://github.com/VirusTotal/yara-x/releases/download/${ver}/yara-x-${ver}-${arch}.tar.gz}"
            info "No YARA engine on this host; trying one-time yara-x download (optional)..."
            local tgz="$RS_CACHE/yrx.tgz.$$"
            if fetch "$url" "$tgz" && [ -s "$tgz" ]; then
                # archive contains a single bare binary named 'yr'
                if tar -xzf "$tgz" -C "$RS_BIN" yr 2>/dev/null && chmod +x "$RS_BIN/yr" \
                   && "$RS_BIN/yr" --version >/dev/null 2>&1; then
                    YARA_ENGINE="$RS_BIN/yr"; YARA_ENGINE_KIND="yara-x"
                    ok "Installed yara-x engine -> $RS_BIN/yr"
                else
                    rm -f "$RS_BIN/yr"
                    info "yara-x not runnable here (glibc/noexec) - built-in matcher covers the same rules."
                fi
            else
                info "yara-x download skipped - built-in matcher covers the same rules."
            fi
            rm -f "$tgz"
        fi
    fi
}

# native_yara: minimal YARA-subset matcher (strings + regex + any/all-of-them),
# used when no engine binary is available. Rules with positional/module/complex
# conditions are skipped (only a real engine evaluates those faithfully).
native_yara() {
    local rulefile="$1" target="$2"
    awk -v TARGET="$target" '
    function reset(){ rule=""; nstr=0; delete strs; delete isregex; allof=0; skip=0; condtext="" }
    function q(s){ gsub(/\x27/,"\x27\\\x27\x27",s); return "\x27" s "\x27" }
    /^[[:space:]]*rule[[:space:]]+/ { reset(); rule=$2; sub(/[^a-zA-Z0-9_].*/,"",rule); next }
    /^[[:space:]]*\$[a-zA-Z0-9_]*[[:space:]]*=/ {
        line=$0; val=line
        sub(/^[[:space:]]*\$[a-zA-Z0-9_]*[[:space:]]*=[[:space:]]*/,"",val)
        gsub(/[[:space:]]+(nocase|wide|ascii|fullword).*$/,"",val)
        if (val ~ /^".*"/) { s=val; sub(/^"/,"",s); sub(/".*$/,"",s); strs[nstr]=s; isregex[nstr]=0; nstr++ }
        else if (val ~ /^\/.*\//) { s=val; sub(/^\//,"",s); sub(/\/[a-z]*[[:space:]]*$/,"",s); strs[nstr]=s; isregex[nstr]=1; nstr++ }
        else { skip=1 }
        next
    }
    /^[[:space:]]*condition[[:space:]]*:/ { incond=1; condtext=$0; sub(/.*condition[[:space:]]*:/,"",condtext); next }
    incond && !/^[[:space:]]*\}/ { condtext=condtext " " $0 }
    /^[[:space:]]*\}/ {
        if (rule!="" && nstr>0 && !skip) {
            if (condtext ~ /at |in \(|filesize|@|#[a-zA-Z]|# |hash\.|pe\.|math\.|[0-9]+ of | and .* and | or .* and |not /) {
                # unsupported by native matcher -> skip
            } else {
                allof=(condtext ~ /all of them/); matched=0
                for (i=0;i<nstr;i++) {
                    cmd=(isregex[i]?"grep -lE -- ":"grep -lF -- ") q(strs[i]) " " q(TARGET) " 2>/dev/null"
                    if ((cmd|getline r)>0 && r!="") matched++
                    close(cmd)
                }
                if ((allof && matched==nstr) || (!allof && matched>0)) print rule
            }
        }
        incond=0; reset(); next
    }
    ' "$rulefile"
}

# scan_updraftcentral_grep_fallback: explicit grep-equivalent of
# RS_updraftcentral_oct2026_backdoor, run UNCONDITIONALLY (not just when no
# YARA engine is present). A real engine always evaluates this rule's
# condition correctly; the built-in native_yara() matcher does NOT - its
# skip-regex bails on any condition with two " and "s, which this rule's
# "$desc or ($t and $c and $h)" has. Rather than loosen native_yara()'s
# skip logic for every rule (broad, risky), this runs the identical check
# directly and reports under the SAME category string the real engine
# would use, so finalize_report's existing sev|item|signature dedup
# collapses it to one line if a real engine also caught it.
scan_updraftcentral_grep_fallback() {
    local f rel
    while IFS= read -r -d '' f; do
        rel="${f#"$WPROOT"/}"
        grep -Fxq "$rel" "$VERIFIED" 2>/dev/null && continue
        if grep -qF "Small maintenance toolkit: keeps option storage tidy." "$f" 2>/dev/null; then
            report "HIGH" "yara:RS_updraftcentral_oct2026_backdoor" "$rel" \
                "matched YARA rule RS_updraftcentral_oct2026_backdoor"
        elif grep -qF "_sync_token'" "$f" 2>/dev/null \
             && grep -qF "wp_set_auth_cookie" "$f" 2>/dev/null \
             && grep -qF "hash_equals" "$f" 2>/dev/null; then
            report "HIGH" "yara:RS_updraftcentral_oct2026_backdoor" "$rel" \
                "matched YARA rule RS_updraftcentral_oct2026_backdoor"
        fi
    done < "$PHPLIST"
}

# scan_updraftcentral_notice: advisory only, not a finding - never calls
# report(). UpdraftPlus itself isn't vulnerable code; this tells an operator
# running it to check for the Oct 2026 UpdraftCentral key-compromise IOCs.
scan_updraftcentral_notice() {
    [ -d "$WPROOT/wp-content/plugins/updraftplus" ] || return
    notice "UpdraftPlus detected. UpdraftCentral keys were compromised in Oct 2026."
    notice "  Check for and remove the key:"
    notice "    wp option get updraft_central_localkeys"
    notice "    wp option delete updraft_central_localkeys"
    notice "  Search access logs for 'class-udrpc.php'."
    notice "  See https://patchstack.com/articles/updraftcentral-key-compromise-wordpress-backdoors/"
}

scan_updraftcentral_variant2_grep_fallback() {
    local f rel
    while IFS= read -r -d '' f; do
        rel="${f#"$WPROOT"/}"
        grep -Fxq "$rel" "$VERIFIED" 2>/dev/null && continue
        if grep -qF "keep service accounts out of the main user list" "$f" 2>/dev/null \
           || grep -qF "Improves cron tasks efficiency for content sites with minimal overhead" "$f" 2>/dev/null; then
            report "HIGH" "yara:RS_updraftcentral_variant2_oct2026_backdoor" "$rel" \
                "matched YARA rule RS_updraftcentral_variant2_oct2026_backdoor"
        elif grep -qF "pre_user_query" "$f" 2>/dev/null \
             && grep -qF "pre_count_users" "$f" 2>/dev/null \
             && grep -qF "wp_set_auth_cookie" "$f" 2>/dev/null \
             && grep -qF "hash_equals" "$f" 2>/dev/null; then
            report "HIGH" "yara:RS_updraftcentral_variant2_oct2026_backdoor" "$rel" \
                "matched YARA rule RS_updraftcentral_variant2_oct2026_backdoor"
        fi
    done < "$PHPLIST"
}

# scan_updraftcentral_variant2_indicators: read-only extras from Patchstack's
# write-up - a plugin that declares itself "Site Health Cache", and two named
# backdoor accounts / the shared display name "Site Tools". Changes nothing.
scan_updraftcentral_variant2_indicators() {
    local plugdir f P="${DBPREFIX:-wp_}"
    for plugdir in "$WPROOT"/wp-content/plugins/*/; do
        [ -d "$plugdir" ] || continue
        for f in "$plugdir"*.php; do
            [ -f "$f" ] || continue
            if grep -qiE '^[[:space:]*/]*Plugin Name:[[:space:]]*Site Health Cache[[:space:]]*$' "$f" 2>/dev/null; then
                report "HIGH" "updraftcentral-supplychain-artifact" "${f#"$WPROOT"/}" \
                    "plugin declares itself 'Site Health Cache', a published UpdraftCentral key-compromise indicator (Oct 2026) - verify and remove"
            fi
        done
    done

    [ -n "$WPCLI" ] || [ "$HAVE_MYSQL" = "1" ] || return
    db_query "SELECT ID, user_login, display_name FROM ${P}users
              WHERE user_login IN ('data-ops43','media-staff96') OR display_name='Site Tools';" \
    | while IFS=$'\t' read -r id login disp; do
        [ -n "$id" ] || continue
        report "HIGH" "updraftcentral-supplychain-artifact" "user:$id" \
            "'$login' (display name '$disp') matches a published UpdraftCentral key-compromise account indicator (Oct 2026) - verify and remove"
    done
}

# ======================= RANK MATH PRO SUPPLY-CHAIN (Oct 2026) ================
# CVE-2026-111862: backdoored packages of Rank Math SEO PRO 3.0.123. See the
# VULNPLUGIN entry (ratsweepr-sigs.conf) for the version check, and
# RS_rankmath_pro_supplychain_oct2026 (ratsweepr.yar) for the IOC-string rule.
# These are the parts a version check and a content-string rule can't cover:
# the exact fake core-file path, a .htaccess/.cache execution trick, and
# read-only DB/crontab extras. Nothing here is php-gated - all pure bash.

scan_rankmath_grep_fallback() {
    local f rel
    while IFS= read -r -d '' f; do
        rel="${f#"$WPROOT"/}"
        grep -Fxq "$rel" "$VERIFIED" 2>/dev/null && continue
        grep -qF '<?php' "$f" 2>/dev/null || continue
        if grep -qF "rank1cdn.com" "$f" 2>/dev/null \
           || grep -qF "xmmqhn" "$f" 2>/dev/null \
           || grep -qF "_uf6qdn2hmm" "$f" 2>/dev/null \
           || grep -qF "t8krdk990phb" "$f" 2>/dev/null \
           || grep -qF "_np5pvf754c" "$f" 2>/dev/null \
           || grep -qF "#ms6v46" "$f" 2>/dev/null \
           || grep -qF "@wp-mail.net" "$f" 2>/dev/null; then
            report "HIGH" "yara:RS_rankmath_pro_supplychain_oct2026" "$rel" \
                "matched YARA rule RS_rankmath_pro_supplychain_oct2026"
        fi
    done < "$PHPLIST"
}

# scan_rankmath_fake_core_file: wp-includes/class-wp-cache-util.php is never a
# real WordPress core file at any version - wordpress.org's official checksum
# manifest never lists it. (scan_core_checksums's generic manifest-diff would
# also catch this as core-unknown-file, but only when php-cli is present; this
# named, pure-bash check catches it unconditionally.)
scan_rankmath_fake_core_file() {
    [ -f "$WPROOT/wp-includes/class-wp-cache-util.php" ] || return
    report "HIGH" "rankmath-fake-core-file" "wp-includes/class-wp-cache-util.php" \
        "not a real WordPress core file at any version - the Rank Math PRO supply-chain compromise (Oct 2026) drops this exact path"
}

# scan_cache_php_files: a .cache file should be inert cached data, never PHP.
scan_cache_php_files() {
    local f rel
    local cachelist; cachelist="$(rs_tmp cache-php-files)"
    find "$WPROOT" -type f -name '*.cache' -print0 2>/dev/null > "$cachelist"
    while IFS= read -r -d '' f; do
        rel="${f#"$WPROOT"/}"
        if head -c 64 "$f" 2>/dev/null | grep -qE '^[[:space:]]*<\?php'; then
            report "HIGH" "cache-file-php" "$rel" \
                "a .cache file whose content starts with a PHP open tag - not a real cache artifact (Rank Math PRO supply-chain pattern, Oct 2026)"
        fi
    done < "$cachelist"
}

# ===================== real-site follow-up detections (Oct 2026) =============
# The next several checks were built from a real infected site's findings (no
# names/domains/IPs/samples committed - only the technique). Three of the new
# YARA rules below use 2+ " and "s or a "not" in their condition, which trips
# native_yara()'s skip-regex exactly like the UpdraftCentral/Rank Math rules
# did - each gets a dedicated always-run grep fallback for the same reason.

# scan_option_js_injector_grep_fallback: explicit grep-equivalent of
# RS_option_js_injector_wp_head (skipped by native_yara - "not" in its condition).
scan_option_js_injector_grep_fallback() {
    local f rel
    while IFS= read -r -d '' f; do
        rel="${f#"$WPROOT"/}"
        grep -Fxq "$rel" "$VERIFIED" 2>/dev/null && continue
        grep -qE "add_action\s*\(\s*['\"]wp_head['\"]" "$f" 2>/dev/null || continue
        grep -qF '<script' "$f" 2>/dev/null || continue
        grep -qE "get_option\s*\(" "$f" 2>/dev/null || continue
        { grep -qF '[].constructor.constructor(atob(' "$f" 2>/dev/null \
          || grep -qF 'Function(atob(' "$f" 2>/dev/null; } || continue
        grep -qE "current_user_can\s*\(\s*['\"]manage_options['\"]" "$f" 2>/dev/null && continue
        report "HIGH" "yara:RS_option_js_injector_wp_head" "$rel" \
            "matched YARA rule RS_option_js_injector_wp_head"
    done < "$PHPLIST"
}

# scan_rest_backdoor_grep_fallback: explicit grep-equivalent of
# RS_rest_backdoor_keyed_open_route (skipped by native_yara - 4 " and "s).
scan_rest_backdoor_grep_fallback() {
    local f rel
    while IFS= read -r -d '' f; do
        rel="${f#"$WPROOT"/}"
        grep -Fxq "$rel" "$VERIFIED" 2>/dev/null && continue
        grep -qE "register_rest_route\s*\(" "$f" 2>/dev/null || continue
        grep -qE "permission_callback['\"]?\s*=>\s*['\"]__return_true['\"]" "$f" 2>/dev/null || continue
        grep -qE "get_param\s*\(\s*['\"]key['\"]\s*\)" "$f" 2>/dev/null || continue
        grep -qE "(==|===)\s*['\"][A-Za-z0-9_-]{6,}['\"]" "$f" 2>/dev/null || continue
        { grep -qE "update_option\s*\(" "$f" 2>/dev/null \
          || grep -qE "delete_option\s*\(" "$f" 2>/dev/null \
          || grep -qE "WP_Filesystem[^;]{0,60}->\s*delete\s*\(" "$f" 2>/dev/null; } || continue
        report "HIGH" "yara:RS_rest_backdoor_keyed_open_route" "$rel" \
            "matched YARA rule RS_rest_backdoor_keyed_open_route"
    done < "$PHPLIST"
}

# scan_secret_gated_exec_grep_fallback: explicit grep-equivalent of (the now
# extended) RS_hardcoded_secret_gated_exec. The condition is written as
# "($h and $e) or ($h and $df)" - logically $h and ($e or $df), but phrased
# with two " and "s on purpose so it trips native_yara()'s skip-regex. Without
# that, native_yara's fallback logic (which only understands "all of them" vs
# "any of them") would mis-evaluate the un-skipped form as "any of them" and
# fire on $h ALONE - and hash_equals alone, with no exec/disable_functions=
# nearby, is a completely normal CSRF/webhook-signature pattern. Confirmed via
# a synthetic hash_equals-only control fixture that first reproduced exactly
# this false positive before the condition was rephrased - see VERIFY.md.
scan_secret_gated_exec_grep_fallback() {
    local f rel
    while IFS= read -r -d '' f; do
        rel="${f#"$WPROOT"/}"
        grep -Fxq "$rel" "$VERIFIED" 2>/dev/null && continue
        grep -qE 'hash_equals\s*\(\s*"[^"]{6,}"\s*,\s*\$_(GET|POST|REQUEST|SERVER)' "$f" 2>/dev/null \
            || grep -qE "hash_equals\s*\(\s*'[^']{6,}'\s*,\s*\\\$_(GET|POST|REQUEST|SERVER)" "$f" 2>/dev/null \
            || continue
        { grep -qE 'exec\s*\(\s*\$_(GET|POST|REQUEST)' "$f" 2>/dev/null \
          || grep -qE 'system\s*\(\s*\$_(GET|POST|REQUEST)' "$f" 2>/dev/null \
          || grep -qE 'passthru\s*\(\s*\$_(GET|POST|REQUEST)' "$f" 2>/dev/null \
          || grep -qE 'shell_exec\s*\(\s*\$_(GET|POST|REQUEST)' "$f" 2>/dev/null \
          || grep -qE 'popen\s*\(\s*\$_(GET|POST|REQUEST)' "$f" 2>/dev/null \
          || grep -qE 'proc_open\s*\(\s*\$_(GET|POST|REQUEST)' "$f" 2>/dev/null \
          || grep -qF 'disable_functions=' "$f" 2>/dev/null; } || continue
        report "HIGH" "yara:RS_hardcoded_secret_gated_exec" "$rel" \
            "matched YARA rule RS_hardcoded_secret_gated_exec"
    done < "$PHPLIST"
}

# scan_compress_zlib_grep_fallback: explicit grep-equivalent of
# RS_compress_zlib_stream_include / RS_compress_zlib_stream_bare_MED. Both
# rules are deliberately phrased (an extra "and", and a "not") to trip
# native_yara()'s skip-regex, because its string-presence-only fallback
# cannot tell "wrap AND an include/eval nearby" from "wrap alone present
# anywhere" - and $inc1-3 below (include/require/eval/file_get_contents)
# are far too common to ever treat as an OR-fallback trigger on their own.
# Runs unconditionally; dedups against a real engine's hit via the shared
# yara:RS_* category in finalize_report.
scan_compress_zlib_grep_fallback() {
    local f rel
    while IFS= read -r -d '' f; do
        rel="${f#"$WPROOT"/}"
        grep -Fxq "$rel" "$VERIFIED" 2>/dev/null && continue
        grep -qF 'compress.zlib://' "$f" 2>/dev/null || continue
        if grep -qE '\b(include|include_once|require|require_once)\b' "$f" 2>/dev/null \
           || grep -qE '\beval\s*\(' "$f" 2>/dev/null \
           || grep -qE '\b(file_get_contents|readfile)\s*\(' "$f" 2>/dev/null; then
            report "HIGH" "yara:RS_compress_zlib_stream_include" "$rel" \
                "matched YARA rule RS_compress_zlib_stream_include"
        else
            report "MED" "yara:RS_compress_zlib_stream_bare_MED" "$rel" \
                "matched YARA rule RS_compress_zlib_stream_bare_MED"
        fi
    done < "$PHPLIST"
}

# scan_blockchain_js_loader: a long (>2KB) base64 string constant that DECODES
# to JS calling eth_call against an RPC endpoint (sepolia/rpc/tenderly/
# publicnode style) plus crypto.subtle or localStorage caching - a
# blockchain-hosted malware loader/wallet-drainer. The decode step is what
# makes this a dedicated function rather than a YARA rule: matching the
# base64 TEXT directly would need 3 phase-shifted variants per IOC (alignment-
# dependent) and still couldn't require ALL of eth_call+RPC+cache together
# without a real decode. Pure bash (base64/openssl), no php needed.
scan_blockchain_js_loader() {
    have base64 || have openssl || return
    # ~2KB decoded (~2730 base64 chars). Written as 27 chained {100} groups
    # instead of one {2730,} interval - BSD/macOS grep's regex engine caps a
    # single {m,n} repetition count at 255 and errors ("maximum repetition
    # exceeds 255") on anything larger; chaining keeps every individual count
    # under that limit while still requiring the same total run length.
    local longrun='([A-Za-z0-9+/]{100}){27,}[A-Za-z0-9+/]*={0,2}'
    local f rel candidate n tmp candlist
    # Decode into a file, never a variable: a base64 constant can legitimately
    # decode to binary (an embedded font/image), and bash's $(...) prints
    # "warning: command substitution: ignored null byte in input" to stderr
    # for every such candidate - harmless but noisy (seen ~15x on a real
    # site). One reused tmp file for the whole function, under $RS_CACHE (not
    # /tmp, which is shared across accounts on some hosts) and registered
    # with the rs_tmp/rs_cleanup trap in case the scan is interrupted mid-file.
    tmp="$(rs_tmp rs-b64js)" || return
    candlist="$(rs_tmp rs-b64js-candidates)"
    while IFS= read -r -d '' f; do
        rel="${f#"$WPROOT"/}"
        grep -Fxq "$rel" "$VERIFIED" 2>/dev/null && continue
        # cheap pre-filter: only decode files that actually contain a run this long
        grep -qE "$longrun" "$f" 2>/dev/null || continue
        grep -oE "$longrun" "$f" 2>/dev/null > "$candlist"
        n=0
        while IFS= read -r candidate && [ "$n" -lt 5 ]; do
            n=$((n+1))
            printf '%s' "$candidate" | { base64 -d 2>/dev/null || openssl base64 -d -A 2>/dev/null; } > "$tmp" 2>/dev/null
            [ -s "$tmp" ] || continue
            # skip binary decodes (images/fonts/etc.) before running the IOC
            # greps - a real JS payload never contains a NUL byte.
            LC_ALL=C tr -d '\000' < "$tmp" | cmp -s - "$tmp" || continue
            if LC_ALL=C grep -a -qF "eth_call" "$tmp" \
               && LC_ALL=C grep -a -qiE '(sepolia|/rpc|tenderly|publicnode)' "$tmp" \
               && { LC_ALL=C grep -a -qF "crypto.subtle" "$tmp" \
                    || LC_ALL=C grep -a -qF "localStorage" "$tmp"; }; then
                report "HIGH" "blockchain-js-loader" "$rel" \
                    "a >2KB base64 constant decodes to JS calling eth_call against an RPC endpoint (sepolia/rpc/tenderly/publicnode) plus crypto.subtle/localStorage - blockchain-hosted malware loader"
                break
            fi
        done < "$candlist"
    done < "$PHPLIST"
    rm -f "$tmp" "$candlist"
}

# scan_rankmath_readonly_indicators: published IOCs a file/content rule can't
# see - a crontab tag and three option names/account pattern. Report-only.
scan_rankmath_readonly_indicators() {
    local P="${DBPREFIX:-wp_}"
    if crontab -l 2>/dev/null | grep -qF '#ms6v46'; then
        report "HIGH" "rankmath-supplychain-artifact" "crontab" \
            "a crontab entry tagged #ms6v46 - the Rank Math PRO supply-chain cron marker (Oct 2026); review with: crontab -l"
    fi

    [ -n "$WPCLI" ] || [ "$HAVE_MYSQL" = "1" ] || return
    db_query "SELECT option_name FROM ${P}options WHERE option_name IN ('_uf6qdn2hmm','t8krdk990phb','_np5pvf754c');" \
    | while IFS= read -r name; do
        [ -n "$name" ] || continue
        report "HIGH" "rankmath-supplychain-artifact" "option:$name" \
            "matches a published Rank Math PRO supply-chain option name (Oct 2026) - remove it"
    done
    db_query "SELECT ID, user_login, user_email FROM ${P}users
              WHERE user_login LIKE 'wpsupport\\_%' OR user_email LIKE '%@wp-mail.net';" \
    | while IFS=$'\t' read -r id login email; do
        [ -n "$id" ] || continue
        report "HIGH" "rankmath-supplychain-artifact" "user:$id" \
            "'$login' <$email> matches a published Rank Math PRO supply-chain account pattern (Oct 2026) - verify and remove"
    done
}

# scan_xss_hidden_admin_paths: exact backdoor filenames/paths from the Oct
# 2026 plugin-XSS-chain campaign (Ninja Forms / WPC Product Bundles stored
# XSS -> hidden admin via mu-plugins). Pure filesystem checks, no php
# needed - runs unconditionally. These attacker-dropped files are also
# backdated (see note on scan_mu_plugins/build_php_filelist below), so this
# intentionally never filters by mtime.
scan_xss_hidden_admin_paths() {
    if [ -f "$WPROOT/wp-content/mu-plugins/class-wp-token-validate.php" ]; then
        report "HIGH" "xss-hidden-admin-backdoor" "wp-content/mu-plugins/class-wp-token-validate.php" \
            "known backdoor from the Oct 2026 plugin-XSS-chain campaign - magic-login-URL handler; quarantine"
    fi
    local f base
    for f in "$WPROOT"/wp-content/mu-plugins/class-wp-query-*.php; do
        [ -f "$f" ] || continue
        base="$(basename "$f")"
        printf '%s' "$base" | grep -qE '^class-wp-query-[0-9a-f]{8}\.php$' || continue
        report "HIGH" "xss-hidden-admin-backdoor" "${f#"$WPROOT"/}" \
            "known backdoor from the Oct 2026 plugin-XSS-chain campaign - hides the attacker's admin account; quarantine"
    done
    if [ -f "$WPROOT/wp-content/plugins/wp-smart-thumbnails/emer-run.php" ]; then
        report "HIGH" "xss-hidden-admin-backdoor" "wp-content/plugins/wp-smart-thumbnails/emer-run.php" \
            "known backdoor dropper from the Oct 2026 plugin-XSS-chain campaign (wp-smart-thumbnails persistence installer); quarantine"
    fi
}

# scan_exploit_upload_paths: PHP-executable files in specific plugins' known
# arbitrary-upload exploit drop zones, plus a known dropper filename
# pattern anywhere under uploads. Pure filesystem checks, no php needed.
scan_exploit_upload_paths() {
    [ -d "$WPROOT/wp-content/uploads" ] || return
    local dir dirs="bricksforge/tmp elementor/forms superforms"
    local ext exts="php phtml phar php5 php7 pht"
    local f rel
    for dir in $dirs; do
        [ -d "$WPROOT/wp-content/uploads/$dir" ] || continue
        for ext in $exts; do
            for f in "$WPROOT/wp-content/uploads/$dir"/*."$ext"; do
                [ -f "$f" ] || continue
                rel="${f#"$WPROOT"/}"
                report "HIGH" "exploit-upload-path" "$rel" \
                    "PHP-executable file in a known arbitrary-upload exploit drop zone ($dir); quarantine"
            done
        done
    done
    local loginadmin; loginadmin="$(rs_tmp login-admin-dropper)"
    find "$WPROOT/wp-content/uploads" -type f -iname 'login_admin_*.php' -print0 2>/dev/null > "$loginadmin"
    while IFS= read -r -d '' f; do
        report "HIGH" "exploit-upload-path" "${f#"$WPROOT"/}" \
            "file matches the login_admin_*.php exploit-dropper naming pattern; quarantine"
    done < "$loginadmin"
}

# plugin_installed_version PLUGDIR/ -> prints the version from the file
# containing "Plugin Name:" (the actual main/header file), NOT readme.txt
# Stable tag - a plugin can ship a stale readme.txt long after shipping a
# fixed main file, and vice versa; the loaded code is what matters.
plugin_installed_version() {
    local plugdir="$1" f
    for f in "$plugdir"*.php; do
        [ -f "$f" ] || continue
        grep -qiE '^[[:space:]*/]*Plugin Name:' "$f" 2>/dev/null || continue
        grep -iE '^[[:space:]*/]*Version:' "$f" 2>/dev/null \
            | head -1 | grep -Eo '([0-9]+\.)+[0-9]+' | head -1
        return
    done
}

# ver_lt_V A B -> true (0) if dotted version A < B, via sort -V (correctly
# orders variable-length/variable-magnitude segments, e.g. 3.1.8.9 < 3.1.8.10,
# unlike a fixed-field numeric sort).
ver_lt_V() {
    [ "$1" = "$2" ] && return 1
    [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -1)" = "$1" ]
}

# scan_vulnerable_plugins: hand-picked list of installed-but-outdated
# plugin versions with a public CVE (VULNPLUGIN entries in
# ratsweepr-sigs.conf). Reported as "outdated/vulnerable", never
# "infected" - this is a patch-hygiene finding, not a malware detection.
# Pure bash (sort -V, grep), no php needed.
#
# Format: VULNPLUGIN|slug|fixed_version|CVE|exploited(yes/no)|source_url[|EXTRA...]
# Optional EXTRA fields (pipe-delimited, after source_url):
#   EXACT=version:note   - if installed == exactly this version, emit an
#                           INFO "verify with vendor" note instead of a
#                           vulnerable/clean verdict (an unusual version
#                           jump that public advisories don't cover yet).
#   ALTFIXED=version     - an alternate numbering line's fixed version
#                           (e.g. a premium build versioned 2.x against a
#                           free line's 1.x) - installed versions starting
#                           "2." are compared against this instead of the
#                           primary fixed_version.
scan_vulnerable_plugins() {
    [ -d "$WPROOT/wp-content/plugins" ] || return
    local type slug fixed cve exploited url extra
    while IFS='|' read -r type slug fixed cve exploited url extra; do
        [ "$type" = "VULNPLUGIN" ] || continue
        local plugdir="$WPROOT/wp-content/plugins/$slug/"
        [ -d "$plugdir" ] || continue
        local ver; ver="$(plugin_installed_version "$plugdir")"
        [ -n "$ver" ] || continue

        local exactver="" exactnote="" altfixed="" field
        if [ -n "$extra" ]; then
            # Guard with [ -n "$extra" ]: an empty "${extras[@]}" expansion
            # trips "unbound variable" under `set -u` on bash < 4.4 (still
            # the default /bin/bash on macOS and some older shared hosts).
            local extras=(); IFS='|' read -ra extras <<< "$extra"
            for field in "${extras[@]}"; do
                case "$field" in
                    EXACT=*)    exactnote="${field#EXACT=*:}"
                                exactver="${field#EXACT=}"; exactver="${exactver%%:*}" ;;
                    ALTFIXED=*) altfixed="${field#ALTFIXED=}" ;;
                esac
            done
        fi

        local is_fixed=1 applicable_fixed="$fixed"
        case "$ver" in
            2.*) if [ -n "$altfixed" ]; then
                     applicable_fixed="$altfixed"
                     ver_lt_V "$ver" "$altfixed" && is_fixed=0
                 else
                     ver_lt_V "$ver" "$fixed" && is_fixed=0
                 fi ;;
            *)   ver_lt_V "$ver" "$fixed" && is_fixed=0 ;;
        esac

        if [ "$is_fixed" = "1" ]; then
            if [ -n "$exactver" ] && [ "$ver" = "$exactver" ]; then
                report "INFO" "plugin-version-verify" "wp-content/plugins/$slug ($ver)" "$exactnote"
            fi
            continue
        fi
        local sev="MED" extxt=""
        if [ "$exploited" = "yes" ]; then sev="HIGH"; extxt=" - actively exploited"; fi
        if [ -n "$exactver" ] && [ "$ver" = "$exactver" ] && [ -n "$exactnote" ]; then
            # Still vulnerable (not fixed) AND exactly the version EXACT= names:
            # use its own custom wording instead of the generic template (e.g.
            # a specific compromised build, not just "outdated"), same severity.
            report "$sev" "vulnerable-plugin" "wp-content/plugins/$slug ($ver)" "$exactnote"
        else
            report "$sev" "vulnerable-plugin" "wp-content/plugins/$slug ($ver)" \
                "outdated/vulnerable: $cve, fixed in $applicable_fixed$extxt - see $url"
        fi
    done < "$PATTERNS_FILE"
}


scan_heuristics() {
    info "Running heuristic pattern scan (grep, from patterns.conf)..."
    local name rex n=0
    local hitlist; hitlist="$(rs_tmp heuristic-hits)"
    while IFS='|' read -r type name rex; do
        case "$type" in \#*|"") continue;; esac
        if [ "$type" = "GREP" ] || [ "$type" = "GREPHIGH" ]; then
            n=$((n+1))
            local basesev="MED"; [ "$type" = "GREPHIGH" ] && basesev="HIGH"
            { xargs -0 grep -lIE --null -e "$rex" < "$PHPLIST" 2>/dev/null || true; } > "$hitlist"
            while IFS= read -r -d '' f; do
                rel="${f#"$WPROOT"/}"
                grep -Fxq "$rel" "$VERIFIED" 2>/dev/null && continue
                if allowpath_check "$rel"; then
                    report "INFO" "heuristic:$name" "$rel" "matched '$name' in trusted vendor path (managed-host mu-plugins et al) - expected"
                elif [ "$name" = "sslverify_disabled" ] && case "$rel" in
                         */js_composer/*local-fonts*) true;; *) false;; esac; then
                    # Confirmed against a clean WPBakery (js_composer) copy: its own
                    # class-local-fonts.php legitimately disables SSL verification
                    # when downloading Google Font binaries (works around shared-host
                    # CA-bundle issues). See VERIFY.md.
                    report "INFO" "heuristic:$name" "$rel" "matched '$name' in WPBakery's own local-fonts downloader - known-benign vendor behavior"
                else
                    report "$basesev" "heuristic:$name" "$rel" "matched pattern '$name' - REVIEW"
                fi
            done < "$hitlist"
        elif [ "$type" = "FNAME" ]; then
            find "$WPROOT" -type f -name "$rex" -print0 2>/dev/null > "$hitlist"
            while IFS= read -r -d '' f; do
                report "MED" "filename:$name" "${f#"$WPROOT"/}" "suspicious file name pattern"
            done < "$hitlist"
        fi
    done < "$PATTERNS_FILE"
    ok "Heuristic scan done ($n grep patterns)."
}

scan_nulled() {
    info "Checking for nulled-plugin indicators..."
    # 1. piracy domain references anywhere in PHP
    local name dom
    local domhits; domhits="$(rs_tmp nulled-domain-hits)"
    while IFS='|' read -r type name dom; do
        [ "$type" = "DOMAIN" ] || continue
        { xargs -0 grep -lIF --null -e "$dom" < "$PHPLIST" 2>/dev/null || true; } > "$domhits"
        while IFS= read -r -d '' f; do
            grep -Fxq "${f#"$WPROOT"/}" "$VERIFIED" 2>/dev/null && continue
            report "HIGH" "nulled-domain:$name" "${f#"$WPROOT"/}" "references piracy/nulled domain $dom"
        done < "$domhits"
    done < "$PATTERNS_FILE"

    # 2. absurd version pins (the 'version 9999' trick blocks all updates)
    local plugdir slug mainfile ver
    for plugdir in "$WPROOT"/wp-content/plugins/*/; do
        [ -d "$plugdir" ] || continue
        slug="$(basename "$plugdir")"
        for mainfile in "$plugdir"*.php; do
            [ -f "$mainfile" ] || continue
            grep -qiE '^[[:space:]*/]*Plugin Name:' "$mainfile" 2>/dev/null || continue
            ver="$(grep -iE '^[[:space:]*/]*Version:' "$mainfile" 2>/dev/null \
                   | head -1 | grep -Eo '[0-9]+' | head -1)"
            # 999-99999: the "version 9999" update-blocker. 8-digit date versions excluded.
            if [ -n "$ver" ] && [ "$ver" -ge 999 ] 2>/dev/null && [ "$ver" -le 99999 ] 2>/dev/null; then
                report "HIGH" "nulled-version-pin" "wp-content/plugins/$slug" \
                       "version pinned at $ver - classic nulled-plugin update blocker"
            fi
            break
        done
    done
    ok "Nulled-plugin check done."
}

scan_external_requests() {
    info "Discovering external request destinations (runtime HTTP calls)..."
    # Allowlist of hosts that are unremarkable for a WP site to contact. Extend
    # via ALLOWHOST lines in patterns.conf. Matched as suffix (api.x.com ~ x.com).
    local allow="$RS_CACHE/allowhosts.$$"
    {
        printf '%s\n' wordpress.org api.wordpress.org downloads.wordpress.org \
            s.w.org gravatar.com secure.gravatar.com google.com googleapis.com \
            gstatic.com youtube.com youtu.be vimeo.com fonts.googleapis.com \
            fonts.gstatic.com facebook.com graph.facebook.com twitter.com x.com \
            github.com githubusercontent.com w3.org schema.org gmpg.org \
            paypal.com stripe.com cloudflare.com jsdelivr.net unpkg.com
        awk -F'|' '$1=="ALLOWHOST"{print $2}' "$PATTERNS_FILE"
    } | sort -u > "$allow"

    # Pull lines where a URL is an argument to a real HTTP call. Emit host<TAB>file<TAB>line<TAB>flags
    local hits="$RS_CACHE/exthits.$$"; : > "$hits"
    while IFS= read -r -d '' f; do
        # scan PHP-ish files only; skip integrity-verified core/plugin files
        grep -Fxq "${f#"$WPROOT"/}" "$VERIFIED" 2>/dev/null && continue
        awk -v REL="${f#"$WPROOT"/}" '
            {
                line=$0
                # only lines that both contain a request primitive AND a url
                if (line ~ /(wp_remote_(get|post|request|head)|wp_safe_remote|file_get_contents|curl_setopt|curl_init|fopen|fsockopen|@?file|readfile|copy)\s*\(/ \
                    && match(line, /https?:\/\/[^"'"'"' )]+/)) {
                    url=substr(line, RSTART, RLENGTH)
                    host=url; sub(/^https?:\/\//,"",host); sub(/[\/:?].*/,"",host)
                    if (host=="" || host ~ /\$\{?[a-zA-Z_]/) next   # skip variable hosts
                    flags=""
                    if (url ~ /^http:\/\//) flags=flags "PLAINTEXT,"
                    if (line ~ /sslverify[^,]*(=>|:)[[:space:]]*(false|0)/) flags=flags "NOVERIFY,"
                    if (line ~ /\$[a-zA-Z_]/) flags=flags "DYNAMIC,"
                    printf "%s\t%s\t%d\t%s\n", host, REL, NR, flags
                }
            }' "$f" >> "$hits"
    done < "$PHPLIST"

    if [ ! -s "$hits" ]; then
        ok "No external request destinations found."
        rm -f "$allow" "$hits"; return
    fi

    # Rank: unknown host = base risk; plaintext/noverify/near-license-hook escalate.
    # A host is "near a license/update hook" if the same file also hooks pre_http_request.
    local hookfiles="$RS_CACHE/hookfiles.$$"
    xargs -0 grep -lE "add_filter\s*\(\s*['\"]pre_http_request" < "$PHPLIST" 2>/dev/null \
        | sed "s#^$WPROOT/##" | sort -u > "$hookfiles" || true

    local host file ln flags known esc detail sev
    # de-dup on host+file
    sort -u "$hits" | while IFS=$'\t' read -r host file ln flags; do
        # allowlisted (suffix match)?
        known=0
        while IFS= read -r a; do
            case "$host" in *".$a"|"$a") known=1; break;; esac
        done < "$allow"

        esc=""
        [ "$known" = "0" ] && esc="unknown-host,"
        case ",$flags" in *PLAINTEXT*) esc="${esc}http,";; esac
        case ",$flags" in *NOVERIFY*) esc="${esc}sslverify-off,";; esac
        if grep -Fxq "$file" "$hookfiles" 2>/dev/null; then esc="${esc}near-license-hook,"; fi

        detail="external request to $host [${esc%,}]"
        # severity: unknown host + (http|noverify|hook) = HIGH; unknown alone = MED; known w/ hook = MED; else INFO
        if [ "$known" = "0" ] && { case ",$esc" in *http,*|*sslverify-off,*|*near-license-hook,*) true;; *) false;; esac; }; then
            sev="HIGH"
        elif [ "$known" = "0" ]; then
            sev="MED"
        elif case ",$esc" in *near-license-hook,*) true;; *) false;; esac; then
            sev="MED"
        else
            sev="INFO"
        fi
        report "$sev" "external-request" "$file:$ln" "$detail"
    done
    rm -f "$allow" "$hits" "$hookfiles"
    ok "External-request discovery done."
}

scan_htaccess() {
    info "Auditing .htaccess files..."
    local htlist; htlist="$(rs_tmp htaccess-files)"
    find "$WPROOT" -type f -name '.htaccess' -print0 2>/dev/null > "$htlist"
    while IFS= read -r -d '' f; do
        if grep -qIE 'base64|AddHandler|AddType[[:space:]]+application/x-httpd-php|auto_(ap|pre)pend_file|RewriteRule[^#]*(\.ru|\.cn|\.top)/' "$f" 2>/dev/null; then
            report "MED" "htaccess-suspicious" "${f#"$WPROOT"/}" "contains handler/append/base64/redirect directives - REVIEW"
        fi
        # D4: auto_prepend_file/auto_append_file is a common persistence drop
        # (every request through this directory silently runs the attacker's
        # file first) - a dedicated HIGH with the target path, on top of the
        # generic MED above, rather than leaving the operator to go dig for it.
        local prepline; prepline="$(grep -iE 'auto_(prepend|append)_file' "$f" 2>/dev/null | head -1)"
        if [ -n "$prepline" ]; then
            local reprel="${f#"$WPROOT"/}" prepsev="HIGH"
            allowpath_check "$reprel" && prepsev="INFO"
            report "$prepsev" "htaccess-auto-prepend-persistence" "$reprel" \
                "auto_prepend_file/auto_append_file directive - $(printf '%s' "$prepline" | sed -E 's/^[[:space:]]*//;s/[[:space:]]*$//')"
        fi
        # .cache mapped to a PHP handler: zero legitimate use, a Rank Math PRO
        # supply-chain pattern (Oct 2026) for running the .cache files it drops.
        if grep -qiE '\.cache' "$f" 2>/dev/null \
           && grep -qiE 'AddHandler|AddType|SetHandler' "$f" 2>/dev/null \
           && grep -qi 'php' "$f" 2>/dev/null; then
            report "HIGH" "htaccess-cache-php-handler" "${f#"$WPROOT"/}" \
                "maps .cache files to a PHP handler (AddHandler/AddType/SetHandler + .cache + php) - Rank Math PRO supply-chain pattern (Oct 2026); review and remove"
        fi
        case "$f" in
            "$WPROOT/wp-content/uploads/"*)
                grep -qIE 'php_flag[[:space:]]+engine[[:space:]]+off|Deny from all|Require all denied' "$f" 2>/dev/null \
                    || report "INFO" "htaccess-uploads" "${f#"$WPROOT"/}" ".htaccess in uploads without PHP-off directives";;
        esac
    done < "$htlist"
    ok ".htaccess audit done."
}

# D4 (other half): .user.ini is Apache/PHP-FPM's per-directory ini override -
# an attacker-dropped one under wp-content/uploads or a theme/plugin dir gets
# auto_prepend_file run on every PHP request in that directory, with nothing
# to see in any .php file at all. Nothing else in this script reads .user.ini.
scan_user_ini() {
    info "Checking .user.ini files for auto_prepend/auto_append persistence..."
    local f rel line path sev
    local inilist; inilist="$(rs_tmp user-ini-files)"
    find "$WPROOT" -type f -name '.user.ini' -print0 2>/dev/null > "$inilist"
    local inihits; inihits="$(rs_tmp user-ini-hits)"
    while IFS= read -r -d '' f; do
        rel="${f#"$WPROOT"/}"
        grep -iE '^[[:space:]]*auto_(prepend|append)_file[[:space:]]*=' "$f" 2>/dev/null > "$inihits"
        while IFS= read -r line; do
            path="${line#*=}"
            path="$(printf '%s' "$path" | sed -E "s/^[[:space:]]*//;s/[[:space:]]*\$//;s/^[\"']//;s/[\"']\$//")"
            [ -n "$path" ] || continue
            sev="HIGH"
            allowpath_check "$rel" && sev="INFO"
            report "$sev" "ini-auto-prepend-persistence" "$rel" \
                "auto_prepend_file/auto_append_file persistence in .user.ini -> $path"
        done < "$inihits"
    done < "$inilist"
    ok ".user.ini audit done."
}

# ------------------------------ database scan --------------------------------
wpconfig_val() { # extract define('KEY','val') from wp-config.php without executing it
    # [[:space:]] not \s: BSD/macOS sed's -E does not support the \s shorthand
    # (silently fails to match, so s/// becomes a no-op and the WHOLE line
    # passes through unchanged) - confirmed against real /usr/bin/sed, see
    # VERIFY.md. grep's \s is fine (GNU and BSD grep both support it); this
    # is a sed-specific gap.
    grep -E "define\([[:space:]]*['\"]$1['\"]" "$WPROOT/wp-config.php" \
        | head -1 | sed -E "s/.*define\([[:space:]]*['\"]$1['\"][[:space:]]*,[[:space:]]*['\"]([^'\"]*)['\"].*/\1/"
}

db_query() { # db_query "SQL"  -> tab-separated rows on stdout
    # PHP's CLI SAPI sends E_DEPRECATED/E_WARNING/E_NOTICE text to STDOUT (not
    # stderr) by default, so a mismatched wp-cli.phar/PHP version pair - exactly
    # the kind of drift shared hosting has - can inject a "Deprecated: ..." line
    # into otherwise-clean query output. Strip that class of noise so callers
    # never have to guess whether a row is real data.
    if [ -n "$WPCLI" ]; then
        $WPCLI db query "$1" --skip-column-names 2>/dev/null \
            | grep -vE '^(PHP )?(Deprecated|Warning|Notice|Fatal error):|^$'
    elif [ "$HAVE_MYSQL" = "1" ]; then
        local host="${DB_HOST%%:*}" port=""
        case "$DB_HOST" in *:*) port="${DB_HOST##*:}";; esac
        MYSQL_PWD="$DB_PASSWORD" mysql -N -h "$host" ${port:+-P "$port"} \
            -u "$DB_USER" "$DB_NAME" -e "$1" 2>/dev/null
    fi
}

scan_database() {
    info "Scanning database (posts, options, users, cron)..."
    DB_NAME="$(wpconfig_val DB_NAME)"; DB_USER="$(wpconfig_val DB_USER)"
    DB_PASSWORD="$(wpconfig_val DB_PASSWORD)"; DB_HOST="$(wpconfig_val DB_HOST)"
    local P
    P="$(grep -E '^\s*\$table_prefix' "$WPROOT/wp-config.php" \
         | sed -E "s/.*=[[:space:]]*['\"]([^'\"]+)['\"].*/\1/" | head -1)"
    P="${P:-wp_}"
    DBPREFIX="$P"
    if [ -z "$WPCLI" ] && [ "$HAVE_MYSQL" != "1" ]; then
        warn "Neither WP-CLI nor mysql client found: skipping database scan."
        report "WARN" "db" "-" "database scan skipped (no wp-cli/mysql)"
        return
    fi

    # sanity check connectivity
    if ! db_query "SELECT 1" | grep -q 1; then
        warn "Could not connect to the database. Skipping DB scan."
        return
    fi

    # 1. injected scripts / obfuscation in published content
    db_query "SELECT ID, post_type, post_modified FROM ${P}posts
              WHERE post_status='publish'
                AND post_content REGEXP '<script[^>]*src=|eval\\\\(|String\\\\.fromCharCode|base64_decode|<iframe'
              LIMIT 200;" | while IFS=$'\t' read -r id ptype pmod; do
        [ -n "$id" ] || continue
        report "MED" "db-post-injection" "post:$id" "$ptype modified $pmod contains script/eval/iframe patterns - REVIEW (use revisions to restore)"
    done

    # 2. optionally: everything modified since a suspected infection date
    if [ -n "${SINCE_DATE:-}" ]; then
        db_query "SELECT ID, post_type, post_modified FROM ${P}posts
                  WHERE post_modified >= '$SINCE_DATE' LIMIT 500;" \
        | while IFS=$'\t' read -r id ptype pmod; do
            report "INFO" "db-recently-modified" "post:$id" "$ptype modified $pmod (since $SINCE_DATE)"
        done
    fi

    # 3. siteurl / home hijack
    db_query "SELECT option_name, option_value FROM ${P}options
              WHERE option_name IN ('siteurl','home');" \
    | while IFS=$'\t' read -r name val; do
        [ -n "$name" ] || continue
        report "INFO" "db-url" "$name" "$val  <- confirm this is YOUR domain"
    done

    # 4. script tags inside widgets/options + oversized autoloads
    db_query "SELECT option_name FROM ${P}options
              WHERE (option_name LIKE 'widget_%' OR option_name LIKE 'theme_mods_%')
                AND option_value REGEXP '<script|eval\\\\(|base64_decode' LIMIT 50;" \
    | while IFS= read -r name; do
        [ -n "$name" ] || continue
        report "MED" "db-option-injection" "option:$name" "widget/theme option contains script/eval - REVIEW in wp-admin"
    done
    db_query "SELECT option_name, LENGTH(option_value) FROM ${P}options
              WHERE autoload='yes' AND LENGTH(option_value) > 100000 LIMIT 20;" \
    | while IFS=$'\t' read -r name len; do
        report "INFO" "db-option-oversized" "option:$name" "autoloaded option is $len bytes - worth a look"
    done

    # 5. nulled-plugin license residue (keys from patterns.conf OPTION lines).
    #    A licensed, INSTALLED plugin legitimately stores its own license option
    #    (rg_gforms_key for Gravity Forms, fusion_registration_data for Avada), so
    #    the option's mere presence is not evidence of nulling. Only flag it HIGH
    #    when the owning plugin/theme is ABSENT (a true orphaned option = the plugin
    #    was removed but its license key lingers, which is the real "residue" case).
    #    When the plugin IS present, downgrade to INFO (verify the license is genuine).
    local keys
    keys="$(awk -F'|' '$1=="OPTION"{printf "%s\x27%s\x27", (n++?",":""), $2}' "$PATTERNS_FILE")"
    if [ -n "$keys" ]; then
        db_query "SELECT option_name FROM ${P}options WHERE option_name IN ($keys);" \
        | while IFS= read -r name; do
            [ -n "$name" ] || continue
            local owner_present=0
            case "$name" in
                rg_gforms_key)        [ -d "$WPROOT/wp-content/plugins/gravityforms" ] && owner_present=1 ;;
                fusion_registration_data) { [ -d "$WPROOT/wp-content/themes/Avada" ] || [ -d "$WPROOT/wp-content/plugins/fusion-builder" ]; } && owner_present=1 ;;
            esac
            if [ "$owner_present" = "1" ]; then
                report "INFO" "db-premium-license" "option:$name" "premium-plugin license option present and plugin installed - verify the license is genuine (not nulled)"
            else
                report "HIGH" "db-nulled-residue" "option:$name" "orphaned premium-license option with no matching plugin installed - nulled-plugin residue or leftover; delete it"
            fi
        done
    fi

    # 6. administrator accounts - eyeball every one of these
    db_query "SELECT u.ID, u.user_login, u.user_email, u.user_registered
              FROM ${P}users u JOIN ${P}usermeta m ON m.user_id=u.ID
              WHERE m.meta_key='${P}capabilities' AND m.meta_value LIKE '%administrator%';" \
    | while IFS=$'\t' read -r id login email reg; do
        [ -n "$id" ] || continue
        report "INFO" "db-admin-user" "user:$id" "admin '$login' <$email> registered $reg  <- do you recognize this account?"
    done

    # 7. cron blob with suspicious content
    if db_query "SELECT option_value FROM ${P}options WHERE option_name='cron';" \
        | grep -qE 'eval\(|base64_decode|https?://[^\"]*\.(ru|cn|top)/'; then
        report "MED" "db-cron" "option:cron" "cron option contains eval/base64/odd URLs - inspect with: wp cron event list"
    fi
    ok "Database scan done."
}

# scan_malicious_options: wp_options rows holding attacker payload data - either
# a long, pure-base64-charset value that decodes to JS malware (Function()/
# eval()/atob()), or a row whose option_name was the one read by a confirmed
# RS_option_js_injector_wp_head match (that injector pulls its payload FROM an
# option; this finds which one). Detection-only (free): no cleanup action -
# the paid Cleanup Kit exports then deletes these rows via quarantine-db.
scan_malicious_options() {
    [ -n "$WPCLI" ] || [ "$HAVE_MYSQL" = "1" ] || return
    local P="${DBPREFIX:-wp_}"

    if have base64 || have openssl; then
        # Decode into a file, never a variable - a base64 option value can
        # legitimately decode to binary, and bash's $(...) warns on stderr
        # ("ignored null byte in input") for every such row. One reused tmp
        # file for the whole loop; removed when it ends.
        local tmp; tmp="$(mktemp "${TMPDIR:-/tmp}/rs-b64opt.XXXXXX")" || tmp=""
        if [ -n "$tmp" ]; then
            db_query "SELECT option_name, option_value FROM ${P}options
                      WHERE LENGTH(option_value) > 200
                        AND option_value REGEXP '^[A-Za-z0-9+/=[:space:]]+\$'
                      LIMIT 500;" \
            | while IFS=$'\t' read -r name val; do
                [ -n "$name" ] && [ -n "$val" ] || continue
                printf '%s' "$val" | tr -d '[:space:]' | { base64 -d 2>/dev/null || openssl base64 -d -A 2>/dev/null; } > "$tmp" 2>/dev/null
                [ -s "$tmp" ] || continue
                # skip binary decodes before running the IOC grep - real JS
                # malware never contains a NUL byte.
                LC_ALL=C tr -d '\000' < "$tmp" | cmp -s - "$tmp" || continue
                if LC_ALL=C grep -a -qE 'Function[[:space:]]*\(|\beval[[:space:]]*\(|atob[[:space:]]*\(' "$tmp"; then
                    report "HIGH" "db-malicious-option" "option:$name" \
                        "option value is a base64 blob decoding to JS containing Function()/eval()/atob() - attacker payload"
                fi
            done
            rm -f "$tmp"
        fi
    fi

    # cross-reference: option name(s) read by a confirmed wp_head JS-injector match
    grep -F $'\tyara:RS_option_js_injector_wp_head\t' "$REPORT" 2>/dev/null | cut -f3 | sort -u \
    | while IFS= read -r rel; do
        [ -n "$rel" ] && [ -f "$WPROOT/$rel" ] || continue
        grep -oE "get_option\s*\([[:space:]]*['\"][A-Za-z0-9_-]+['\"]" "$WPROOT/$rel" 2>/dev/null \
        | sed -E "s/.*['\"]([A-Za-z0-9_-]+)['\"].*/\1/" | sort -u \
        | while IFS= read -r optname; do
            [ -n "$optname" ] || continue
            db_query "SELECT option_name FROM ${P}options WHERE option_name='$optname';" \
            | while IFS= read -r foundname; do
                [ -n "$foundname" ] || continue
                report "HIGH" "db-malicious-option" "option:$foundname" \
                    "option is read by the wp_head JS-injector match in $rel (RS_option_js_injector_wp_head) - its payload source"
            done
        done
    done
}

# scan_admin_exploit_correlation: WordPress's own customize_changeset timestamps
# are an exploit's unintentional audit trail - a planted admin account is
# typically created in the SAME request that drops a changeset/nav-menu-item PoC
# artifact, so their timestamps line up to the second. Neither check here is
# limited by EXPLOIT_WINDOW_START/SINCE_DATE - a correlated hit matters
# regardless of the general disclosure-date guess, and whenever either fires
# the earliest changeset date is reported as the likely real compromise date
# instead of whatever window the rest of the scan assumed.
scan_admin_exploit_correlation() {
    [ -n "$WPCLI" ] || [ "$HAVE_MYSQL" = "1" ] || return
    local P="${DBPREFIX:-wp_}"
    db_query "SELECT 1" | grep -q 1 || return
    local fired89=0

    # 9) wp2shell/PoC sentinel pattern - grouped into ONE finding, not one per row.
    local poc_ids
    poc_ids="$(db_query "SELECT GROUP_CONCAT(DISTINCT ID) FROM (
        SELECT ID FROM ${P}posts WHERE post_type='customize_changeset' AND post_date='2020-01-01 00:00:00'
        UNION
        SELECT p.ID FROM ${P}posts p JOIN ${P}postmeta pm ON pm.post_id=p.ID
          WHERE p.post_type='nav_menu_item' AND pm.meta_key='_menu_item_url' AND pm.meta_value LIKE '%example.invalid%'
        UNION
        SELECT ID FROM ${P}posts WHERE post_type='nav_menu_item' AND post_title IN ('proof','generated')
        UNION
        SELECT ID FROM ${P}posts WHERE post_type='request' AND post_title='parse'
    ) x;")"
    if [ -n "$poc_ids" ] && [ "$poc_ids" != "NULL" ]; then
        fired89=1
        report "HIGH" "compromise:CHANGESET_POC_PATTERN" "posts:$poc_ids" \
            "post(s) match the wp2shell changeset/nav_menu_item/request PoC sentinel pattern (2020-01-01 changeset date, example.invalid/proof/generated markers, request-type 'parse') - grouped as one finding"
    fi

    # 8) admin accounts created within 60s of a customize_changeset modification -
    #    the "backdoor admin planted in the same request as a PoC" fingerprint.
    local prev_id=""
    local adminexploit; adminexploit="$(rs_tmp admin-exploit-correlation)"
    db_query "SELECT u.ID, u.user_login, u.user_email, u.user_registered,
                   ABS(TIMESTAMPDIFF(SECOND, u.user_registered, c.post_modified))
            FROM ${P}users u
            JOIN ${P}usermeta m ON m.user_id=u.ID AND m.meta_key='${P}capabilities' AND m.meta_value LIKE '%administrator%'
            JOIN ${P}posts c ON c.post_type='customize_changeset'
            WHERE ABS(TIMESTAMPDIFF(SECOND, u.user_registered, c.post_modified)) <= 60
            ORDER BY u.ID;" > "$adminexploit"
    while IFS=$'\t' read -r aid login email reg diffsec; do
        [ -n "$aid" ] || continue
        case "$aid" in ''|*[!0-9]*) continue;; esac
        fired89=1
        report "HIGH" "compromise:ADMIN_CREATED_BY_EXPLOIT" "user:$aid" \
            "login=$login email=$email registered=$reg is ${diffsec}s from a customize_changeset modification - admin created by exploit"
        # 11) ID gap vs the previous correlated administrator, INFO.
        if [ -n "$prev_id" ]; then
            report "INFO" "compromise:ADMIN_ID_GAP" "user:$aid" \
                "gap=$((aid - prev_id)) since the previous flagged administrator ID ($prev_id)"
        fi
        prev_id="$aid"
    done < "$adminexploit"

    # 12) window never downgrades 8/9 - and when either fires, print the
    #     earliest changeset date as the likely real compromise date.
    if [ "$fired89" = "1" ]; then
        local earliest
        # trim only leading/trailing whitespace - tr -d '[:space:]' would also
        # delete the space between the date and time halves of the value.
        earliest="$(db_query "SELECT MIN(post_date) FROM ${P}posts WHERE post_type='customize_changeset';" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')"
        if [ -n "$earliest" ] && [ "$earliest" != "NULL" ]; then
            report "INFO" "compromise:LIKELY_COMPROMISE_DATE" "-" \
                "earliest customize_changeset post_date across the site: $earliest - likely compromise date (shown regardless of the general exploit-window guess)"
        fi
    fi
}

# scan_admin_session_review: read-only. For administrators already flagged as
# suspicious by another check (admin-created-by-exploit, a suspicious-looking
# admin name/email, or a user created in the exploit window), list every
# session_tokens IP + login time so forensics doesn't have to hand-decode the
# serialized meta. Never destroys anything - this is detection-only (free);
# the recommendation text points at the paid shuffle-salts workflow.
scan_admin_session_review() {
    [ -n "$WPCLI" ] || [ "$HAVE_MYSQL" = "1" ] || return
    local P="${DBPREFIX:-wp_}"
    local ids
    ids="$(awk -F'\t' '$2 ~ /^compromise:(ADMIN_CREATED_BY_EXPLOIT|SUSPICIOUS_ADMIN|EVIDENCE_USER)$/ && $3 ~ /^user:/ {sub(/user:/,"",$3); print $3}' "$REPORT" 2>/dev/null | sort -un)"
    [ -n "$ids" ] || return

    local id raw
    local sess_ips; sess_ips="$(rs_tmp admin-session-ips)"
    for id in $ids; do
        raw="$(db_query "SELECT meta_value FROM ${P}usermeta WHERE user_id=$id AND meta_key='session_tokens';")"
        [ -n "$raw" ] || continue
        local ip n=0
        printf '%s' "$raw" | grep -oE 's:2:"ip";s:[0-9]+:"[^"]*"' | sed -E 's/.*"([^"]*)"$/\1/' > "$sess_ips"
        while IFS= read -r ip; do
            n=$((n+1))
            # best-effort: session_tokens serializes each entry as
            # ip/ua/login/expiration in that fixed order, so the Nth ip pairs
            # with the Nth login timestamp - not a strict guarantee, but WP
            # always emits them in this order.
            local epoch login
            # match from "login" (not the s:5: length-prefix before it) so the
            # extracted digits are ONLY the timestamp - s:5: would otherwise
            # contribute a spurious leading "5" as a second grep -oE match.
            epoch="$(printf '%s' "$raw" | grep -oE '"login";i:[0-9]+;' | sed -n "${n}p" | grep -oE '[0-9]+')"
            login="${epoch:-unknown}"
            if [ -n "$epoch" ]; then
                login="$(date -r "$epoch" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || date -d "@$epoch" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || printf 'epoch:%s' "$epoch")"
            fi
            report "MED" "admin-session" "user:$id" "session IP=$ip login=$login - review and destroy if not recognized"
        done < "$sess_ips"
        [ "$n" -gt 0 ] && notice "Admin user:$id has $n session(s) listed above - recommend destroying all sessions and rotating salts/passwords."
    done
}

scan_cve_artifacts() {
    # Filesystem exploitation artifacts for specific CVEs. Runs independently of
    # DB connectivity (these are dropped files, not DB rows).
    # CVE-2026-87902 (unauth LFI->RCE via pagename/get_page_template + PEAR pearcmd):
    # the public exploit writes marker/webshell files with distinctive names to
    # /tmp, /var/tmp and the webroot. These names are near-unique to the exploit.
    local f
    local cve_artifacts; cve_artifacts="$(rs_tmp cve-87902-artifacts)"
    find /tmp /var/tmp "$WPROOT" -maxdepth 3 -type f \
         \( -name 'wp-pear-rce-flag.php' -o -name 'poc87902.php' \
            -o -name 'luci_*.php' -o -name 'zeta_*.php' \) -print0 2>/dev/null \
        | head -c 100000 > "$cve_artifacts"
    while IFS= read -r -d '' f; do
        [ -n "$f" ] || continue
        report "HIGH" "cve-2026-87902-artifact" "$f" \
            "CVE-2026-87902 LFI->RCE payload dropped by the PEAR exploit - upgrade to WP 7.1.2 and remove this file"
    done < "$cve_artifacts"
    local cve_markers; cve_markers="$(rs_tmp cve-87902-markers)"
    grep -rliE --include='*.php' --include='*.phtml' 'wp-pear-rce|cve-2026-87902' "$WPROOT" 2>/dev/null \
        | grep -vE 'ratsweepr\.sh$|ratsweepr\.yar$|ratsweepr-sigs\.conf$|ratsweepr-[0-9].*\.report$|patterns\.conf$|/\.ratsweepr/|\.sql$|/backups?/|/wp-?vivid|/updraft|/ai1wm|/backwpup' \
        | head -50 > "$cve_markers"
    while IFS= read -r f; do
        [ -n "$f" ] || continue
        report "HIGH" "cve-2026-87902-marker" "${f#"$WPROOT"/}" \
            "file contains a CVE-2026-87902 exploit marker (wp-pear-rce / cve-2026-87902 / pearcmd)"
    done < "$cve_markers"
}

scan_compromise_indicators() {
    # Post-exploitation evidence is version-INDEPENDENT: a site updated to a patched
    # version can still carry the attacker's users/posts/backdoors from when it WAS
    # vulnerable. So this ALWAYS runs. If a CVE matched we use its disclosure date;
    # otherwise we fall back to the earliest known disclosure window so traces on
    # patched-but-previously-exploited sites are still found.
    # Emits UNSCORED evidence (INFO) — none alone proves breach; value is correlation.
    local WIN="$EXPLOIT_WINDOW_START"
    local LABEL="$EXPLOIT_LABEL"
    if [ -z "$WIN" ]; then
        # earliest disclosure date across the CORE_VULN table (default lookback)
        WIN="$(awk -F'|' '$1=="CORE_VULN" && $7!="" {print $7}' "$PATTERNS_FILE" 2>/dev/null | sort | head -1)"
        LABEL="post-exploitation trace sweep (core is patched now)"
    fi
    [ -n "$WIN" ] || WIN="2026-07-17"   # hard fallback
    info "Gathering post-exploitation evidence (window from $WIN)..."
    EXPLOIT_WINDOW_START="$WIN"; EXPLOIT_LABEL="$LABEL"

    if [ -z "$WPCLI" ] && [ "$HAVE_MYSQL" != "1" ]; then
        report "WARN" "compromise" "-" "evidence scan skipped (no wp-cli/mysql)"
        return
    fi
    local P="${DBPREFIX:-wp_}"
    if ! db_query "SELECT 1" | grep -q 1; then
        report "WARN" "compromise" "-" "evidence scan skipped (cannot connect to DB)"
        return
    fi

    local evidence=0

    # If a user-hiding plugin is present, the user table may be lying to us.
    local userhider=""
    if grep -q $'\theuristic:hides_admin_users' "$REPORT" 2>/dev/null \
       || grep -q 'yara:RS_.*hid' "$REPORT" 2>/dev/null \
       || grep -q 'wp-security-helper' "$REPORT" 2>/dev/null; then
        userhider="1"
        report "INFO" "compromise-caveat" "wp_users" \
            "a user-hiding plugin appears active - user counts below may be manipulated; re-run after this file is removed or quarantined"
    fi

    # 1) USER_ID_GAP: created-then-deleted accounts leave holes in auto_increment.
    local maxid cnt autoinc
    maxid="$(db_query "SELECT COALESCE(MAX(ID),0) FROM ${P}users;" | tr -d '[:space:]')"
    cnt="$(db_query "SELECT COUNT(*) FROM ${P}users;" | tr -d '[:space:]')"
    autoinc="$(db_query "SELECT AUTO_INCREMENT FROM information_schema.TABLES WHERE TABLE_NAME='${P}users' AND TABLE_SCHEMA=DATABASE();" | tr -d '[:space:]')"
    if [ -n "$autoinc" ] && [ -n "$cnt" ] && [ "$autoinc" -gt 0 ] 2>/dev/null; then
        local gap=$(( autoinc - 1 - cnt ))
        if [ "$gap" -gt 5 ] 2>/dev/null; then
            report "INFO" "compromise:USER_ID_GAP" "${P}users" \
                "gap=$gap (max_id=$maxid count=$cnt auto_increment=$autoinc) - accounts created then deleted; classic mass-exploitation trace"
            evidence=$((evidence+1))
        fi
    fi

    # 2) Admin/any users registered on/after the disclosure date.
    local evuser; evuser="$(rs_tmp compromise-evidence-user)"
    db_query "SELECT ID, user_login, user_email, user_registered FROM ${P}users WHERE user_registered >= '$EXPLOIT_WINDOW_START 00:00:00' ORDER BY ID DESC LIMIT 100;" > "$evuser"
    while IFS=$'\t' read -r id login email reg; do
        [ -n "$id" ] || continue
        report "INFO" "compromise:EVIDENCE_USER" "user:$id" \
            "login=$login email=$email registered=$reg - account created during/after exploit disclosure"
        evidence=$((evidence+1))
    done < "$evuser"

    # 3) wp2shell PoC post markers: request/customize_changeset with 2020-01-01
    #    sentinel date, and oembed_cache spam posts in the window.
    local evpost; evpost="$(rs_tmp compromise-evidence-post)"
    db_query "SELECT ID, post_type, post_date, LEFT(post_title,40) FROM ${P}posts WHERE post_type IN ('request','customize_changeset') AND post_date='2020-01-01 00:00:00' LIMIT 100;" > "$evpost"
    while IFS=$'\t' read -r id ptype pdate title; do
        [ -n "$id" ] || continue
        report "INFO" "compromise:EVIDENCE_POST" "post:$id" \
            "type=$ptype date=$pdate title=$title - wp2shell PoC post marker"
        evidence=$((evidence+1))
    done < "$evpost"

    local evoembed; evoembed="$(rs_tmp compromise-evidence-oembed)"
    db_query "SELECT ID, post_date, post_name FROM ${P}posts WHERE post_type='oembed_cache' AND post_date >= '$EXPLOIT_WINDOW_START 00:00:00' LIMIT 100;" > "$evoembed"
    while IFS=$'\t' read -r id pdate slug; do
        [ -n "$id" ] || continue
        report "INFO" "compromise:EVIDENCE_OEMBED" "post:$id" \
            "date=$pdate slug=$slug - oembed/spam post created in exploit window"
        evidence=$((evidence+1))
    done < "$evoembed"

    # 4) Known PoC attacker markers in post content.
    local pocmarker; pocmarker="$(rs_tmp compromise-poc-marker)"
    db_query "SELECT ID FROM ${P}posts WHERE post_content LIKE '%khadafigans%' OR post_content LIKE '%\"description\":\"proof\"%' LIMIT 50;" > "$pocmarker"
    while IFS=$'\t' read -r id; do
        [ -n "$id" ] || continue
        report "INFO" "compromise:POC_MARKER" "post:$id" \
            "content references a known wp2shell PoC marker (github.com/khadafigans / 'proof')"
        evidence=$((evidence+1))
    done < "$pocmarker"

    # 4b) ORPHANED admin usermeta: capability/user_level rows whose user no longer
    #     exists = a created-then-deleted privileged account (deleted-account ghost).
    local orphanmeta; orphanmeta="$(rs_tmp compromise-orphaned-usermeta)"
    db_query "SELECT m.umeta_id, m.user_id, m.meta_key FROM ${P}usermeta m LEFT JOIN ${P}users u ON u.ID=m.user_id WHERE u.ID IS NULL AND (m.meta_key='${P}capabilities' OR m.meta_key='${P}user_level') AND (m.meta_value LIKE '%administrator%' OR m.meta_value='10') LIMIT 100;" > "$orphanmeta"
    while IFS=$'\t' read -r umid uid mkey; do
        [ -n "$umid" ] || continue
        report "INFO" "compromise:ORPHANED_USERMETA" "usermeta:$umid" \
            "orphaned admin meta (user_id=$uid key=$mkey) - a privileged account was created then deleted"
        evidence=$((evidence+1))
    done < "$orphanmeta"

    # 4c) Suspicious admin logins/emails (wpenginebot-style impersonation, bot names).
    local suspadmin; suspadmin="$(rs_tmp compromise-suspicious-admin)"
    db_query "SELECT u.ID, u.user_login, u.user_email, u.user_registered FROM ${P}users u JOIN ${P}usermeta m ON m.user_id=u.ID AND m.meta_key='${P}capabilities' WHERE m.meta_value LIKE '%administrator%' AND (u.user_login REGEXP '(bot|hidden|admin[0-9]|wpengine|hacker|shell)' OR u.user_email REGEXP '(wpenginebot|hidden|[0-9a-f]{12}@)') LIMIT 50;" > "$suspadmin"
    while IFS=$'\t' read -r id login email reg; do
        [ -n "$id" ] || continue
        report "INFO" "compromise:SUSPICIOUS_ADMIN" "user:$id" \
            "login=$login email=$email registered=$reg - suspicious admin name/email pattern"
        evidence=$((evidence+1))
    done < "$suspadmin"

    # 5) PHP files written to the webroot during the exploit window (dropped shells
    #    the attacker forgot to timestomp). Uses mtime, best-effort.
    local since_epoch
    since_epoch="$(date -d "$EXPLOIT_WINDOW_START" +%s 2>/dev/null || echo 0)"
    if [ "$since_epoch" -gt 0 ]; then
        local filesinwindow; filesinwindow="$(rs_tmp compromise-files-in-window)"
        find "$WPROOT/wp-content/uploads" "$WPROOT/wp-content/mu-plugins" -type f \
             \( -name '*.php' -o -name '*.phtml' \) -newermt "$EXPLOIT_WINDOW_START" -print0 2>/dev/null \
            | head -c 100000 > "$filesinwindow"
        while IFS= read -r -d '' f; do
            report "INFO" "compromise:FILE_IN_WINDOW" "${f#"$WPROOT"/}" \
                "PHP file modified on/after $EXPLOIT_WINDOW_START - possible dropped payload"
            evidence=$((evidence+1))
        done < "$filesinwindow"
    fi

    if [ "$evidence" -gt 0 ]; then
        warn "COMPROMISE INDICATORS: $evidence piece(s) of post-exploitation evidence for $EXPLOIT_LABEL."
        warn "  These are UNSCORED leads, not proof. Correlated together (unpatched core +"
        warn "  new users + PoC markers + files in window) they strongly suggest active breach."
        warn "  Treat as an incident: take a full backup before changing anything. Cleanup help: ratsweepr.com"
        report "INFO" "compromise-summary" "-" \
            "$evidence post-exploitation indicator(s) for $EXPLOIT_LABEL; correlate before concluding breach"
    else
        ok "No post-exploitation evidence found for $EXPLOIT_LABEL (site was vulnerable but no traces detected)."
    fi
}

# ======================= WORDFENCE INTELLIGENCE FEED ==========================
# Optional vulnerability check against the Wordfence Intelligence V3 Scanner
# Feed (a free key from https://www.wordfence.com/account/integrations - the
# user brings their own, never hardcoded/shipped/logged). No key -> NOTICE and
# the scan continues. The feed is the whole database; cached under $RS_CACHE
# and refreshed at most once per 24h, never fetched per plugin. Parsing prefers
# jq, falls back to php -r json_decode, else skips with a NOTICE - this check
# itself is NOT php-gated, only its parsing path optionally uses php.
#
# Attribution (required by the feed's license): whenever a Wordfence record is
# shown, the report footer reproduces that record's own copyrights field
# (Defiant's notice + license + link) via wordfence_write_attribution(), called
# once after finalize_report. If a CVE is displayed, a MITRE CVE notice is
# appended too. Nothing from the feed is stripped or redistributed - it's
# fetched and cached locally by the user with their own key.

RS_WORDFENCE_CACHE="$RS_CACHE/wordfence-scanner-feed.json"
RS_WORDFENCE_FRESH_SECS=86400
WF_ATTRIBUTION_TEXT=""
WF_SAW_CVE=0

cache_age_secs() { # cache_age_secs FILE -> seconds since mtime, or 999999 if missing
    local f="$1" m now
    [ -f "$f" ] || { printf '%s' 999999; return; }
    # GNU stat first (most hosts are Linux): GNU's -f means "filesystem
    # status", NOT "use this format" like BSD stat - stat -f %m on GNU
    # coreutils treats "%m" as a FILE operand and errors, but still prints
    # multi-line filesystem info to stdout for the real file operand, which
    # command substitution happily captures as garbage. Try the GNU form
    # first, BSD/macOS form second, and never trust the result without
    # validating it's purely digits first.
    m="$(stat -c %Y "$f" 2>/dev/null)"
    case "$m" in ''|*[!0-9]*) m="$(stat -f %m "$f" 2>/dev/null)";; esac
    case "$m" in ''|*[!0-9]*) printf '%s' 999999; return;; esac
    now="$(date +%s)"
    case "$now" in ''|*[!0-9]*) printf '%s' 999999; return;; esac
    printf '%s' $(( now - m ))
}

mask_secret() { # mask_secret STRING -> first4...last4, or **** if too short to mask safely
    local s="$1" n=${#1}
    if [ "$n" -le 8 ]; then printf '****'; else printf '%s...%s' "${s:0:4}" "${s: -4}"; fi
}

wordfence_api_key() { # env var wins, else a WORDFENCE_API_KEY= line in $RS_HOME/config
    local key="${WORDFENCE_API_KEY:-}"
    if [ -z "$key" ] && [ -f "$RS_HOME/config" ]; then
        key="$(grep -E '^WORDFENCE_API_KEY=' "$RS_HOME/config" 2>/dev/null | tail -1 | cut -d= -f2-)"
        key="$(printf '%s' "$key" | sed -e 's/^[[:space:]"'"'"']*//' -e 's/[[:space:]"'"'"']*$//')"
    fi
    printf '%s' "$key"
}

wordfence_feed_refresh() { # populates $RS_WORDFENCE_CACHE if a key is present; returns 1 to skip the check entirely
    local key; key="$(wordfence_api_key)"
    if [ -z "$key" ]; then
        notice "No Wordfence API key configured - vulnerability-feed check skipped."
        notice "Get a free key at https://www.wordfence.com/account/integrations and set WORDFENCE_API_KEY (env var, or a 'WORDFENCE_API_KEY=...' line in $RS_HOME/config)."
        return 1
    fi
    have curl || { notice "curl is required for the Wordfence feed check - skipped."; return 1; }

    local age; age="$(cache_age_secs "$RS_WORDFENCE_CACHE")"
    if [ "$age" -lt "$RS_WORDFENCE_FRESH_SECS" ]; then
        return 0
    fi

    local tmp="$RS_CACHE/wordfence-scanner-feed.json.$$" code
    code="$(curl -sS -o "$tmp" -w '%{http_code}' --connect-timeout 20 --max-time 180 \
            -H "Authorization: Bearer $key" \
            "https://www.wordfence.com/api/intelligence/v3/vulnerabilities/scanner" 2>/dev/null)"
    if [ "$code" = "200" ] && [ -s "$tmp" ]; then
        mv "$tmp" "$RS_WORDFENCE_CACHE"
        return 0
    fi
    rm -f "$tmp"
    if [ "$code" = "429" ]; then
        warn "Wordfence feed rate-limited (HTTP 429) for key $(mask_secret "$key")."
    else
        warn "Wordfence feed fetch failed (HTTP ${code:-?}) for key $(mask_secret "$key")."
    fi
    if [ -s "$RS_WORDFENCE_CACHE" ]; then
        notice "Using cached Wordfence feed, $(( age / 3600 ))h old."
        return 0
    fi
    notice "No cached Wordfence feed available - vulnerability-feed check skipped."
    return 1
}

wordfence_range_match() { # wordfence_range_match VERSION FROM FROM_INCL TO TO_INCL
    local version="$1" fromv="$2" frominc="$3" tov="$4" toinc="$5"
    if [ "$fromv" != "*" ]; then
        if [ "$frominc" = "true" ]; then
            ver_lt_V "$version" "$fromv" && return 1
        else
            ver_lt_V "$fromv" "$version" || return 1
        fi
    fi
    if [ "$tov" != "*" ]; then
        if [ "$toinc" = "true" ]; then
            ver_lt_V "$tov" "$version" && return 1
        else
            ver_lt_V "$version" "$tov" || return 1
        fi
    fi
    return 0
}

wordfence_query_software() { # wordfence_query_software TYPE SLUG -> TSV rows: id,title,informational,refs,from,frominc,to,toinc,patchedlist
    local type="$1" slug="$2"
    case "$JSON_PARSER" in
        jq)
            jq -r --arg type "$type" --arg slug "$slug" '
                to_entries[] | .value as $v |
                ($v.id) as $id | ($v.title) as $title |
                ($v.informational // false) as $info |
                ($v.references // [] | join("|")) as $refs |
                ($v.software // [])[] | select(.type==$type and .slug==$slug) |
                (.patched_versions // [] | join(",")) as $patchedlist |
                (.affected_versions // {} | to_entries[].value) |
                [$id, $title, ($info|tostring), $refs, .from_version, (.from_inclusive|tostring), .to_version, (.to_inclusive|tostring), $patchedlist] | @tsv
            ' "$RS_WORDFENCE_CACHE" 2>/dev/null
            ;;
        php)
            WF_FEED="$RS_WORDFENCE_CACHE" WF_TYPE="$type" WF_SLUG="$slug" php -r '
                $f=getenv("WF_FEED"); $type=getenv("WF_TYPE"); $slug=getenv("WF_SLUG");
                $d=json_decode(file_get_contents($f),true);
                if(!is_array($d)) exit(0);
                foreach($d as $v){
                    if(!is_array($v)) continue;
                    $id=$v["id"]??""; $title=$v["title"]??"";
                    $info=empty($v["informational"])?"false":"true";
                    $refs=implode("|",$v["references"]??[]);
                    foreach(($v["software"]??[]) as $sw){
                        if(($sw["type"]??"")!==$type || ($sw["slug"]??"")!==$slug) continue;
                        $patchedlist=implode(",",$sw["patched_versions"]??[]);
                        foreach(($sw["affected_versions"]??[]) as $av){
                            $row=[$id,$title,$info,$refs,
                                  $av["from_version"]??"*",
                                  (!empty($av["from_inclusive"]))?"true":"false",
                                  $av["to_version"]??"*",
                                  (!empty($av["to_inclusive"]))?"true":"false",
                                  $patchedlist];
                            echo implode("\t",$row)."\n";
                        }
                    }
                }
            ' 2>/dev/null
            ;;
    esac
}

wordfence_copyright_text() { # wordfence_copyright_text ID -> one flattened line of that record's attribution text
    case "$JSON_PARSER" in
        jq)
            jq -r --arg id "$1" '
                .[] | select(.id==$id) |
                ( .copyrights.message // "" ) as $msg |
                ( .copyrights // {} | to_entries | map(select(.key!="message")) |
                  map("\(.value.notice) (\(.value.license): \(.value.license_url))") | join(" | ") ) as $c |
                (if $msg != "" then $msg + " " else "" end) + $c
            ' "$RS_WORDFENCE_CACHE" 2>/dev/null | head -1
            ;;
        php)
            WF_FEED="$RS_WORDFENCE_CACHE" WF_ID="$1" php -r '
                $f=getenv("WF_FEED"); $id=getenv("WF_ID");
                $d=json_decode(file_get_contents($f),true);
                if(!is_array($d)) exit(0);
                foreach($d as $v){
                    if(($v["id"]??"")!==$id) continue;
                    $cr=$v["copyrights"]??[]; $parts=[];
                    if(!empty($cr["message"])) $parts[]=$cr["message"];
                    foreach($cr as $k=>$c){
                        if($k==="message" || !is_array($c)) continue;
                        $parts[]=($c["notice"]??"")." (".( $c["license"]??"").": ".($c["license_url"]??"").")";
                    }
                    echo implode(" ",$parts);
                    break;
                }
            ' 2>/dev/null
            ;;
    esac
}

scan_wordfence_vulnerabilities() {
    [ -n "$JSON_PARSER" ] || { notice "No jq or php-cli available - Wordfence feed check skipped."; return; }
    wordfence_feed_refresh || return
    [ -s "$RS_WORDFENCE_CACHE" ] || return

    info "Checking installed software against the Wordfence Intelligence feed..."
    local count=0

    wordfence_check_one() { # wordfence_check_one TYPE SLUG VERSION LABEL
        local type="$1" slug="$2" version="$3" label="$4"
        [ -n "$version" ] || return
        local rows; rows="$(wordfence_query_software "$type" "$slug")"
        [ -n "$rows" ] || return
        local id title informational refs fromv frominc tov toinc patchedlist
        while IFS=$'\t' read -r id title informational refs fromv frominc tov toinc patchedlist; do
            [ -n "$id" ] || continue
            if [ "$informational" = "true" ] && [ -z "${RS_VERBOSE:-}" ]; then continue; fi
            wordfence_range_match "$version" "$fromv" "$frominc" "$tov" "$toinc" || continue

            local sev="MED" extra=""
            if [ "$type" = "plugin" ] && awk -F'|' -v s="$slug" \
                '$1=="VULNPLUGIN" && $2==s && $5=="yes" {f=1} END{exit !f}' "$PATTERNS_FILE" 2>/dev/null; then
                sev="HIGH"; extra=" - actively exploited"
            fi
            local patchedtxt="no patch available"
            [ -n "$patchedlist" ] && patchedtxt="patched_versions: $patchedlist"
            local reflink="${refs%%|*}"
            local cvenote=""
            cvenote="$(printf '%s %s' "$id" "$title" | grep -ioE 'CVE-[0-9]{4}-[0-9]{4,}' | head -1)"
            [ -n "$cvenote" ] && { cvenote=" ($cvenote)"; WF_SAW_CVE=1; }

            report "$sev" "vulnerable-$type" "$label ($version)" \
                "known vulnerability, update: \"$title\"$cvenote, $patchedtxt$extra - $reflink"
            count=$((count + 1))
            if [ -z "$WF_ATTRIBUTION_TEXT" ]; then
                WF_ATTRIBUTION_TEXT="$(wordfence_copyright_text "$id")"
            fi
        done <<< "$rows"
    }

    [ -n "${WPVER:-}" ] && wordfence_check_one "core" "wordpress" "$WPVER" "WordPress core"

    local plugdir slug ver
    for plugdir in "$WPROOT"/wp-content/plugins/*/; do
        [ -d "$plugdir" ] || continue
        slug="$(basename "$plugdir")"
        ver="$(plugin_installed_version "$plugdir")"
        wordfence_check_one "plugin" "$slug" "$ver" "wp-content/plugins/$slug"
    done

    local themedir
    for themedir in "$WPROOT"/wp-content/themes/*/; do
        [ -d "$themedir" ] || continue
        slug="$(basename "$themedir")"
        [ -f "$themedir/style.css" ] || continue
        ver="$(grep -m1 -iE '^[[:space:]*/]*Version:' "$themedir/style.css" 2>/dev/null \
               | grep -Eo '([0-9]+\.)+[0-9]+' | head -1)"
        wordfence_check_one "theme" "$slug" "$ver" "wp-content/themes/$slug"
    done

    unset -f wordfence_check_one
    ok "Wordfence feed check done ($count match(es))."
}

wordfence_write_attribution() { # called once, after finalize_report, so these lines survive dedup untouched
    [ -n "$WF_ATTRIBUTION_TEXT" ] || return
    report "INFO" "license-notice" "-" \
        "Vulnerability data provided by Wordfence Intelligence. $WF_ATTRIBUTION_TEXT"
    if [ "$WF_SAW_CVE" = "1" ]; then
        report "INFO" "license-notice" "-" \
            "CVE(R) is a trademark of The MITRE Corporation; CVE Record data is used/reproduced under license from MITRE (see https://cve.mitre.org/about/termsofuse.html)."
    fi
}

# ============================ OUTDATED PLUGINS (free) ==========================
# No key needed: compares each wordpress.org-hosted plugin's installed version
# against the wordpress.org plugin-info API (cached 24h). Never says
# "vulnerable" - only "outdated" - unless a feed/list entry already flagged it.

wporg_latest_version() { # wporg_latest_version SLUG -> latest stable version, or empty if unknown/not on wp.org
    local slug="$1"
    local cache="$RS_CACHE/wporg-$slug.json"
    if [ "$(cache_age_secs "$cache")" -ge 86400 ]; then
        local tmp="$cache.$$"
        if fetch "https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&slug=$slug" "$tmp" 2>/dev/null \
           && [ -s "$tmp" ]; then
            mv "$tmp" "$cache"
        else
            rm -f "$tmp"
        fi
    fi
    [ -s "$cache" ] || return
    case "$JSON_PARSER" in
        jq)  jq -r '.version // empty' "$cache" 2>/dev/null ;;
        php) php -r '$d=json_decode(file_get_contents($argv[1]),true); if(is_array($d) && isset($d["version"])) echo $d["version"];' "$cache" 2>/dev/null ;;
    esac
}

scan_outdated_plugins() {
    [ -d "$WPROOT/wp-content/plugins" ] || return
    have curl || have wget || { notice "No curl/wget - outdated-plugin check skipped."; return; }
    [ -n "$JSON_PARSER" ] || { notice "No jq or php-cli - outdated-plugin check skipped."; return; }

    local plugdir slug ver latest
    for plugdir in "$WPROOT"/wp-content/plugins/*/; do
        [ -d "$plugdir" ] || continue
        slug="$(basename "$plugdir")"
        # already flagged as vulnerable (hand-picked list or Wordfence feed) this run? don't pile on.
        awk -F'\t' -v s="wp-content/plugins/$slug " '$2 ~ /^vulnerable-/ && index($3, s)==1 {f=1} END{exit !f}' \
            "$REPORT" 2>/dev/null && continue
        ver="$(plugin_installed_version "$plugdir")"
        [ -n "$ver" ] || continue
        latest="$(wporg_latest_version "$slug")"
        if [ -z "$latest" ]; then
            report "INFO" "plugin-outdated-unknown" "wp-content/plugins/$slug ($ver)" \
                "can't check - not found on wordpress.org (likely premium): verify with the vendor"
        elif ver_lt_V "$ver" "$latest"; then
            report "INFO" "plugin-outdated" "wp-content/plugins/$slug ($ver)" \
                "Outdated: installed $ver, latest $latest. Updates often include security fixes."
        fi
    done
}

# ============================ SCAN ORCHESTRATOR ===============================

# summarize_clustered SEVERITY
# Groups findings by (category + file basename) so a malware family sprayed
# across many directories collapses to one line with a count + sample paths,
# instead of hundreds of near-identical lines. Singletons print normally.
summarize_clustered() {
    local sev="$1"
    awk -F'\t' -v SEV="$sev" '
        $1==SEV {
            cat=$2; item=$3
            path=item; sub(/ \(.*/,"",path); sub(/:[0-9]+$/,"",path)
            n=split(path,seg,"/"); base=seg[n]
            key=cat "\x1f" base
            cnt[key]++
            if (cnt[key]<=3) { samp[key]=samp[key] (samp[key]==""?"":", ") path }
            cat_of[key]=cat; base_of[key]=base
            if (cnt[key]==1) first[key]=item
            catcnt[cat]++
        }
        END {
            for (k in cnt) if (cnt[k]>1) {
                printf "  [%3dx] %-26s %s\n         in: %s%s\n", \
                    cnt[k], cat_of[k], base_of[k], samp[k], (cnt[k]>3?", ...":"")
            }
            print "  -- per-category totals --"
            for (c in catcnt) printf "  %-28s %d finding(s)\n", c, catcnt[c]
        }
    ' "$REPORT"
}
finalize_report() {
    # (a) Suppress plugin-premium INFO for any plugin that has a HIGH/MED finding.
    #     A contradictory "verify later" line on confirmed-bad plugins is misleading.
    local flagged="$RS_CACHE/flagged.$$"
    awk -F'\t' '($1=="HIGH"||$1=="MED") && $3 ~ /^wp-content\/plugins\// {
        n=split($3,a,"/"); print a[3]
    }' "$REPORT" | sort -u > "$flagged"

    # (b) Collapse duplicate findings: same severity+file+signature-basename.
    #     yara:RS_large_base64_payload and heuristic:large_base64_payload on the
    #     same file are the same detection -> keep one (prefer yara attribution).
    awk -F'\t' -v FLAGGED="$flagged" '
        BEGIN { while ((getline l < FLAGGED) > 0) isflag[l]=1 }
        {
            sev=$1; cat=$2; item=$3; detail=$4
            # drop contradictory plugin-premium
            if (cat=="plugin-premium") {
                n=split(item,a," "); slug=a[1]; sub(/^wp-content\/plugins\//,"",slug)
                if (slug in isflag) next
            }
            # normalize signature basename for dedup key
            base=cat
            sub(/^yara:RS_/,"SIG:",base); sub(/^heuristic:/,"SIG:",base)
            # canonicalize a few known yara<->heuristic name pairs
            gsub(/large_base64_payload|RS_large_base64_payload/,"large_base64",base)
            key=sev "|" item "|" base
            if (key in seen) next
            seen[key]=1
            # prefer yara attribution: if we later see yara for a heuristic already
            # printed, we cannot un-print; so we buffer instead
            lines[NR]=$0; order[++cnt]=NR; kk[NR]=key
        }
        END {
            for (i=1;i<=cnt;i++) print lines[order[i]]
        }
    ' "$REPORT" > "$REPORT.dedup" && mv "$REPORT.dedup" "$REPORT"
    rm -f "$flagged"
}

run_scan() {
    banner
    : > "$REPORT"
    VERIFIED="$RS_CACHE/verified.$RUNSTAMP"
    : > "$VERIFIED"
    load_signatures
    build_php_filelist
    rs_timed scan_core_vulns
    rs_timed scan_core_checksums
    rs_timed scan_core_orphans
    rs_timed scan_fake_plugins
    rs_timed scan_plugin_header_mismatch
    rs_timed scan_plugin_checksums
    rs_timed scan_wordfence_vulnerabilities
    rs_timed scan_vulnerable_plugins
    rs_timed scan_outdated_plugins
    rs_timed scan_mu_plugins
    rs_timed scan_xss_hidden_admin_paths
    rs_timed scan_rankmath_fake_core_file
    rs_timed scan_cache_php_files
    rs_timed scan_blockchain_js_loader
    rs_timed scan_wpconfig_content
    rs_timed scan_uploads_php
    rs_timed scan_asset_tampering
    rs_timed scan_exploit_upload_paths
    rs_timed scan_hashdb
    rs_timed scan_yara
    rs_timed scan_updraftcentral_grep_fallback
    rs_timed scan_updraftcentral_notice
    rs_timed scan_updraftcentral_variant2_grep_fallback
    rs_timed scan_rankmath_grep_fallback
    rs_timed scan_option_js_injector_grep_fallback
    rs_timed scan_rest_backdoor_grep_fallback
    rs_timed scan_secret_gated_exec_grep_fallback
    rs_timed scan_compress_zlib_grep_fallback
    rs_timed scan_heuristics
    rs_timed scan_nulled
    rs_timed scan_external_requests
    rs_timed scan_htaccess
    rs_timed scan_user_ini
    rs_timed scan_database
    rs_timed scan_updraftcentral_variant2_indicators
    rs_timed scan_rankmath_readonly_indicators
    rs_timed scan_malicious_options
    rs_timed scan_admin_exploit_correlation
    rs_timed scan_cve_artifacts
    rs_timed scan_compromise_indicators
    rs_timed scan_admin_session_review
    rm -f "$PHPLIST"
    finalize_report
    wordfence_write_attribution

    # ------- summary -------
    say ""
    say "==================== SCAN SUMMARY ===================="
    local high med infoc incomplete
    high="$(awk -F'\t' '$1=="HIGH"'  "$REPORT" | wc -l)"
    med="$(awk  -F'\t' '$1=="MED"'   "$REPORT" | wc -l)"
    infoc="$(awk -F'\t' '$1=="INFO"' "$REPORT" | wc -l)"
    incomplete="$(awk -F'\t' '$2=="check-incomplete"' "$REPORT" | wc -l | tr -d ' ')"
    say "  HIGH findings : $high   (very likely malicious / integrity failures)"
    say "  MED  findings : $med   (suspicious - review before acting)"
    say "  INFO findings : $infoc   (context for your review)"
    say ""
    # A check that could not run (empty/missing input, a failed producer -
    # see check_incomplete) must never be read as "nothing to report": its
    # files are UNVERIFIED, not clean. This line, and the VERDICT override
    # below, are what stop a partial scan from ever presenting as a clean one.
    if [ "$incomplete" -gt 0 ]; then
        bad "SCAN INCOMPLETE: $incomplete check(s) could not run - see check-incomplete findings below; results are NOT a clean bill of health"
        say ""
    fi
    # VERDICT: a coarse read from HIGH counts alone, not a replacement for
    # actually reading the findings - 0 HIGH is CLEAN, 1-2 is SUSPICIOUS
    # (worth a close look), 3+ is COMPROMISED (act on it). An incomplete scan
    # can never read as CLEAN, no matter how few HIGH findings it collected.
    if [ "$incomplete" -gt 0 ] && [ "$high" -lt 1 ]; then
        warn "VERDICT: INCOMPLETE  (0 HIGH findings, but $incomplete check(s) did not run - re-run once fixed)"
    elif [ "$high" -ge 3 ]; then
        bad "VERDICT: COMPROMISED  ($high HIGH finding(s))"
    elif [ "$high" -ge 1 ]; then
        warn "VERDICT: SUSPICIOUS  ($high HIGH finding(s))"
    else
        ok "VERDICT: CLEAN  (0 HIGH findings)"
    fi
    say ""
    if [ "$high" -gt 0 ]; then
        say "  --- HIGH (clustered) ---"
        summarize_clustered "HIGH"
    fi
    if [ "$med" -gt 0 ]; then
        say "  --- MED (clustered) ---"
        summarize_clustered "MED"
    fi
    say ""
    # Grouped external-request digest: one line per unique host, worst severity.
    if grep -q $'\texternal-request\t' "$REPORT" 2>/dev/null; then
        say ""
        say "  --- External contact points (review unknowns) ---"
        awk -F'\t' '$2=="external-request"{
            n=split($4,a," "); h=""
            for(i=1;i<n;i++) if(a[i]=="to"){h=a[i+1];break}
            if(h==""){next}
            rank["HIGH"]=3;rank["MED"]=2;rank["INFO"]=1
            if(rank[$1]>best[h]){best[h]=rank[$1];bs[h]=$1}
            cnt[h]++
        } END{
            for(h in cnt) printf "  %-5s %-40s (%d call site%s)\n", bs[h], h, cnt[h], (cnt[h]>1?"s":"")
        }' "$REPORT" | sort
    fi
    say ""
    say "  Full report: $REPORT"
    say ""
    say "  Next step: review MED findings (heuristics DO false-positive - check each file)."
    say ""
    say "  This free version only reports. It did not change, move or delete anything."
    if grep -qE $'^(HIGH|MED)\t(wp-config-rogue-include|wp-config-injected-code)\t' "$REPORT" 2>/dev/null; then
        say ""
        say "  wp-config.php was flagged. Never delete or move it - the site needs it to run."
        say "  Run: ratsweepr.sh wp-config-review   (shows the exact lines, secrets masked)"
        say "  Then remove ONLY the listed lines by hand, and re-run: ratsweepr.sh scan"
    fi
    say "  Is it empty but you suspect there's something wrong? Or don't understand the results?"
    say "  Download the report and send it to hello@ratsweepr.com"
    say "  Cleanup is available in the RatSweepr Cleanup Kit or Done-For-You at https://ratsweepr.com"
    say "======================================================="
}

# ======================= SHARE / HELP (free edition) ==========================
# Nothing in this section uploads anything. share_report only writes a redacted
# copy of the latest report next to it, after an explicit y/N confirmation.

HELP_REPORT_TEXT="Is it empty but you suspect there's something wrong? Or don't understand the results?
Download the report and send it to hello@ratsweepr.com"

# latest_report: newest ratsweepr-*.report in the WP root (redacted copies excluded).
latest_report() {
    local f best=""
    for f in "$WPROOT"/ratsweepr-*.report; do
        [ -f "$f" ] || continue
        case "$f" in *.shared.report) continue;; esac
        if [ -z "$best" ] || [ "$f" -nt "$best" ]; then best="$f"; fi
    done
    printf '%s' "$best"
}

# redact_report IN OUT
# Writes a redacted copy of report IN to OUT. Pure bash + sed/awk (no php).
#  - the absolute WP root          -> <WPROOT>
#  - the home dir / username       -> ~<USER> / <USER>
#  - the site's domain(s)          -> <DOMAIN>   (wp-config WP_HOME/WP_SITEURL,
#                                     siteurl/home from the report, the folder name)
#  - DB name/user/password/host, auth keys & salts, password-like values,
#    email addresses, IPv4/IPv6 addresses, WordPress login names -> placeholders
redact_report() {
    local in="$1" out="$2"
    # $lit/$litsorted briefly hold DB_PASSWORD and the auth salts in plaintext
    # (see below) - rs_tmp keeps them under $RS_CACHE (umask 077) and registers
    # them with the rs_cleanup trap, so Ctrl+C mid-redaction can't leave them
    # behind the way a plain "$$"-named temp file would.
    local lit; lit="$(rs_tmp redact-literals)"

    # --- collect literal values to replace (mode<TAB>needle<TAB>replacement) ---
    # mode: u = replace anywhere, b = token-bounded, d = domain (case-insensitive, bounded)
    local v k
    printf 'u\t%s\t<WPROOT>\n' "$WPROOT" >> "$lit"
    if [ -n "${HOME:-}" ] && [ "$HOME" != "/" ]; then
        printf 'u\t%s\t~<USER>\n' "$HOME" >> "$lit"
    fi
    {
        id -un 2>/dev/null
        printf '%s\n' "${USER:-}" "${LOGNAME:-}"
        [ -n "${HOME:-}" ] && basename "$HOME"
        # usernames that appear in home-style paths inside the report itself
        sed -nE 's#.*/(home[0-9]*|Users)/([^/[:space:]]+).*#\2#p' "$in"
    } | awk 'length($0)>=2 && $0!~/^</' | sort -u | while IFS= read -r v; do
        printf 'b\t%s\t<USER>\n' "$v"
    done >> "$lit"

    # domains: wp-config defines, siteurl/home rows in the report, folder names
    {
        for k in WP_HOME WP_SITEURL DOMAIN_CURRENT_SITE; do wpconfig_val "$k" 2>/dev/null; done
        awk -F'\t' '$2=="db-url"{split($4,a," "); print a[1]}' "$in"
        sed -nE 's#.*/(domains|vhosts)/([^/[:space:]]+).*#\2#p' "$in"
        printf '%s\n' "$WPROOT" | sed -nE 's#.*/(domains|vhosts)/([^/]+).*#\2#p'
        k="$(basename "$WPROOT")"
        case "$k" in
            public_html|htdocs|httpdocs|www|html|web) basename "$(dirname "$WPROOT")";;
            *) printf '%s\n' "$k";;
        esac
    } | sed -E 's#^[a-zA-Z]+://##; s#[/:?].*$##; s#^www\.##' \
      | awk 'index($0,".")>0 && length($0)>=4' | sort -u | while IFS= read -r v; do
        printf 'd\t%s\t<DOMAIN>\n' "$v"
    done >> "$lit"

    # secrets straight from wp-config.php (never executed, just read)
    for k in DB_NAME DB_USER DB_PASSWORD DB_HOST AUTH_KEY SECURE_AUTH_KEY LOGGED_IN_KEY \
             NONCE_KEY AUTH_SALT SECURE_AUTH_SALT LOGGED_IN_SALT NONCE_SALT; do
        v="$(wpconfig_val "$k" 2>/dev/null)"
        [ "${#v}" -ge 3 ] || continue
        case "$v" in localhost|127.0.0.1|localhost:*|wordpress|wp|mysql|root|admin|db) continue;; esac
        case "$k" in
            DB_NAME|DB_USER|DB_HOST) printf 'b\t%s\t<REDACTED>\n' "$v" >> "$lit";;
            *)                       printf 'u\t%s\t<REDACTED>\n' "$v" >> "$lit";;
        esac
    done

    # longest needles first so e.g. the WP root wins over the home dir
    local litsorted; litsorted="$(rs_tmp redact-literals-sorted)"
    awk -F'\t' '{ print length($2) "\t" $0 }' "$lit" | sort -t"$(printf '\t')" -k1,1rn \
        | cut -f2- > "$litsorted"

    {
        printf '# RatSweepr Free - REDACTED report for research sharing (v%s)\n' "$RS_VERSION"
        printf '# Source: %s   Created: %s\n' "$(basename "$in")" "$(date '+%Y-%m-%d %H:%M %Z')"
        printf '# Automatic redaction can miss things: please skim this file before sending it.\n'
        # stage 1: credentials in URLs and email addresses (before domains are replaced)
        sed -E \
            -e 's#[A-Za-z][A-Za-z0-9+.-]*://[^/:@[:space:]]+:[^@/[:space:]]+@#<URL-CREDENTIALS>@#g' \
            -e 's#[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}#<EMAIL>#g' "$in" \
        | awk -F'\t' -v LIT="$litsorted" '
            function isw(c, mode) {
                if (c == "") return 0
                if (mode == "d") return (c ~ /[A-Za-z0-9-]/)
                return (c ~ /[A-Za-z0-9]/)
            }
            function rep(s, needle, repl, mode,    out, hay, n, pos, pre, nxt, L) {
                out = ""; L = length(needle)
                n = (mode == "d") ? tolower(needle) : needle
                while (1) {
                    hay = (mode == "d") ? tolower(s) : s
                    pos = index(hay, n)
                    if (pos == 0) { out = out s; break }
                    pre = (pos > 1) ? substr(s, pos - 1, 1) : ""
                    nxt = substr(s, pos + L, 1)
                    if (mode == "u" || (!isw(pre, mode) && !isw(nxt, mode))) {
                        out = out substr(s, 1, pos - 1) repl
                        s = substr(s, pos + L)
                    } else {
                        out = out substr(s, 1, pos)
                        s = substr(s, pos + 1)
                    }
                }
                return out
            }
            BEGIN {
                FS = "\t"; nl = 0
                while ((getline line < LIT) > 0) {
                    split(line, f, "\t")
                    if (f[2] == "") continue
                    nl++; md[nl] = f[1]; nd[nl] = f[2]; rp[nl] = f[3]
                }
            }
            { s = $0; for (i = 1; i <= nl; i++) s = rep(s, nd[i], rp[i], md[i]); print s }
        ' | sed -E \
            -e "s#((DB_(NAME|USER|PASSWORD|PASS|HOST))|[A-Z_]*(_KEY|_SALT))(['\"]?[[:space:]]*(,|=>|=|:)[[:space:]]*)('[^']*'?|\"[^\"]*\"?|[^[:space:],);]+)#\\1\\5<REDACTED>#g" \
            -e 's#(MYSQL_PWD|[Pp]ass(word|wd)?|PASS(WORD|WD)?|[Pp]wd|PWD|[Ss]ecret|SECRET)([[:space:]]*(=|:)[[:space:]]*)[^[:space:]]+#\1\4<REDACTED>#g' \
            -e 's#(^|[^0-9.])([0-9]{1,3}\.){3}[0-9]{1,3}([^0-9.]|$)#\1<IP>\3#g' \
            -e 's#(^|[^0-9.])([0-9]{1,3}\.){3}[0-9]{1,3}([^0-9.]|$)#\1<IP>\3#g' \
            -e 's#(^|[^0-9A-Za-z:])([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}([^0-9A-Za-z:]|$)#\1<IP>\3#g' \
            -e 's#(^|[^0-9A-Za-z:])([0-9A-Fa-f]{1,4}:){1,6}:([0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4}){0,5})?([^0-9A-Za-z:]|$)#\1<IP>\5#g' \
            -e "s#(admin ')[^']*(')#\\1<LOGIN>\\2#g" \
            -e 's#(login=)[^[:space:]]+#\1<LOGIN>#g' \
            -e 's#(/(home[0-9]*|Users)/)[^/[:space:]]+#\1<USER>#g' \
            -e 's#(/(domains|vhosts)/)[^/[:space:]]+#\1<DOMAIN>#g'
    } > "$out"
    rm -f "$lit" "$litsorted"
}

share_report() {
    local rpt; rpt="$(latest_report)"
    [ -n "$rpt" ] || { warn "No report found - run a scan first (option 1 or: ./ratsweepr.sh scan)."; return 1; }
    local shared="${rpt%.report}.shared.report"
    local tmp; tmp="$(rs_tmp shared-preview)"
    info "Preparing a redacted copy of: $rpt"
    redact_report "$rpt" "$tmp" || { rm -f "$tmp"; warn "Redaction failed - nothing created."; return 1; }
    say ""
    say "  Preview (first 20 lines of the redacted copy):"
    say "  ------------------------------------------------------------"
    head -n 20 "$tmp" | sed 's/^/  | /'
    say "  ------------------------------------------------------------"
    say ""
    local ans=""
    printf 'Create this redacted copy? [y/N] '
    read -r ans || ans=""
    case "$ans" in
        y|Y|yes|YES|Yes) ;;
        *) rm -f "$tmp"; say "No copy created. Nothing was written or sent."; return 0;;
    esac
    mv -- "$tmp" "$shared" || { rm -f "$tmp"; warn "Could not write $shared"; return 1; }
    say ""
    ok "Redacted copy created: $shared"
    say "  It was NOT sent anywhere. RatSweepr Free never uploads reports."
    say "  To contribute it, email the file to hello@ratsweepr.com. It is used only to"
    say "  improve detection signatures. Please skim it first: redaction is automatic"
    say "  and can miss something."
}

help_report() {
    say ""
    say "$HELP_REPORT_TEXT"
    say ""
    local rpt shared
    rpt="$(latest_report)"
    if [ -z "$rpt" ]; then
        say "  No report found yet. Run a scan first (option 1 or: ./ratsweepr.sh scan)."
        return 0
    fi
    shared="${rpt%.report}.shared.report"
    if [ -f "$shared" ]; then
        say "  Redacted report (private details stripped): $shared"
        say "  Full report (contains private details):    $rpt"
    else
        say "  Latest report: $rpt"
        say "  Tip: run option 3 (./ratsweepr.sh share-report) first to make a redacted"
        say "  copy with private details (paths, domain, emails, IPs, DB details) stripped."
    fi
}

# ================================ MENU / CLI ==================================

usage() {
    cat << 'EOU'
RatSweepr Free - read-only WordPress malware scanner
Usage (run from the WordPress root, where wp-config.php lives):
  ratsweepr.sh                  interactive menu
  ratsweepr.sh scan             full read-only scan -> report
  ratsweepr.sh scan --since 2026-07-01   also list DB content modified since a date
  ratsweepr.sh update-sigs      refresh rfxn hash DB + pattern file
  ratsweepr.sh share-report     make a redacted copy of the latest report (opt-in, nothing is uploaded)
  ratsweepr.sh wp-config-review review flagged wp-config.php lines (read-only, secrets masked)
  ratsweepr.sh help-report      report looks empty, or you don't understand it?
  ratsweepr.sh help             this help
EOU
}

main_menu() {
    banner
    PS3=$'\nSelect an option: '
    select choice in \
        "Scan (read-only)" \
        "Update malware signatures" \
        "Prepare report to share for research (opt-in)" \
        "Review flagged wp-config.php lines" \
        "Report looks empty, or you don't understand it?" \
        "Exit"
    do
        case "$REPLY" in
            1) run_scan; break;;
            2) update_signatures; break;;
            3) share_report; break;;
            4) wp_config_review; break;;
            5) help_report; break;;
            6) exit 0;;
            *) say "Pick a number from the list.";;
        esac
    done
}

SINCE_DATE=""
cmd="${1:-menu}"; shift || true
while [ $# -gt 0 ]; do
    case "$1" in
        --since) SINCE_DATE="${2:-}"; shift 2;;
        *) set -- "$1" "${@:2}"; break;;
    esac
done

# Commands that don't need a WordPress root are handled before preflight, so
# help and unknown/removed commands work from any directory.
case "$cmd" in
    menu|scan|update-sigs|share-report|wp-config-review|help-report) ;;
    help|-h|--help)  usage; exit 0;;
    *)               usage; die "Unknown command: $cmd (RatSweepr Free is read-only; cleanup commands are not included)";;
esac

preflight

case "$cmd" in
    menu)            main_menu;;
    scan)            update_signatures; run_scan;;
    update-sigs)     update_signatures;;
    share-report)    share_report;;
    wp-config-review) wp_config_review;;
    help-report)     help_report;;
esac
