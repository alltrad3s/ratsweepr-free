# RatSweepr Free

```
██████╗  █████╗ ████████╗███████╗██╗    ██╗███████╗███████╗██████╗ ██████╗
██╔══██╗██╔══██╗╚══██╔══╝██╔════╝██║    ██║██╔════╝██╔════╝██╔══██╗██╔══██╗
██████╔╝███████║   ██║   ███████╗██║ █╗ ██║█████╗  █████╗  ██████╔╝██████╔╝
██╔══██╗██╔══██║   ██║   ╚════██║██║███╗██║██╔══╝  ██╔══╝  ██╔═══╝ ██╔══██╗
██║  ██║██║  ██║   ██║   ███████║╚███╔███╔╝███████╗███████╗██║     ██║  ██║
╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚══════╝ ╚══╝╚══╝ ╚══════╝╚══════╝╚═╝     ╚═╝  ╚═╝
```

## 1. What this is

RatSweepr Free is a **read-only** WordPress malware scanner. You run one
command, it writes a plain-text report, and it stops. It never changes,
moves, quarantines, restores, or deletes anything on your site — no root,
no agent, no background process.

It checks, among other things:

- **Core & plugin integrity** against the official wordpress.org checksums
- **Known malware** via the free rfxn/maldet hash database
- **YARA content rules** for webshells, backdoors, and obfuscated payloads
- **Fake plugins** (randomly-named plugin folders, bare `payload.php` files)
- **`wp-config.php` content** (it's excluded from checksums, so scanners
  that only check file hashes miss injected code there — this one reads it)
- **Database signs of compromise** (read-only `SELECT` queries only):
  injected scripts in posts, suspicious admin accounts, hijacked site URLs
- **Vulnerable core versions**, nulled-plugin residue, and outbound requests
  your code makes to hosts you may not recognize

Full detail on every check is in [What it scans](#4-what-it-scans) below.

## 2. Before you start

1. **Take a backup first.** RatSweepr Free doesn't touch your site, but you
   should never run anything on a possibly-compromised site without a
   recent backup — if your host offers one-click backups, use it now.
2. **You need a terminal.** Either:
   - SSH access to your hosting account, or
   - your host's control panel Terminal (cPanel: **Advanced → Terminal**;
     Plesk: a similar "SSH Terminal" tile), or
   - if neither is available, ask your host to run the commands below for
     you, or to enable SSH/Terminal access on your plan.

## 3. Step by step

### 3.1 Log in

Open SSH, or your hosting panel's Terminal.

### 3.2 Find and enter your WordPress folder

You're looking for the folder that directly contains `wp-config.php` —
commonly `public_html`, `httpdocs`, or `www`. If you're not sure, your
host's panel usually shows a "Document Root" for the domain (cPanel:
**Domains**; Plesk: the domain's **Hosting Settings**). Then:

```bash
cd ~/public_html          # or whatever your WordPress root is
ls wp-config.php          # confirm it's here before continuing
```

### 3.3 Download a pinned release, and verify it

Always pin an exact version tag — never a moving branch — and check the
file against the checksums published with that release:

```bash
curl -fsSL -o ratsweepr.sh \
  https://github.com/alltrad3s/ratsweepr-free/releases/download/v2.9.17-free/ratsweepr.sh
curl -fsSL -o SHA256SUMS \
  https://github.com/alltrad3s/ratsweepr-free/releases/download/v2.9.17-free/SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
```

The last command should print `ratsweepr.sh: OK`. If it prints `FAILED` or
doesn't say `OK`, **do not run the script** — delete both files and try the
download again; if it fails a second time, email hello@ratsweepr.com before
proceeding.

(`install.sh` in this repo automates these three steps if you'd rather run
one command — see its header comment for usage.)

### 3.4 Run the scan

```bash
bash ratsweepr.sh scan
```

This is read-only and takes a few minutes depending on site size. You can
also just run `bash ratsweepr.sh` for an interactive menu.

### 3.5 Find the report

The scan prints the report's path when it finishes — it's a file named
`ratsweepr-<date>_<time>.report` in the same folder you ran it from.

### 3.6 Read the results

Each line is `SEVERITY   CATEGORY   ITEM   DETAIL`. What to do for each
severity:

| Severity | Meaning | What to do |
|---|---|---|
| **HIGH** | Something that matches a known malware pattern, a backdoor signature, or a confirmed integrity failure. | Treat as likely compromised. Read the `DETAIL` column for the specific file/line. This is what the Cleanup Kit or a security professional should see first. |
| **MED** | Suspicious, but these checks DO produce false positives — heuristic pattern matches, unknown files, external requests. | Open the file and judge for yourself, or ask for help rather than assuming it's malicious. |
| **INFO** | Evidence, not proof — forensic leads (e.g. a user account created in a suspicious window), or informational notes (e.g. "confirm this is your domain"). | Useful context when correlated with HIGH findings; not actionable alone. |
| **WARN** | A caveat about the scan itself (e.g. a check that was skipped because `php-cli` isn't installed). | Means some area wasn't fully checked, not that something was found. |

### 3.7 If `wp-config.php` was flagged

RatSweepr Free will tell you plainly if this happens, because it matters:
**never delete or move `wp-config.php`** — your site needs it to run, and
there's no cleanup command here that would do that anyway (this edition
changes nothing). Instead:

```bash
bash ratsweepr.sh wp-config-review
```

This read-only command shows you exactly which line(s) were flagged, with
2 lines of context and any passwords/keys/salts masked, so you can safely
open the file yourself and remove *only* those specific lines by hand.
Then re-run `bash ratsweepr.sh scan` to confirm it's clear.

### 3.8 Share a report for research (optional, opt-in)

There is no automatic upload — nothing leaves your server unless you send
it yourself. If you'd like to help improve detection:

```bash
bash ratsweepr.sh share-report
```

This makes a **redacted copy** next to your report (your WP root path, home
folder/username, domain, DB credentials, keys/salts, emails, and IPs are
stripped), shows you the first 20 lines, and asks
`Create this redacted copy? [y/N]` — default is No. Skim the result, then
email it to **hello@ratsweepr.com** if you're comfortable sharing it; it's
used only to improve detection signatures.

### 3.9 Confused, or the report looks empty but you suspect something's wrong?

> Is it empty but you suspect there's something wrong? Or don't understand
> the results? Download the report and send it to hello@ratsweepr.com

Run step 3.8 first so private details are stripped from what you send.

### 3.10 Clean up after yourself

**Reports are a map of exactly where the weak spots are** — don't leave them
sitting in your webroot for an attacker to read. When you're done:

```bash
rm -f ratsweepr.sh ratsweepr-*.report ratsweepr-*.shared.report SHA256SUMS
```

## 4. What it scans

1. **Core integrity**: api.wordpress.org checksums. Modified, missing and
   *unknown* files in core areas (dropped shells, injected core files). A
   fallback still flags unexpected PHP in core folders when the checksum API
   can't be reached.
2. **Fake plugins**: plugin folders named like `word-<random hex>` (for
   example `native-database-checker-c975`) and plugins shipping a file named
   `payload.php`. This is a filename check, so it works without `php-cli`.
3. **Plugin integrity**: downloads.wordpress.org plugin checksums for each
   installed version: modified and unknown files inside each plugin.
4. **YARA content rules (36)**: the bundled `ratsweepr.yar` ruleset (obfuscated eval
   chains, `pack()`/`str_rot13`/`gzinflate` droppers, cookie- and header-fed
   backdoors, command-exec webshells, self-hiding fake plugins, dual-use file
   managers, obfuscated JavaScript injection, external script tags pointing at
   typosquat CDNs, goto-obfuscated malware, anti-cleanup `.htaccess` files),
   plus recent campaign-specific backdoors: two variants of the October 2026
   UpdraftCentral key-compromise fake "maintenance toolkit", the 2026
   plugin-XSS-chain hidden-admin dropper, the October 2026 Rank Math SEO
   PRO supply-chain compromise (CVE-2026-111862, with dedicated checks for its
   fake core file, its `.htaccess`/`.cache` trick and its published IOCs -
   see "Rank Math PRO supply-chain extras" below), and three built from a real
   infected site's findings: a `wp_head` script injecting obfuscated JS sourced
   from a `wp_options` value without the `manage_options` capability check a
   real admin-notice script would have; an unauthenticated REST route gated by
   a hardcoded key literal that calls `update_option`/`delete_option`/
   `WP_Filesystem->delete`; and an `include`/`require` filename rebuilt from
   2+ concatenated string fragments to dodge static grep.
   It uses a system `yara`, or downloads the static `yara-x` CLI once into
   `~/.ratsweepr/bin`, or falls back to a built-in matcher.
5. **Known malware**: the free rfxn/maldet MD5 database, refreshed by
   `update-sigs` and matched locally.
6. **Heuristics**: grep patterns for webshell constructs and suspicious file
   names. These are MED severity because they can false-positive.
7. **Nulled-plugin signs**: piracy-site references, "version 9999" update
   blockers, licence-check interception, `sslverify => false`, leftover fake
   licence options.
8. **Vulnerable core versions**: the WordPress version is checked against a
   known-vulnerable table, with the fixed version and a WAF stopgap.
9. **Post-exploitation traces**: user-ID gaps, admins created in an exposure
   window, orphaned admin user meta, suspicious admin names, known exploit
   markers, PHP files written to uploads/mu-plugins in the window. These are
   INFO leads, not proof. Two correlation checks ARE escalated to HIGH,
   because the correlation itself is the evidence: an administrator whose
   registration lands within 60 seconds of a `customize_changeset`
   modification, and the wp2shell PoC sentinel pattern (a changeset dated
   exactly `2020-01-01 00:00:00`, a `nav_menu_item` pointing at
   `example.invalid` or titled `proof`/`generated`, or a `request`-type post
   titled `parse` - grouped into one finding). Neither is limited by the scan
   window; whenever either fires, the report also prints the earliest
   `customize_changeset` date site-wide as the likely real compromise date.
   For any admin flagged this way, `admin-session` lines list every
   `session_tokens` IP and login time, read-only.
10. **External request discovery**: every host the code calls over HTTP,
    ranked (unknown host + plain HTTP / disabled SSL checks = HIGH).
11. **PHP in uploads, mu-plugins and wp-config.php** (with exact flagged
    line numbers for wp-config.php — see 3.7), plus suspicious `.htaccess`
    rules.
12. **Database (read-only)**: script/iframe injection in posts and widgets,
    siteurl/home hijack, administrator list, suspicious cron entries, and
    `db-malicious-option` - a `wp_options` row whose value is a long base64
    blob decoding to JS with `Function()`/`eval()`/`atob()`, or whose name
    was the one a confirmed wp_head JS-injector match reads from. HIGH,
    detection-only (no cleanup action in Free).
13. **Plugin/theme/core CVEs (optional)**: Wordfence Intelligence feed
    lookups if you set a free `WORDFENCE_API_KEY` - see "Wordfence
    Intelligence feed" below. A free outdated-plugin check (no key needed)
    also runs - see "Outdated-plugin check" below.
14. **Rank Math PRO supply-chain extras** (CVE-2026-111862, Oct 2026):
    beyond the YARA rule in item 4, a dedicated check for the fake core file
    `wp-includes/class-wp-cache-util.php`, a `.htaccess` rule for `.cache`
    mapped to a PHP handler, a file rule for any `.cache` file that actually
    contains PHP, and read-only extras (crontab, and - with WP-CLI or a
    mysql client - three published option names and a `wpsupport_*`
    username / `@wp-mail.net` email pattern). None of these change anything.
15. **Plugin header mismatch**: a plugin's own declared metadata can out a
    fake/dropped plugin before any code pattern does - a Text Domain
    unrelated to its Plugin Name, a Text Domain with a random-hex suffix
    (the same disguise fake plugin *directory* names use, here on the header
    field), or an Author claiming to be
    `WordPress.org Community`/`WordPress`/`Automattic` on a plugin that
    isn't theirs. One hit is MED; two or more on the same plugin is HIGH.
16. **Blockchain-hosted JS loader**: a >2KB base64 string constant that
    actually *decodes* to JS calling `eth_call` against an RPC endpoint
    (`sepolia`/`/rpc`/`tenderly`/`publicnode`-style) plus `crypto.subtle` or
    `localStorage` caching - a wallet-drainer-style loader. Not a YARA rule:
    this needs a real base64 decode (`base64`/`openssl`, no php required).

`eval`/`assert` matches require a word boundary, so a plain function call
like `doubleval(...)` or `retrieval(...)` - both contain the literal
substring `eval(` - can't false-positive. `sslverify_disabled` is
downgraded to INFO specifically for WPBakery's (`js_composer`) own
local-fonts downloader, which legitimately disables SSL verification
fetching Google Font files.

The scan summary ends with one **VERDICT** line - a coarse read from the
HIGH count alone (0 = CLEAN, 1-2 = SUSPICIOUS, 3+ = COMPROMISED).

Host-provided mu-plugins (from certain managed WordPress hosts) are
on an allowlist so they aren't reported as unknown. Their content is still
scanned. This is only to avoid false positives and doesn't imply any
affiliation with those companies.

### Vulnerable plugin versions

`VULNPLUGIN` entries in `ratsweepr-sigs.conf` flag an installed plugin
that's outdated against a **public CVE** — reported as `vulnerable-plugin`,
severity MED (or HIGH if the entry marks it as actively exploited). This is
a patch-hygiene finding, never reported as "infected": it means the site
*could* be hit, not that it has been.

```
VULNPLUGIN|slug|fixed_version|CVE|exploited(yes/no)|source_url[|EXTRA...]
```

- `slug` — the plugin's `wp-content/plugins/<slug>` directory name.
- `fixed_version` / installed version are compared with `sort -V`, read
  from the `Version:` header of the plugin's own main file (the one
  containing `Plugin Name:`) — **not** `readme.txt`'s Stable tag, which can
  lag behind or outrun what's actually installed.
- `exploited` controls severity: `yes` → HIGH, `no` → MED.
- Optional trailing fields, pipe-delimited:
  - `EXACT=version:note` — if the installed version is *exactly* this: when
    that version is otherwise clean, emit an INFO "verify with vendor" note
    instead of a clean verdict (an unusual jump the advisory doesn't
    cover). When that version is *still vulnerable* (e.g. a specific
    compromised build), use the note as the finding's own detail text
    instead of the generic wording, at the entry's normal severity.
  - `ALTFIXED=version` — an alternate numbering line's fixed version (e.g.
    a premium build versioned `2.x` against a free line's `1.x`); any
    installed version starting `2.` is compared against this instead.

**This list is hand-picked from public advisories we've reviewed — it is
not a vulnerability database and won't track every plugin or every CVE.**
Treat a clean result as "nothing on our short list is outdated," not as
"this site has no vulnerable plugins."

**UpdraftPlus has two separate issues, don't confuse them:** the
`VULNPLUGIN` entry is CVE-2026-10795, an authenticated command-forgery bug
fixed in 1.26.5/2.26.5 - Patchstack reports exploitation attempts against
unpatched sites continue, so it's now marked actively exploited. That's
different from the **October 2026 UpdraftCentral key-compromise** campaign,
which has no CVE, isn't a code bug in UpdraftPlus itself, and affects
installs at **any** version - that's why the NOTICE below never checks the
installed version.

### Notices

Some results print as a **NOTICE**: advice, not a finding. If
`wp-content/plugins/updraftplus` exists (at any version), the scan reminds
you that UpdraftCentral keys were compromised in October 2026, and tells
you to check for a key with `wp option get updraft_central_localkeys`,
remove it with `wp option delete updraft_central_localkeys`, and search
your access logs for `class-udrpc.php`.

**Rank Math PRO at exactly `3.0.123`** means the installed *build* may
itself be a backdoored supply-chain package (CVE-2026-111862), not just an
outdated version - see the finding's own detail text and the other Rank
Math checks above before concluding anything.

### Wordfence Intelligence feed (optional, free key)

A free key from Wordfence enables a live check against the **Wordfence
Intelligence V3 Scanner Feed** (Defiant, Inc.) covering WordPress core,
plugins, and themes - the same vulnerability intelligence behind
Wordfence's own plugin.

**Setup:** get a free key at
<https://www.wordfence.com/account/integrations>, then either:

```bash
export WORDFENCE_API_KEY=your-key-here
```

or add a line to `~/.ratsweepr/config`:

```
WORDFENCE_API_KEY=your-key-here
```

No key: the scan runs normally and prints a NOTICE with the link above.
The key is never hardcoded, logged, or shipped, and is masked in any debug
output.

The feed (the whole database - large) is cached under `~/.ratsweepr/cache`
and refreshed at most once every 24 hours, never per plugin. On a rate
limit or network error, it falls back to the cache and says how old it is.
Parsing prefers `jq`, falls back to `php -r` (on every WordPress host), or
skips with a NOTICE if neither is available - everything else still runs.

Matches are `vulnerable-core` / `vulnerable-plugin` / `vulnerable-theme`
(MED, "known vulnerability, update" - never "infected"; HIGH + "actively
exploited" when the same plugin is also marked `exploited=yes` in the
hand-picked list above). Each line shows the title, installed version,
patched version (or "no patch available"), and a link to the record.
Purely informational feed entries are skipped unless `RS_VERBOSE` is set.

**Attribution** (required by the feed's license): whenever a Wordfence
record is shown, the report includes a `license-notice` line reproducing
that record's own copyright/license text, plus a MITRE notice whenever a
CVE is displayed. See `THIRD-PARTY-NOTICES.md`. The feed is fetched and
cached locally with your own key - never redistributed by RatSweepr.

### Outdated-plugin check (free, no key needed)

For every plugin hosted on wordpress.org, RatSweepr Free compares the
installed version against the wordpress.org plugin-info API (cached 24h).
If it's behind: `Outdated: installed X, latest Y. Updates often include
security fixes.` Never worded as "vulnerable" - that's reserved for an
actual `VULNPLUGIN` entry or Wordfence feed match. Premium plugins not on
wordpress.org report `can't check, verify with the vendor` instead.

## 5. Known limitations (stated honestly)

- **No infrastructure/DNS visibility.** This only sees the files and
  database on the server it runs on. It cannot detect DNS/subdomain
  hijacks, a rogue domain mapped from a different hosting account, or
  edge/CDN-cached spam. If the site "scans clean" but still misbehaves
  (e.g. a redirect that only shows up in a real browser), look at DNS and
  domain mapping next, not another file scan.
- **Some hosts limit what a scan can see.** A few cPanel/shared hosts
  disable `/dev/fd` or cap concurrent processes, which can silently weaken
  the core/plugin integrity checks (YARA, hash-DB, and heuristic checks
  still run normally). If results on such a host seem unexpectedly clean,
  that's worth knowing.
- **`php-cli` and WP-CLI/`mysql` improve accuracy.** Without `php-cli`, the
  core and plugin checksum checks are skipped. Without WP-CLI or a `mysql`
  client, the database checks are skipped. The report tells you when a
  check was skipped.
- **Heuristics false-positive.** MED findings need a human look before
  you act on them.
- **A compromised server can lie to the scanner running on it.** For a
  serious incident, also scan a copy of the site on a machine you trust.

## 6. Need it cleaned?

RatSweepr Free only finds problems — it changes nothing. If you want help
removing what it finds, the RatSweepr Cleanup Kit and the Done-For-You
cleanup service are at https://ratsweepr.com.

## 7. Privacy

RatSweepr Free sends nothing from your site anywhere. It makes no outbound
request that contains your data — every network call it makes is a plain
`GET` to check something against a public source, never a POST of your
files, database contents, or report. The calls it can make:

| When | URL | Why |
|---|---|---|
| Scanning (if `php-cli` present) | `api.wordpress.org/core/checksums/1.0/` | official core file checksums |
| Scanning (if `php-cli` present) | `downloads.wordpress.org/plugin-checksums/` | official plugin file checksums |
| `update-sigs` / every scan | `www.rfxn.com/downloads/rfxn.hdb` | the free malware hash database |
| First YARA scan only, if no local `yara`/`yara-x` | `github.com/VirusTotal/yara-x/releases/download/...` | downloads the YARA engine binary once (skip with `RS_NO_ENGINE_DL=1`) |
| Only if you set `WORDFENCE_API_KEY` | `www.wordfence.com/api/intelligence/v3/vulnerabilities/scanner` | optional core/plugin/theme CVE lookup (free key, fetched by you, cached 24h) |
| Every scan (plugins hosted on wordpress.org) | `api.wordpress.org/plugins/info/1.2/` | free outdated-plugin check, cached 24h |
| Only if you set `RS_PATTERN_URL` / `RS_RULES_URL` | whatever you set | optional custom signature feed — off by default |

The only thing that ever leaves your server with your site's own data in
it is the redacted report you choose to send yourself (3.8) — and even that
never happens automatically.

## 8. License

Source-available, all rights reserved — see [LICENSE](LICENSE). In short:
you can read the code, run it on sites you own or are authorized to
administer (including a client's, if you're a freelancer or agency), and
share scan results for malware-research purposes. You may not redistribute,
fork, modify, or bundle it into a product or service you offer others —
including handing a client the script itself — without written permission.
This is not an open-source license.

## Third-party notices

RatSweepr Free calls out to a few free, publicly documented third-party
services and data formats (Wordfence Intelligence, MITRE CVE data, the
rfxn/maldet hash database, yara-x, the wordpress.org APIs, and optional
user-supplied YARA rulesets). None of it is bundled or redistributed -
see `THIRD-PARTY-NOTICES.md` for what's used, how, and under which terms.

## Requirements

Everything is standard on shared hosts and none of it needs root:

- `bash` 4+, coreutils (`md5sum`, `sha256sum`, `sort`, `comm`), `grep`, `awk`, `sed`, `find`
- `curl` or `wget`
- Recommended: `php-cli` (needed for the wordpress.org checksum checks),
  WP-CLI or a `mysql` client (needed for the database checks), `openssl`
  (verifies signed signature files).

## Commands

```
ratsweepr.sh                      interactive menu
ratsweepr.sh scan [--since DATE]  read-only scan -> ratsweepr-<date>.report
ratsweepr.sh update-sigs          refresh the rfxn hash DB + pattern file
ratsweepr.sh wp-config-review     review flagged wp-config.php lines (read-only, secrets masked)
ratsweepr.sh share-report         make a redacted copy of the latest report (opt-in)
ratsweepr.sh help-report          what to do if the report is empty or unclear
ratsweepr.sh help                 usage
```

`--since 2026-07-01` also lists database content modified since that date.

## Configuration

| Env var | Purpose |
|---|---|
| `RS_HOME` | tool home and cache (default `~/.ratsweepr`) |
| `RS_PATTERN_URL` | URL of a hosted `ratsweepr-sigs.conf` |
| `RS_RFXN_URL` | override the maldet/rfxn MD5 feed |
| `RS_RULES_URL` | optional online YARA rule feed (must be signed if a public key is present) |
| `RS_YARA_RULES` | folder with extra `.yar`/`.yara` rulesets |
| `RS_NO_ENGINE_DL=1` | don't download the yara-x engine |
| `RS_YARAX_URL` / `RS_YARAX_VER` | override the yara-x download |
| `WORDFENCE_API_KEY` | enable the Wordfence Intelligence feed check (free key) |
| `RS_VERBOSE` | also show feed entries marked informational-only |
| `RS_ALLOW_ROOT=1` | bypass the root refusal (don't) |

`WORDFENCE_API_KEY` can also be set as a line in `~/.ratsweepr/config`
instead of an env var. If `~/.ratsweepr/ratsweepr-pub.pem` exists,
downloaded pattern and rule files must pass `openssl` signature
verification or they are rejected. Third-party data sources and their
licenses are listed in `THIRD-PARTY-NOTICES.md`.

## Repo layout

```
ratsweepr.sh            the scanner (single self-contained bash script)
ratsweepr.yar           bundled YARA ruleset (identical to the copy inside ratsweepr.sh)
ratsweepr-sigs.conf     distributable signature/pattern file (RS_PATTERN_URL)
install.sh              downloads a pinned, checksum-verified ratsweepr.sh into the current folder
Makefile                lint / yara-sync / safety / sign-sigs / version helpers
.github/workflows/      push = checks; tag = publish a release (ratsweepr.sh, ratsweepr.yar, ratsweepr-sigs.conf, SHA256SUMS)
```
