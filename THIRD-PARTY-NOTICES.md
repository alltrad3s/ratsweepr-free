# Third-party notices

RatSweepr Free is a single self-contained script. It doesn't bundle or
redistribute any of the following - it calls out to free, publicly
documented services and formats, with your own credentials where one is
needed, and caches what it fetches locally on your own server.

## Wordfence Intelligence (Defiant, Inc.)

The optional vulnerability-feed check (`WORDFENCE_API_KEY`) queries the
**Wordfence Intelligence V3 Scanner Feed**, a product of Defiant, Inc.
It is fetched by you, with your own free API key, and cached locally under
`~/.ratsweepr/cache` - RatSweepr Free does not ship, bundle, or
redistribute any Wordfence Intelligence data itself.

Use of the feed is subject to Wordfence's own terms:
<https://www.wordfence.com/wti-community-edition-terms-and-conditions/>

Whenever a Wordfence record is shown in a scan report, RatSweepr Free
reproduces that record's own `copyrights` field (Defiant's notice, license
name, and license URL) in a `license-notice` report line, as required by
those terms. Nothing in the cached feed's `copyrights` data is stripped
before caching.

## MITRE CVE

When a scan report displays a CVE identifier (from the Wordfence feed or
from the hand-picked `VULNPLUGIN` list), it also reproduces a notice that
CVE(R) is a trademark of The MITRE Corporation and that CVE Record data is
used/reproduced under license from MITRE. Authoritative terms:
<https://cve.mitre.org/about/termsofuse.html>

## rfxn/maldet hash database (R-Fx Networks / Ryan MacDonald)

`update-sigs` downloads the free rfxn/maldet MD5 malware-hash database
(`rfxn.hdb`) from rfxn.com, used under its own license, GPLv2. It's
downloaded by you and cached locally under `~/.ratsweepr/cache` -
RatSweepr Free does not bundle or redistribute it.

## yara-x

The optional one-time-downloaded static `yara-x` engine binary
(`RS_NO_ENGINE_DL` to opt out) is licensed BSD-3-Clause. RatSweepr is not
affiliated with, and this project is not endorsed by, VirusTotal or the
yara-x maintainers.

## WordPress.org APIs

Core-checksum verification, plugin-checksum verification, and the free
outdated-plugin check all call public, unauthenticated wordpress.org APIs
(`api.wordpress.org`, `downloads.wordpress.org`). No API key is required
and nothing from these APIs is bundled - responses are cached locally
under `~/.ratsweepr/cache` for at most 24 hours.

## Optional user-supplied YARA rulesets (`RS_YARA_RULES`)

If you point `RS_YARA_RULES` at a directory of third-party `.yar`/`.yara`
files (for example a signature-base-style ruleset), those rules run
alongside RatSweepr's own. Many such rulesets (including Neo23x0's
signature-base) are published under the Detection Rule License 1.1 or
LGPL-3.0, which require attribution. When an external rule matches,
RatSweepr includes that rule's own `author`/`meta` fields in the report
finding. **If you use Neo23x0's signature-base, use only versions from
after 13 Aug 2021** (the project's own license terms changed then); see
the project's own repository for current terms before using older copies.

---

Nothing above is bundled with, shipped inside, or redistributed by
RatSweepr Free. Every item here is fetched directly by your own server,
using your own credentials where one applies, and cached only on your own
infrastructure.
