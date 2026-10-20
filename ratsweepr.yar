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
