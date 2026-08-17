# cloud-file-web methodology digest

Distilled from 6 successfully fetched writeups (3 skipped — see Coverage notes). Treat all payloads as test-only on authorized scope.

## Hunting procedures

### 1. API Gateway isolation bypass via path traversal + URL parsing discrepancy

- **When to test:** Multi-segment URL paths that look like gateway dispatching (e.g. `/match/ad/apps/rec/discover`), consistent response formats across unrelated paths, any 403 on internal-looking endpoints (`/_/metrics`, `/_/heapdump`, `/users`, `/internal`). A 403 means the resource *exists* — it is a lead, not an endpoint.
- **Procedure:**
  1. Map public endpoints; note path structures that suggest backend-service routing rather than a single REST app.
  2. Append traversal sequences to a public route: `/public/route/../`, `/public/route/../../`, `..;/`, encoded variants (`%2e%2e%2f`).
  3. Watch for 200s returning content from *different* backend routes instead of 404 — this confirms the path is resolved before internal forwarding.
  4. Enumerate the traversed API index for internal endpoints (metrics, health, config, user APIs).
  5. For endpoints that still 403, hunt a parser discrepancy between LB/WAF and gateway: inject control chars and encodings before the traversal, e.g. `../%0d%0a/../../_/metrics`, plus `%00`, `%09`, double-encoding (`%252e%252e`), mixed `/` + `\`.
  6. Confirm the same request flips 403 → 200.
- **Verify:** Full internal resource (e.g. Prometheus metrics page) returned on a request the gateway's policy should block. Vendor upgraded the real case from High to Critical because unauthenticated internal APIs leaked personal info — frame impact as gateway-isolation bypass, not "exposed metrics".

### 2. Web cache poisoning → single-request persistent DoS (responsibly)

- **When to test:** Any CDN/cached front end (Akamai, Cloudflare, Fastly, Varnish, Drupal behind cache). Look for responses whose content depends on request headers that are NOT in the cache key.
- **Procedure:**
  1. Run Burp Param Miner with the "twitchy cache poison" option against the target to find unkeyed headers.
  2. Always add a cache-buster query param (e.g. `?dontpoisoneveryone=1`) so only YOUR request is poisoned — this is what makes the PoC non-destructive and reportable.
  3. Test known DoS-yielding unkeyed inputs:
     - `X-Forwarded-Port: 123` → cached 302 redirect to invalid port → timeout for all visitors (HackerOne, $2,500).
     - Invalid `Transfer-Encoding` header → cached "501 Not Implemented" replacing core JS files (PayPal, $9,700; Bitbucket, $1,800).
     - Header with WAF-triggering string (`Any-Header: burpcollaborator.net`) → cached WAF block page for the URL (Tesla, $300).
     - `Accept_Encoding: br` (underscore instead of hyphen) → brotli response cached for clients that can't decode it (Instagram, $1,000).
     - `Range: bytes=cow` → cached 400 for static JS assets (Twitter/abs.twimg.com).
     - Also try `Accept`, `Upgrade`, `Origin`, `Max-Forwards`, `X-Forwarded-SSL`.
     - Stale IE9 User-Agent (Burp Repeater "Paste URL as request") → cached "update your browser" page ($7,500 accidental find).
  4. Verify poisoning by re-requesting the URL WITHOUT the malicious header but WITH the same cache-buster — if you get the poisoned response back, the cache stored it.
- **Verify:** Second request without the attack header returns the poisoned body; removing the cache-buster changes the key so real users are unaffected during testing. Check program policy — many forbid *launching* DoS but allow *reporting* cache-poisoning DoS with a cache-buster PoC.

### 3. WAF (AWS WAF) bypass via fuzzing for unfiltered tags/events

- **When to test:** Target sits behind AWS WAF managed rule sets (CommonRuleSet, KnownBadInputs, SQLi) blocking XSS/SQLi payloads with 403s.
- **Procedure:**
  1. Manually probe with varied tags/attributes to learn what the WAF blocks; if you control the environment, use WAF metrics/logs to see which rule fired.
  2. Automate: fuzz the cartesian product of HTML tags × event handlers × attributes (base payload list: PortSwigger XSS cheat sheet). Sysdig's open-source fuzzer "Wafer" does this.
  3. Verify execution in a real browser via Selenium: hook `alert/confirm/prompt` (`window.alert = function(){window.alert_trigger=true}`) and fire all common events (`click`, `mouseover`, `focus`, `blur`, `keydown`, pointer events) on injected elements.
  4. Apply regex-evasion transforms: split tags with spaces/newlines, insert random Unicode chars that normalize to ASCII.
  5. Known-good AWS WAF bypass payload (fixed Dec 2023, but the *class* — exotic/experimental DOM events — remains valid): `<button popovertarget=x>click me</button><test onbeforetoggle=alert(document.domain) popover id=x>aaa</test>` — the `onbeforetoggle` event wasn't in the rule set.
- **Verify:** Alert fires in an automated browser despite WAF 403ing standard payloads. Note: F5 and ModSecurity caught this specific payload — bypasses are WAF-specific, so re-fuzz per vendor.

### 4. Cloudflare origin exposure via split-DNS (grey-cloud apex)

- **When to test:** Target behind Cloudflare (`server: cloudflare`, `/cdn-cgi/trace` returns 200). Especially large/old orgs that migrated gradually: apex kept DNS-only for MX/SPF/legacy reasons while only `www` is proxied.
- **Procedure:**
  1. Resolve both apex and `www`; flag when apex IP is not a Cloudflare range (batch-scriptable across thousands of domains — ~30/40,000 hit rate in the case study).
  2. Confirm direct origin access: `curl -vk --resolve example.com:443:<ORIGIN_IP> https://example.com/` — a 200 without Cloudflare headers = exposed origin.
  3. Test host/SNI variants: `--resolve www.example.com:443:<IP> https://www.example.com/`, and `--connect-to ::<IP>:443` or plain `curl https://<IP>/ -H "Host: www.example.com"` when `--resolve` host strings don't match.
  4. Prove WAF bypass: request a blocked payload (e.g. `/%3Cscript%3Ealert()%3C/script%3E`) through Cloudflare (403) vs directly at origin (404/other) — different response = Cloudflare skipped.
  5. Cross-check `/cdn-cgi/trace`: 200 + `server: cloudflare` via CF, 404 with no cloudflare header at origin.
  6. For browser testing, pin the hostname in Burp: Proxy → Options → Network → Hostname Resolution → map host to origin IP.
- **Verify:** Response from origin IP lacks Cloudflare headers and answers attacker-controlled Host headers. Stop at exposure verification — document headers/status/SSL; don't exploit further without scope. Impact framing: all CF WAF/DDoS/bot protections void; author chained it to XSS→ATO on an employee portal.

### 5. SSRF/LFR bypass of PHP `filter_var(FILTER_VALIDATE_URL)` URL validation

- **When to test:** PHP apps fetching user-supplied URLs (curl, `file_get_contents`, `exec curl`) validated with `filter_var($url, FILTER_VALIDATE_URL, FILTER_FLAG_QUERY_REQUIRED)` — the bare-minimum validation pattern.
- **Procedure:**
  1. Baseline `file:///etc/passwd` fails validation — good, validation exists.
  2. Trick the validator with a fake query: `file:/etc/passwd?/` — the `?` mimics a URL query (needs a non-empty value after it), and only ONE slash is needed after `file:`.
  3. Double-URL-encode for evasion: `file:/etc/passwd%3F/`, `file:/etc%252Fpasswd/`, `file:/etc%252Fpasswd%3F/`.
  4. For path-normalizing fetchers: `file:///etc/?/../passwd` (use `?` as a fake directory then traverse back out), also `file:///etc/%3F/../passwd`.
  5. When the URL lands in a shell (`exec('curl -L '.$url)`), obfuscate with bash variable expansion of unset vars: `file:${br}/et${u}c/pas${te}swd?/` or `$(x)` forms — empty expansions are discarded, defeating keyword filters.
  6. Polyglot covering all three sinks: `file:///etc/passwd?/../passwd`.
- **Verify:** `/etc/passwd` contents returned in the response. Extend by encoding `:`, `.`, `/` in more positions. Adding `localhost` to the polyglot unlocks classic host-based SSRF tricks too.

### 6. Cloud object storage unauthorized PUT (Alibaba OSS; generalizes to S3/GCS/Azure)

- **When to test:** Any 403 from a host whose `Server:` header or fingerprint reveals cloud storage (`AliyunOSS`, `AmazonS3`, GCS XML error bodies). A 403 on GET says nothing about write permissions — ACLs are per-method.
- **Procedure:**
  1. Fingerprint the backend from a 403 response (Wappalyzer, `Server: AliyunOSS`, XML `<Error><Code>AccessDenied</Code>` bodies, `x-oss-request-id`).
  2. Replay the request in Burp Repeater; swap `GET /` for `PUT /poc.json` with a benign JSON body (`{"id": "poc"}`) and correct `Content-Length`.
  3. 200 OK + `ETag`/`Content-MD5` in response = write succeeded.
  4. GET the uploaded object to confirm read-back, then DELETE your PoC file.
- **Verify:** Uploaded object retrievable. Impact framing: defacement, overwriting sensitive files, hosting malicious content on the victim's domain/storage, potential stored XSS if Content-Type is attacker-controlled. Also test DELETE and ACL-reading (`?acl`) methods.

## High-value tips

- **A 403 is a lead, not a wall.** It proves the resource exists and a control is blocking you; the next step is finding a parser that disagrees with that control (CRLF injection, encoding, traversal).
- **Cache-poisoning DoS is reportable where volumetric DoS is not** — always include a cache-buster param so the PoC never affects real users; read policy wording ("launching" vs "reporting").
- **Multi-layer infra = parser discrepancy surface.** LB, WAF, reverse proxy, gateway, and framework each normalize URLs differently; the policy-enforcing layer and the routing layer disagreeing is a whole vuln class.
- **Unkeyed headers are the cache-poisoning goldmine:** `X-Forwarded-Port`, `Transfer-Encoding`, `Accept_Encoding` (underscore evades the key), `Range`, `X-Forwarded-SSL`, `Origin`, `Max-Forwards`, exotic User-Agents.
- **WAFs lag the HTML spec.** Brand-new/experimental DOM events (`onbeforetoggle`, popover API) bypass managed rule sets; automate tag×event fuzzing and verify in a real browser, not by response inspection.
- **Grey-cloud apex is a mass-huntable misconfig:** diff apex vs `www` resolution across your whole scope; `--resolve` + missing `server: cloudflare` is a two-command confirmation.
- **URL validators are bypassable by design artifacts:** a `?` satisfies "query required" checks while pointing at `file:`; bash `${unset}` expansion erases itself mid-keyword.
- **Per-method ACL asymmetry:** storage/CDN endpoints that 403 on GET may accept PUT/DELETE. Always verb-fuzz object storage.
- **Frame impact at the architecture level.** "Exposed metrics endpoint" scored High; "gateway isolation bypass reaching unauthenticated internal APIs" scored Critical. Same bug, different story.
- **Internal endpoints to probe once you traverse:** `/_/metrics`, `/_/heapdump`, `/health`, `/configuration`, `/fetch`, `/preview`, `/users`.

## Case index

| Vuln class | Target/program | Bounty | One-line technique | URL |
|---|---|---|---|---|
| Path traversal / gateway bypass | Private program (Intigriti) | n/a (High→Critical) | `../%0d%0a/../../_/metrics` CRLF+traversal parser discrepancy bypasses API gateway | https://medium.com/@7azimo/breaking-api-gateway-isolation-with-path-traversal-and-url-parsing-discrepancies-01cac2a2724a |
| Cache poisoning / DoS | PayPal | $9,700 | Invalid `Transfer-Encoding` header caches 501 over core JS files | https://hackerone.com/reports/622122 (login wall); method via https://portswigger.net/research/responsible-denial-of-service-with-web-cache-poisoning |
| Cache poisoning / DoS | Tesla / HackerOne / Bitbucket / Instagram / unnamed | $300 / $2,500 / $1,800 / $1,000 / $7,500 | Unkeyed headers (`Any-Header` WAF string, `X-Forwarded-Port`, `Accept_Encoding: br`, IE9 UA) poison cached responses | https://portswigger.net/research/responsible-denial-of-service-with-web-cache-poisoning |
| WAF bypass (XSS) | AWS WAF managed rules (research) | n/a | `onbeforetoggle` + popover payload found by Selenium tag×event fuzzer (Wafer) | https://sysdig.com/blog/fuzzing-and-bypassing-the-aws-waf/ |
| Cloud misconfig / origin exposure | Multiple CF-fronted orgs (~30/40k) | n/a | Grey-cloud apex leaks origin IP; `curl --resolve` hits origin directly, bypassing CF WAF | https://medium.com/@smitgharat0001/cloudflare-bypass-origin-server-deserves-some-love-too-e8bd2182cfea |
| SSRF / LFR | PHP lab cases (research) | n/a | `file:/etc/passwd?/` and `${var}` obfuscation defeat `filter_var` URL validation | https://rodoassis.medium.com/on-ssrf-server-side-request-forgery-or-simple-stuff-rodolfo-found-part-i-4edf7ee75389 |
| Cloud storage misconfig | Alibaba Cloud OSS bucket | n/a | 403 on GET but anonymous `PUT /poc.json` returns 200 — per-method ACL gap | https://medium.com/@muhammadwaseem29/unauthorized-data-upload-in-alibaba-cloud-object-storage-service-cefa6abcef7f |
| HTTP smuggling | (H1 report 2253540) | $1,500 | HTTP smuggling → sensitive data access (page unreachable — see notes) | https://hackerone.com/reports/2253540 |
| SSRF → cloud takeover | Shopify | $25,000 | SSRF → GCP metadata v1beta1 (no header required) → kube-env → kubelet certs → kubectl → root on containers (from feed context; report body behind login) | http://hackerone.com/reports/341876 |

## Coverage notes

- **Skipped/dead:** `hackerone.com/reports/2253540` returned HTTP 403 to the fetcher (smuggling case — no content recovered, only the feed blurb). `hackerone.com/reports/341876` and `hackerone.com/reports/622122` returned only the HackerOne login wall; the PayPal cache-poisoning case is fully covered by the PortSwigger article (same author, albinowax), and the Shopify SSRF chain is summarized from the feed's own takeaway (metadata v1beta1 needs no `Metadata-Flavor` header — worth testing both v1 and v1beta1 on GCP SSRF).
- **Thin evidence:** HTTP request smuggling has zero procedural detail in this batch (only a bounty blurb) — treat smuggling as uncovered here. The GCP metadata → Kubernetes privilege-escalation chain is secondhand (one-line summary, no steps). The Cloudflare and Alibaba OSS cases are single-author Medium posts with lab-scale evidence; the AWS WAF bypass was patched in Dec 2023, so its payload is historical but its fuzzing methodology is the durable lesson.
- No Telegram/WhatsApp links appeared in this batch.
