# bugbounty-brain

> **16,700+ verified bug bounty writeups, attack patterns, and exploit chains — curated, structured, and searchable.**

The collective brain of bug bounty. A knowledge base and AI skill that synthesizes real-world disclosed reports into actionable hunting intelligence. Feed it to your AI and turn any LLM into a top-1% bug bounty hunter.

---

## What's Inside

| Component | Description | Lines |
|-----------|-------------|-------|
| `SKILL.md` | Complete bug bounty hunting skill — attack chains, recon methodologies, vuln testing, report writing, triage psychology | 1,269 |
| `WRITINGS.md` | Curated catalog of 500+ writeup sources organized by platform, vulnerability type, and bounty range | 506 |
| `X_INTEL.md` | Live intel distilled from a curated bug bounty X/Twitter feed — 32 tools, 25 bounty writeups, 35 techniques, 31 CVEs | ~250 |
| `data/final_all.json` | 16,700+ verified writeups with titles, URLs, and platform metadata | — |
| `data/final_count.json` | Summary statistics and platform breakdown | — |

### What SKILL.md Covers

- **20 Attack Chains** that earned $5K-$50K+ bounties (SSRF→cloud creds, IDOR→XSS→mass ATO, OAuth chains, race conditions)
- **Top 10 Highest-Paying Vuln Classes** with payloads, endpoints, and exploitation steps
- **Complete Testing Checklists** for XSS, SQLi, SSRF, IDOR, CSRF, XXE, OAuth, API security
- **Expert Recon Methodologies** from Frans Rosén, NahamSec, Shubham Shah, Orange Tsai, Jason Haddix
- **Report Writing Masterclass** with 5 real-world $15K-$50K report examples
- **Triage Psychology** — what gets accepted vs rejected, pro tips
- **Emerging Attack Surfaces** — AI/ML prompt injection, WASM, HTTP/3, serverless, WebSocket hijacking
- **Automation Scripts** — IDOR scanner, GraphQL analyzer, cookie bomb generator, HTTP smuggling test
- **Platform Cheat Sheets** — HackerOne, Bugcrowd, Shopify, GraphQL-specific
- **Bug Bounty Economics** — how programs set bounties, maximizing earnings

### Data Coverage

| Platform | Reports | Source |
|----------|---------|--------|
| HackerOne | 12,934 | GraphQL API scrape + 6 datasets merged |
| Bugcrowd | 1,056 | CrowdStream REST API |
| Medium | 350 | Websearch verified |
| Dev.to | 41 | Websearch verified |
| Intigriti | 36 | Bug Bytes + research |
| YesWeHack | 30 | Blog + dojo + reports |
| Hashnode | 27 | Websearch verified |
| InfoSecWriteups | 31 | Cross-posts |
| Other | 2,203 | PortSwigger, GitHub, LinkedIn, Arabic, Portuguese, Hindi |

---

## Installation

### OpenCode (Recommended)

OpenCode auto-discovers skills from `~/.agents/skills/`. One command:

```bash
git clone https://github.com/EngOREOO/bugbounty-brain-.git ~/.agents/skills/bugbounty
```

Done. The skill activates automatically when you ask about bug bounty, security testing, or vulnerability hunting.

### Claude CLI

Claude CLI loads skills from `~/.agents/skills/` or project-level `.claude/skills/`.

**Global install (all projects):**
```bash
git clone https://github.com/EngOREOO/bugbounty-brain-.git ~/.agents/skills/bugbounty
```

**Project-level install:**
```bash
git clone https://github.com/EngOREOO/bugbounty-brain-.git .claude/skills/bugbounty
```

Then reference it in your prompts:
```
Use the bug bounty skill to test this API for IDOR: https://api.target.com/v1/users/{id}
```

Or let it auto-activate by just asking:
```
Find bugs on https://target.com
```

### Codex (OpenAI)

Codex reads instructions from `AGENTS.md` or `CODEX.md`. To use this skill:

```bash
# Install the skill
git clone https://github.com/EngOREOO/bugbounty-brain-.git ~/.agents/skills/bugbounty

# Reference it in your project's AGENTS.md
echo "When doing security testing, read and follow ~/.agents/skills/bugbounty/SKILL.md" >> AGENTS.md
```

Or inline the skill in your prompt:
```
Read ~/.agents/skills/bugbounty/SKILL.md and use it to test https://target.com for SSRF
```

### Claude Desktop / Cursor / Windsurf

These tools support project-level rules. Add to your `.cursorrules` or project rules:

```
When performing security assessments or bug bounty hunting, 
read ~/.agents/skills/bugbounty/SKILL.md for methodology and attack patterns.
Also reference ~/.agents/skills/bugbounty/WRITINGS.md for writeup examples.
```

### Manual Usage

You can also just read the files directly and use them as reference:

```bash
# Read the full skill
cat ~/.agents/skills/bugbounty/SKILL.md

# Browse the writeup catalog
cat ~/.agents/skills/bugbounty/WRITINGS.md

# Query the dataset
python3 -c "
import json
with open('data/final_all.json') as f:
    data = json.load(f)
ssrf = [v for v in data.values() if 'ssrf' in v['title'].lower()]
print(f'{len(ssrf)} SSRF writeups found')
for w in ssrf[:5]:
    print(f'  - {w[\"title\"]}')
"
```

---

## Example Prompts

### Recon & Attack Surface
```
Map the attack surface of https://target.com — find subdomains, endpoints, tech stack
What's the best recon methodology for a SaaS application?
Run subfinder and httpx on target.com
```

### Vulnerability Hunting
```
Test this endpoint for SSRF: POST /api/import/url
Find IDOR vulnerabilities in this API: GET /api/v1/users/{id}/orders
Test this OAuth flow for redirect_uri bypass
Give me payloads for XSS in a React application
How do I test for race conditions on a payment endpoint?
```

### Chaining & Escalation
```
I found an SSRF on a cloud-hosted app. What's the escalation chain?
I have a self-XSS — how do I chain it to achieve account takeover?
I found a CORS misconfiguration — what can I chain this with?
```

### Report Writing
```
Write a bug bounty report for the IDOR I found on /api/v1/users/{id}
Help me write a CVSS score for an SSRF that leaks AWS IAM credentials
What's the business impact of a GraphQL introspection leak?
```

### Learning
```
Teach me how to test for SSRF like Orange Tsai
What are the top 5 highest-paying vulnerability classes in 2025?
Walk me through a real-world OAuth ATO chain
Show me the report writing template for HackerOne
```

---

## Quick Start: First Hunt

Ask your AI:

```
I want to start bug bounty hunting. I have Burp Suite and a HackerOne account. 
Walk me through my first target — step by step.
```

The skill will guide you through:
1. Picking a program (scope, bounty range, difficulty)
2. Recon (subdomain enum, port scan, JS analysis)
3. Finding attack surfaces (APIs, GraphQL, auth flows)
4. Testing for vulns (IDOR, SSRF, XSS, auth bypass)
5. Writing your first report

---

## Stats

- **16,700+** verified writeups from 19 platforms
- **12,934** HackerOne reports (full metadata)
- **20** advanced attack chains from $5K-$50K+ bounties
- **5** complete report writing examples
- **8** expert hunter methodologies
- **15** quick-win techniques
- **10** vulnerability class deep-dives with payloads
- **$81M** total bounties paid on HackerOne in 2024-2025

---

## License

MIT — Use freely, share widely, hunt responsibly.
