# Source Notes — "Ai For Bug Bounty" (Red Nexus)

Source: https://www.youtube.com/watch?v=Sx0-_UrHots (~52 min, auto-captions, heavily garbled).
Study workspace: `video-studies/sx0-urhots/` (claims.json, procedures.md, per-chunk reports).
Evidence quality: 14 verified / 18 inferred consolidated claims; no speaker claim was promoted to verified on authority alone.

## Key timestamped evidence

- 00:01–00:04 — Agent CLI install on a Linux VPS via a link + `bash`; access-type prompt (subscription vs prepaid console API vs third-party); login and folder-trust prompt (grants read/write). (reports 0002–0004)
- 00:05–00:10 — "Skills" concept: single Markdown file (name, description, metadata, tool-download instructions) as a named folder in the agent config directory; discovered at startup; invoked slash-style with a target. Skill-not-found fix: Ctrl+C, correct folder name, relaunch, re-trust. (reports 0005–0008)
- 00:12–00:16 — Bypass-permissions mode (captioned "Dangerously Bypass", likely `--dangerously-skip-permissions`; UI shows "Bypass Permissions On"); passive vs active recon tool split; organized output folders. (reports 0009–0011)
- 00:17–00:21 — Hunting sequence: parameter discovery (Arjun/ParamSpider-like) → scope filtering → injection testing (SQLi/XSS/SSTI), orchestrated by a skill.md; provider blocking resolved via the provider's security form. (reports 0012–0013)
- 00:21–00:27 — Skill bundles (SKILL.md + bootstrap.sh) deployed to a fast VPS; results inspected via `sqlite3 <db>` → `.tables` → SELECT FQDN rows; continuous monitoring idea: recurring scans + Telegram/Discord alerts + full scan per new domain. (reports 0014–0016)
- 00:29–00:35 — wget-based skill install + bootstrap placement; recognizable user agent / handle advised; scope pasted with customer assets explicitly out of scope (demo: ~1,900 of ~10,000 discovered Swisscom domains in scope). (reports 0018–0020, 0022)
- 00:40–00:47 — Backend swap: OpenAI route blocked → Ollama local model on CPU-only VPS (~9 GB model; RAM exhaustion ended the demo); cheap cloud API alternative (~$1/1M tokens, likely DeepSeek — name garbled). (reports 0024–0027)
- 00:48–00:52 — Closing advice: VPS + subscription API + self-written skills; an AI tool solving certification labs autonomously (offensive demo withheld by speaker). (reports 0028–0030)

## Unresolved conflicts (recorded, not decided)

1. Enter-at-prompt behavior ambiguity (0002 vs 0003).
2. Whether skill.md persists or is removed after install (0007 vs 0018).
3. Skill destination: `.cloud`/`.claude` config dir vs separate "BB Setup" folder (0008 vs 0017).
4. Local agent claimed both free and costly (0021 vs 0026).
5. "Runs fully offline" claim vs VPS-dependent setup (0024 vs 0026).
6. Contradictory closing model recommendations (0028).

## Unknowns (confirm externally before relying on)

- Exact installer URL/commands, the real skip-permissions flag text, and the config directory path (captioned `.cloud`, likely `~/.claude`).
- Identity of the community GitHub project (~4000 stars claim), the "scope filter" tool, the certification-lab tool ("Trauma"), and the cheap Chinese API provider.
- Bootstrap script contents; never run unreviewed.
