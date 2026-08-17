---
name: ai-agent-bug-bounty-recon
description: Set up and operate an AI CLI agent (Claude Code-style) on a VPS for bug bounty recon and hunting using skill files — installing skills, creating custom skill.md workflows, running scope-disciplined recon-to-injection pipelines, and inspecting results. Use when the user asks to automate bug bounty recon with an AI agent, install or write agent skills for hunting, run an AI-driven subdomain/parameter/injection workflow against an in-scope target, or move that setup onto a VPS.
---

# AI Agent Bug Bounty Recon

## Purpose and scope

Run a repeatable, AI-agent-orchestrated bug bounty workflow: an agent CLI on a Linux VPS executes "skills" (Markdown instruction bundles) that drive recon (subdomain enumeration), parameter discovery, and injection testing, with results organized for manual or AI-assisted review.

Non-goals: exploiting out-of-scope assets, unattended bypass of authorization checks, reproducing any specific commercial tool whose identity was not confirmed by the source, and one-off manual scanning that needs no agent.

## Inputs and preconditions

- An in-scope, authorized bug bounty target with its program scope list (in-scope and out-of-scope assets) in hand.
- A Linux VPS with terminal/SSH access (preferred over a home connection when bandwidth is poor).
- An agent CLI installed (the source demonstrates a Claude Code-style CLI; exact installer unknown — use the vendor's official docs).
- An account: subscription plan, prepaid console API key (billed per call), a third-party/cloud LLM API key, or a local model backend (Ollama).
- `sqlite3` for inspecting tool output databases.

## Decision tree

1. **No skill exists for the task?** Write a custom one (Procedure B) before running.
2. **Skill installed but not found by the agent?** Folder-name mismatch — Ctrl+C, fix the folder name to match exactly, relaunch, re-trust the folder.
3. **Run stalls on yes/no permission prompts?** Either attend the machine and approve each, or — only on an isolated, fully authorized setup — relaunch with the skip-permissions flag (see Security section).
4. **Cloud API blocked or too expensive?** Fall back to a local Ollama model on the VPS (CPU-only works; size the model to available RAM).
5. **Provider blocks your scanning traffic?** Stop; use the provider's security/abuse form stating authorized bug bounty work. Do not keep hammering.
6. **Target assets change daily?** Schedule recurring scans with Telegram/Discord alerts and trigger a full scan per newly seen domain.

## Procedure

### A. Run an agent recon workflow against an authorized target

1. Install the agent CLI on the VPS per its official docs; log in (subscription or API key) and deliberately confirm the trust-folder prompt, which grants the agent read/write on that directory.
2. Install skill bundles (named folder + `skill.md` in the agent's config directory, e.g. `~/.claude/skills/`), or fetch them with `wget` and a reviewed bootstrap script that places each skill.
3. Invoke the skill slash-style: type its name, then the target domain when prompted. On first run, approve each tool download/configuration prompt.
4. Tell the agent this is authorized bug bounty work; paste the program link and the full scope, explicitly marking customer-related assets out of scope.
5. Set a recognizable user agent / handle (e.g. your platform handle) so the target can identify your traffic.
6. Let the pipeline run: passive enumeration first, then active enumeration, then (with a hunting skill) parameter discovery (Arjun/ParamSpider-style tools) and injection testing (SQLi/XSS/SSTI). Expect long runs — tens of minutes before filtering/dedup completes.

### B. Create a custom skill

1. In the agent's config directory, create a folder named exactly after the skill.
2. Write `skill.md` inside it: name, description, metadata, and the ordered instructions (tool downloads, commands, output handling).
3. Relaunch the agent, confirm "Yes Trust", and check the skill list — the new skill must appear.
4. Invoke it slash-style with a target argument to smoke-test.

### C. Inspect results

1. Open the recon results database: `sqlite3 <results.db>`.
2. List tables with `.tables`; `SELECT` the FQDN/subdomain rows.
3. Alternatively hand the output back to the agent ("list the subdomains in this file") for filtering.

## Verification

- The skill appears in the agent's skill list and executes against the target.
- Organized output folders/files (or a results DB) appear and grow during the run.
- The agent restates the scope you supplied; out-of-scope assets are untouched.
- `sqlite3` lists collected FQDNs; partial or failed items mean re-running the recon step, not more querying.

## Failure recovery

- **Skill not found:** Ctrl+C → verify folder name matches exactly → relaunch → re-trust → re-check the list.
- **Permission-prompt loop:** attend and approve, or deliberately switch to bypass mode (isolated setups only — see below).
- **Provider blocking:** stop, file the provider's security form, wait for confirmation.
- **Local model RAM exhaustion:** switch to a smaller/quantized model, a local Linux machine, or a paid cloud API.
- **Missing root password or unknown installer content:** stop; never paste or run what you don't understand. Review remote scripts before piping to bash.

## Security and authorization

- **Bypass-permissions mode** (e.g. `--dangerously-skip-permissions`) disables ALL human confirmation of agent actions. Use only on isolated VPS setups against fully authorized in-scope targets; confirm the exact flag in the tool's own docs. Never combine with production or out-of-scope assets.
- Folder-trust grants the agent read/write on that directory — answer deliberately.
- API keys, auth tokens, and program scope details are secrets: never write them into skill files, study notes, or shared transcripts.
- Active scanning and injection testing require explicit authorization and must respect rate limits; expect and handle provider blocking through official channels, not evasion.
- HUMAN CONFIRMATION REQUIRED before: enabling bypass mode, running any downloaded bootstrap script, and launching injection testing.

## Source notes

Distilled from "Ai For Bug Bounty" (Red Nexus), https://www.youtube.com/watch?v=Sx0-_UrHots — see [references/source-notes.md](references/source-notes.md) for timestamped claims, conflicts, and unknowns. The source auto-captions were heavily garbled; tool and flag names marked "likely" must be confirmed against official docs before use.
