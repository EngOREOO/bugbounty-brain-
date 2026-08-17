---
name: bb-intel-llm-code-review
description: LLM-assisted secure code review methodology for turning source access into verified vulnerability leads. Use when you have source code of an authorized target (open-source app, cloned/leaked repo, client-provided code) and are dropped into an unfamiliar stack, when tracing a suspicious endpoint end-to-end (e.g. a Cypher/custom-DSL query route), when enumerating async daemons/workers as second-order attack surface, or when triaging unknown services/binaries on a host. Not for black-box-only testing.
---

# LLM-Assisted Secure Code Review

## Purpose and scope

A methodology for using an LLM CLI (e.g. Claude Code with `--system-prompt-file`) as a code-review accelerator: build understanding of an unfamiliar codebase, trace sources to sinks, and generate *annotated leads* that you verify manually. High-value on complex paths: async worker/daemon pipelines, custom query-language translation layers (frontend DSL → backend SQL), and triage of unknown services on a host.

Non-goals:
- Not a "find all vulns for me" prompt recipe — that yields a false-positive firehose.
- Not a substitute for manual verification; model output is leads, not findings.
- Not for black-box targets with no source access.

## Preconditions

- AUTHORIZED, in-scope target only. Source access must be legitimate: public open-source, in-scope leaked/cloned repo used per program rules, or client-provided code on an engagement.
- OPSEC: never send private/client code to public hosted models. Use a local model or an approved self-hosted option (e.g. Amazon Bedrock) with explicit client approval.
- You can run an interactive LLM CLI session; optionally wire it to Burp Suite via MCP so the model can consult proxy history and execute its recommended requests.

## Decision tree

- Unfamiliar language/framework blocking review → build the structured system prompt (Technique 1) and use the `[TeachMe]` trigger for in-context explanations.
- You observed a suspicious endpoint in the browser (endpoint + request body known) → request-path tracing (Technique 2).
- App has async daemons/workers consuming DB tables or queues → daemon enumeration (Technique 3); prioritize workers acting on user-influenceable data.
- Frontend DSL translated to backend queries (e.g. Cypher → PostgreSQL) → translation-layer analysis inside Technique 2, hunting blocklist gaps and dangerous primitives.
- Unknown binary/service on a host during a pentest → service triage (Technique 4).
- Model states a wrong fact (wrong DB engine, wrong framework) → issue a persistent "memorize" correction, then re-ask (Technique 1, step 4).

## Techniques

### 1. Structured system prompt + one session per line of inquiry

**When to test:** first contact with any target codebase; the foundation for every other technique.

1. Write a reusable `system-prompt.md` containing:
   - Persona: attacker-minded code security analyst; consider bypasses, edge cases, race conditions.
   - Mode switch: default terse analysis; a trigger token (e.g. `[TeachMe]`) switches to verbose educational mode explaining language/framework mechanics in the target's context.
   - Methodology: no speculation without code evidence; label every conclusion High/Medium/Low confidence; trace where input enters, where it is transformed/validated, whether validation/encoding/parameterization is sufficient, and whether data is stored and reused unsafely.
   - Response format: code snippets with line numbers + parent function names, full file paths, narration, and "next steps" with concrete curl commands/payloads. Path analysis structure: 1) Data Flow Summary, 2) Sources, 3) Sinks, 4) Full Data Flow Walkthrough (function call → definition).
   - Source list: HTTP query params, request body, JSON, headers, cookies, WebSocket messages, uploaded files, query-language input (e.g. Cypher).
   - Sink list: DB queries (SQL + graph/NoSQL), cloud storage, filesystem, OS command execution, template rendering, deserialization, authn/authz decisions, external API calls, SSRF-capable HTTP clients.
   - Application Information block: app name, type, purpose, data stores, authorization model, URL, language/frameworks, API spec link, and **full absolute paths** to components (router, controllers, frontend, daemons) so the model doesn't burn tokens locating them.
   - Optionally an example output block to tune formatting.
2. Launch one interactive session per line of inquiry:
   `claude --system-prompt-file /path/system-prompt.md '<PROMPT>'`
   The rolling context window is all the memory the model has — keep related follow-ups in one session; start fresh for unrelated questions.
3. Ask for understanding, not vulns: structure, data flow, sources/sinks. Accept or reject its security annotations as you go.
4. Correct factual errors with persistent memory, e.g. `Memorize that BloodHound uses PostgreSQL, not Neo4j; DAWGS performs the Cypher→PostgreSQL translation.`
5. **Verification:** every lead is confirmed by reading the cited code yourself before any live test.
6. **Failure recovery:** if output is vague or speculative, add missing absolute component paths to the Application Info block and narrow the question to one function or one route.

### 2. Request-path tracing (incl. DSL→SQL translation layers)

**When to test:** you can describe an observed endpoint and request body from the browser/proxy; especially query-translation layers where authz bypass and injection hide.

1. Describe only what you observed: endpoint + body. Example prompt: `Show me the code path for Cypher queries submitted to POST /api/v2/graphs/cypher` plus the observed JSON body.
2. Have the model trace end-to-end and identify: input filters/tokenizers (e.g. ANTLR parsing + procedure allowlist), mutation checks, read-only enforcement.
3. Hunt filter gaps: newly added procedures missing from the blocklist, bypassable read-only enforcement, dangerous primitives like `LOAD FROM CSV` still reachable.
4. **Verification:** re-read the cited tokenizer/filter code, then send the bypass candidate request yourself (or via Burp MCP) and confirm server-side behavior.
5. **Failure recovery:** if the trace dead-ends at a generated/external component, point the model at its absolute path or paste the relevant function and ask it to continue from there.

### 3. Async daemon/worker enumeration (second-order surface)

**When to test:** the app runs background workers consuming cron, message queues, or DB tables — high yield when web-app input can tamper with the consumed data.

1. Prompt the model to enumerate async workers with: functionality, trigger type (cron / message queue / DB table), inputs, and source locations.
2. Prioritize workers that act on user-controlled data (e.g. a data-pipe daemon consuming DB tables you can influence via the web app); write off no-input maintenance workers as low risk.
3. Trace how attacker-influenced rows/queue messages reach the worker's sinks (command exec, file writes, queries).
4. **Verification:** confirm the write path from the web app to the table/queue in code, then prove influence with a benign marker value and observe the worker processing it.
5. **Failure recovery:** if triggers are unclear, search the codebase for the queue/table name and cron schedulers directly, then feed matches back to the model.

### 4. Unknown service/binary triage

**When to test:** an unfamiliar custom service or binary on an in-scope host during a pentest.

1. Provide a minimal Application Info block (name, paths, purpose if known).
2. Ask for "features of security interest that receive untrusted input: filesystem interactions, hosted services, named pipes, secret handling" presented as a table.
3. Have the model generate PoC scripts (e.g. PowerShell) for the top candidates.
4. **Verification:** run the PoC yourself in the authorized environment; treat script output as a hypothesis until observed behavior confirms it.
5. **Failure recovery:** if the model lacks enough context, supply the binary's config files, service definition, and strings output, then re-ask.

## Safety and authorization

- Test only authorized, in-scope targets; source access itself must be permitted by the engagement/program.
- Never send private or client code to public hosted models — local model or approved self-hosted only.
- All model output is unverified lead material; no finding is reported without manual code confirmation and/or a live request you executed.
- Live-request PoCs must be non-destructive: benign markers, no data exfiltration beyond minimal proof, no modification of other users' data.
- Cache-buster requirement: any live test that could be cached must include a unique cache-busting parameter per request.
- For exposed services/daemons, keep PoCs contained: prove reachability/influence with the smallest possible action (e.g. a marker row), never pivot or persist.

## Source notes

Distilled from `references/writeup-cases.md` (batch `llm-mobile-oauth`): a single genuine methodology post — SpecterOps, "Leveling Up Secure Code Reviews with Claude Code" (2026-03-26) — plus one excluded non-security pricing blog. Note the batch name is misleading: no mobile or OAuth writeups were present, and no cross-writeup corroboration exists.
