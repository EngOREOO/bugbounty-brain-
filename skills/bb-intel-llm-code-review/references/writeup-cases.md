# llm-mobile-oauth methodology digest

Batch note: despite the batch name, both collected URLs were tagged `llm-ai` only; no mobile or OAuth writeups were present in this batch. One URL was a genuine methodology post (LLM-assisted secure code review); the other was a non-security model-pricing blog.

## Hunting procedures

### 1. LLM-assisted secure code review with a structured system prompt (Claude Code)

**When to test:** you have source access to a target (open-source app, leaked/cloned repo, client-provided code on a pentest) and are dropped into an unfamiliar language/framework/stack. Especially valuable for complex paths: async worker/daemon pipelines, custom query-language translation layers (e.g., frontend Cypher → backend SQL), and triage of unknown custom services on a host.

**Procedure:**
1. Build a reusable system prompt file (save as `system-prompt.md`) containing:
   - Persona: attacker-minded code security analyst; consider bypasses, edge cases, race conditions.
   - A mode switch: default terse analysis mode; a trigger token (e.g. `[TeachMe]`) switches to verbose educational mode explaining language/framework mechanics.
   - Analysis methodology: no speculation without code evidence; label every conclusion High/Medium/Low confidence; explicitly trace where input enters, where it's transformed/validated, whether validation/encoding/parameterization is sufficient, and whether data is stored and reused unsafely.
   - Response format: code snippets with line numbers + parent function names, full file paths, narration, and "next steps" with concrete curl commands/payloads. Structure path analysis as: 1) Data Flow Summary, 2) Sources, 3) Sinks, 4) Full Data Flow Walkthrough (step-by-step, function call → definition).
   - Explicit source list: HTTP query params, request body, JSON, headers, cookies, WebSocket messages, uploaded files, query-language input (e.g. Cypher).
   - Explicit sink list: DB queries (SQL + graph/NoSQL), cloud storage, filesystem, OS command execution, template rendering, deserialization, authn/authz decisions, external API calls, SSRF-capable HTTP clients.
   - Application Information block: app name, type, purpose, data stores, authorization model, URL, language/frameworks, API spec link, and **full absolute paths** to components (router, controllers, frontend, daemons) so the model doesn't burn tokens locating them.
2. Launch one interactive session per line of inquiry:
   `claude --system-prompt-file /path/system-prompt.md '<PROMPT>'`
   Keeping one inquiry per session keeps the relevant context in the window for follow-ups.
3. Daemon/worker enumeration: prompt the model to enumerate async workers with functionality, trigger type (cron / message queue / DB table), inputs, and source locations. Prioritize workers that act on user-controlled data (e.g., a data-pipe daemon consuming from DB tables you can influence via the web app); write off no-input maintenance workers as low risk.
4. Request-path tracing: describe only what you see in the browser (endpoint + request body) and let the model trace it end-to-end, e.g. `Show me the code path for Cypher queries submitted to POST /api/v2/graphs/cypher` with the observed JSON body. Look for: input filters/tokenizers (e.g., ANTLR parsing + procedure allowlist), mutation checks, and whether filtering has gaps (newly added procedures missing from the blocklist, bypassable read-only enforcement, dangerous primitives like `LOAD FROM CSV` reachable).
5. Correct model errors with persistent memory: e.g. `Memorize that BloodHound uses PostgreSQL, not Neo4j; DAWGS performs the Cypher→PostgreSQL translation.` Corrections persist across sessions and improve later output.
6. Triage unknown binaries/services: with a minimal Application Info block, ask for "features of security interest that receive untrusted input: filesystem interactions, hosted services, named pipes, secret handling" presented as a table, then have the model generate PoC scripts (e.g., PowerShell) for manual validation.
7. Verify manually: treat all model output as leads, not findings — confirm each suspected vuln by reading the cited code and testing the endpoint yourself.

**Tools:** Claude Code CLI (`--system-prompt-file`), optionally wired to Burp Suite via MCP server so the model can execute the requests it recommends.

**Verification:** a candidate vuln counts only when you confirm it in code and/or with a live request; expect the model's raw "find all vulns" output to be mostly false positives — that is why the methodology uses it for understanding + annotated leads instead.

## High-value tips

- Don't ask an LLM to "find vulns" — you get a false-positive firehose. Use it to build understanding of the code (structure, data flow, sources/sinks) and accept/reject its security annotations as you go.
- The system prompt is the lever: persona, response schema, confidence labels, source/sink definitions, and absolute component paths dramatically cut false positives and wasted tokens.
- Use a conditional second persona (trigger token like `[TeachMe]`) to get framework/language explanations in the context of the target app — replaces the spin-up cost of unfamiliar stacks.
- One interactive session per line of inquiry; the rolling context window is all the "memory" the model has, so keep related follow-ups in one session and start fresh for unrelated questions.
- Async daemons/workers fed from DB tables or queues are a high-yield review target: if web-app input can tamper with the queue/table data, the worker becomes a second-order attack surface.
- Query-translation layers (frontend DSL → backend SQL, e.g. Cypher→PostgreSQL) are where authz bypass and injection hide — trace the tokenizer/filter step and look for procedures missing from the blocklist.
- Provide example output in the system prompt to tune response formatting further.
- OPSEC: never send private/client code to public hosted models; use a local model or self-hosted (e.g., Amazon Bedrock) with client approval.
- Hooking the LLM to Burp via MCP lets it both consult proxy history and execute its own recommended test requests.
- Model output had at least one factual error (wrong DB engine) — always sanity-check; use persistent "memorize" corrections to fix recurring mistakes.

## Case index

| vuln class | target/program | bounty | one-line technique summary | URL |
|---|---|---|---|---|
| llm-ai (methodology) | N/A (BloodHound CE + BadWindowsService as demos) | N/A | Structured system prompt + per-inquiry Claude Code sessions to trace sources→sinks, enumerate daemons, and triage services | https://specterops.io/blog/2026/03/26/leveling-up-secure-code-reviews-with-claude-code/ |
| llm-ai (non-security) | N/A | N/A | Model pricing/benchmark comparison — no hunting methodology | https://nitingavhane.medium.com/deepseek-v4-flash-costs-99-less-than-claude-opus-4-8-and-beats-it-on-exactly-one-benchmark-1ffc735d8acb |

## Coverage notes

- Batch contained only 2 URLs (well under the 20-fetch cap); both were fetched.
- **Skipped as non-writeup:** the Medium post (DeepSeek vs Claude pricing/benchmark blog) — fetched successfully but contains zero security methodology; excluded from procedures.
- **No dead links** in this batch.
- **Thin evidence:** the batch name implies mobile and OAuth topics, but neither collected URL covered mobile app testing, OAuth flows, or any vulnerability class with a real target/bounty. All procedural content above derives from a single methodology post (LLM-assisted code review); there is no cross-writeup corroboration in this batch.
