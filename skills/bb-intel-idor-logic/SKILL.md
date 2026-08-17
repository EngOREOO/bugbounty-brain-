---
name: bb-intel-idor-logic
description: IDOR, mass-assignment (BOPLA), and business-logic exploitation techniques distilled from real bug bounty writeups. Use when hunting IDOR / broken object-level authorization on an authorized target, when numeric or opaque IDs appear in API requests, when an update endpoint accepts a settings/profile object, when a feature is gated by client-side response flags, when cart or checkout pricing can be tampered, or when a structured ID (Salesforce, Base64 composite, UUID) needs enumeration.
---

# IDOR, Mass Assignment & Business-Logic Exploitation

## Purpose and scope

Techniques for finding and proving authorization and logic flaws — classic IDOR, cross-tenant IDOR, mass assignment, response manipulation, price tampering, ID enumeration — as reported in real writeups. Non-goals: this is not a recon guide, not a scanner config, and not generic web testing. It assumes you already have a mapped application and authenticated sessions. It does not cover infrastructure bugs or injection classes (SQLi/XSS/RCE) except where they intersect a logic flaw.

## Preconditions

- The target is an **authorized, in-scope** bug bounty program; you have written permission to test it.
- You can register at least **two accounts** (TestA = victim, TestB = attacker). Almost every technique here needs two sessions.
- Traffic is proxied through Burp (or equivalent) with full request history; you have already browsed every feature to enumerate endpoints. Old-school manual mapping beats automation for these bugs — every source writeup was found by hand.

## Decision tree

- Numeric ID in path/body/query, resource carries PII or documents → **T1: Classic two-account IDOR** (also probe write/delete side effects, then sibling endpoints).
- Opaque/Base64/composite ID in a multi-tenant SaaS → decode it → **T2: Cross-tenant IDOR via composite IDs** (partial swap vs full swap).
- Update endpoint accepts a `settings`/profile JSON object; billing or plan state lives there → **T3: BOPLA / mass assignment**.
- Feature gated by flags in API responses (`userverified`, plan state) or a workflow blocked by an error response → **T4: Response manipulation** (Burp Match & Replace on responses).
- Cart/checkout on a hybrid stack (e.g. Next.js + WooCommerce), `meta-*` fields or promo actions → **T5: Price manipulation via metadata injection**.
- Structured IDs (18-char Salesforce, UUIDs with constant prefixes) gate data → **T6: ID truncation + brute force** (checksum removal collapses the keyspace).
- Valid action scoped to an allowlist (e.g. add managers *only from contacts*) → **T7: Privilege-boundary IDOR** (swap the scoping parameter).
- A cache-poison payload is rejected (400) when sent alone → **T8: Race the validator** (single-connection request group).
- GraphQL queries take document/billing IDs (`BillingDocumentDownload`, `BillDetails`) → apply T1 to the GraphQL layer — financial-document endpoints are high value.

## Techniques

### T1. Classic two-account IDOR (document/resource endpoints)

- **When to test:** numeric IDs in request paths/bodies; document-upload flows (licenses, IDs, insurance) with PII; delivery/HR/KYC apps.
- **Steps:**
  1. Map every feature with Burp proxying; note each endpoint using a numeric ID (URL path, JSON body, query param).
  2. On TestA, create the sensitive resource (driver application, vehicle docs).
  3. Capture TestA's PUT/GET (ID in URL). Swap in TestB's session cookie, keep TestA's ID.
  4. Check read access AND side effects — one case also re-linked the object to the attacker's account and deleted it from the victim's (unauthorized write + deletion → higher severity).
  5. Repeat on sibling endpoints — a parallel "vehicle application" endpoint paid a second bounty ($1500 × 2).
- **Verify:** victim-only data renders with attacker session; document the unauthorized state change; report each endpoint separately.
- **Failure recovery:** if 403, the ID may be validated against the session — try a different verb (PUT vs GET), or a parallel endpoint for the same object.

### T2. Cross-tenant IDOR via composite (Base64) object IDs

- **When to test:** multi-tenant SaaS; long Base64 IDs on shared-resource delete/edit endpoints (API specs, contracts), REST or GraphQL.
- **Steps:**
  1. Decode the opaque ID — one decoded to `accountId | NXXP | REST_API_CONTRACT | GUID`.
  2. Swap only the inner GUID (victim's), keep your accountId → expect Access Denied (partial validation exists).
  3. Swap **both** accountId and GUID to the victim's values. The server validated accountId↔GUID consistency but never checked caller authorization → victim's OpenAPI spec deleted.
  4. Enumeration: GUIDs are obtainable if you were ever a member of the victim org (join, leave, keep IDs).
- **Verify:** an attacker account with zero relationship to the victim org deletes the victim's resource (200 + resource gone).
- **Failure recovery:** if full swap also fails, the server checks caller membership — pivot to T7 (allowlist scoping) or look for GUID leaks in shared UI/emails.

### T3. BOPLA / mass assignment on settings objects

- **When to test:** org/account update endpoints accepting a `settings` or profile JSON object; anything where billing/plan state lives in a user-writable object.
- **Steps:**
  1. Create an org/resource; note its ID.
  2. `PUT /api/users/{user_id}/organizations/{id}` with `{"settings":{"plan":"premium"}}`.
  3. Re-GET the resource to confirm persistence server-side — the UI still showed "14 days trial left" while the backend stored `premium`.
- **Verify:** backend GET echoes the modified value. CWE-285/CWE-840, OWASP API3:2023.
- **Failure recovery:** if the field is ignored, try nested variants (`settings.plan.name`), dot-notation, or duplicate JSON keys; also test other privileged fields (`role`, `is_admin`, `verified`).

### T4. Response manipulation to bypass client-enforced gates

- **When to test:** features gated on verification/plan flags returned in API responses; error responses that block a workflow (downgrade blocked by too many projects).
- **Steps:**
  1. Diff responses between a verified/paid and an unverified/free account; find flag fields.
  2. Burp → Proxy settings → Match & Replace on the *response* body: `userverified:''` → `userverified:'y'`, `userphone:''` → `userphone:'y'`. Reload the gated feature — verification skipped.
  3. Variant: intercept the response of a blocked action, use "do intercept → response to this request", replace the error body with a success body, forward → server downgraded plan while keeping all projects.
- **Verify:** gated feature usable / plan state changed with constraints violated.
- **Failure recovery:** if the server re-checks state on the next request, combine with T3 (make the forged state real server-side) — response flips that don't persist are weaker evidence.

### T5. Price manipulation via metadata injection (hybrid-stack checkout)

- **When to test:** hybrid stacks (Next.js frontend + legacy WooCommerce checkout); cart "modify item" or promo (BXGX) server actions accepting `meta-`-prefixed JSON fields; unauthenticated carts stored client-side and rebuilt server-side at checkout.
- **Steps:**
  1. Intercept the cart-modify server action (`POST /cart/` with `Next-Action` header, multipart body, `1_change_metaData` JSON field).
  2. Confirm the backend merges any `meta-*` key into item metaData. Try `meta-__proto__` first (prototype pollution) — failed in this case.
  3. Mirror the item's real properties as `meta-` keys with attacker values: `meta-price`, `meta-regularPrice`, `meta-lp_override_price` set to `-779`. Cart UI looks normal; proceed to checkout — the WordPress side merges metaData into core item properties → negative price, order for free.
  4. Variant: promo endpoint (`1_bxgx_offer`) creating a free item — inject a custom `poc_price` field (seen in responses) to set the free item's price negative.
- **Verify:** the price change only manifests at checkout (the trust-boundary handoff), not in cart UI — always click through to payment. Cancel/void before any real charge.
- **Failure recovery:** if metaData isn't merged at checkout, look for other handoff boundaries (payment-intent creation, order API) and inject there; revisit targets after stack migrations — hybrid stacks duplicate trust decisions.

### T6. Salesforce-ID brute force via checksum truncation

- **When to test:** endpoints using Salesforce-format IDs (18-char, e.g. `005VM000007BILCYA4`), e.g. `/webruntime/api/apex/execute` with `params.userId`.
- **Steps:**
  1. Confirm swapping `userId` for a second account you own returns its data.
  2. Key insight: first 15 chars are the real object ID; last 3 are a case-insensitive checksum — the server accepts the 15-char version. If a prefix (e.g. first 11 chars) is constant, the brute space collapses to 4 chars.
  3. Generate the wordlist: `crunch 4 4 ABCDEFGHIJKLMNOPQRSTUVWXYZ -d 1 -o wordlist.txt`
  4. Burp Intruder over the 4-char suffix → valid IDs return 200 with user PII (email, phone, name, country).
- **Verify:** PII of an account you don't own is returned; stop after proof (a handful of hits, not a full dump).
- **Failure recovery:** if 15-char IDs are rejected, test other truncation points and the same mindset on any structured ID (UUID prefixes, sequential segments).

### T7. Privilege-boundary IDOR (cross-allowlist, not cross-account)

- **When to test:** role/permission management where your valid action is scoped (owner may add managers *only from contacts*).
- **Steps:**
  1. Spend real time (2–3 days in the source case) understanding the permission model before testing.
  2. Capture the request assigning permissions; find the scoping parameter (`contactId`).
  3. Replace it with an arbitrary user ID outside your contacts → 200 OK, arbitrary user injected into your group with permissions.
- **Verify:** the injected user appears with granted permissions using only your own accounts and IDs you legitimately observed.
- **Failure recovery:** frame the report correctly — not classic IDOR but an authorization-scope bypass (BFLA-adjacent); if triage pushes back, show the missing server-side allowlist check explicitly.

### T8. Race the validator (→ cache poisoning)

- **When to test:** cache-poisoning probes rejected (400) when sent alone — a WAF/middleware/parser check may be racy.
- **Steps:**
  1. Identify the poison request that fails individually with 400.
  2. Burp Repeater: create a **Group** with the valid request first, poison request second; use **Send group (single connection)**.
  3. The concurrent mix slips the poison payload past malformed-request detection; the server processes it and reaches the cacheable state → cache poisoned.
- **Verify:** the poisoned response is served to a fresh unauthenticated request for the same cache key.
- **Failure recovery:** if single-connection grouping fails, try HTTP/2 single-packet attack or last-byte sync; if still rejected, the check is likely atomic — move on.

## Safety and authorization

- Test only on authorized, in-scope targets. Use accounts you own for both sides of every IDOR proof; never pivot to a real third-party user's data beyond the minimum proof.
- Non-destructive PoC: demonstrate reads with your own victim account's data; for write/delete proofs (T1 side effects, T2 deletion) target resources you created, then restore them. No data exfiltration beyond proof — a screenshot of one record beats a dump.
- Brute force (T6) must be throttled and stopped after a few positive hits proving the oracle; respect rate-limit scope rules.
- Cache attacks (T8) require a **cache-buster parameter** on every probe so you never poison a shared production cache key; only after the program explicitly allows it may you test a real key, and you must revert it immediately.
- Price manipulation (T5): never complete a real payment at a manipulated price; stop at the order-review/checkout page showing the tampered total, or use the program's test-payment mode.
- Response manipulation (T4) is client-side by nature — evidence must show server-side state actually changed (re-GET), otherwise it's not reportable.

## Source notes

Techniques distilled from 9 real writeups (bounties up to $9,000; sources include medusa0xf, X-Ghost, RioCNS, yassentaalab51, Ayoub Nouri, brbr0s, omerasraan, ltidi). Full case details, payload fragments, and the case index with URLs: [references/writeup-cases.md](references/writeup-cases.md).
