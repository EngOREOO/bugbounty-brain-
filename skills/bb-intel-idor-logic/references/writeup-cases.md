# idor-logic methodology digest

Distilled from 9 fetched writeups (2 skipped: one H1 report behind login wall, one dead Medium link). Sources cover classic IDOR, cross-tenant IDOR, mass-assignment/BOPLA, response manipulation, price manipulation, and a race-condition → cache-poisoning edge case.

## Hunting procedures

### 1. Classic two-account IDOR on document/resource endpoints

- **When to test:** any app with numeric IDs in request paths/bodies, especially document-upload flows (licenses, IDs, insurance) that carry PII. Delivery, HR, and KYC-style apps are prime targets.
- **Procedure:**
  1. Map the app first — browse every feature with Burp proxying; note every endpoint using a numeric ID (URL path, JSON body, query param).
  2. Create two accounts (TestA/TestB). On TestA, create the sensitive resource (driver application, vehicle docs, etc.).
  3. Capture TestA's PUT/GET request for the resource (ID in URL). Swap in TestB's session cookie, keep TestA's ID.
  4. Check both read access (PII/documents rendered) AND side effects — in the delivery-app case the object also got *re-linked* to the attacker's account and removed from the victim's (unauthorized action + deletion).
  5. Repeat for sibling endpoints — the second IDOR ($1500) was the same pattern on a parallel "vehicle application" endpoint.
- **Verify:** fetch victim-only data with attacker session; document the unauthorized state change. Report each endpoint separately — the writeup earned $1500 × 2.
- **Source:** medusa0xf, $3000 delivery-app IDOR.

### 2. Cross-tenant IDOR via composite (Base64) object IDs

- **When to test:** multi-tenant SaaS; object IDs that are long/Base64 — decode them. GraphQL or REST delete/edit endpoints on shared resources (API specs, contracts).
- **Procedure:**
  1. Decode any opaque ID. This one decoded to `accountId | NXXP | REST_API_CONTRACT | GUID`.
  2. First swap only the *inner* GUID (victim's) keeping your accountId → expect Access Denied (means partial validation exists).
  3. Then swap **both** accountId and GUID to the victim's values. Here the server validated accountId↔GUID *consistency* but never checked the caller was authorized for that account → victim's OpenAPI spec deleted.
  4. Enumeration angle: GUIDs are often obtainable if you were ever a member of the victim org (join, leave, keep IDs).
- **Tools:** Burp Suite; any base64 decoder.
- **Verify:** attacker account with zero relationship to victim org deletes victim's resource (200 + resource gone).
- **Source:** X-Ghost, cross-tenant OpenAPI spec deletion.

### 3. BOPLA / mass-assignment on settings objects (subscription plan manipulation)

- **When to test:** org/account update endpoints that accept a `settings` or profile JSON object; anything where billing/plan state lives in a user-writable object.
- **Procedure:**
  1. Create an org/resource; note its ID.
  2. `PUT /api/users/{user_id}/organizations/{id}` with `{"settings":{"plan":"premium"}}`.
  3. Re-GET the resource to confirm the value persisted server-side (don't trust the UI — frontend still showed "14 days trial left" while backend stored `premium`).
- **Verify:** backend GET echoes the modified plan. CWE-285/CWE-840, OWASP API3:2023.
- **Source:** RioCNS.

### 4. Response manipulation to bypass client-enforced gates

- **When to test:** features gated on verification flags or plan state returned in API responses (e.g. `userverified`, `userphone`), and error responses that block a workflow (downgrade blocked because too many projects).
- **Procedure:**
  1. Compare responses between a verified/paid account and an unverified/free one; diff the JSON for flag fields.
  2. Burp → Proxy settings → Match & Replace rules on the *response* body, e.g. `userverified:''` → `userverified:'y'`, `userphone:''` → `userphone:'y'`. Reload the gated feature — email/phone verification skipped.
  3. Second pattern: intercept the response of a blocked action ("Don't Renew" → error "delete extra websites first"), use "do intercept → response to this request", replace the error with a success body, forward → server downgraded plan while keeping all projects (whole subscription system bypassed).
- **Verify:** gated feature usable / plan state changed with constraints violated.
- **Source:** yassentaalab51 (two bugs, one target).

### 5. Price manipulation via metadata injection in Next.js server actions

- **When to test:** hybrid stacks (this was Next.js frontend + legacy WordPress/WooCommerce checkout); cart "modify item" or promo (BXGX) actions that accept JSON with `meta-`-prefixed fields; unauthenticated carts stored client-side (cookies) and rebuilt server-side at checkout.
- **Procedure:**
  1. Intercept the cart-modify server action (`POST /cart/` with `Next-Action` header, multipart body, `1_change_metaData` JSON field).
  2. Observe the backend merges any `meta-*` key into the item's metaData. First try `meta-__proto__` (prototype pollution) — didn't work here.
  3. Mirror the item's real properties as `meta-` keys with attacker values: `meta-price`, `meta-regularPrice`, `meta-lp_override_price` set to `-779`. Cart UI looks normal; proceed to checkout — the WordPress side blindly merges metaData into core item properties → price becomes negative, order for free.
  4. Variant: promo endpoint (`1_bxgx_offer`) creating a free item — inject a custom `poc_price` field seen in responses to set the "free" item's price negative, reducing total cart price.
- **Verify:** price change only manifests at checkout (the handoff boundary), not in cart UI — always click through to payment.
- **Source:** Ayoub Nouri, $9K, two bugs, patched within a day.

### 6. IDOR on Salesforce IDs — checksum truncation for brute force

- **When to test:** endpoints using Salesforce-format IDs (18-char, e.g. `005VM000007BILCYA4`), e.g. `/webruntime/api/apex/execute` with `params.userId`.
- **Procedure:**
  1. Confirm swapping `userId` for a second account you own returns its data.
  2. Key insight: first 15 chars are the real object ID; last 3 are a case-insensitive checksum. The server accepts the 15-char version. If a prefix (e.g. first 11 chars) is constant across users, brute space collapses to 4 chars.
  3. Generate the wordlist: `crunch 4 4 ABCDEFGHIJKLMNOPQRSTUVWXYZ -d 1 -o wordlist.txt`
  4. Burp Intruder over the 4-char suffix → valid IDs return 200 with real user PII (email, phone, name, country).
- **Verify:** PII of an account you don't own returned.
- **Source:** brbr0s.

### 7. Privilege-boundary IDOR (not cross-account — cross-*allowlist*)

- **When to test:** role/permission management where your valid action is scoped (e.g. owner may add managers *only from contacts*).
- **Procedure:**
  1. Spend real time (2–3 days in this case) understanding the permission model before testing.
  2. Capture the request assigning permissions; find the scoping parameter (`contactId`).
  3. Replace with an arbitrary user ID outside your contacts → 200 OK, arbitrary user injected into your group with permissions.
- **Note:** frame it correctly in the report — not classic IDOR, but an authorization-scope bypass (BFLA-adjacent).
- **Source:** omerasraan, first YesWeHack bounty.

### 8. Race condition to bypass poison-payload detection (→ cache poisoning)

- **When to test:** cache-poisoning probes that get rejected (400) when sent alone — a WAF/middleware/parser check may be racy.
- **Procedure:**
  1. Identify the poison request that fails individually with 400.
  2. Burp Repeater: create a **Group** with the valid request first, poison request second; use **Send group (single connection)**.
  3. The concurrent mix slips the poison payload past the malformed-request detection; server processes it and reaches the cacheable state → cache poisoned.
- **Verify:** poisoned response served to a fresh unauthenticated request for the same cache key.
- **Source:** ltidi.

### 9. GraphQL/REST billing-document IDOR (thin evidence)

- HackerOne report 2207248 ($5,000, IDOR on GraphQL `BillingDocumentDownload` and `BillDetails` queries) was behind a login wall. Signal only: enumerate GraphQL queries that take document/billing IDs and test with a second account's session — download and detail endpoints on financial documents are high-value.

## High-value tips

- **Always verify server-side persistence.** A 200 OK means nothing; re-GET the object. Frontend/backend state mismatch (trial UI vs premium backend) is itself reportable evidence of broken state handling.
- **Decode opaque IDs.** Base64 IDs are often composite (`accountId|type|GUID`). Test partial swaps vs full swaps — partial rejection + full acceptance reveals exactly which relationship the server validates and which it doesn't.
- **Match & Replace on responses is a first-class technique**, not a gimmick: it bypassed both verification gating and subscription enforcement in one program. Diff responses between privileged and unprivileged accounts to find the flags to flip.
- **Price bugs hide at trust boundaries.** The cart showed the real price; the checkout (different stack reading the same client-side cart) applied injected metadata. Always walk the full flow to payment.
- **Shorten IDs before brute forcing.** Salesforce 18-char IDs = 15-char ID + 3-char checksum; constant prefixes collapse the keyspace to 4 chars (`crunch 4 4 ABCDEFGHIJKLMNOPQRSTUVWXYZ`). Same mindset applies to any structured ID (UUID prefixes, sequential segments).
- **Don't stop at read access.** The delivery-app IDOR also re-linked and deleted the victim's object — unauthorized write/delete side effects turn a P2 read into a P1.
- **Report sibling endpoints separately.** Same bug class on driver-application and vehicle-application endpoints paid twice ($1500 each).
- **Map before you test.** Multiple authors spent days clicking through the app with Burp before firing a single payload; the bugs were in endpoints automation never reaches.
- **Old-school manual browsing beats automation** for logic/IDOR work — every writeup here was found by hand after feature-mapping.
- **Race the validator.** If a payload is rejected individually, send it in a single-connection group behind a valid request (Burp Repeater "Send group (single connection)") — middleware checks are often racy.
- **Revisit targets after stack migrations.** The $9K price bugs existed because a Next.js frontend was bolted onto a legacy WooCommerce checkout — hybrid stacks duplicate trust decisions.
- **Impact framing matters.** The "$0 IDOR" essay: an any-user PII read sat as Informative/duplicate for 3+ years while a GraphQL-alias DoS paid $12,500 — write impact as what an attacker can do at scale, not what your screenshot shows.

## Case index

| Vuln class | Target/program | Bounty | One-line technique | URL |
|---|---|---|---|---|
| business-logic / BOPLA | Undisclosed org subscription API | — | PUT `settings.plan=premium` on org update endpoint; verified via re-GET | https://riocns.medium.com/i-found-an-api-business-logic-flaw-that-allowed-subscription-plan-manipulation-d74203d8b9ab |
| idor / graphql | HackerOne program (report 2207248) | $5,000 | IDOR on GraphQL `BillingDocumentDownload`/`BillDetails` (login wall — signal only) | https://hackerone.com/reports/2207248 |
| idor (cross-tenant) | APM SaaS (undisclosed) | — | Swap accountId+GUID inside Base64 composite contractId on delete endpoint | https://medium.com/@X-Ghost/idor-allows-deletion-of-openapi-specification-files-across-organizations-22fe4d79711d |
| idor (methodology essay) | — | $0 (vs $12,500 comparison) | Impact-framing essay; user-ID swap PII read closed as 3-year-old duplicate | https://medium.com/bugbountywriteup/the-0-idor-that-was-worth-more-than-a-12-500-p1-4444d32f2f61 |
| business-logic / info-disclosure | Undisclosed web app | — | Burp response Match & Replace flips `userverified`/`userphone`; error-response swap bypasses plan downgrade block | https://medium.com/@yassentaalab51/dont-trust-the-server-how-response-manipulation-exposed-a-business-logic-flaw-8b554e36c6fe |
| idor / privesc | YesWeHack public program (device mgmt) | yes (amount undisclosed) | `contactId` swap adds arbitrary non-contact user to group with permissions | https://medium.com/@omerasraan/privilege-escalation-via-idor-allows-unauthorized-user-injection-f822aa64b528 |
| idor | Delivery app (subdomain) | $3,000 ($1500×2) | Numeric ID swap in PUT URL with second-account session; read + re-link/delete side effects | https://medusa0xf.medium.com/how-i-found-a-3000-idor-vulnerability-in-a-delivery-app-d15167b6f963 |
| business-logic (price manipulation) | Telecom (Next.js + WooCommerce hybrid) | $9,000 | `meta-*` injection in server action poisons cart metadata merged at checkout; `poc_price` injection in BXGX promo | https://blog.ayoubnouri.me/blog/when-the-price-goes-wrong (original: https://ay0ub-n0uri.medium.com/when-the-price-goes-wrong-9k-from-2-price-manipulation-343b839bd522) |
| idor | Undisclosed chat app | — | IDOR on `/v1/chats/{chat_id}/view` (dead link — 410 Gone) | https://medium.com/@ctrl_cipher/--unauthorized-eyes-on-private-chats-an-idor-vulnerability-in-v1-chats-chat-id-view-4dabc5433a1e |
| idor (PII) | Salesforce-based web app | — | Truncate 18-char SF ID to 15, brute-force 4-char suffix via crunch + Intruder | https://brbr0s.medium.com/idor-allows-unauthorized-access-to-other-users-personal-data-8f73486cbab0 |
| race-condition / cache-poisoning | Wide-scope targets | — | Burp Repeater group (single connection): valid request first, poison second, slips past payload detection | https://ltidi.medium.com/race-condition-leads-to-cache-poisoning-77bdfb9483fd |

## Coverage notes

- **Skipped/dead:** `hackerone.com/reports/2207248` (login wall — only bounty amount and GraphQL query names known from the tweet); `medium.com/@ctrl_cipher/...v1-chats-chat-id-view...` (HTTP 410 Gone). No Telegram/WhatsApp or homepage links were present in this batch.
- **Redirected:** the ayoub-n0uri Medium post was a stub pointing to `blog.ayoubnouri.me`, which contained the full article (fetched and used).
- **Partial:** the Meena "$0 IDOR" piece is Medium member-only; only the opening was retrievable — it's an impact/methodology essay, not a step-by-step, so the loss is small.
- **Thin evidence:** GraphQL IDOR (only the H1 title-level signal; no procedure recoverable); the race-condition/cache-poisoning piece is conceptual (no exact poison payload disclosed). Classic numeric-ID IDOR, response manipulation, and price/metadata manipulation had the strongest procedural evidence.
