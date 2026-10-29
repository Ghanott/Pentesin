---
name: deep
description: Exhaustive black-box security assessment with full enumeration, deep parameter fuzzing, parser differentials, and exploit chaining
---

# Deep Testing Mode

Exhaustive black-box web and API assessment. Maximum attack-surface discovery, deep protocol/parser testing, and multi-step vulnerability chaining.

## Phase 1: Exhaustive Reconnaissance & Discovery

- **Subdomain & Host Enumeration**: enumerate subdomains, virtual hosts, and open ports/services across the authorized scope
- **High-Signal Exposure & Schema Audit**: probe `/.env`, `/.git/HEAD`, `/swagger.json`, `/openapi.json`, `/v3/api-docs`, `/graphql`, `/actuator/*`, `/debug/*`, and extract hidden endpoints/keys from all client `.js` bundles and `*.js.map` files
- **Deep Content & Parameter Discovery**: run directory/route discovery (`ffuf`, `katana`) and mine hidden query/body/JSON parameters across GET/POST/PUT/PATCH/DELETE
- **Stack & Edge Fingerprinting**: map reverse proxies, CDN/WAF rules, caching layers, auth/session tokens, and role hierarchies

## Phase 2: Application & State Machine Modeling

Build a complete model of workflows and invariants:
- **User flows & state machines**: trace every transition (e.g., Created -> Verified -> Paid -> Fulfilled -> Refunded)
- **Trust boundaries**: identify gateway-to-microservice hops, internal APIs, webhook callbacks, and cross-tenant boundaries
- **Implicit assumptions**: identify client-side enforcement, hidden fields, unverified step tokens, and idempotency keys

## Phase 3: Comprehensive Vulnerability Testing

Decompose the target by component and vulnerability class, scaling subagents across discovered surfaces. Use targeted `xray_scan` (`mode="url"`, explicit plugins) on parameterized URLs alongside custom Python sprays.

- **Injection & Execution**: SQLi (`sql_injection`), NoSQLi (`nosql_injection`), XSS (`xss`), SSTI (`ssti`), RCE/command injection (`rce`), XXE (`xxe`), argument injection (`argument_injection`), insecure deserialization (`insecure_deserialization`)
- **Authentication & Protocols**: JWT manipulation (`authentication_jwt`), OAuth/OIDC flow abuse (`oauth`), GraphQL introspection/batching/aliases (`graphql`), session fixation/reset poisoning, weak credentials (`weak_password_detection`)
- **Authorization & Isolation**: horizontal/vertical IDOR (`idor`), BFLA (`broken_function_level_authorization`), mass assignment (`mass_assignment`), HTTP method & content-type tampering
- **Parser, Framing & Edge Differentials**:
  - WAF evasion (`waf_bypass`): content-type switching, body padding, chunked transfer, NFKC unicode, double encoding
  - HTTP Parameter Pollution (`http_parameter_pollution`): gateway vs backend duplicate parameter precedence, array coercion, encoded delimiter injection (`%26`/`%23`)
  - Cross-component semantic drift (`semantic_confusion`) and HTTP request smuggling (`http_request_smuggling`)
- **Client & Browser Surfaces**: DOM XSS, postMessage/XS-Leaks (`browser_security`), prototype pollution (`prototype_pollution`), CORS exploitation, CSRF (`csrf`)
- **File, SSRF & Infrastructure**: upload polyglots/traversal (`insecure_file_uploads`, `path_traversal_lfi_rfi`), SSRF with cloud metadata/internal pivots (`ssrf`), subdomain takeover (`subdomain_takeover`), abandoned dependencies (`infrastructure_lifecycle`)
- **Business Logic & Concurrency**: single-packet / parallel race conditions (`race_conditions`), state skipping, currency/rounding arbitrage, quota/refund abuse (`business_logic`)
- **LLM / Agentic Surfaces (when present)**: load `llm_applications`, `llm_prompt_injection`, and `agentic_system_security`

## Phase 4: Persistent Evasion & Chaining

- Treat every low/medium primitive (info disclosure, open redirect, HPP, CORS, unauthenticated schema) as a pivot; ask what boundary it unlocks next
- When initial payloads fail or hit `403`/`406`, pivot representations (JSON <-> form <-> multipart, HPP splitting, alternate API versions `/api/v1` vs `/api/v2`)
- Validate end-to-end chains with working PoCs, attach proxy `http_exchange_ids`, and reconcile all surfaces in `record_coverage`
