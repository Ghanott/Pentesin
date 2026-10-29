---
name: quick
description: Alias for the standard black-box assessment mode
---

# Standard Testing Mode (Quick Alias)

Black-box web and API assessment combining fast high-signal triage with structured coverage of critical user flows and vulnerabilities.

## Phase 1: High-Signal Triage & Reconnaissance

1. **Fast Exposure Probes (single-request checks, no brute-force loops)**
   - Config & repo leaks: `/.env`, `/.git/HEAD`, `/.git/config`, `/config.json`, `/phpinfo.php`
   - API & debug schemas: `/swagger.json`, `/openapi.json`, `/v3/api-docs`, `/graphql` (introspection), `/actuator/env`, `/actuator/heapdump`, `/_next/data/`
   - Client-side bundles & source maps: inspect main `.js` bundles and `*.js.map` for hardcoded keys, hidden API routes, and role flags
   - Header/origin quick wins: test CORS (`Origin: https://evil.example`, `Origin: null`, prefix/suffix origins with `Access-Control-Allow-Credentials: true`) and Host/reset-link poisoning (`Host`, `X-Forwarded-Host`)

2. **Attack Surface Mapping**
   - Crawl reachable pages, forms, and API endpoints; capture baseline traffic in the proxy
   - Fingerprint stack, auth mechanism (cookies, JWT, OAuth), and edge/WAF controls (load `waf_bypass` if requests hit `403`/`406`)
   - Enumerate parameters, content types, and user roles/tenants

## Phase 2: Business Logic & Trust Boundaries

Map how the application enforces rules before spraying payloads:
- **Critical workflows**: login, registration, password reset, checkout/payments, profile/account settings, admin actions
- **Role & tenant boundaries**: which object IDs, org IDs, or endpoints isolate User A from User B or Admin
- **State transitions**: multi-step flows, status flags, coupons/quotas, idempotency

## Phase 3: Systematic Vulnerability Testing

Spawn focused subagents per surface and vulnerability class. When recon uncovers specific URLs with query parameters or form inputs, use `xray_scan` (`mode="url"`) with targeted plugins alongside manual/scripted testing.

- **Access Control & Authz**: IDOR/BOLA (`idor`), broken function-level authorization (`broken_function_level_authorization`), mass assignment (`mass_assignment`)
- **Authentication & Session**: login bypass, JWT tampering (`authentication_jwt`), OAuth redirect/state flaws (`oauth`), password reset flaws
- **Injection**: SQLi (`sql_injection`), XSS (`xss`), SSTI (`ssti`), command injection/RCE (`rce`), XXE (`xxe`), NoSQLi (`nosql_injection`)
- **Server-Side & Parser**: SSRF (`ssrf`), path traversal/LFI (`path_traversal_lfi_rfi`), open redirect (`open_redirect`), duplicate parameter override (`http_parameter_pollution`)
- **Business Logic**: workflow step skipping, negative/boundary values, replay, and race conditions (`business_logic`, `race_conditions`)
- **WAF / Filter Evasion**: when an endpoint blocks payloads (`403`/`406`), load `waf_bypass` and test content-type switching (`json` ↔ `urlencoded` ↔ `multipart`), chunked framing, and encoding differentials

## Phase 4: Validation & Chaining

- Confirm every candidate with a reproducible proof-of-concept and proxy `http_exchange_ids`
- Chain primitives (e.g., info leak / open redirect / CORS -> token theft / SSRF / ATO) to prove maximum real-world impact
- Record every tested surface via `record_coverage` before finishing
