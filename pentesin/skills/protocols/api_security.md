---
name: api-security
description: Offensive black-box API security testing for REST, GraphQL, WebSocket, and SOAP — two-session BOLA/BFLA diffing, v1/v2 differential testing, JWT/OAuth abuse, business logic, and rate-limit trust confusion
---

# API Security Testing (REST, GraphQL, WebSocket, SOAP)

The offensive counterpart to `api_recon`. Attack the mapped API surface methodically with concrete PoCs, proxy evidence (`http_exchange_ids` with `baseline` vs `proof`), and measured impact.

## Boundaries & Proof Standard

- **Two-session proof for access control:** An IDOR/BOLA or BFLA finding is confirmed only when a second account or lower-privilege role proves the boundary is broken against a target object/action it should not access (using test accounts or minimal non-destructive reads/writes).
- **Non-DoS rate-limit & race testing:** Test rate-limit bypasses as trust-boundary flaws (e.g. header spoofing or path normalization), never via volumetric flooding. Test TOCTOU race conditions with a small burst of concurrent requests (5–20), never load generators.
- **Replayable evidence:** Every confirmed finding must reference its captured Caido exchanges (`baseline` control request + `proof` exploit request) or exact reproducible `curl`/Python PoC.

## Attack Checklists

### 1. Authentication & Token Abuse (JWT / OAuth / API Keys)
- **JWT (`jwt_tool` / custom Python):** `alg: none`, RS256→HS256 key confusion, weak HMAC secret, `kid` path traversal/SQLi, `jku`/`x5u` SSRF, tampered claims (`sub`, `role`, `tenant_id`, `exp`, `aud`).
- **OAuth / OIDC:** `redirect_uri` open-redirect chaining, missing `state`/PKCE, token leakage via `Referer`, scope elevation.
- **GraphQL Auth:** Mutations reachable over `GET` (CSRF), batched queries bypassing per-operation authz.

### 2. Authorization (BOLA / IDOR / BFLA)
- **BOLA (Object-Level):**
  - Swap numeric IDs, UUIDs harvested from list/search endpoints, emails, or tenant IDs in path, query, and JSON body.
  - Run automated **two-session replay** via `caido_api` / Python: replay User A's captured requests using User B's session/cookie/token and diff status code + body length + sensitive fields.
- **BFLA (Function-Level):**
  - Replay admin/internal endpoints with a standard-user token.
  - Swap HTTP methods (`GET` → `POST`/`PUT`/`PATCH`/`DELETE`), test version downgrades (`/api/v2/admin` → `/api/v1/admin`), and inject privileged IDs into bulk/batch endpoints.

### 3. REST Input, Parser & Representation Abuse
- **Content-Type switching:** `application/json` ↔ `application/x-www-form-urlencoded` ↔ `multipart/form-data` ↔ `application/xml` (test XXE when XML is accepted).
- **Mass Assignment:** Inject unexpected fields (`role`, `is_admin`, `verified`, `plan`, `owner_id`, `balance`) into `POST`/`PUT`/`PATCH` payloads.
- **HTTP Parameter Pollution & Type Confusion:** Duplicate keys (`?role=user&role=admin`), array/object coercion (`{"password": {"$ne": ""}}`, `id[]=1`).
- **SSRF & Webhooks:** Test URL-taking fields (avatars, imports, webhooks, PDF generators) with `interactsh-client` OAST callbacks and internal metadata pivots.

### 4. Business Logic & Differential Testing
- **Version Diffing:** Compare `/v1/` vs `/v2/` responses for removed auth guards, extra leaked fields, or weaker validation.
- **Role Matrix:** Run the same multi-step workflow (create → approve → export → delete) across unauthenticated, standard user, and admin tokens.
- **State & Value Manipulation:** Negative quantities, zero/rounding prices, coupon reuse, step-skipping, and TOCTOU parallel bursts on balance/credit/claim endpoints.

### 5. GraphQL & WebSocket & SOAP
- **GraphQL:** Three-tier introspection (full → trimmed → minimal `__schema { types { name } }`), field-suggestion error leaks, alias/batch amplification (bounded), nested traversal reaching unauthorized relations.
- **WebSocket:** Upgrade handshake origin checks (CSWH), missing per-frame authz, JSON frame injection/type confusion, prototype pollution.
- **SOAP / XML:** WSDL enumeration (`?wsdl`), XXE entity expansion, WS-Security header bypass, parameter injection in XML tags.

### 6. Rate-Limit Trust Confusion & Excessive Data Exposure
- **Trust Confusion:** Test `X-Forwarded-For`, `X-Real-IP`, `True-Client-IP`, `Forwarded`, and path variants (`/api/`, `/api`, `/Api/`, `/api;v=1/`) to prove the bypass mechanism without flooding.
- **Data Exposure:** Diff raw API JSON responses against what the frontend UI actually renders (hidden PII, password hashes, internal tokens), test extreme pagination (`limit=10000`), and inspect verbose error stack traces.

## Chaining & Reporting

- Whenever you confirm a low/medium API primitive (info leak, open redirect, CORS reflection, read-only IDOR, rate-limit bypass), immediately call `suggest_exploit_chains` to test high-impact pivots and escalate with `link_exploit_chain`.
- Attach both `baseline` and `proof` Caido request IDs in `http_exchange_ids` when filing via `create_vulnerability_report`.
