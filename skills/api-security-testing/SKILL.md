---
name: api-security-testing
description: Security-test a REST, GraphQL, or gRPC API with pentesin — autonomous agents that enumerate endpoints from an OpenAPI/GraphQL schema (or by crawling), then actually exploit the API-specific vulnerability classes in the OWASP API Security Top 10 (2023) — broken object-level authorization (BOLA/IDOR), broken object property level authorization (excessive data exposure and mass assignment), broken function-level authorization, unrestricted resource consumption, SSRF, injection, and auth/token flaws. Every finding comes with a working proof-of-concept request. Use when the user asks to pentest, security-test, audit, or find vulnerabilities in an API, endpoint, or backend service.
license: Apache-2.0
metadata:
  author: Ghanott
  homepage: https://github.com/Ghanott/Pentesin/tree/main/docs
---

# Security-test an API

APIs fail differently from web UIs: there is no rendered surface to crawl, the interesting bugs are authorization-shaped rather than injection-shaped, and the same endpoint behaves differently per token. This workflow targets those specifics with pentesin's autonomous agents, using the current [OWASP API Security Top 10 (2023)](https://owasp.org/API-Security/editions/2023/en/0x11-t10/) as the coverage checklist. For the web-app equivalent, the current edition is the OWASP Top 10:2025 — see **owasp-top-10-testing**.

Install, LLM setup, full CLI flags, and the managed-cloud path are in the **penetration-testing-with-pentesin** skill. Read it if `pentesin --version` fails or the target is not an API. For a run with no Docker and no LLM key, the same binary drives the managed platform: `pentesin cloud login`, then `pentesin cloud scans start ...` (details in **managed-pentesting-with-pentesin**).

## 1. Gather what the agents need

APIs are near-impossible to test blind, so collect first:

| Input | Why it matters |
|---|---|
| **Schema** — OpenAPI/Swagger file or Postman collection; GraphQL endpoint (introspection) | Turns guesswork into full endpoint enumeration. pentesin host-parses OpenAPI/Swagger/Postman into a sanitized endpoint map; spec-declared HTTP(S) servers become scope. Raw spec, examples, and secret values are never mounted into the sandbox. |
| **Two sets of credentials/tokens**, ideally in different tenants | BOLA/IDOR — API1:2023, still the #1 API risk — can only be *proven* by accessing tenant A's objects with tenant B's token. |
| **A low-privilege and a high-privilege token** | Required to prove broken function-level authorization (API5:2023 — a `user` calling admin-only routes). |
| **Example object IDs** | Lets agents test ID tampering immediately instead of hunting for valid identifiers. |
| **Out-of-scope routes** | Payments, mass notification, destructive admin endpoints. |
| **Rate limits / WAF** in front of the API | Avoids agents burning budget on throttled requests; mention them so testing adapts. |

Ask the user for anything missing — do not fabricate tokens or scan an API they do not own.

## 2. Run the scan

Pass the API contract as a **target**, not as prose in the instruction. pentesin parses OpenAPI/Swagger (`.json`/`.yaml`) and Postman exports host-side, supplies only a sanitized endpoint map to agents, and authorizes the contract's declared absolute HTTP(S) servers:

```bash
pentesin -n -t ./openapi.yaml --max-budget 20 \
  --instruction "Tenant A token: <tokenA> (org 1111, user id 11, order id 501).
Tenant B token: <tokenB> (org 2222, user id 22).
Admin token: <tokenAdmin>.
Focus: BOLA across orgs (API1), function-level authz on /admin/* (API5), object property level authz on PATCH /users/{id} — both mass assignment and over-exposed fields in list responses (API3), unrestricted resource consumption (API4).
Out of scope: POST /billing/*, POST /notifications/broadcast."
```

- **Postman instead of OpenAPI:** a collection export works as a target (`-t ./collection.postman_collection.json`), or pull one live with `-t postman://<collection-uuid>` (optionally `"postman://<collection-uuid>?env=<environment-uuid>"`), which needs `POSTMAN_API_KEY`. Environment values resolve declared servers host-side, then are discarded; do not put credential values in instructions or workspace files.
- **Many services at once:** put one target per line in a file and pass `--target-list ./targets.txt`, repeatable and combinable with `-t`.
- **Source code/repositories:** not accepted by this black-box build. Validate authorization and ownership strictly from live API responses and explicitly supplied test credentials.
- **gRPC / binary schemas:** not parsed as API endpoint maps by this build; test only a live HTTP(S) surface or use another approved tool.
- **GraphQL:** point at the GraphQL endpoint and say whether introspection is enabled; call out that you want batching/aliasing abuse, depth/complexity limits, and per-field authorization tested.
- **Internal/private APIs** unreachable from your machine: use the managed platform's network connector — see **managed-pentesting-with-pentesin**.
- Use `--instruction-file` when the credential/context block gets long, and keep tokens out of shell history and out of committed files.
- **Supporting notes/wordlists:** pass only non-secret auxiliary files such as a wordlist or tenancy notes with `--workspace-file ./notes.md`. API specs must be passed via `--target` so they are parsed host-side and never copied raw. Do not put credentials, source code, examples, or environment exports in workspace files.

## 3. Verify findings

`pentesin_runs/<run>/penetration_test_report.md` first, then `vulnerabilities/*.md` — each contains the exact request that proved the issue. Replay it (for example, with `curl`) before reporting; for authorization findings, confirm the response really contains the other tenant's data rather than an empty 200.

`findings.sarif` uploads to GitHub code scanning; `vulnerabilities.json` is the structured index for ticketing.

## 4. Fix, re-test, and keep it tested

Remediate with **fix-security-vulnerabilities-with-pentesin** (fix the authorization check, not the single endpoint), then re-run against the same target to prove the exploit is dead. Wire it into pull-request CI with **ci-security-scanning-with-pentesin** so new endpoints get tested as they ship.
