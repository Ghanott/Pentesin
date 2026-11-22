---
name: api-recon
description: Frontend-to-backend API surface mapping for SPAs and modern web apps — extract JS routes, XHR/fetch endpoints, UI trigger points, and hidden parameters before active exploitation
---

# API Recon (Frontend & Hidden API Surface Mapping)

Map the complete API surface of an authorized live web application before launching deep exploitation: **backend API endpoints** (paths, HTTP methods, query/body/header parameters, response schemas), **frontend SPA routes**, and **UI trigger points** (tabs, modals, table actions, role-gated views).

This is a **fast initial mapping pass** (not a cage): once the surface is mapped and triaged, immediately hand off high-value routes to specialist attack/chaining agents (`api_security`, `idor`, `sql_injection`, `business_logic`).

## High-Value Surface Sources

1. **Live Browser & Proxy Capture (`agent-browser` + Caido)**
   - Navigate public and authenticated views with `agent-browser --session <name>` so all XHR, `fetch()`, GraphQL, and WebSocket handshakes land in Caido (`list_requests`, `list_sitemap`).
   - Trigger UI state transitions: tabs, filters, pagination, edit modals, delete buttons, export/download actions, and settings pages.
2. **JavaScript Bundle & Source Map Mining**
   - Extract `.js` and `.js.map` URLs via `katana` / `gospider` / `list_sitemap`.
   - Run `JS-Snooper`, `jsniper.sh`, `js-beautify`, or targeted regex/Python scripts to harvest:
     - Relative/absolute API paths (`/api/v1/...`, `/api/v2/...`, `/internal/...`, `/admin/...`, `/graphql`)
     - Undocumented query/JSON fields (`isAdmin`, `role`, `tenantId`, `debug`, `include`)
     - Alternate API versions, feature flags, and client-side role checks
3. **API Schema & Spec Probing**
   - Check `/openapi.json`, `/swagger.json`, `/v3/api-docs`, `/api-docs`, `/swagger-ui/`, `/graphql`, `/graphiql`, `/robots.txt`, and `/.well-known/*`.
4. **Hidden Parameter Discovery**
   - Use `arjun` against high-priority API endpoints to uncover hidden query/JSON parameters not shown in the UI.
   - Use `ffuf` with targeted API wordlists for undocumented sibling routes (`/users`, `/export`, `/impersonate`, `/bulk`, `/debug`).

## Triage & Handoff Workflow

1. **Compress & Prioritize:** Feed raw `katana`, `httpx`, `ffuf`, or `arjun` outputs into `triage_recon_data` to deduplicate noisy URLs into parameterized patterns (`P1` auth/API/upload/payment vs `P2`).
2. **Record Durable Inventory:** Save the consolidated API map (grouped by auth level, method, and sensitivity) via `create_note(category="recon_clues", ...)` so attack subagents build on it immediately without re-crawling.
3. **Record Coverage:** Log mapped surfaces with `record_coverage` and distinguish unauthenticated vs authenticated visibility.
4. **Pivot to Attack:** Pair mapped endpoints with `api_security` (two-session BOLA/BFLA diffing, version differential testing, WebSocket/GraphQL abuse) and `suggest_exploit_chains` for any exposed primitives.

## Guardrails

- Do not probe third-party/out-of-scope domains discovered inside JS bundles (CDNs, analytics, external SaaS); record them as third-party intel only.
- Keep crawls bounded by depth/time and delete raw multi-megabyte crawl dumps after extracting the deduplicated endpoint list.
