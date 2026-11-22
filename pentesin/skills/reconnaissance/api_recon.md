---
name: api-recon
description: Frontend-to-backend API surface mapping for SPAs and modern web apps — extract JS routes, XHR/fetch endpoints, UI trigger points, and hidden parameters before active exploitation
---

# API Recon (Frontend & Hidden API Surface Mapping)

Map the complete API surface of an authorized live web application before launching deep exploitation: **backend API endpoints** (paths, HTTP methods, query/body/header parameters, response schemas), **frontend SPA routes**, and **UI trigger points** (tabs, modals, table actions, role-gated views).

This is a **fast initial mapping pass** (not a cage): once the surface is mapped and triaged, immediately hand off high-value routes to specialist attack/chaining agents (`api_security`, `idor`, `sql_injection`, `business_logic`).

## High-Value Surface Sources

1. **Bundled ARTEX Static & MPA Surface Harvester (`harvest_api_surface`)**
   - Call `harvest_api_surface(target_url="https://target.tld", mode="auto")` FIRST on modern SPAs or classic web apps:
     - In SPA mode, it fetches the entry HTML, expands webpack & Vite runtime chunk manifests recursively, downloads reachable chunks, and writes `api_static.txt`, `routes.txt`, `paths_other.txt`, and `route_map.json`.
     - If SPA JS extraction yields sparse routes, `mode="auto"` (or `mode="mpa"`) automatically crawls HTML forms, links, and inline-JS AJAX URLs into `forms.txt` and `api_inline.txt` (pass `cookie="..."` for authenticated MPA coverage).
2. **Live Browser & Proxy Capture (`agent-browser` + Caido)**
   - Navigate public and authenticated views with `agent-browser --session <name>` so all XHR, `fetch()`, GraphQL, and WebSocket handshakes land in Caido (`list_requests`, `list_sitemap`).
   - Trigger UI state transitions: tabs, filters, pagination, edit modals, delete buttons, export/download actions, and settings pages.
3. **JavaScript Bundle & Source Map Mining**
   - Complement `harvest_api_surface` with `.js.map` / runtime extraction (`katana -jc` / `gospider`) for:
     - Undocumented query/JSON fields (`isAdmin`, `role`, `tenantId`, `debug`, `include`)
     - Alternate API versions, feature flags, and client-side role checks
4. **API Schema & Spec Probing**
   - Check `/openapi.json`, `/swagger.json`, `/v3/api-docs`, `/api-docs`, `/swagger-ui/`, `/graphql`, `/graphiql`, `/robots.txt`, and `/.well-known/*`.
5. **Hidden Parameter Discovery**
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
