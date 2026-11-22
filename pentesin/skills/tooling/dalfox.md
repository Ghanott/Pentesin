---
name: dalfox
description: Dedicated XSS & DOM-XSS parameter analyzer and payload verifier — fast reflection probing, blind OAST callbacks, WAF evasion, and structured JSON output
---

# Dalfox XSS Scanner Playbook

Use `dalfox` when reconnaissance discovers parameterized URLs, forms, or SPAs susceptible to Reflected, Stored, or DOM XSS and you need faster parameter/encoding mutation coverage than manual Python scripts alone.

## High-Signal Flags

- `dalfox url "<url>"` — scan a single parameterized URL (`https://target.tld/search?q=test`)
- `dalfox file urls.txt` — scan a narrowed list of P1 parameterized endpoints (from `triage_recon_data`)
- `-p, --param <name>` — target specific parameter(s) instead of all parameters
- `-H "Cookie: ..."` / `--cookie "..."` — authenticated XSS scanning
- `-b, --blind <interactsh-domain>` — blind XSS payload injection with OAST DNS/HTTP callback
- `--skip-bav` — skip unrelated basic arbitrary vuln checks to keep focus and speed on XSS
- `--delay <ms>` — throttle requests per worker under rate-limited / quiet profiles
- `-w, --worker <n>` — worker concurrency (default 100; lower to `10-20` on sensitive targets)
- `--waf-evasion` — enable encoding and syntax variations against WAF filtering
- `--silence --format json -o dalfox.json` — clean machine-readable JSON findings

## Safe Baseline Commands

- Focused URL verification:
  `dalfox url "https://target.tld/search?q=test" -w 15 --silence --format json -o dalfox_hit.json`
- Parameter-list scan with blind callback:
  `dalfox file p1_urls.txt -w 15 --delay 50 -b <interactsh_host> --skip-bav --silence --format json -o dalfox_results.json`
- Authenticated scan with custom header:
  `dalfox url "https://target.tld/profile?name=test" -H "Authorization: Bearer <token>" -w 10 --format json`

## Validation Discipline

- **Treat a `dalfox` hit as a lead until verified:** confirm whether HTML/attribute/JS context actually allows executable script (not sanitized inside `text/plain`, CSP-blocked inline without bypass, or HTML-entity encoded).
- Replay the winning payload through Caido proxy (`repeat_request`) or `agent-browser --session <name>` to verify execution and capture `http_exchange_ids` (`baseline` + `proof`) before calling `create_vulnerability_report`.
- Remove temporary JSON dump files from `/workspace` once findings and safe coverage (`record_coverage`) are recorded.
