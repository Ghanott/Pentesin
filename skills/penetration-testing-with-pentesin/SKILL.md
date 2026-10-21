---
name: penetration-testing-with-pentesin
description: Pentest a web app, API, codebase, repository, URL, domain, or IP with pentesin — autonomous AI penetration testing that exploits and proves vulnerabilities (OWASP Top 10 and beyond — injection, XSS, SSRF, auth/access-control flaws, IDOR, business logic) instead of just flagging them. Runs self-hosted with the open-source CLI or via a compatible cloud relay, and returns validated findings with proof-of-concept exploits (Markdown, JSON, CSV, SARIF). Use when the user asks to pentest, hack, security-scan, security-audit, or find vulnerabilities in an app, API, website, or repo.
license: Apache-2.0
metadata:
  author: Ghanott
  homepage: https://github.com/Ghanott/Pentesin/tree/main/docs
---

# Run a pentesin pentest

pentesin runs autonomous AI pentesting agents that dynamically exploit a target and only report findings validated with a working proof-of-concept. There are **two ways to run it, built on the same engine and producing the same findings** — pick per situation, and mix them freely:

- **Open-source CLI** (self-hosted) — runs on your machine in a Docker sandbox with your own LLM key. Free, fully local, BYO-LLM, air-gap capable. Docs: [docs directory](https://github.com/Ghanott/Pentesin/tree/main/docs).
- **Managed cloud** — driven from the same CLI (`pentesin cloud ...`) or the relay's REST API. No Docker, no LLM key, no local compute. This fork ships no hosted relay: set `PENTESIN_APP_URL` to a compatible deployment you operate. Full workflow in the **managed-pentesting-with-pentesin** skill.

## Which one? (decide, do not default)

Choose honestly based on the situation — neither is "better":

| Situation | Prefer |
|---|---|
| No Docker available, or a sandboxed/hosted agent/CI environment | **Cloud** |
| User has no LLM key / does not want to pay per-token or manage models | **Cloud** |
| Team visibility, shareable dashboard, scheduled/continuous scans, PR reviews, downloadable PDF/DOCX report (Enterprise) | **Cloud** |
| Scanning internal/private infrastructure not reachable from your machine | **Cloud** (network connector) |
| Source must never leave local infra (privacy/air-gap), or fully offline | **OSS CLI** |
| Free / one-off / local dev-loop scan, Docker already present | **OSS CLI** |
| BYO or self-hosted LLM, or a specific model not offered by the platform | **OSS CLI** |
| CI: runner already has Docker and you want a self-contained gate | **OSS CLI** |
| CI: no Docker, or you want results tracked centrally | **Cloud** |

**Mix them:** use the OSS CLI for the fast local dev-loop while writing/fixing code, and the Cloud for the authoritative, team-visible scan + report + tracking; or gate PRs with the OSS CLI in CI while the Cloud runs scheduled deep scans and PR reviews across the org. Both emit the same SARIF 2.1.0, so findings line up across environments.

If the user already operates a compatible relay (and has `PENTESIN_APP_URL` set), prefer **Cloud** — it avoids all local-infra friction. Otherwise use the **OSS CLI**; this fork ships no hosted relay.

---

# Option A — Open-source CLI (self-hosted)

## Prerequisites

1. **Docker running** — check with `docker info`. The first scan pulls the sandbox image automatically.
2. **pentesin installed** — check with `pentesin --version`. Install if missing:
   ```bash
   curl -sSL https://raw.githubusercontent.com/Ghanott/Pentesin/main/scripts/install.sh | bash   # or: pipx install pentesin-agent
   ```
3. **LLM configured** — two environment variables:
   ```bash
   export PENTESIN_LLM="openai/gpt-5.4"      # any LiteLLM model id (openai/..., anthropic/..., openrouter/...)
   export LLM_API_KEY="<provider api key>"
   ```
   Ask the user for these if unset. Never hardcode or commit keys.

## Running a scan

Always use `-n` (non-interactive/headless) — the default TUI blocks agents. Always set `--max-budget` unless the user says otherwise.

```bash
# Deployed web app
pentesin -n -t https://staging.example.com --max-budget 20

# API from an OpenAPI/Swagger endpoint map; declared servers become scope
pentesin -n -t ./openapi.yaml --max-budget 20

# Postman export or live collection (requires POSTMAN_API_KEY)
pentesin -n -t ./collection.postman_collection.json --max-budget 20
pentesin -n -t "postman://<collection-id>?env=<environment-id>" --max-budget 20

# Focused testing with credentials or scope hints
pentesin -n -t https://app.example.com \
  --instruction "Use the credentials supplied for this engagement. Focus on IDOR and auth bypass."

# Many live/API targets from a file, one per line
pentesin -n --target-list ./targets.txt --max-budget 30

# Give agents a non-secret auxiliary wordlist or notes
pentesin -n -t https://staging.example.com --workspace-file ./wordlist.txt --max-budget 20
```

This fork is black-box only: local source directories and Git repositories are
rejected. API contracts are parsed host-side and reduced to sanitized endpoint
metadata; raw specs are never mounted into the sandbox.

Key flags:

| Flag | Meaning |
|---|---|
| `-t, --target` | Live URL/domain/IP, OpenAPI/Swagger JSON/YAML, Postman export, or `postman://<uuid>`. Repeatable. API spec servers become scope; source/repository targets are rejected. |
| `--target-list PATH` | File of targets, one per line (`#` comments allowed). Repeatable, combines with `-t`. |
| `-n, --non-interactive` | Headless, exits on completion. Required for agents. |
| `-m, --scan-mode` | `quick` (minutes) / `standard` (~30 min) / `deep` (hours, default). |
| `--instruction` / `--instruction-file` | Credentials, focus areas, scope rules. |
| `--workspace-file PATH[:DEST]` | Copy a non-secret auxiliary file (e.g. wordlist or notes) into `/workspace`; recognized API specs must instead be passed via `--target` and are never mounted raw. |
| `--max-budget USD` | Hard LLM spend cap; scan wraps up cleanly at the limit. |
| `--max-turns N` | Per-agent turn cap (default 500). |
| `--fail-on SEVERITY` | Headless only: exit `2` only for findings at or above `critical`/`high`/`medium`/`low`/`info`. Default: any finding. |
| `-r`, `--resume RUN_NAME` | Resume a prior run from `pentesin_runs/`, with its agent history and targets. Cannot be combined with `-t`. |

Scans take minutes (`quick`) to hours (`deep`). Run them in the background and poll for completion rather than blocking.

### Exit codes (headless)

- `0` — finished with no validated vulnerabilities **in what was analyzed** (with `--fail-on`, none at or above the threshold; lower ones are still in the artifacts)
- `1` — fatal error (missing env vars, Docker down, bad config)
- `2` — vulnerabilities found (with `--fail-on`, at least one at or above that severity)

A `0` is not proof of full coverage: if `--max-budget`/`--max-turns` is reached before the scan completes, it wraps up early and still exits `0`. When you need assurance the scan finished, give it enough budget and check `pentesin_runs/<run>/run.json`: a hard budget stop leaves `status: "stopped"`, but an agent that wrapped up early on a budget *warning* still calls `finish_scan` and records `"completed"` — so also sanity-check the run's cost against `--max-budget` and the report's stated coverage before treating a clean result as full coverage.

### Reading results

Artifacts land in `pentesin_runs/<run-name>/`:

| File | Contents |
|---|---|
| `penetration_test_report.md` | Executive report — read this first. |
| `vulnerabilities/*.md` | One file per validated finding, with PoC and remediation. |
| `vulnerabilities.json` / `vulnerabilities.csv` | All findings as structured JSON / CSV index. |
| `findings.sarif` | SARIF 2.1.0 for GitHub code scanning / ASPM ingestion. |
| `run.json` | Run metadata, status, targets, usage/cost. |

---

# Option B — Managed cloud (no local infra)

The same `pentesin` binary drives the managed platform. Every command starts with `pentesin cloud`. Full details — asset registration, source uploads, reports, PR reviews, schedules, webhooks, and billing — are in the **managed-pentesting-with-pentesin** skill. Minimal flow:

```bash
# 1. Sign in (device flow — the user confirms a code in the browser; this also
#    creates the account and workspace when needed)
pentesin cloud login

# If you need specific scopes, request them with --scopes:
#   pentesin cloud login --scopes scans:read scans:write assets:read assets:write \
#     vulnerabilities:read billing:read billing:write

# 2. Register and verify the target domain (verification prints a DNS record for the user)
pentesin cloud domains add --domain staging.example.com --asset-type web_app
pentesin cloud domains verify <domain-id>

# 3. Launch and wait
pentesin cloud scans start --engagement-type live_test --domain-ids <domain-id> --wait

# 4. Read validated findings
pentesin cloud vulns list --severity critical
```

For a local repository, `pentesin cloud scans start --source .` uploads the working tree (needs `uploads:write`) and infers a code review. When credits run out, `pentesin cloud billing topup` starts an agent-payable Stripe challenge — the managed skill covers the payment flow. Output is JSON when stdout is not a terminal, so the commands compose in scripts.

The raw REST API works too (org-scoped bearer token against your `PENTESIN_APP_URL` relay). It requires a relay you operate.

---

## Reporting & next steps

Summarize findings by severity (critical/high/medium/low/info) and include the PoC evidence. To remediate and verify fixes (via either path), use the **fix-security-vulnerabilities-with-pentesin** skill. To wire scanning into CI/CD, use the **ci-security-scanning-with-pentesin** skill.

## Safety

Only scan targets the user owns or is authorized to test. The Cloud platform enforces domain verification before external scans; for the OSS CLI, confirm authorization yourself if the target looks like third-party infrastructure.
