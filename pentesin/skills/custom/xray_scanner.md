---
name: xray-scanner
description: Drive the Chaitin Xray scanner against one in-scope live target — when to run it, what zero findings does and does not mean, and how to treat 403-bypass probes as reachability signals rather than findings
---

# Xray Scanner

`xray_scan` runs the Chaitin Xray scanner inside the sandbox against **one
recon candidate URL**. It tests that exact path and query using explicitly
selected plugins and returns normalized findings. Never use Xray for spidering,
crawling, or indiscriminate host-wide scans.

## When to use it

- **After recon identifies a candidate**, not merely a live host. Record the
  exact URL, path/parameters, suspected bug class, and why the selected plugin
  applies. For `/search?q=test`, choose `xss` for suspected reflection or `sqldet`
  for a SQL-backed input. Preserve all query parameters and values.
- **When you need a second opinion on a candidate.** Xray's result is evidence
  that a payload class reached a sink, not that the finding is exploitable.
- **When the target answers 403 and you need to know whether the route is truly
  closed.** Pass `bypass_403=True` — see below.

Do **not** use it as the opening move or as a crawler. Discovery belongs to recon.
Xray tests only selected candidates within the authorized scope.

## Arguments

| Argument | Use |
|---|---|
| `target` | Exact in-scope URL found during recon, including path and query. No credentials or fragment. |
| `mode` | `url` only (default). Crawler mode is refused. |
| `plugins` | Required nonempty selection relevant to the candidate, e.g. `["xss"]` or `["sqldet"]`. No default full-plugin scan. |
| `timeout_s` | Wall clock, default 1800, max 7200. |
| `bypass_403` | Add reachability probes. Off by default. |

A target outside the run's scope is **refused**, including a non-authorized port
on an authorized host. That refusal is correct — do not try to work around it
with `exec_command`; if a host genuinely belongs in scope, say so and stop.

## Reading the result

`findings` is a list; each entry has `plugin`, `severity`, `url`, `title`.
`by_severity` is the roll-up. Two things matter more than the count:

- **Zero findings is not a clean bill of health.** It means xray's plugins
  confirmed nothing on this candidate. Check request reachability and the
  selected plugins before recording `no_issue_found` for this URL and bug class.
- **A finding is a lead, not a report.** Reproduce it by hand, confirm the input
  was attacker-controlled, and establish impact before filing. Xray reports
  payload reflection; it does not know whether that reflection executes, or
  whether the data behind it is worth anything.

## 403 bypass probes

`bypass_403=True` sends additional requests that vary the headers and path
(`X-Forwarded-For`, `X-Original-URL`, path normalization, and similar). A probe
that returns anything other than `403` comes back with `plugin: "403-bypass"`
so it is never confused with a plugin result.

That is a **reachability signal, not a vulnerability**. A 200 tells you the
route answered differently for that request shape. You still have to read the
body and decide whether anything sensitive is exposed. Only `plugin:
"403-bypass"` entries are probes; everything else came from a real xray plugin.

This is off by default because it multiplies request volume. Turn it on when
403 is the actual obstacle, not as a default part of every scan.

## Reporting what you find

File findings through `create_vulnerability_report` like any other finding, with
the xray plugin name and the concrete request in the PoC section. Put the
scanner's raw output behind an evidence reference rather than pasting it in.
Never file a `403-bypass` probe as a finding on its own — only once you have
established what the reachable route actually returns.
