---
name: xray-scanner
description: Drive the Chaitin Xray scanner against one in-scope live target — when to run it, what zero findings does and does not mean, and how to treat 403-bypass probes as reachability signals rather than findings
---

# Xray Scanner

`xray_scan` runs the Chaitin Xray scanner inside the sandbox against **one
authorized live target**. It crawls, runs xray's plugin set, and returns
normalized findings.

## When to use it

- **After recon**, on a host the scan already authorizes. Xray is fast coverage
  for the classes its plugins carry; it is not a substitute for testing the
  application's own logic.
- **When you need a second opinion on a candidate.** Xray's result is evidence
  that a payload class reached a sink, not that the finding is exploitable.
- **When the target answers 403 and you need to know whether the route is truly
  closed.** Pass `bypass_403=True` — see below.

Do **not** use it as the opening move. It is loud: a crawler hits every link it
can reach. If the engagement calls for stealth, test manually first.

## Arguments

| Argument | Use |
|---|---|
| `target` | Absolute http(s) URL on an in-scope host. No query string, no credentials — xray discovers parameters itself. |
| `mode` | `crawler` (default) follows links; `url` scans only that exact URL. Use `url` for a focused, quiet re-test. |
| `plugins` | Optional subset, e.g. `["sqldet", "xss"]`. Omit for xray's full default set. Unknown names are rejected. |
| `timeout_s` | Wall clock, default 1800, max 7200. |
| `bypass_403` | Add reachability probes. Off by default. |

A target outside the run's scope is **refused**, including a non-authorized port
on an authorized host. That refusal is correct — do not try to work around it
with `exec_command`; if a host genuinely belongs in scope, say so and stop.

## Reading the result

`findings` is a list; each entry has `plugin`, `severity`, `url`, `title`.
`by_severity` is the roll-up. Two things matter more than the count:

- **Zero findings is not a clean bill of health.** It means xray's plugins
  reached nothing. Check `output_path` and what the crawler actually saw before
  you record `no_issue_found` in coverage.
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
