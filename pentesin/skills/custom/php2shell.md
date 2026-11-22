---
name: php2shell
description: Escalate a confirmed PHP LFI / file-inclusion vulnerability to verified RCE via session.upload_progress (CVE-2026-109618/109619) on PHP 5.4.0-8.5.11, plus passive version gating and hardening checks
---

# PHP LFI-to-RCE via `session.upload_progress` (CVE-2026-109618 / CVE-2026-109619)

Adapted from ARTEX's `php2shell` playbook. Load this skill whenever a PHP target exposes a reachable **Local File Inclusion (LFI)** or unsafe `include`/`require` primitive and you need to assess whether it escalates cleanly to Remote Code Execution (RCE), or verify passive hardening posture.

## Hard Safety & Verification Gates

1. **Detection Before Exploitation:** Fingerprint PHP version passively first via HTTP response headers (`X-Powered-By`, `Server`), error pages, or `/phpinfo.php`. Only unpatched builds (**PHP 5.4.0 through 8.5.11**; patched in `8.2.35`, `8.3.36`, `8.4.27`, `8.5.12`) with default `session.upload_progress.enabled=On` are candidates.
2. **Never Fire Blind Memory-Corruption PoCs Live:** UAF / serializer-mismatch (`var_destroy`) crash primitives are strictly lab-only and must NEVER be sent against a live production target.
3. **One-Shot Proof Only:** Use `session.upload_progress` strictly to prove arbitrary code execution once with a deterministic harmless marker (e.g., echoing a unique verification token or `php_uname()`/`id` hash), capture baseline vs proof exchanges in Caido proxy (`http_exchange_ids`), and stop immediately without writing persistent webshells.
4. **Without an LFI Primitive:** Expose-only PHP version or `session.upload_progress` defaults alone are **not** exploitable findings — record posture/coverage accurately rather than forcing an RCE claim.

## Exploitation Workflow (Session File Injection + LFI Race)

1. **Confirm the Include Constraint:** Identify exact prefix/suffix appending or null-byte/wrapper behavior on the vulnerable LFI parameter and determine the PHP session storage directory (commonly `/tmp/sess_<PHPSESSID>`, `/var/lib/php/sessions/sess_<PHPSESSID>`, or OS equivalent).
2. **Inject Payload into `session.upload_progress` Filename:**
   - Because PHP's default `session.upload_progress.enabled=On` and `session.upload_progress.cleanup=On` temporarily persist upload progress inside `sess_<id>`, send a concurrent multipart `POST` containing form field `PHP_SESSION_UPLOAD_PROGRESS=<payload>` alongside an arbitrary `Cookie: PHPSESSID=<custom_id>` (alphanumeric 26–32 chars) and a padded upload body to widen the in-flight window.
   - Inject minimal PHP proof code (e.g., `<?php echo "PENTESIN_PROOF_" . phpversion(); ?>`) in `PHP_SESSION_UPLOAD_PROGRESS` or uploaded `filename=`.
3. **Race the Session Include:** Concurrently issue `GET`/`POST` LFI requests including `/tmp/sess_<custom_id>` (or `/var/lib/php/sessions/sess_<custom_id>`) using bounded concurrency in a short Python `asyncio` / `ThreadPoolExecutor` script until the marker appears once in the HTTP body.
4. **Verify & File Evidence:**
   - Capture the benign baseline LFI request (`evidence_roles: "baseline"`) and the proving LFI response showing the executed PHP marker output (`evidence_roles: "proof"`).
   - Provide verbatim response excerpts in `verified_quotes` and state tested paths/payload counts cleanly.
