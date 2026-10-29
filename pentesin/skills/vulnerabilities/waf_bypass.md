---
name: waf-bypass
description: WAF and edge-filter bypass methodology using parser differentials, content-type switching, encoding transforms, and HTTP framing variations
---

# WAF and Edge Filter Bypass

A WAF is a secondary parser sitting in front of the application, not the application itself. Bypassing a block is an exercise in finding a representation that the edge filter considers benign (or fails to inspect) while the origin server still parses into the intended payload.

Note: WAF evasion is a delivery primitive, not a standalone vulnerability. Only report a finding when the bypass reaches and proves an underlying vulnerability on the origin (SQLi, XSS, SSRF, RCE, authz bypass).

## Phase 1: Fingerprint the Block Before Mutating

Do not spray random encodings. Establish what triggered the block:

1. **Baseline clean request**: Record status, headers (`Server`, `cf-ray`, `x-amzn-RequestId`, `x-iinfo`, `x-sucuri-id`), cookies (`__cf_bm`, `incap_ses_*`, `visid_incap_*`), and response body.
2. **Isolate the trigger**: Binary-search the payload to find the exact token, character sequence, header, or parameter location causing the `403`/`406`/`429`/connection reset.
3. **Classify the enforcement layer**:
   - **Rule/signature block**: Instant `403`/`406` tied to specific payload tokens (`UNION SELECT`, `<script`, `../`, `/etc/passwd`).
   - **Bot/JS/TLS challenge**: Interstitial challenge page, CAPTCHA, or `403` even on clean `curl` requests (fingerprint mismatch—switch to `browser_action` or match browser headers/TLS).
   - **Rate limit**: `429` or temporary IP block after burst requests; slow down concurrency before continuing.

## Phase 2: Content-Type and Body Parser Switching

WAFs often inspect `application/x-www-form-urlencoded` strictly while skipping or misparsing alternative body formats that the backend framework accepts automatically:

- **Form to JSON**: Change `Content-Type: application/x-www-form-urlencoded` (`a=1&b=payload`) to `Content-Type: application/json` (`{"a":1,"b":"payload"}`), or vice versa. Express (`body-parser`), Spring, Rails, and Laravel often accept both on the same route.
- **Form to Multipart**: Wrap parameters in `Content-Type: multipart/form-data; boundary=----WebKitFormBoundary...`. Vary boundary quoting, trailing whitespace, duplicate `Content-Disposition` headers, or malformed `filename=` attributes.
- **Charset Mutation**: Append charset parameters to `Content-Type` that the origin decodes but the WAF rule engine ignores:
  - `Content-Type: application/x-www-form-urlencoded; charset=ibm500`
  - `Content-Type: application/json; charset=utf-16le` or `utf-7`
- **Content-Type Confusion**: Send `Content-Type: text/plain` or `application/csp-report` with a JSON body when the backend parses raw body bytes unconditionally (`JSON.parse(req.body)` / `request.get_json(force=True)`).

## Phase 3: Inspection Size and Framing Limits

Edge proxies buffer a fixed prefix of the request body (commonly 8 KB, 16 KB, 64 KB, or 128 KB) for latency reasons and pass the remainder uninspected to the origin:

- **Body Padding**: Prepend benign junk parameters or JSON fields (`"pad": "A" * 65536`) before the parameter holding the payload.
- **Chunked Transfer Encoding**: Send `Transfer-Encoding: chunked` and split trigger keywords across small chunks (`5\r\nUNION\r\n7\r\n SELECT\r\n0\r\n\r\n`), or include chunk extensions (`5;ext=val\r\n`).
- **Method Override**: If `POST` or `DELETE` rules are stricter, send `GET` or `POST` with `X-HTTP-Method-Override: PUT`, `X-Method-Override`, or `_method=DELETE` in query/body.

## Phase 4: Encoding and Normalization Differentials

Exploit mismatches between how the WAF decodes input and how the origin normalizes it:

- **Double URL Encoding**: `%2527` (`'`), `%253c` (`<`), `%252f` (`/`) when an intermediate rewrite or backend decodes twice.
- **Unicode / Overlong / Fullwidth Normalization**: Fullwidth characters (`%ef%bc%9c` -> `<`, `%ef%bc%87` -> `'`, `%ef%bc%9b` -> `;`) normalized via NFKC/NFKD on the backend.
- **JSON Unicode Escapes**: Inside JSON strings, replace characters watched by regex signatures with `'` (`'`), `<` (`<`), `union` (`union`).
- **XML/HTML Entity Encoding**: Inside XML/SOAP or HTML-parsed fields, encode payload tokens as `&#x27;`, `&#39;`, or `&#x3c;`.
- **Null Byte and Control Whitespace**: Insert `%00`, `%09` (tab), `%0a` (LF), `%0b` (VT), `%0c` (FF), `%0d` (CR), or `%a0` where the WAF tokenizes on `0x20` spaces only.

## Phase 5: Vulnerability-Specific Payload Shaping

### SQL Injection
- Replace spaces with inline comments or parentheses: `UNION/**/SELECT`, `UNION(SELECT(1),(2))`, `/*!50000UNION*//*!50000SELECT*/` (MySQL versioned comments).
- Replace blocked comparisons/functions: `LIKE` / `REGEXP` / `RLIKE` instead of `=`, `MID()` / `SUBSTR()` / `LEFT()` instead of `SUBSTRING()`, `CASE WHEN ... THEN ... END` instead of `IF()`.
- Scientific notation and hex/char construction: `1e0UNION SELECT`, `0x61646d696e` or `CHR(97)||CHR(100)...` instead of quoted literals.

### Cross-Site Scripting (XSS)
- Avoid `<script>` and `on*=`: use `<svg/onload=...>`, `<details/open/ontoggle=...>`, `<img src=x onerror=...>`, `<math><mtext><table><mglyph><style><img src=x onerror=...>`.
- Avoid parentheses and `alert`: ``onerror=confirm`1` ``, `onerror=throw/1/,Uncaught=eval,1`, `Reflect.apply(confirm,window,[1])`, `top['al'+'ert'](1)`.
- Exploit DOM sinks where the payload remains in the URL fragment (`#...`), which is never sent over the wire to the WAF.

### SSRF and Path Traversal
- Alternate IP representations: decimal (`2130706433`), octal (`0177.0.0.1`), hex (`0x7f000001`), IPv6 mapped (`[::ffff:127.0.0.1]`, `[::1]`), short notation (`127.1`).
- DNS rebinding or wildcard DNS (`127.0.0.1.nip.io`) when string-based host blocklists are used.
- Traversal sequences: `....//`, `..;/` (Tomcat/Nginx path parameters), `%2e%2e%2f`, `%252e%252e%252f`.

## Phase 6: Origin and Route Bypass

- **Header Spoofing for IP Allowlists**: Test `X-Forwarded-For: 127.0.0.1`, `X-Real-IP: 127.0.0.1`, `True-Client-IP: 127.0.0.1`, `CF-Connecting-IP: 127.0.0.1`, `X-Originating-IP: 127.0.0.1`.
- **Path Normalization Drift**: If `/admin/users` is blocked at the edge, test `/admin//users`, `/./admin/users`, `/admin/users/`, `/admin;v=1/users`, `/ADMIN/users`, or `/api/v1/../admin/users`.
- **Alternate Host / API Version**: Check whether `/api/v1/` is behind WAF rules while `/api/v2/`, `/graphql`, mobile API subdomains, or staging hosts route to the same backend handler without the rule set.
