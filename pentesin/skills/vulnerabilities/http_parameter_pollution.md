---
name: http-parameter-pollution
description: Server-side and client-side HTTP Parameter Pollution (HPP) testing for duplicate parameter precedence, array coercion, and gateway-to-backend parameter overrides
---

# HTTP Parameter Pollution (HPP)

HTTP Parameter Pollution occurs when an application, proxy, or gateway handles repeated parameters with the same name (`?id=1&id=2` or mixed query/body parameters) inconsistently across layers. Because the HTTP specification does not mandate how duplicate parameter keys must be resolved, different servers, frameworks, and WAFs pick the first, the last, an array, or a comma-joined string.

## Server and Framework Precedence Reference

When `?param=first&param=second` is received:

| Technology / Framework | Resolution Behavior | Result of `?p=1&p=2` |
|---|---|---|
| **PHP (Apache / Nginx)** | Last occurrence wins | `$_GET['p'] == "2"` |
| **Python (Flask / Werkzeug / FastAPI)** | First occurrence by default (`request.args.get`), list via `getlist` | `"1"` |
| **Python (Django)** | Last occurrence by default (`request.GET['p']`), list via `getlist` | `"2"` |
| **Node.js (Express / qs)** | Builds an array | `["1", "2"]` |
| **Go (`net/http`)** | Slice in `r.URL.Query()["p"]`, first in `r.FormValue("p")` | `"1"` |
| **ASP.NET / IIS** | Concatenates all occurrences with commas | `"1,2"` |
| **Java (Servlet / Spring / Tomcat)** | First occurrence via `getParameter()`, array via `getParameterValues()` | `"1"` |
| **Ruby on Rails / Rack** | Last occurrence wins for scalar keys | `"2"` |

## High-Value Attack Patterns

### 1. Gateway / Middleware vs Backend Override (Authorization & Billing)

A reverse proxy, API gateway, or authentication middleware validates one occurrence of a parameter while the downstream microservice or backend framework consumes another.

- **First-check, Last-use (e.g., Java/Go/Flask gateway -> PHP/Django/Rails backend)**:
  - Send `?user_id=YOUR_ID&user_id=VICTIM_ID` or `?account=self&account=admin`.
  - The gateway checks the first parameter (`YOUR_ID`, authorized), while the backend processes the last (`VICTIM_ID`).
- **Last-check, First-use (e.g., PHP/Rails middleware -> Go/Java/Flask backend)**:
  - Send `?user_id=VICTIM_ID&user_id=YOUR_ID`.
  - Middleware validates the last value (`YOUR_ID`), while the backend executes against the first (`VICTIM_ID`).

### 2. Cross-Source Parameter Precedence (Query vs Body vs Cookie)

Frameworks that expose unified request helpers (`$_REQUEST` in PHP, `req.param()` in older Express, `request.values` in Flask, Java Servlet `getParameter()` on `POST`) merge parameters from multiple locations in a fixed order:

- Send the benign/authorized value in the URL query string and the attacker value in the `POST` body (or vice versa):
  ```http
  POST /api/transfer?amount=10&from_account=mine HTTP/1.1
  Content-Type: application/x-www-form-urlencoded

  amount=10&from_account=victim
  ```
- Test JSON body + URL query string simultaneously: an API gateway may inspect `req.query.role` while the controller binds `req.body.role` (or vice versa).

### 3. Internal API Query String Injection (Server-Side HPP)

When a frontend server takes a user parameter and concatenates it into an internal HTTP request to a backend service without URL-encoding `&` and `=`:

- **Probe**: Supply `value%26extra_param%3D1` (URL-encoded `&` and `=`) inside a single parameter.
- If the frontend decodes `%26` into a literal `&` when building the internal URL `http://internal-service/checkout?item=book&price=100`, injecting `item=book%26price%3D1` produces:
  `http://internal-service/checkout?item=book&price=1&price=100` (or overrides `price` if appended after).
- **Test vectors**:
  - Override internal-only parameters (`&role=admin`, `&is_verified=true`, `&price=0`, `&currency=IDR`).
  - Truncate the remaining internal query string using `%23` (`#` fragment) so default parameters appended by the server are ignored by the internal HTTP client.

### 4. Array Coercion and Type Confusion

In Express/Node.js (`qs`), PHP (`param[]=1&param[]=2`), and Rails:

- Supplying `?token=a&token=b` or `?token[]=a` turns an expected string into an Array.
- **Bypass checks**:
  - `.length`, `.includes()`, `.slice()` work on both strings and arrays in JavaScript, bypassing `if (token.length > 0)` while changing downstream behavior in SQL/NoSQL queries, `crypto.timingSafeEqual`, or string templates.
  - In SQL builders that flatten arrays or in ASP.NET where `?id=1&id=2` becomes `"1,2"`, split SQL injection tokens across duplicate parameters (`?id=1/*&id=*/UNION/*&id=*/SELECT+1`) to evade single-parameter WAF signatures.

### 5. Client-Side HPP (Link & OAuth Flow Manipulation)

When a page reflects a URL parameter into generated `href`, form `action`, or `iframe src` links without encoding `&`:

- Inject `%26redirect_uri%3Dhttps://attacker.example` or `%26action%3Ddelete` into parameters used to construct shareable links, password reset links, or OAuth authorization URLs.
- Verify whether the generated link in the DOM or email contains the injected parameter and whether clicking it alters the target action.

## Validation Checklist

1. **Confirm differential behavior**: Send `?param=A&param=B` and `?param=B&param=A`. Observe whether the response reflects `A`, `B`, `A,B`, or `["A","B"]`.
2. **Test cross-location**: Send `param=A` in query and `param=B` in `POST` body (both `x-www-form-urlencoded` and `application/json`).
3. **Test encoded delimiter injection**: Send `param=A%26injected%3DB` and check if the backend behaves as if `injected=B` was supplied.
4. **Prove security impact**: Demonstrate unauthorized resource access (IDOR), state/price tampering, filter bypass, or privilege escalation—do not report harmless first/last parameter selection without a security boundary violation.
