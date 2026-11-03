"""Offensive security exploit chaining signal matrix and candidate generator.

Maps discovered vulnerability primitives (e.g. Open Redirect, SSRF, CORS, IDOR)
into multi-step exploit chain hypotheses (A -> B -> C) to demonstrate critical
business impact and prevent isolated low-severity finding drop-offs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class ChainCandidate:
    """A concrete hypothesis for chaining an existing finding into higher impact."""

    chain_id: str
    title: str
    primary_vuln_type: str
    target_b: str
    target_c: str | None
    escalated_severity: str
    escalated_impact: str
    suggested_endpoint_patterns: list[str]
    actionable_steps: list[str]
    success_criteria: str
    matched_target_urls: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "title": self.title,
            "primary_vuln_type": self.primary_vuln_type,
            "target_b": self.target_b,
            "target_c": self.target_c,
            "escalated_severity": self.escalated_severity,
            "escalated_impact": self.escalated_impact,
            "suggested_endpoint_patterns": list(self.suggested_endpoint_patterns),
            "actionable_steps": list(self.actionable_steps),
            "success_criteria": self.success_criteria,
            "matched_target_urls": list(self.matched_target_urls),
        }


@dataclass(frozen=True, slots=True)
class ChainRecipe:
    """A predefined template pattern for chaining."""

    chain_id: str
    title: str
    vuln_patterns: list[str]
    cwe_patterns: list[str]
    target_b: str
    target_c: str | None
    escalated_severity: str
    escalated_impact: str
    suggested_endpoint_patterns: list[str]
    actionable_steps: list[str]
    success_criteria: str


CHAIN_PATTERNS: tuple[ChainRecipe, ...] = (
    ChainRecipe(
        chain_id="chain_open_redirect_oauth_ato",
        title="Open Redirect -> OAuth Authorization Code Theft -> Account Takeover",
        vuln_patterns=[
            "open_redirect",
            "open-redirect",
            "redirect",
            "unvalidated_redirect",
            "cwe-601",
        ],
        cwe_patterns=["cwe-601"],
        target_b="OAuth / OIDC / SSO authorization flow with redirect_uri parameter",
        target_c="Account Takeover via authorization code exfiltration & token exchange",
        escalated_severity="critical",
        escalated_impact=(
            "Full account takeover of any user who clicks a legitimate-looking login link"
        ),
        suggested_endpoint_patterns=[
            r"/oauth/.*",
            r"/auth/.*",
            r"/login/.*",
            r"/connect/.*",
            r".*[?&](redirect_uri|redirect|callback|return_to|next)=",
        ],
        actionable_steps=[
            (
                "1. Inspect sitemap and proxy traffic for OAuth/OIDC authorization endpoints "
                "(e.g. /oauth/authorize, /auth/login)."
            ),
            (
                "2. Test if the authorization flow accepts the open redirect URL or host-relative "
                "redirect path as 'redirect_uri'."
            ),
            (
                "3. If accepted, craft a login link where redirect_uri points to the open redirect "
                "destination configured to capture query parameters."
            ),
            (
                "4. Verify that authorizing the request forwards the '?code=' or '#access_token=' "
                "to the attacker controlled location."
            ),
        ],
        success_criteria=(
            "Demonstrate the OAuth authorization code or session token delivered to an external "
            "destination via the redirect."
        ),
    ),
    ChainRecipe(
        chain_id="chain_ssrf_cloud_metadata_creds",
        title="SSRF -> Cloud Metadata & Internal Services -> Credential Exfiltration",
        vuln_patterns=["ssrf", "server_side_request_forgery", "cwe-918", "oob"],
        cwe_patterns=["cwe-918"],
        target_b=(
            "Cloud metadata endpoints (AWS 169.254.169.254, GCP, Azure) or internal services "
            "(localhost, 10.x, 172.16.x)"
        ),
        target_c=(
            "IAM role assumption, cloud infrastructure compromise, or internal database access"
        ),
        escalated_severity="critical",
        escalated_impact=(
            "Unauthorized access to cloud infrastructure, IAM credentials, or internal services"
        ),
        suggested_endpoint_patterns=[
            r".*[?&](url|uri|target|dest|domain|feed|webhook|preview|fetch|proxy)=",
            r"/api/.*/(import|export|download|fetch|proxy|webhook).*",
        ],
        actionable_steps=[
            (
                "1. Test SSRF sink against AWS metadata "
                "(http://169.254.169.254/latest/meta-data/iam/security-credentials/)."
            ),
            (
                "2. Test against GCP metadata "
                "(http://metadata.google.internal/computeMetadata/v1/) "
                "with 'Metadata-Flavor: Google' if headers allowed."
            ),
            (
                "3. Probe internal RFC1918 addresses (127.0.0.1, 10.0.0.0/8, 172.16.0.0/12) for "
                "sensitive admin ports (e.g. 6379, 9200, 8080)."
            ),
            (
                "4. If direct IP is blocked, test DNS rebinding or redirection via a confirmed "
                "open redirect."
            ),
        ],
        success_criteria=(
            "Extract valid cloud temporary credentials (AccessKeyId, SecretAccessKey, Token) "
            "or internal unauthenticated service responses."
        ),
    ),
    ChainRecipe(
        chain_id="chain_cors_data_exfil",
        title="CORS Misconfiguration -> Sensitive API -> Cross-Origin PII/Token Theft",
        vuln_patterns=["cors", "cors_misconfiguration", "cwe-942"],
        cwe_patterns=["cwe-942"],
        target_b="Authenticated API endpoints returning sensitive user profile, tokens, or PII",
        target_c=(
            "Cross-origin exfiltration of victim account data without user interaction "
            "beyond site visit"
        ),
        escalated_severity="high",
        escalated_impact=(
            "Silent theft of private customer data, PII, or internal tokens when victim visits page"
        ),
        suggested_endpoint_patterns=[
            r"/api/.*/(user|me|profile|account|orders|settings|billing|keys|tokens).*",
            r"/graphql.*",
        ],
        actionable_steps=[
            (
                "1. Verify target API returns 'Access-Control-Allow-Origin: <arbitrary|null>' with "
                "'Access-Control-Allow-Credentials: true'."
            ),
            (
                "2. Search sitemap/history for GET endpoints carrying sensitive account details "
                "(PII, email, payment info, auth tokens)."
            ),
            (
                "3. Write a minimal standalone HTML/JS PoC that sends a fetch() with "
                "credentials: 'include' to the sensitive endpoint."
            ),
            "4. Verify the response body can be read and exfiltrated by the cross-origin script.",
        ],
        success_criteria=(
            "Demonstrate reading authenticated victim response body (e.g. email, balance, profile) "
            "from an external origin."
        ),
    ),
    ChainRecipe(
        chain_id="chain_idor_state_tampering",
        title="IDOR / BOLA -> State Modification -> Account Takeover or Resource Destruction",
        vuln_patterns=["idor", "bola", "broken_object_level_authorization", "cwe-639", "cwe-284"],
        cwe_patterns=["cwe-639", "cwe-284"],
        target_b=(
            "State-modifying methods (PUT, POST, PATCH, DELETE) on same resource path or sibling"
        ),
        target_c=("Unauthorized modification or deletion of another user's critical account data"),
        escalated_severity="high",
        escalated_impact=(
            "Arbitrary account data modification, unauthorized password reset, or data destruction"
        ),
        suggested_endpoint_patterns=[
            r"/api/.*/(users?|accounts?|profiles?|orders?|items?|documents?)/[0-9a-zA-Z_-]+.*",
            r".*[?&](user_id|account_id|id|uuid)=",
        ],
        actionable_steps=[
            (
                "1. If IDOR was confirmed on GET (read-only), immediately test PUT, PATCH, and "
                "DELETE on the exact same endpoint."
            ),
            (
                "2. Test sibling endpoints in the same API controller (e.g. /api/user/{id}/email, "
                "/api/user/{id}/password_reset)."
            ),
            (
                "3. Test older API versions (/v1/ vs /v2/) that may lack the authorization "
                "middleware implemented in newer routes."
            ),
            (
                "4. Verify whether modification of an account attribute (e.g. email address) "
                "enables complete account recovery / takeover."
            ),
        ],
        success_criteria=(
            "Successfully modify or delete another user's resource or elevate "
            "permissions using IDOR."
        ),
    ),
    ChainRecipe(
        chain_id="chain_path_traversal_lfi_rce",
        title="Path Traversal / LFI -> Sensitive Configurations & Log Poisoning -> Code Execution",
        vuln_patterns=[
            "path_traversal",
            "lfi",
            "local_file_inclusion",
            "directory_traversal",
            "cwe-22",
        ],
        cwe_patterns=["cwe-22", "cwe-98"],
        target_b="System configuration files, environment variables, or server access logs",
        target_c="Log poisoning leading to Remote Code Execution (RCE)",
        escalated_severity="critical",
        escalated_impact=(
            "Full server compromise and arbitrary code execution through file inclusion"
        ),
        suggested_endpoint_patterns=[
            r".*[?&](file|path|doc|template|page|include|load|view|read)=",
            r"/files?/.*",
            r"/download/.*",
        ],
        actionable_steps=[
            (
                "1. Test reading system files: /etc/passwd, /proc/self/environ, "
                "/proc/self/cmdline, Windows\\win.ini."
            ),
            (
                "2. Search for application config files: .env, config/database.php, settings.py, "
                "appsettings.json to extract DB or app secret keys."
            ),
            (
                "3. If LFI evaluates files (e.g. PHP include), attempt log poisoning by sending a "
                "payload in User-Agent to /var/log/nginx/access.log."
            ),
            "4. Include the poisoned log file to achieve command execution.",
        ],
        success_criteria=(
            "Read application secret keys from files or trigger code execution via poisoned logs."
        ),
    ),
    ChainRecipe(
        chain_id="chain_secret_leak_api_hijack",
        title="Exposed Secrets / API Keys -> Privileged API Access & Data Exfiltration",
        vuln_patterns=[
            "secret_leak",
            "information_disclosure",
            "hardcoded_credentials",
            "cwe-200",
            "cwe-798",
        ],
        cwe_patterns=["cwe-200", "cwe-798"],
        target_b="Internal API routes, cloud services (S3/GCS buckets), or database backends",
        target_c="Privileged administrative actions or massive data exfiltration",
        escalated_severity="high",
        escalated_impact=(
            "Unauthorized administrative API access or direct cloud infrastructure control"
        ),
        suggested_endpoint_patterns=[
            r".*\.(js|json|map|env|bak)$",
            r"/api/.*",
            r"https?://.*\.s3\.amazonaws\.com/.*",
        ],
        actionable_steps=[
            (
                "1. Identify the service provider and permissions of the leaked key (Stripe, AWS, "
                "SendGrid, Firebase, internal JWT secret)."
            ),
            (
                "2. Make a controlled read-only API call using the leaked token to inspect "
                "authorized identity and scopes."
            ),
            (
                "3. Test whether the key permits reading customer records, modifying backend "
                "state, or dispatching administrative operations."
            ),
            "4. Record the exact request/response demonstrating active privileged authorization.",
        ],
        success_criteria=(
            "Execute an authenticated request using the leaked credential proving access beyond "
            "public."
        ),
    ),
    ChainRecipe(
        chain_id="chain_xss_to_account_takeover",
        title="Stored XSS -> CSRF / Session Token Theft -> Administrative Account Escalation",
        vuln_patterns=["xss", "stored_xss", "cross_site_scripting", "cwe-79"],
        cwe_patterns=["cwe-79"],
        target_b="Admin portal views or sensitive account action forms (email change, API key gen)",
        target_c=(
            "Persistent administrative backdoor or full account takeover without user awareness"
        ),
        escalated_severity="critical",
        escalated_impact=(
            "Complete compromise of administrative accounts or arbitrary client-side manipulation"
        ),
        suggested_endpoint_patterns=[
            r"/admin/.*",
            r"/api/.*/(users?|settings|keys|roles).*",
        ],
        actionable_steps=[
            (
                "1. Identify where stored input renders in the application, specifically checking "
                "if privileged users/admins view it."
            ),
            (
                "2. Test if session cookies lack HttpOnly flag, allowing direct exfiltration via "
                "document.cookie."
            ),
            (
                "3. If HttpOnly is set, construct a client-side action payload that triggers a "
                "state-changing POST (e.g. create admin user, change email)."
            ),
            (
                "4. Verify that viewing the injected entity triggers the privileged action "
                "seamlessly in the background."
            ),
        ],
        success_criteria=(
            "Demonstrate executing an administrative action or extracting session context via "
            "the script."
        ),
    ),
    ChainRecipe(
        chain_id="chain_file_upload_polyglot_rce",
        title="File Upload Restriction Bypass -> SVG XSS or Web Shell -> Remote Code Execution",
        vuln_patterns=["file_upload", "insecure_file_upload", "cwe-434"],
        cwe_patterns=["cwe-434"],
        target_b="Uploaded file storage URL, public static directories, or server-side parser",
        target_c="Remote code execution or persistent high-impact XSS",
        escalated_severity="critical",
        escalated_impact="Arbitrary server-side script execution or stored XSS on the host domain",
        suggested_endpoint_patterns=[
            r"/api/.*/(upload|media|avatar|documents?|attachments?).*",
            r"/uploads?/.*",
            r"/storage/.*",
        ],
        actionable_steps=[
            (
                "1. Test uploading SVG containing XML/JavaScript payload to verify if served "
                "inline with image/svg+xml header."
            ),
            (
                "2. Test polyglot payloads and alternate executable extensions (.php, .phtml, "
                ".php5, .jsp, .jspx, .war, .ashx)."
            ),
            (
                "3. Test double extensions (image.php.png) or null byte / path traversal filenames "
                "(../../shell.php)."
            ),
            "4. Access the uploaded file path to verify code execution or DOM script firing.",
        ],
        success_criteria=(
            "Demonstrate command execution (e.g. output of 'id' or 'whoami') or inline SVG script "
            "execution."
        ),
    ),
)


def _normalize_text(s: str | None) -> str:
    if not s:
        return ""
    return re.sub(r"[^a-z0-9]", "_", s.lower()).strip("_")


def _collect_tokens(
    vuln_type: str | None,
    title: str | None,
    description: str | None,
    cwe: str | None,
) -> set[str]:
    tokens = {
        _normalize_text(vuln_type),
        _normalize_text(title),
        _normalize_text(cwe),
    }
    for text in (title, description):
        if text:
            for word in re.findall(r"[A-Za-z0-9_-]+", text.lower()):
                tokens.add(_normalize_text(word))
    return {t for t in tokens if t}


def _matches_recipe(recipe: ChainRecipe, cwe_clean: str, tokens: set[str]) -> bool:
    if cwe_clean and any(p == cwe_clean for p in recipe.cwe_patterns):
        return True
    for pattern in recipe.vuln_patterns:
        p_norm = _normalize_text(pattern)
        if any(p_norm in token or token in p_norm for token in tokens):
            return True
    return False


def _match_urls(patterns: list[str], available_urls: list[str]) -> list[str]:
    matched_urls: list[str] = []
    for pattern_str in patterns:
        try:
            regex = re.compile(pattern_str, re.IGNORECASE)
            for url in available_urls:
                if regex.search(url) and url not in matched_urls:
                    matched_urls.append(url)
        except re.error:
            continue
    return matched_urls[:10]


def find_chain_candidates(
    *,
    vuln_type: str | None = None,
    title: str | None = None,
    description: str | None = None,
    cwe: str | None = None,
    sitemap_urls: list[str] | None = None,
) -> list[ChainCandidate]:
    """Identify relevant exploit chaining candidates for a discovered finding.

    Matches the finding's type, title, CWE, and description against the chaining
    signal matrix and cross-references suggested endpoints with known in-scope
    URLs.
    """
    candidates: list[ChainCandidate] = []
    seen_chain_ids: set[str] = set()

    search_tokens = _collect_tokens(vuln_type, title, description, cwe)
    cwe_clean = (cwe or "").lower().replace(" ", "").strip()
    available_urls = list(sitemap_urls or [])

    for recipe in CHAIN_PATTERNS:
        if recipe.chain_id in seen_chain_ids:
            continue
        if not _matches_recipe(recipe, cwe_clean, search_tokens):
            continue

        seen_chain_ids.add(recipe.chain_id)
        matched_urls = _match_urls(recipe.suggested_endpoint_patterns, available_urls)

        candidates.append(
            ChainCandidate(
                chain_id=recipe.chain_id,
                title=recipe.title,
                primary_vuln_type=recipe.vuln_patterns[0],
                target_b=recipe.target_b,
                target_c=recipe.target_c,
                escalated_severity=recipe.escalated_severity,
                escalated_impact=recipe.escalated_impact,
                suggested_endpoint_patterns=list(recipe.suggested_endpoint_patterns),
                actionable_steps=list(recipe.actionable_steps),
                success_criteria=recipe.success_criteria,
                matched_target_urls=matched_urls,
            )
        )

    return candidates
