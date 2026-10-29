# pentesin — Agent Guide

pentesin (black-box-only fork) is an autonomous AI pentesting tool for **live web
targets**. This file is for AI coding agents that want to **use** it (run
security scans) or **contribute** to it.

This fork accepts live targets (URLs, domains, IPs) and OpenAPI/Swagger/Postman
API contracts as endpoint maps. Contracts authorize their declared HTTP(S)
servers but never expose source code. Source directories, Git repositories, and
whitebox/source-aware behaviour are unsupported. Chaitin Xray is available to
scan agents through the `xray_scan` tool.

## Using pentesin from an agent

Install the agent skills for step-by-step workflows:

```bash
npx skills add Ghanott/Pentesin
```

- `penetration-testing-with-pentesin` — run a headless pentest against a URL, domain, or IP and read results (covers both run modes below)
- `managed-pentesting-with-pentesin` — drive a pentesin-compatible cloud relay via REST (requires `PENTESIN_APP_URL`; no local Docker/LLM needed)
- `fix-security-vulnerabilities-with-pentesin` — remediate findings and re-run pentesin to verify
- `ci-security-scanning-with-pentesin` — add PR scanning to CI/CD (self-hosted CLI or a relay you operate)

Target-specific workflows built on the same engine:

- `application-security-testing` — whole-product AppSec review: pick the right test per asset, then rank the results
- `web-app-penetration-testing` — black-box pentest of a live web app or staging site
- `api-security-testing` — REST/GraphQL APIs and the OWASP API Security Top 10 (BOLA/IDOR, authz)
- `owasp-top-10-testing` — systematic OWASP Top 10 assessment with honest per-category coverage

**Two ways to run, same engine — pick per situation:**

- **Open-source CLI (self-hosted):** free, fully local, BYO LLM key, needs Docker. Best for local dev loops, air-gapped/offline, and full control.
  ```bash
  curl -sSL https://raw.githubusercontent.com/Ghanott/Pentesin/main/scripts/install.sh | bash        # install
  export PENTESIN_LLM="openrouter/z-ai/glm-5.3"        # any LiteLLM model id
  export LLM_API_KEY="<key>"
  pentesin -n -t https://your-app.com --scan-mode quick --max-budget 10  # headless
  ```
  - Requires Docker running. Scans take minutes (`quick`) to hours (`deep`) — run in the background.
  - Exit codes (headless): `0` clean, `1` fatal error, `2` vulnerabilities found. A `0` only covers what was analyzed — check `run.json` (`status`, `llm_usage.cost` vs the budget) before calling a run clean.
  - Artifacts in `pentesin_runs/<run-name>/`: `penetration_test_report.md`, `vulnerabilities/*.md`, `vulnerabilities.json`, `findings.sarif` (SARIF 2.1.0), `run.json`.

- **Managed cloud (relay):** no Docker, no LLM key, no local install — but this fork ships no hosted relay. Set `PENTESIN_APP_URL` to a compatible deployment you control to use `pentesin cloud`.
  ```bash
  pentesin cloud login --scopes scans:read scans:write uploads:write billing:read
  pentesin cloud domains add --domain example.com --asset-type web_app
  pentesin cloud scans start --engagement-type live_test --domain-ids <uuid> --wait
  pentesin cloud scans start --source . --dry-run --show-files --json  # review + capture source.archive_sha256
  SOURCE_SHA256="<reviewed source.archive_sha256>"
  pentesin cloud scans start --source . --approve-sha256 "$SOURCE_SHA256" --wait
  pentesin cloud vulns list --severity critical
  pentesin cloud billing topup --credits 20 --yes  # explicit approval after exit code 5
  ```
  - Account setup runs from the CLI too: `pentesin cloud workspaces list|create|use` (`workspace` is an alias and `use` accepts a displayed number, name, or ID), `pentesin cloud session scopes|scopes set`, `pentesin cloud org members invite`, `pentesin cloud billing subscribe --plan pentesin_cloud`, `pentesin cloud billing portal`, `pentesin cloud integrations install github`, and `pentesin cloud domains verify <id>`. Workspace switching preserves the server-side profile and can never widen past the login ceiling; ordinary switches do not reprompt. The last four end at a person: the command prints a link or a DNS record for the user to open or add, and it never completes the payment, installation, or DNS change for them.
  - Every REST operation has a `pentesin cloud <resource> <verb>` command. Run `pentesin cloud` to list them. Output is JSON when stdout is not a terminal (or with `--json`), and there are no prompts without a TTY. Binary downloads are the exception: redirect raw bytes intentionally, or combine `--output FILE --json` for structured download metadata. Exit codes: `0` success, `1` error, `2` usage, `4` auth or plan limit, `5` payment required. `--token` or `PENTESIN_API_TOKEN` is a stateless override and never replaces stored auth; set `--workspace-id`/`PENTESIN_WORKSPACE_ID` for an override CLI session. `--data` adds extra request fields as JSON, and accepts `@file` or `-` for standard input.
  - Local source uploads require `uploads:write`. For an agent/CI handoff, review `scans start --source . --dry-run --show-files --json`, capture `source.archive_sha256`, then rerun with the same `--source`, `--exclude`, and `--include-*` selection flags plus `--approve-sha256 HASH`. A changed snapshot is rejected. `--yes` approves only the snapshot built in that invocation, so reserve it for a deliberate human or one-shot approval rather than a digest-bound two-step handoff.
  - Git ignores, hidden files, `.git`, symlinks, dependency/build output, secret-like filenames, and nested archives are excluded by default; `.pentesinignore` and `--exclude` narrow the manifest further (a trailing `/` excludes a directory subtree). Limits: 20,000 files, 25 MiB/file, 250 MiB expanded, 50 MiB compressed. Source-only infers `code_review`; source plus a domain infers `live_test`.
  - The temporary local archive is always removed. A staged upload is deleted after a definitive rejection, but retained when a network error, `5xx`, malformed success response, or interruption leaves the scan launch ambiguous. JSON reports its `upload_id` with `launch_outcome_unknown: true`, or with `cleanup_unknown: true` when automatic deletion cannot be confirmed. Check `scans list` before retrying; if no scan is linked, run `uploads delete UPLOAD_ID`.
  - Non-Enterprise scans consume the scope estimate (a default-tier source-only review currently starts at 60 credits); Enterprise scans are plan-included. A rejected launch does not consume credits.
  - Human output is compact and numbered; non-TTY output and `--json` retain full records. Enable tab completion with `source <(pentesin completions zsh)` (or `bash`), or `pentesin completions fish | source`.
  - The REST API works directly too: https://github.com/Ghanott/Pentesin/tree/main/docs/integrations (OpenAPI: https://github.com/Ghanott/Pentesin/tree/main/docs).

- Repo docs: https://github.com/Ghanott/Pentesin/tree/main/docs. This fork ships no hosted relay; `pentesin cloud` works only when `PENTESIN_APP_URL` points at a compatible relay you operate.
- Only scan targets the user is authorized to test.

## Contributing to this repo

- Python 3.12+, managed with `uv`. Install dev deps: `make dev-install`.
- Lint/format/type-check/security, all in one: `make check-all` (ruff, mypy, bandit).
- Tests: `uv run pytest`.
- Run from source: `uv run pentesin --target <target>`.
- Layout: `pentesin/agents` (agent graph + prompts), `pentesin/tools` (proxy, browser, terminal, scanners), `pentesin/runtime` (Docker sandbox), `pentesin/report` (findings, SARIF), `pentesin/skills` (internal knowledge packs the pentest agents load — different from the consumer skills in `skills/`), `pentesin/interface` (CLI/TUI), `containers/` (sandbox image).
- Pre-commit hooks: `make pre-commit` (or `uv run pre-commit install`).

===

<laravel-boost-guidelines>
=== foundation rules ===

# Laravel Boost Guidelines

## Foundational Context

This application is a Laravel application running on PHP 8.4. Always use the APIs that match the installed major version of each package — do not assume a version.

Before relying on a package's API, confirm its installed version:
- PHP packages: run `composer show --direct` to list direct dependencies with versions, or `composer show <vendor/package>` for a single package.
- JS packages: check `package.json` for the installed versions.

## Conventions

- You must follow all existing code conventions used in this application. When creating or editing a file, check sibling files for the correct structure, approach, and naming.
- Use descriptive names for variables and methods. For example, `isRegisteredForDiscounts`, not `discount()`.
- Check for existing components to reuse before writing a new one.

## Verification Scripts

- Do not create verification scripts or tinker when tests cover that functionality and prove they work. Unit and feature tests are more important.

## Application Structure & Architecture

- Stick to existing directory structure; don't create new base folders without approval.
- Do not change the application's dependencies without approval.

## Frontend Bundling

- If a frontend change doesn't show in the UI or you get a "Unable to locate file in Vite manifest" error, run `npm run build` or ask the user to run `npm run dev` or `composer run dev`.

## Documentation Files

- You must only create documentation files if explicitly requested by the user.

=== boost rules ===

# Laravel Boost

## Project Rules

- This project contains committed, area-grouped rules in `.ai/rules` when that directory exists, including path-scoped framework guidelines under `.ai/rules/boost`. Before you enter plan mode or create/edit any file, you MUST first: open @.ai/rules/index.md (it maps file globs to rule files), read every rule file whose globs cover the path(s) in scope, and run `grep -rin 'keyword' .ai/rules` to catch what a path match alone misses. Do not write code until you have read and are following every matching rule. If `.ai/rules` does not exist, continue without it.

## Artisan

- Run Artisan commands directly via the command line (e.g., `php artisan route:list`). Use `php artisan list` to discover available commands and `php artisan [command] --help` to check parameters.
- Inspect routes with `php artisan route:list`. Filter with: `--method=GET`, `--name=users`, `--path=api`, `--except-vendor`, `--only-vendor`.
- Read configuration values using dot notation: `php artisan config:show app.name`, `php artisan config:show database.default`. Or read config files directly from the `config/` directory.

## Tinker

- Execute PHP in app context for debugging and testing code. Do not create models without user approval, prefer tests with factories instead. Prefer existing Artisan commands over custom tinker code.
- Always use single quotes to prevent shell expansion: `php artisan tinker --execute 'Your::code();'`
  - Double quotes for PHP strings inside: `php artisan tinker --execute 'User::where("active", true)->count();'`

=== php rules ===

# PHP

- Always use curly braces for control structures, even for single-line bodies.
- Use PHP 8 constructor property promotion: `public function __construct(public GitHub $github) { }`. Do not leave empty zero-parameter `__construct()` methods unless the constructor is private.
- Use explicit return type declarations and type hints for all method parameters: `function isAccessible(User $user, ?string $path = null): bool`
- Use TitleCase for Enum keys: `FavoritePerson`, `BestLake`, `Monthly`.
- Prefer PHPDoc blocks over inline comments. Only add inline comments for exceptionally complex logic.
- Use array shape type definitions in PHPDoc blocks.

=== deployments rules ===

# Deployment

- Laravel can be deployed using [Laravel Cloud](https://cloud.laravel.com/), which is the fastest way to deploy and scale production Laravel applications.

=== laravel/core rules ===

# Do Things the Laravel Way

- Use `php artisan make:` commands to create new files (i.e. migrations, controllers, models, etc.). You can list available Artisan commands using `php artisan list` and check their parameters with `php artisan [command] --help`.
- If you're creating a generic PHP class, use `php artisan make:class`.
- Pass `--no-interaction` to all Artisan commands to ensure they work without user input. You should also pass the correct `--options` to ensure correct behavior.

### Model Creation

- When creating new models, create useful factories and seeders for them too. Ask the user if they need any other things, using `php artisan make:model --help` to check the available options.

## APIs & Eloquent Resources

- For APIs, default to using Eloquent API Resources and API versioning unless existing API routes do not, then you should follow existing application convention.

## URL Generation

- When generating links to other pages, prefer named routes and the `route()` function.

## Testing

- When creating models for tests, use the factories for the models. Check if the factory has custom states that can be used before manually setting up the model.
- Faker: Use methods such as `$this->faker->word()` or `fake()->randomDigit()`. Follow existing conventions whether to use `$this->faker` or `fake()`.
- When creating tests, make use of `php artisan make:test [options] {name}` to create a feature test, and pass `--unit` to create a unit test. Most tests should be feature tests.

=== pint/core rules ===

# Laravel Pint Code Formatter

- If you have modified any PHP files, you must run `vendor/bin/pint --dirty --format agent` before finalizing changes to ensure your code matches the project's expected style.
- Do not run `vendor/bin/pint --test --format agent`, simply run `vendor/bin/pint --format agent` to fix any formatting issues.

=== phpunit/core rules ===

# PHPUnit

- This project uses PHPUnit. Create tests with `php artisan make:test --phpunit {name}`.
- Do not include the test suite directory in `{name}`. Use `SomeFeatureTest`, not `Feature/SomeFeatureTest`.
- Read the `testing-best-practices` skill for guidance on coverage, naming, structure, dependency isolation, and review.

## Running Tests

- Run the narrowest set of tests that covers the change. Pass a file path or `--filter=testName` to `php artisan test --compact`.
- Rerun a test after each change to it.
- Run `vendor/bin/phpunit` to call the test runner directly. It accepts the same file path and `--filter=testName` arguments.

</laravel-boost-guidelines>
