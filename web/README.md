# Pentesin private control room

Laravel dashboard for one private Pentesin workspace: black-box web/API scans, a live agent graph with per-agent transcript/chat, findings, run history, and encrypted LLM profiles. The Python scan engine and Docker sandbox remain in the parent repository.

## Requirements

- PHP 8.4+, Composer 2, Node.js 24+
- PostgreSQL for the application database
- Docker Engine/Desktop available to the Python runner
- Pentesin sandbox image `pentesin-sandbox:latest`

## Local setup (PowerShell)

From this directory:

```powershell
composer install
Copy-Item .env.example .env
php artisan key:generate
npm ci
npm run build
```

Edit `.env`: set `APP_URL`, PostgreSQL credentials, and a fresh high-entropy `PENTESIN_RUNNER_TOKEN` (at least 48 characters). Keep `.env` private; never commit it. Example token generation:

```powershell
$bytes = [byte[]]::new(48); [Security.Cryptography.RandomNumberGenerator]::Fill($bytes); [Convert]::ToBase64String($bytes)
```

Create the PostgreSQL database and restricted DB user first, then:

```powershell
php artisan migrate --force
php artisan pentesin:operator operator@example.invalid
```

The operator command securely prompts for a password (minimum 16 characters); it does not create a public signup flow or seed a default account.

In another PowerShell window, from the repository root, start the authenticated loopback runner:

```powershell
$env:PENTESIN_APP_URL = "http://127.0.0.1:8000"
$env:PENTESIN_RUNNER_TOKEN = "<same-secret-as-web-.env>"
$env:Path = "C:\Program Files\Go\bin;$env:Path"  # needed by source-mode TUI only, not dashboard runner
uv run python -m pentesin.interface.web_runner
```

Start Laravel from `web/`:

```powershell
php artisan serve --host=127.0.0.1 --port=8000
```

Open `http://127.0.0.1:8000/login`, sign in, add an LLM profile, run its connectivity/tool-calling test, then submit an authorized lab domain. The graph polls incremental events; clicking a node opens the agent transcript and scoped chat. Scan output and downloaded artifacts stay in private server storage.

## Private VPS deployment

Use Nginx + PHP-FPM, PostgreSQL, and a separate systemd runner process. Terminate HTTPS at Nginx. Keep PostgreSQL, runner control routes, Docker API/socket, and sandbox ports off the public interface. The runner control route is protected with a high-entropy bearer token, but Nginx must not expose `/api/internal/runner/*`; bind the runner bridge to loopback, or use a private network/VPN and firewall rule that cannot be overridden by client-supplied forwarded-IP headers. The runner requires Docker privileges (effectively root-equivalent on the Docker host), so run it as a dedicated account on an isolated host/VM and restrict sandbox egress to the approved lab targets. Set unique `APP_KEY`, `PENTESIN_RUNNER_TOKEN`, DB credentials, and LLM profile keys in protected environment files. Back up PostgreSQL and private artifact storage. Do not seed default users or enable public signup.

This dashboard has no multi-tenant boundary yet. Keep it private/VPN/IP-restricted until multi-user ownership and authorization are independently reviewed.

## Validation

```powershell
php artisan test --compact
vendor/bin/pint --dirty --format agent
npm run build
```

The runner integration tests use fake HTTP/model interactions. They do not launch Docker, contact a live model, or scan a real host. A manual smoke scan should use only a lab target you control, with explicit budget and authorization.
