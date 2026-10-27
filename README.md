# KlyPen

**KlyPen** is a local-first web security assessment tool for websites you own or are explicitly authorized to test. It combines bounded passive checks, a small local dashboard, SQLite scan history, report exports, and optional security-intelligence lookups.

> KlyPen is an assessment aid, not a full penetration-testing suite or a security certification. A clean result or high score does not prove that a target is secure.

## Features

- Dark, responsive dashboard served by the Python backend; no frontend build step is required.
- Bounded same-origin crawling using GET requests only by default.
- Strict URL validation, public-address checks, pinned DNS addresses, same-origin redirect checks, and normal TLS certificate verification.
- Passive checks for response security headers, cookie attributes, wildcard CORS indicators, mixed content, password-form transport, and source-map references visible in HTML.
- SQLite persistence for scan history and findings.
- SSE scan progress, cancellation, finding filters, and JSON/HTML report downloads.
- Free, on-demand [OSV.dev](https://google.github.io/osv.dev/api/) package/version lookup. It accepts a package name, ecosystem, and exact version; it does not guess packages based on server headers.
- Optional [AlienVault OTX](https://otx.alienvault.com/api) reputation enrichment when explicitly enabled and configured.
- Local-only demo lab for safe integration testing.

## Requirements

- Python 3.10 or newer (Python 3.11+ recommended).
- Internet access for installing dependencies and scanning public targets.
- Optional: Node.js only if you want to run the JavaScript syntax check manually. The app itself does not require Node.

## Windows PowerShell quick start

Open PowerShell in the repository root:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\run.ps1
```

On the first run, the script creates `.venv`, installs the requirements, copies `.env.example` to `.env` if needed, and starts KlyPen bound to `127.0.0.1:8000`.

Open **http://127.0.0.1:8000** in your browser.

If you prefer manual setup:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
Copy-Item .env.example .env
.\.venv\Scripts\python.exe -m uvicorn backend.app:app --host 127.0.0.1 --port 8000
```

If `.env` already exists, don't overwrite it blindly. Review its values instead.

## Linux / macOS quick start

```bash
chmod +x run.sh
./run.sh
```

Or manually:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
cp .env.example .env
python -m uvicorn backend.app:app --host 127.0.0.1 --port 8000
```

## Run a scan

1. Open `http://127.0.0.1:8000`.
2. Choose **New assessment**.
3. Enter a full `http://` or `https://` URL.
4. Confirm that you own the target or have explicit permission.
5. Start the scan and wait for the status to finish.
6. Review each finding, verify it in context, and use the remediation guidance.
7. Download JSON or HTML from the scan details page.

The scanner limits page count, request count, response size, time, concurrency, and supported ports. It only follows same-origin redirects and discovered same-origin links. Form contents are never submitted. Do not scan a third-party site without permission.

## Free intelligence sources

### OSV.dev

OSV.dev is used for a user-submitted package name, exact version, and ecosystem. It doesn't require an API key. Results are supplemental vulnerability records, not proof that a live website uses or is vulnerable to a package.

Open **Package lookup** and submit the package identity and version you already know. Supported ecosystems are listed in the selector.

Official API documentation: https://google.github.io/osv.dev/api/

### AlienVault OTX (optional)

OTX is disabled unless both a key is configured and enrichment is enabled. Check its current terms, access requirements, and quotas before use. No key is bundled with KlyPen.

Add the values to the root `.env` file:

```dotenv
OTX_API_KEY=your_own_key_here
KLYPEN_OTX_ENABLED=true
```

Restart KlyPen after editing `.env`. The configured hostname may be sent to OTX for a reputation lookup; target page contents, cookies, and authorization headers are not sent. A match may be stale and no match is not proof of safety.

## Local demo lab (optional)

The demo lab contains intentionally simplified examples that can produce passive findings. It binds only to loopback and does not use real credentials. It is disabled for scanning by default.

1. In the root `.env`, set:

   ```dotenv
   KLYPEN_LAB_ENABLED=true
   ```

2. Restart the KlyPen dashboard/backend so the setting is loaded.
3. Open another PowerShell window in the project root and run:

   ```powershell
   .\.venv\Scripts\python.exe -m backend.lab.app
   ```

4. From KlyPen, scan `http://127.0.0.1:9001/` and confirm authorization. Only the exact local lab origin at port 9001 is exempted from the normal private-address block.
5. Stop the lab using `Ctrl+C`, then set `KLYPEN_LAB_ENABLED=false` and restart KlyPen when finished.

Do not expose the lab or KlyPen on a LAN or public interface.

## Configuration

Copy `.env.example` to `.env`. Defaults are deliberately bounded.

| Variable | Default | Purpose |
| --- | --- | --- |
| `KLYPEN_DB_PATH` | `./data/klypen.db` | SQLite database path |
| `KLYPEN_MAX_PAGES` | `20` | Maximum crawl pages (server cap: 100) |
| `KLYPEN_MAX_REQUESTS` | `40` | Maximum target requests (server cap: 200) |
| `KLYPEN_MAX_SCAN_SECONDS` | `90` | Maximum scan duration (server cap: 300 seconds) |
| `KLYPEN_REQUEST_TIMEOUT` | `8` | Per-request timeout (server cap: 20 seconds) |
| `KLYPEN_LAB_ENABLED` | `false` | Enables only the exact local lab exception at port 9001 |
| `KLYPEN_OTX_ENABLED` | `false` | Allows optional OTX enrichment when a key exists |
| `OTX_API_KEY` | empty | Optional OTX API key; keep private |

The application loads `.env` from the project root. Never commit `.env`, API credentials, scan databases, or reports containing sensitive target details.

## API

FastAPI interactive docs are available locally at `http://127.0.0.1:8000/docs`.

Main endpoints:

- `GET /api/v1/health`
- `GET /api/v1/settings`
- `GET /api/v1/providers`
- `GET /api/v1/scans`
- `POST /api/v1/scans` — requires an explicit `authorized: true` confirmation
- `GET /api/v1/scans/{id}`
- `GET /api/v1/scans/{id}/events` — Server-Sent Events
- `POST /api/v1/scans/{id}/cancel`
- `GET /api/v1/findings`
- `POST /api/v1/intelligence/osv`
- `POST /api/v1/intelligence/otx`
- `GET /api/v1/reports/{id}/json`
- `GET /api/v1/reports/{id}/html`

The process binds to loopback by default. It also rejects unexpected Host headers and non-loopback clients. Do not put it behind a public reverse proxy without separately reviewing the network trust model and access controls.

## Tests

From the project root:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s backend/tests -t .
```

Or on macOS/Linux:

```bash
.venv/bin/python -m unittest discover -s backend/tests -t .
```

The tests do not scan public websites and do not require live API calls. They check URL scope rules, redaction, check logic, and API safety basics.

If Node.js is installed, validate the frontend JavaScript syntax:

```bash
node --check backend/static/app.js
```

## Architecture

```text
Browser
  └── FastAPI local server
      ├── Static dashboard (HTML/CSS/JS)
      ├── Versioned API + SSE progress
      ├── Scanner scope validation
      ├── Pinned-IP HTTP client (normal TLS verification)
      ├── Passive checks + bounded same-origin crawler
      ├── SQLite scan and finding storage
      └── Optional providers: OSV.dev / AlienVault OTX
```

The UI has no external font or script dependencies. OSV and OTX are optional external services and may be unavailable; local scan checks continue without them.

## Known limitations

- This is a pragmatic MVP, not a replacement for a dedicated professional assessment.
- Passive detection has false positives and false negatives.
- Framework/package versions are not inferred from banners for vulnerability reporting. Use Package lookup with an identified dependency/version.
- CORS is classified conservatively; a wildcard CORS header alone is informational.
- Source-map references are detected from page markup, but KlyPen does not fetch arbitrary referenced source maps.
- The current release does not implement login testing, form submission, exploit validation, or active vulnerability payloads.
- The score is a simple heuristic and is not a recognized compliance or security rating.

## Responsible use

Use KlyPen only on systems you own or have explicit permission to assess. Keep the service bound to localhost, avoid sending sensitive URLs or query tokens, and protect any report that contains internal hostnames or application details.
