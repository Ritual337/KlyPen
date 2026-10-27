# KlyPen implementation status

## Implemented in this package

- Local-only FastAPI application and dashboard served from the same origin.
- SQLite scan/finding persistence.
- URL normalization, origin constraints, loopback/private/reserved IP rejection, supported-port allowlist, and explicit local demo-lab exception disabled by default.
- Pinned-IP HTTP requests with normal TLS verification, manual same-origin redirect handling, response-size limits, and bounded request/time/page limits.
- Passive response-header, cookie, CORS-indicator, mixed-content, password-form transport, and visible source-map-reference checks.
- Scan status, cancellation, SSE progress, findings browsing, score summary, and JSON/HTML report exports.
- Optional OSV.dev package/version lookup with response limits and in-memory caching.
- Optional AlienVault OTX domain enrichment, disabled unless explicitly configured.
- Local demo lab, unit/API tests, PowerShell and shell launchers, CI workflow, and documentation.

## Not implemented / limitations

- No active exploit tests, authentication testing, form submissions, or state-changing checks.
- No deep JavaScript analysis or source-map fetching.
- No external web crawling or third-party origins.
- OTX endpoints and credentials are optional; availability depends on the provider and account configuration.
- Tests are local-only and do not certify behavior across all target servers.

## Verification status (executed during packaging)

- `python -m unittest discover -s backend/tests -t .`: **31 tests passed**.
- `node --check backend/static/app.js`: passed.
- `python -m compileall -q backend`: passed.
- Local integration smoke test against the included loopback lab: completed a real scan across two local pages, generated findings, and returned JSON and HTML report responses.

These checks were executed in the packaging environment. They do not replace testing on the user's machine or prove coverage across all production servers.
