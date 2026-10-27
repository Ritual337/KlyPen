# KlyPen build status

## Implemented and tested (stdlib + bs4 only; `cd backend && python -m unittest discover -s tests -t .`)
- `scanner/scope.py`: strict URL normalisation, IPv4/IPv6/mapped/6to4 blocking, metadata blocking,
  numeric-hostname rejection, per-address DNS validation, origin scope enforcement.
- `scanner/http_client.py`: connects only to validated pinned IPs (TLS/SNI use the real hostname),
  manual redirects with per-hop scope check + re-resolution, size/time/request/rate limits, GET/HEAD/OPTIONS only.
- `scanner/findings.py`: finding schema with automatic secret redaction.
- `checks/headers.py`, `checks/cookies.py`: proportionate severity; cookie values never stored.
- 21 tests incl. rebinding, redirect-to-metadata, size limit, timeout, budget, redaction.

## NOT implemented (do not treat as done)
Crawler, remaining checks (TLS cert, CORS, forms/HTML, mixed content, source maps, public-config allowlist),
active-check module, scan engine/scoring, SQLAlchemy models + Alembic, FastAPI API + SSE + cancellation + auth,
reports, React frontend, lab fixture app, Docker, GitHub Actions, README/SECURITY/CONTRIBUTING/LICENSE.

## Not verified here
The sandbox has no network, so FastAPI/httpx/SQLAlchemy/pytest/ruff were never installed or run, and TLS
verification against a real HTTPS host was not exercised.
