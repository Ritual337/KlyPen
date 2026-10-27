from __future__ import annotations

import asyncio
import html
import json
import os
import time
import uuid
from contextlib import asynccontextmanager
from dotenv import load_dotenv
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parent
load_dotenv(ROOT.parent / ".env")

from . import db
from .providers import osv, otx
from .providers.registry import all_statuses
from .scanner.engine import run_scan
from .scanner.scope import ScopeError, normalize_and_validate, redact_url

TASKS: dict[str, asyncio.Task] = {}
_LAST_SCAN_AT = 0.0


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init_db()
    yield
    for task in list(TASKS.values()):
        if not task.done():
            task.cancel()
    if TASKS:
        await asyncio.gather(*TASKS.values(), return_exceptions=True)


app = FastAPI(title="KlyPen API", version="1.0.0", description="Local-first authorized web security assessment", lifespan=lifespan)


@app.middleware("http")
async def local_only_guard(request: Request, call_next):
    # Local-first safety: the server rejects non-loopback clients and unexpected Host/Origin headers.
    client = request.client.host if request.client else ""
    if client not in {"127.0.0.1", "::1", "localhost", "testclient"}:
        return JSONResponse({"detail": "KlyPen is configured for local access only."}, status_code=403)
    host_header = request.headers.get("host", "127.0.0.1").lower()
    host_name = host_header.split(":", 1)[0].strip("[]")
    if host_name not in {"127.0.0.1", "localhost", "::1", "testserver"}:
        return JSONResponse({"detail": "Unexpected Host header."}, status_code=400)
    origin = request.headers.get("origin")
    if origin and request.method.upper() in {"POST", "PUT", "PATCH", "DELETE"}:
        parsed = urlsplit(origin)
        if parsed.scheme not in {"http", "https"} or parsed.hostname not in {"127.0.0.1", "localhost", "::1"} or parsed.netloc.lower() != host_header.lower():
            return JSONResponse({"detail": "Cross-origin state-changing requests are blocked."}, status_code=403)
    return await call_next(request)


class ScanCreate(BaseModel):
    url: str = Field(min_length=1, max_length=2048)
    authorized: bool


class OsvQuery(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    version: str = Field(min_length=1, max_length=100)
    ecosystem: str = Field(min_length=1, max_length=40)


class OtxQuery(BaseModel):
    domain: str = Field(min_length=1, max_length=253)


@app.get("/api/v1/health")
def health():
    return {"status": "ok", "app": "KlyPen", "version": "1.0.0", "mode": "local-only"}


@app.get("/api/v1/settings")
def settings():
    return {"mode": "local-only", "lab_enabled": os.getenv("KLYPEN_LAB_ENABLED", "false").lower() == "true",
            "max_pages": max(1, min(int(os.getenv("KLYPEN_MAX_PAGES", "20")), 100)),
            "max_requests": max(1, min(int(os.getenv("KLYPEN_MAX_REQUESTS", "40")), 200)),
            "max_scan_seconds": max(10, min(int(os.getenv("KLYPEN_MAX_SCAN_SECONDS", "90")), 300)),
            "timeout_seconds": max(2, min(float(os.getenv("KLYPEN_REQUEST_TIMEOUT", "8")), 20)),
            "external_enrichment": os.getenv("KLYPEN_OTX_ENABLED", "false").lower() == "true"}


@app.get("/api/v1/providers")
def providers():
    return {"providers": all_statuses()}


@app.get("/api/v1/scans")
def scans(limit: int = 50):
    return {"scans": db.list_scans(limit)}


@app.get("/api/v1/findings")
def findings(limit: int = 500):
    return {"findings": db.list_findings(limit)}


@app.post("/api/v1/scans", status_code=202)
async def create_scan(payload: ScanCreate):
    global _LAST_SCAN_AT
    if not payload.authorized:
        raise HTTPException(status_code=400, detail="Confirm that you own the target or have explicit permission to assess it.")
    active = [t for t in TASKS.values() if not t.done()]
    if len(active) >= 2:
        raise HTTPException(status_code=429, detail="At most two scans can run at once.")
    if time.monotonic() - _LAST_SCAN_AT < 1.0:
        raise HTTPException(status_code=429, detail="Please wait a moment before starting another scan.")
    try:
        target = normalize_and_validate(payload.url)
    except ScopeError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    _LAST_SCAN_AT = time.monotonic()
    scan_id = str(uuid.uuid4())
    db.create_scan(scan_id, redact_url(target.url), target.origin)
    task = asyncio.create_task(run_scan(scan_id, target.url), name=f"klypen-scan-{scan_id}")
    TASKS[scan_id] = task
    task.add_done_callback(lambda _task, sid=scan_id: TASKS.pop(sid, None))
    db.delete_oldest_scans(200)
    return {"id": scan_id, "status": "queued", "url": redact_url(target.url), "origin": target.origin}


@app.get("/api/v1/scans/{scan_id}")
def scan_detail(scan_id: str):
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return scan


@app.post("/api/v1/scans/{scan_id}/cancel")
async def cancel_scan(scan_id: str):
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")
    task = TASKS.get(scan_id)
    if task and not task.done():
        task.cancel()
        try:
            await asyncio.wait_for(asyncio.shield(task), timeout=1.5)
        except (asyncio.CancelledError, asyncio.TimeoutError):
            pass
    return db.get_scan(scan_id)


@app.get("/api/v1/scans/{scan_id}/events")
async def scan_events(scan_id: str, request: Request):
    if not db.get_scan(scan_id):
        raise HTTPException(status_code=404, detail="Scan not found.")

    async def event_stream():
        sequence = 0
        previous = None
        while not await request.is_disconnected():
            item = db.get_scan(scan_id)
            if item is None:
                yield "event: error\ndata: {\"message\":\"Scan not found\"}\n\n"
                return
            payload = {k: item.get(k) for k in ("id", "status", "stage", "progress", "pages_scanned", "requests_made", "summary", "errors")}
            encoded = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
            if encoded != previous:
                sequence += 1
                yield f"id: {sequence}\nevent: progress\ndata: {encoded}\n\n"
                previous = encoded
            elif sequence == 0:
                yield ": connected\n\n"
            if item["status"] in {"completed", "failed", "cancelled"}:
                return
            await asyncio.sleep(0.9)
    return StreamingResponse(event_stream(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.post("/api/v1/intelligence/osv")
async def osv_lookup(payload: OsvQuery):
    try:
        return await asyncio.wait_for(osv.query_package(payload.name, payload.version, payload.ecosystem), timeout=15)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"OSV.dev lookup unavailable: {str(exc)[:200]}") from exc


@app.post("/api/v1/intelligence/otx")
async def otx_lookup(payload: OtxQuery):
    try:
        return await asyncio.wait_for(otx.lookup_domain(payload.domain), timeout=16)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"OTX lookup unavailable: {str(exc)[:200]}") from exc


@app.get("/api/v1/reports/{scan_id}/json")
def report_json(scan_id: str):
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return JSONResponse(scan, headers={"Content-Disposition": f'attachment; filename="klypen-{scan_id[:8]}.json"'})


@app.get("/api/v1/reports/{scan_id}/html")
def report_html(scan_id: str):
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")
    esc = lambda value: html.escape(str(value if value is not None else ""))
    summary = scan.get("summary") or {}
    cards = "".join(f'<tr><td>{esc(f.get("severity"))}</td><td>{esc(f.get("title"))}</td><td>{esc(f.get("url"))}</td><td>{esc(f.get("description"))}<br><strong>Fix:</strong> {esc(f.get("remediation"))}<br><code>{esc(json.dumps(f.get("evidence", {}), ensure_ascii=False))}</code></td></tr>' for f in scan.get("findings", []))
    doc = f'''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>KlyPen Report</title><style>body{{font:15px system-ui;max-width:1120px;margin:40px auto;padding:0 20px;color:#19232e}}h1{{font-size:32px}}.muted{{color:#64748b}}table{{width:100%;border-collapse:collapse}}td,th{{padding:12px;border-bottom:1px solid #ddd;text-align:left;vertical-align:top;overflow-wrap:anywhere}}code{{white-space:pre-wrap}}.score{{font-size:28px;font-weight:700}}</style><h1>KlyPen Security Assessment</h1><p class="muted">Generated {esc(db.now()) if hasattr(db,'now') else ''}</p><p><strong>Target:</strong> {esc(scan.get('origin'))}</p><p><strong>Status:</strong> {esc(scan.get('status'))}</p><p class="score">Risk indicator: {esc(summary.get('score','N/A'))}/100</p><p>{esc(summary.get('explanation',''))}</p><p>Pages: {esc(scan.get('pages_scanned'))} · Requests: {esc(scan.get('requests_made'))}</p><h2>Findings ({len(scan.get('findings', []))})</h2><table><thead><tr><th>Severity</th><th>Finding</th><th>URL</th><th>Details</th></tr></thead><tbody>{cards or '<tr><td colspan="4">No findings recorded.</td></tr>'}</tbody></table><h2>Limitations</h2><p>This is a bounded passive assessment, not proof of security. Verify findings in context. No exploit attempts or state-changing form submissions were performed.</p></html>'''
    return HTMLResponse(doc, headers={"Content-Disposition": f'attachment; filename="klypen-{scan_id[:8]}.html"'})


STATIC = ROOT / "static"
app.mount("/static", StaticFiles(directory=STATIC), name="static")


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(STATIC / "index.html")
