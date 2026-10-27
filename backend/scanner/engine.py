from __future__ import annotations

import asyncio
import os
import socket
from collections import deque
from urllib.parse import urljoin, urlsplit, urlunsplit

from ..checks.cookies import check_cookies
from ..checks.cors import check_cors
from ..checks.headers import check_headers
from ..checks.html_checks import inspect_html
from ..checks.tls import inspect_tls
from ..db import now, update_scan, add_findings
from ..providers.otx import lookup_domain
from .findings import deduplicate, make_finding, score
from .http_client import safe_fetch_with_redirects
from .scope import ScopeError, Target, normalize_and_validate, redact_url


def _progress(scan_id: str, *, stage: str, progress: int, pages: int, requests: int) -> None:
    update_scan(scan_id, stage=stage, progress=max(0, min(progress, 99)), pages_scanned=pages, requests_made=requests)


def _origin_parts(url: str) -> tuple[str, str, int]:
    p = urlsplit(url)
    return p.scheme.lower(), (p.hostname or "").lower().rstrip("."), p.port or (443 if p.scheme.lower() == "https" else 80)


def _canonical(url: str) -> str:
    p = urlsplit(url)
    return urlunsplit((p.scheme.lower(), p.netloc.lower(), p.path or "/", p.query, ""))


async def run_scan(scan_id: str, raw_url: str) -> None:
    started = now()
    update_scan(scan_id, status="running", started_at=started, stage="validating", progress=1)
    max_pages = max(1, min(int(os.getenv("KLYPEN_MAX_PAGES", "20")), 100))
    max_requests = max(1, min(int(os.getenv("KLYPEN_MAX_REQUESTS", "40")), 200))
    max_seconds = max(10, min(int(os.getenv("KLYPEN_MAX_SCAN_SECONDS", "90")), 300))
    timeout = max(2, min(float(os.getenv("KLYPEN_REQUEST_TIMEOUT", "8")), 20))
    findings: list[dict] = []
    errors: list[str] = []
    seen_findings: set[tuple] = set()
    pages_scanned = 0
    requests_made = 0
    enrichment: list[dict] = []
    started_clock = asyncio.get_running_loop().time()

    async def record(incoming: list[dict]) -> None:
        safe_incoming = []
        for original in incoming:
            f = dict(original)
            f["url"] = redact_url(f.get("url", ""))
            safe_incoming.append(f)
        for f in deduplicate(safe_incoming):
            key = (f.get("title"), f.get("url"), f.get("category"))
            if key in seen_findings:
                continue
            seen_findings.add(key)
            findings.append(f)
            add_findings(scan_id, [f])

    try:
        target = normalize_and_validate(raw_url)
        _progress(scan_id, stage="TLS inspection", progress=3, pages=0, requests=0)
        tls = await inspect_tls(target)
        if target.scheme == "https" and tls.get("valid") is True and isinstance(tls.get("days_until_expiry"), int) and tls["days_until_expiry"] <= 30:
            remaining_days = tls["days_until_expiry"]
            await record([make_finding(title="TLS certificate expires soon", category="tls", severity="medium" if remaining_days <= 7 else "low", confidence="high",
                url=target.url, description="The certificate passed normal validation, but its reported expiration is within 30 days.",
                evidence={"days_until_expiry": remaining_days, "expires_at": tls.get("expires_at")},
                remediation="Renew the certificate before its expiration and verify that automated renewal is working.",
                references=["https://developer.mozilla.org/en-US/docs/Web/Security/Transport_Layer_Security"])])
        if target.scheme == "https" and tls.get("valid") is False:
            await record([make_finding(title="TLS certificate validation failed", category="tls", severity="high", confidence="high",
                url=target.url, description="The TLS handshake could not be validated using the platform trust store. The scan will not disable certificate verification to continue.",
                evidence={"error": tls.get("error", "TLS verification failed")}, remediation="Install a valid certificate for this hostname, ensure the full certificate chain is served, and check hostname matching.",
                references=["https://developer.mozilla.org/en-US/docs/Web/Security/Transport_Layer_Security"])])
            errors.append("TLS validation failed; page crawling was stopped to preserve certificate verification.")
        else:
            if target.scheme == "http":
                await record([make_finding(title="Target uses unencrypted HTTP", category="transport-security", severity="medium", confidence="high",
                    url=target.url, description="The requested page is served over HTTP, so the connection does not provide TLS confidentiality or integrity.",
                    evidence={"scheme": "http"}, remediation="Serve the site over HTTPS and redirect HTTP requests to HTTPS where appropriate.",
                    references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Overview"])])
            queue = deque([target.url])
            visited: set[str] = set()
            while queue and pages_scanned < max_pages and requests_made < max_requests:
                if asyncio.get_running_loop().time() - started_clock > max_seconds:
                    errors.append("Maximum scan duration reached; remaining pages were skipped.")
                    break
                current = queue.popleft()
                canonical = _canonical(current)
                if canonical in visited:
                    continue
                visited.add(canonical)
                try:
                    curr_target = normalize_and_validate(current)
                    if _origin_parts(current) != _origin_parts(target.url):
                        continue
                    remaining = max_requests - requests_made
                    result = await safe_fetch_with_redirects(current, max_redirects=max(0, min(4, remaining - 1)), timeout=timeout, max_bytes=1_000_000)
                    requests_made += len(result.get("history", [])) + 1
                    pages_scanned += 1
                    response_url = result["url"]
                    headers = result["headers"]
                    if "set-cookie" in headers:
                        # aiohttp's response object is converted to a dict; values are redacted in all stored evidence.
                        pass
                    await record(check_headers(response_url, headers, is_https=curr_target.scheme == "https"))
                    await record(check_cookies(response_url, headers, is_https=curr_target.scheme == "https"))
                    await record(check_cors(response_url, headers))
                    links: list[str] = []
                    if "html" in result.get("content_type", "").lower() or "<html" in result.get("body", "")[:500].lower():
                        html_findings, links = inspect_html(response_url, result.get("body", ""), is_https=curr_target.scheme == "https")
                        await record(html_findings)
                    for link in links:
                        if _origin_parts(link) != _origin_parts(target.url):
                            continue
                        cp = urlsplit(link)
                        if cp.path.lower().endswith(('.png','.jpg','.jpeg','.gif','.webp','.svg','.ico','.woff','.woff2','.ttf','.css','.mp4','.mp3','.pdf','.zip','.gz')):
                            continue
                        cand = _canonical(link)
                        if cand not in visited and len(queue) + pages_scanned < max_pages * 3:
                            queue.append(cand)
                except asyncio.CancelledError:
                    raise
                except (ScopeError, TimeoutError, OSError, RuntimeError, ValueError) as exc:
                    errors.append(f"{redact_url(current)}: {str(exc)[:220]}")
                _progress(scan_id, stage="Crawling and passive checks", progress=min(95, 5 + int(90 * pages_scanned / max_pages)), pages=pages_scanned, requests=requests_made)

            # Optional reputation lookup is limited to the target hostname and never changes core scan success.
            otx_enabled = os.getenv("KLYPEN_OTX_ENABLED", "false").lower() == "true" and bool(os.getenv("OTX_API_KEY", "").strip())
            try:
                import ipaddress
                hostname_is_ip = bool(ipaddress.ip_address(target.hostname))
            except ValueError:
                hostname_is_ip = False
            if otx_enabled and not target.is_lab and not hostname_is_ip:
                try:
                    intel = await asyncio.wait_for(lookup_domain(target.hostname), timeout=14)
                    enrichment.append(intel)
                    if intel.get("pulse_count", 0) > 0:
                        await record([make_finding(title="Supplemental threat-intelligence references exist for this domain", category="threat-intelligence", severity="info", confidence="low",
                            url=target.url, description="The configured provider reports one or more intelligence pulses associated with this domain. This can be stale or context-dependent and is not proof of malicious activity.",
                            evidence={"provider": "AlienVault OTX", "pulse_count": intel.get("pulse_count")}, remediation="Review provider references and corroborate independently before drawing conclusions.", source="external", references=["https://otx.alienvault.com/"])])
                except Exception as exc:
                    errors.append(f"Optional AlienVault OTX enrichment unavailable: {str(exc)[:180]}")

        findings = deduplicate(findings)
        summary = score(findings)
        summary.update({"target": target.origin, "pages_scanned": pages_scanned, "requests_made": requests_made,
                        "checks": ["TLS certificate validation", "security headers", "cookies", "CORS response indicators", "forms", "mixed content", "source-map references"],
                        "tls": tls, "enrichment": enrichment, "limitations": ["Passive, bounded assessment only; not a comprehensive penetration test.",
                        "A high score does not prove security.", "No state-changing actions, form submissions, brute force, or exploit attempts were performed."]})
        has_tls_failure = target.scheme == "https" and tls.get("valid") is False
        final_status = "completed" if pages_scanned > 0 or has_tls_failure else "failed"
        final_stage = "completed" if final_status == "completed" else "failed"
        if final_status == "failed" and not errors:
            errors.append("No target pages could be scanned; check reachability and DNS resolution.")
        update_scan(scan_id, status=final_status, completed_at=now(), stage=final_stage, progress=100,
                    pages_scanned=pages_scanned, requests_made=requests_made, summary_json=summary, errors_json=errors)
    except asyncio.CancelledError:
        update_scan(scan_id, status="cancelled", completed_at=now(), stage="cancelled", progress=0,
                    pages_scanned=pages_scanned, requests_made=requests_made, summary_json=score(findings), errors_json=errors + ["Scan cancelled by user."])
        raise
    except Exception as exc:
        errors.append(str(exc)[:350])
        update_scan(scan_id, status="failed", completed_at=now(), stage="failed", progress=100,
                    pages_scanned=pages_scanned, requests_made=requests_made, summary_json=score(findings), errors_json=errors)
