from __future__ import annotations

import asyncio
import datetime
import socket
import ssl
from typing import Any

from ..scanner.scope import Target, resolve_pinned


def _inspect(target: Target) -> dict[str, Any]:
    pins = resolve_pinned(target.hostname, target.port, target.is_lab)
    if target.scheme != "https":
        return {"https": False, "valid": None, "error": "Target uses HTTP, so a TLS certificate is not applicable."}
    context = ssl.create_default_context()
    last_error = None
    for _family, ip in pins:
        try:
            raw = socket.create_connection((ip, target.port), timeout=5)
            try:
                with context.wrap_socket(raw, server_hostname=target.hostname) as tls:
                    cert = tls.getpeercert()
                    expiry = cert.get("notAfter")
                    expires_at = ssl.cert_time_to_seconds(expiry) if expiry else None
                    days = None
                    if expires_at is not None:
                        days = int((datetime.datetime.fromtimestamp(expires_at, datetime.timezone.utc) - datetime.datetime.now(datetime.timezone.utc)).total_seconds() // 86400)
                    return {"https": True, "valid": True, "tls_version": tls.version(), "cipher": tls.cipher()[0] if tls.cipher() else None,
                            "expires_at": expiry, "days_until_expiry": days}
            finally:
                try: raw.close()
                except Exception: pass
        except (OSError, ssl.SSLError, TimeoutError) as exc:
            last_error = str(exc)[:240]
    return {"https": True, "valid": False, "error": last_error or "TLS validation failed"}


async def inspect_tls(target: Target) -> dict[str, Any]:
    return await asyncio.to_thread(_inspect, target)
