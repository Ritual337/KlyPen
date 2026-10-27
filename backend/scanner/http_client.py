from __future__ import annotations

import asyncio
import socket
import ssl
from typing import Any
from urllib.parse import urljoin

import aiohttp
from aiohttp.abc import AbstractResolver

from .scope import ScopeError, Target, normalize_and_validate, resolve_pinned

MAX_RESPONSE_BYTES = 1_000_000


class PinnedResolver(AbstractResolver):
    """Resolver returning only IPs vetted immediately before the request.

    TLS still uses the original URL hostname, so certificate validation and SNI
    are performed against the proper hostname by aiohttp.
    """
    def __init__(self, hostname: str, pins: list[tuple[int, str]]):
        self.hostname = hostname
        self.pins = pins

    async def resolve(self, host: str, port: int = 0, family: int = socket.AF_INET) -> list[dict[str, Any]]:
        if host.lower().rstrip(".") != self.hostname.lower().rstrip("."):
            raise OSError("Unexpected hostname requested from pinned resolver")
        return [{"hostname": host, "host": ip, "port": port, "family": fam, "proto": 0, "flags": 0}
                for fam, ip in self.pins if family in (socket.AF_UNSPEC, fam)]

    async def close(self) -> None:
        return None


async def safe_request(url: str, *, method: str = "GET", timeout: float = 8.0,
                       max_bytes: int = MAX_RESPONSE_BYTES, lab: bool = False) -> dict[str, Any]:
    if method not in {"GET", "HEAD", "OPTIONS"}:
        raise ValueError("Only GET, HEAD, and OPTIONS are allowed")
    target = normalize_and_validate(url)
    pins = resolve_pinned(target.hostname, target.port, target.is_lab)
    resolver = PinnedResolver(target.hostname, pins)
    timeout_cfg = aiohttp.ClientTimeout(total=timeout, connect=min(timeout, 4.0), sock_read=timeout)
    connector = aiohttp.TCPConnector(resolver=resolver, use_dns_cache=False, ssl=ssl.create_default_context(), limit=1, family=socket.AF_UNSPEC)
    headers = {"User-Agent": "KlyPen/1.0 (+local authorized security assessment)", "Accept": "text/html,application/xhtml+xml,application/json,text/plain,*/*;q=0.5"}
    try:
        async with aiohttp.ClientSession(connector=connector, timeout=timeout_cfg, headers=headers, trust_env=False, auto_decompress=True) as session:
            async with session.request(method, target.url, allow_redirects=False, max_line_size=8190, max_field_size=8190) as response:
                chunks = bytearray()
                if method != "HEAD":
                    async for chunk in response.content.iter_chunked(16384):
                        if len(chunks) + len(chunk) > max_bytes:
                            chunks.extend(chunk[: max_bytes - len(chunks)])
                            break
                        chunks.extend(chunk)
                try:
                    body = chunks.decode(response.charset or "utf-8", errors="replace")
                except LookupError:
                    body = chunks.decode("utf-8", errors="replace")
                return {
                    "url": str(response.url), "status": response.status,
                    "headers": {**{k.lower(): v[:2000] for k, v in response.headers.items() if k.lower() != "set-cookie"}, **({"set-cookie": "\n".join(v[:2000] for v in response.headers.getall("Set-Cookie", []))[:10000]} if response.headers.getall("Set-Cookie", []) else {})},
                    "body": body, "bytes_read": len(chunks),
                    "truncated": len(chunks) >= max_bytes,
                    "content_type": response.headers.get("Content-Type", ""),
                    "history": [],
                }
    except asyncio.TimeoutError as exc:
        raise TimeoutError("Request timed out") from exc
    except aiohttp.ClientSSLError as exc:
        raise ssl.SSLError(f"TLS validation failed: {str(exc)[:200]}") from exc
    except aiohttp.ClientError as exc:
        raise OSError(f"HTTP request failed: {str(exc)[:250]}") from exc


async def safe_fetch_with_redirects(url: str, *, max_redirects: int = 5, timeout: float = 8.0,
                                    max_bytes: int = MAX_RESPONSE_BYTES) -> dict[str, Any]:
    current = url
    history: list[dict[str, Any]] = []
    first = normalize_and_validate(url)
    for hop in range(max_redirects + 1):
        target = normalize_and_validate(current)
        if (target.scheme, target.hostname, target.port) != (first.scheme, first.hostname, first.port):
            raise ScopeError("Cross-origin redirect blocked; scanner stays within the explicitly authorized origin.")
        result = await safe_request(current, timeout=timeout, max_bytes=max_bytes)
        result["history"] = history
        if result["status"] not in {301, 302, 303, 307, 308}:
            return result
        location = result["headers"].get("location")
        if not location:
            return result
        history.append({"status": result["status"], "url": current})
        if hop >= max_redirects:
            raise RuntimeError("Redirect limit exceeded")
        current = urljoin(current, location)
        next_target = normalize_and_validate(current)
        if (next_target.scheme, next_target.hostname, next_target.port) != (first.scheme, first.hostname, first.port):
            raise ScopeError("Cross-origin redirect blocked")
    raise RuntimeError("Redirect limit exceeded")
