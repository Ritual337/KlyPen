"""HTTP transport that connects only to validated, pinned IP addresses.

TLS verification and SNI use the original hostname even though the TCP
connection goes to the pinned IP. Redirects are followed manually and every
hop is scope-checked and re-resolved/revalidated.
"""
from __future__ import annotations

import http.client
import socket
import ssl
import time
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from .scope import Policy, Resolver, Scope, TargetError, default_resolver, normalize_url, resolve_and_validate


class FetchError(Exception):
    pass


@dataclass
class Response:
    url: str
    status: int
    headers: list[tuple[str, str]]
    body: bytes
    truncated: bool
    peer_ip: str
    redirects: list[str] = field(default_factory=list)

    def header_all(self, name: str) -> list[str]:
        return [v for k, v in self.headers if k.lower() == name.lower()]

    def header(self, name: str) -> str | None:
        vals = self.header_all(name)
        return vals[0] if vals else None


def _connect_pinned(ips: list[str], port: int, timeout: float) -> tuple[socket.socket, str]:
    last: Exception | None = None
    for ip in ips:
        try:
            return socket.create_connection((ip, port), timeout), ip
        except OSError as exc:
            last = exc
    raise FetchError(f"connection failed: {last}")


class _HTTP(http.client.HTTPConnection):
    def __init__(self, host, port, ips, timeout):
        super().__init__(host, port, timeout=timeout)
        self._ips = ips
        self.peer_ip = ""

    def connect(self):
        self.sock, self.peer_ip = _connect_pinned(self._ips, self.port, self.timeout)


class _HTTPS(http.client.HTTPSConnection):
    def __init__(self, host, port, ips, timeout, context):
        super().__init__(host, port, timeout=timeout, context=context)
        self._ips = ips
        self.peer_ip = ""

    def connect(self):
        raw, self.peer_ip = _connect_pinned(self._ips, self.port, self.timeout)
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)


class SafeClient:
    def __init__(self, scope: Scope, policy: Policy | None = None, *, resolver: Resolver = default_resolver,
                 max_redirects: int = 3, max_bytes: int = 1_000_000, timeout: float = 8.0,
                 deadline: float | None = None, min_interval: float = 0.0, max_requests: int = 200,
                 ssl_context: ssl.SSLContext | None = None):
        self.scope, self.policy, self.resolver = scope, policy or Policy(), resolver
        self.max_redirects, self.max_bytes, self.timeout = max_redirects, max_bytes, timeout
        self.deadline, self.min_interval, self.max_requests = deadline, min_interval, max_requests
        self.request_count = 0
        self._last = 0.0
        self._ctx = ssl_context or ssl.create_default_context()

    def _budget(self) -> float:
        if self.request_count >= self.max_requests:
            raise FetchError("request budget exhausted")
        now = time.monotonic()
        if self.deadline is not None and now >= self.deadline:
            raise FetchError("scan deadline exceeded")
        wait = self._last + self.min_interval - now
        if wait > 0:
            time.sleep(wait)
        self._last = time.monotonic()
        self.request_count += 1
        remaining = (self.deadline - time.monotonic()) if self.deadline else self.timeout
        return max(0.1, min(self.timeout, remaining))

    def fetch(self, url: str, method: str = "GET") -> Response:
        if method not in ("GET", "HEAD", "OPTIONS"):
            raise FetchError("method not allowed")
        chain: list[str] = []
        current = normalize_url(url)
        for _ in range(self.max_redirects + 1):
            if not self.scope.contains(current):
                raise TargetError(f"out of scope: {current}")
            resp = self._once(current, method, self._budget())
            resp.redirects = list(chain)
            loc = resp.header("Location")
            if resp.status in (301, 302, 303, 307, 308) and loc:
                nxt = self.scope.join(current, loc)
                if nxt is None:
                    raise TargetError("redirect leaves scope or is invalid")
                chain.append(nxt)
                current = nxt
                continue
            return resp
        raise FetchError("too many redirects")

    def _once(self, url: str, method: str, timeout: float) -> Response:
        p = urlsplit(url)
        host, https = p.hostname or "", p.scheme == "https"
        port = p.port or (443 if https else 80)
        ips = resolve_and_validate(host, port, self.policy, self.resolver)  # fresh, per hop
        conn = _HTTPS(host, port, ips, timeout, self._ctx) if https else _HTTP(host, port, ips, timeout)
        started = time.monotonic()
        try:
            path = (p.path or "/") + (f"?{p.query}" if p.query else "")
            conn.request(method, path, headers={"User-Agent": "KlyPen/0.1 (+authorized assessment)",
                                                 "Accept": "*/*", "Connection": "close"})
            r = conn.getresponse()
            body, truncated = b"", False
            if method != "HEAD":
                chunks, size = [], 0
                while True:
                    if time.monotonic() - started > timeout * 2:
                        raise FetchError("response took too long")
                    chunk = r.read(8192)
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > self.max_bytes:
                        chunks.append(chunk[: len(chunk) - (size - self.max_bytes)])
                        truncated = True
                        break
                    chunks.append(chunk)
                body = b"".join(chunks)
            return Response(url, r.status, r.getheaders(), body, truncated, conn.peer_ip)
        except (OSError, http.client.HTTPException, ssl.SSLError) as exc:
            raise FetchError(f"request failed: {type(exc).__name__}: {exc}") from exc
        finally:
            conn.close()
