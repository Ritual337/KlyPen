"""Target validation and scope enforcement (SSRF defence).

Client-side validation is never trusted; every URL the scanner touches goes
through normalize_url() + resolve_and_validate() immediately before connecting.
"""
from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass
from typing import Callable
from urllib.parse import urljoin, urlsplit, urlunsplit

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
Resolver = Callable[[str, int], list[str]]


class TargetError(ValueError):
    """Raised when a URL or destination is not allowed."""


METADATA_HOSTS = {"metadata.google.internal", "metadata.goog", "instance-data", "localhost"}
METADATA_IPS = {
    ipaddress.ip_address("169.254.169.254"),
    ipaddress.ip_address("169.254.170.2"),
    ipaddress.ip_address("100.100.100.200"),
    ipaddress.ip_address("fd00:ec2::254"),
}
_BAD_CHARS = re.compile(r"[\x00-\x20\x7f\\]")


@dataclass(frozen=True)
class Policy:
    """allow_private is for the local lab/tests only (loopback + RFC1918)."""
    allow_private: bool = False


def _unmap(ip: IPAddress) -> IPAddress:
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped:
            return ip.ipv4_mapped
        if ip.sixtofour:
            return ip.sixtofour
    return ip


def ip_violation(ip: IPAddress, policy: Policy) -> str | None:
    """Return a reason string if the address must not be contacted."""
    ip = _unmap(ip)
    if ip in METADATA_IPS:
        return "cloud metadata address"
    if ip.is_multicast or ip.is_unspecified or ip.is_link_local or ip.is_reserved:
        return "multicast/unspecified/link-local/reserved address"
    if policy.allow_private:
        return None
    if not ip.is_global:
        return "non-public address (loopback/private/shared/reserved)"
    return None


def normalize_url(raw: str) -> str:
    """Strictly parse and canonicalise an http(s) URL."""
    if not isinstance(raw, str) or not raw or len(raw) > 2048:
        raise TargetError("URL missing or too long")
    if _BAD_CHARS.search(raw):
        raise TargetError("URL contains whitespace, control characters or backslashes")
    parts = urlsplit(raw)
    if parts.scheme.lower() not in ("http", "https"):
        raise TargetError("only http and https are supported")
    if parts.username is not None or parts.password is not None:
        raise TargetError("credentials in URL are not allowed")
    host = parts.hostname
    if not host:
        raise TargetError("URL has no host")
    try:
        port = parts.port
    except ValueError as exc:
        raise TargetError("invalid port") from exc
    if port is not None and not (1 <= port <= 65535):
        raise TargetError("invalid port")
    try:
        ipaddress.ip_address(host)
        is_literal = True
    except ValueError:
        is_literal = False
    if not is_literal:
        host = host.rstrip(".").lower()
        # inet_aton accepts decimal/hex/octal shorthand ("2130706433", "0x7f.1");
        # refuse anything whose last label looks numeric.
        last = host.rsplit(".", 1)[-1]
        if last.isdigit() or last.startswith("0x"):
            raise TargetError("ambiguous numeric hostname")
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise TargetError("invalid hostname") from exc
        if host in METADATA_HOSTS or host.endswith(".localhost") or host.endswith(".internal"):
            raise TargetError("hostname is not allowed")
        if not re.fullmatch(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*", host):
            raise TargetError("invalid hostname")
    netloc = f"[{host}]" if ":" in host else host
    if port is not None:
        netloc += f":{port}"
    path = parts.path or "/"
    return urlunsplit((parts.scheme.lower(), netloc, path, parts.query, ""))


def default_resolver(host: str, port: int) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise TargetError(f"DNS resolution failed: {exc}") from exc
    seen: list[str] = []
    for info in infos:
        addr = info[4][0].split("%")[0]
        if addr not in seen:
            seen.append(addr)
    return seen


def resolve_and_validate(host: str, port: int, policy: Policy, resolver: Resolver = default_resolver) -> list[str]:
    """Resolve once and validate EVERY address. Callers must connect to the
    returned IPs, never re-resolve (DNS-rebinding / TOCTOU defence)."""
    try:
        literal = ipaddress.ip_address(host)
        addrs = [str(literal)]
    except ValueError:
        addrs = resolver(host, port)
    if not addrs:
        raise TargetError("hostname did not resolve")
    for a in addrs:
        reason = ip_violation(ipaddress.ip_address(a), policy)
        if reason:
            raise TargetError(f"destination {a} rejected: {reason}")
    return addrs


@dataclass(frozen=True)
class Scope:
    host: str
    ports: frozenset[int]

    @classmethod
    def from_url(cls, url: str) -> "Scope":
        p = urlsplit(normalize_url(url))
        ports = {80, 443}
        if p.port:
            ports = {p.port}
        return cls(host=p.hostname or "", ports=frozenset(ports))

    def contains(self, url: str) -> bool:
        try:
            p = urlsplit(normalize_url(url))
        except TargetError:
            return False
        port = p.port or (443 if p.scheme == "https" else 80)
        return p.hostname == self.host and port in self.ports

    def join(self, base: str, ref: str) -> str | None:
        """Resolve ref against base; return normalised URL only if in scope."""
        try:
            candidate = normalize_url(urljoin(base, ref))
        except TargetError:
            return None
        return candidate if self.contains(candidate) else None
