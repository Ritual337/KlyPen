from __future__ import annotations

import ipaddress
import os
import socket
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

ALLOWED_PORTS = {80, 443, 8080, 8443, 9001}
LAB_HOSTS = {"127.0.0.1", "localhost"}


class ScopeError(ValueError):
    """A URL is malformed, unsafe, or outside the allowed scan scope."""


@dataclass(frozen=True)
class Target:
    url: str
    origin: str
    scheme: str
    hostname: str
    port: int
    path: str
    is_lab: bool = False


def _is_public_ip(value: str) -> bool:
    ip = ipaddress.ip_address(value.split("%", 1)[0])
    # Reject transition/mapping forms rather than trusting a dual-stack interpretation.
    if isinstance(ip, ipaddress.IPv6Address) and (ip.ipv4_mapped is not None or ip.sixtofour is not None or ip.teredo is not None):
        return False
    # Treat special-purpose, reserved, private, loopback, link-local and multicast as blocked.
    return ip.is_global and not ip.is_multicast and not ip.is_unspecified


def normalize_and_validate(url: str, *, resolve_dns: bool = True) -> Target:
    if not isinstance(url, str) or not url.strip() or len(url) > 2048:
        raise ScopeError("Enter a valid URL no longer than 2048 characters.")
    raw = url.strip()
    if any(ord(c) < 32 for c in raw) or "\\" in raw:
        raise ScopeError("Control characters and backslashes are not allowed in URLs.")
    try:
        parts = urlsplit(raw)
    except ValueError as exc:
        raise ScopeError("Malformed URL syntax.") from exc
    scheme = parts.scheme.lower()
    if scheme not in {"http", "https"}:
        raise ScopeError("Only HTTP and HTTPS URLs are supported.")
    if parts.username is not None or parts.password is not None:
        raise ScopeError("URLs containing embedded credentials are not allowed.")
    if not parts.hostname:
        raise ScopeError("The URL must contain a hostname.")
    hostname = parts.hostname.rstrip(".").lower()
    if not hostname or hostname.endswith(".local") or hostname == "localhost.localdomain":
        raise ScopeError("Local hostnames are blocked.")
    if ":" not in hostname:
        try:
            hostname = hostname.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise ScopeError("Invalid internationalized hostname.") from exc
    try:
        # Accessing .port also validates malformed port syntax.
        port = parts.port or (443 if scheme == "https" else 80)
    except ValueError as exc:
        raise ScopeError("Invalid port.") from exc
    if port not in ALLOWED_PORTS:
        raise ScopeError("Ports are restricted to 80, 443, 8080, 8443, and the demo lab port 9001.")
    is_lab = port == 9001 and hostname in LAB_HOSTS and os.getenv("KLYPEN_LAB_ENABLED", "false").lower() == "true"
    if port == 9001 and not is_lab:
        raise ScopeError("Port 9001 is reserved for the explicitly enabled local demo lab.")
    if (hostname in LAB_HOSTS or hostname in {"::1"}) and not is_lab:
        raise ScopeError("Loopback targets are blocked except for the explicitly enabled local demo lab on port 9001.")
    try:
        ip = ipaddress.ip_address(hostname)
        if not _is_public_ip(str(ip)) and not is_lab:
            raise ScopeError("Private, reserved, loopback, and link-local IP addresses are blocked.")
    except ValueError:
        # DNS names are resolved and every returned address must be public.
        if not hostname or len(hostname) > 253:
            raise ScopeError("Invalid hostname.")
        if hostname.isdigit() or all(part.isdigit() for part in hostname.split(".")):
            raise ScopeError("Numeric or ambiguous IP-style hostnames are blocked.")
        labels = hostname.split(".")
        if len(labels) < 2 or any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-") for label in labels):
            raise ScopeError("Enter a fully qualified domain name.")
        if any(not all(ch.isalnum() or ch == "-" for ch in label) for label in labels):
            raise ScopeError("Hostname contains unsupported characters.")
    if resolve_dns and not is_lab:
        try:
            answers = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise ScopeError("Hostname could not be resolved.") from exc
        ips = {entry[4][0].split("%", 1)[0] for entry in answers}
        if not ips:
            raise ScopeError("Hostname returned no IP addresses.")
        if any(not _is_public_ip(ip) for ip in ips):
            raise ScopeError("Hostname resolves to a private or special-purpose address; scan blocked.")
    path = parts.path or "/"
    clean_netloc = f"[{hostname}]" if ":" in hostname and not hostname.startswith("[") else hostname
    if port != (443 if scheme == "https" else 80):
        clean_netloc += f":{port}"
    normalized = urlunsplit((scheme, clean_netloc, path, parts.query, ""))
    origin = f"{scheme}://{clean_netloc}"
    return Target(normalized, origin, scheme, hostname, port, path, is_lab)


def resolve_pinned(hostname: str, port: int, is_lab: bool = False) -> list[tuple[int, str]]:
    if is_lab and os.getenv("KLYPEN_LAB_ENABLED", "false").lower() == "true" and hostname in LAB_HOSTS:
        return [(socket.AF_INET, "127.0.0.1")]
    try:
        answers = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ScopeError("Hostname could not be resolved during connection.") from exc
    pins: list[tuple[int, str]] = []
    for answer in answers:
        family, ip = answer[0], answer[4][0].split("%", 1)[0]
        if not _is_public_ip(ip):
            raise ScopeError("DNS result changed to a private or special-purpose address; request blocked.")
        pair = (family, ip)
        if pair not in pins:
            pins.append(pair)
    if not pins:
        raise ScopeError("No validated addresses available.")
    return pins


def same_origin(a: Target, b: Target) -> bool:
    return (a.scheme, a.hostname, a.port) == (b.scheme, b.hostname, b.port)


def redact_url(url: str) -> str:
    """Redact common credential-like query parameters before persistence or display."""
    try:
        parts = urlsplit(url)
        pairs = []
        for key, value in parse_qsl(parts.query, keep_blank_values=True):
            if any(word in key.lower().replace("-", "_") for word in ("token", "secret", "password", "passwd", "api_key", "apikey", "credential", "session", "signature", "auth", "jwt", "access_key")):
                value = "[REDACTED]"
            pairs.append((key, value))
        return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(pairs), ""))
    except Exception:
        return url[:2048]
