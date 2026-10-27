from __future__ import annotations

from ..scanner.findings import make_finding


def check_cookies(url: str, headers: dict[str, str], *, is_https: bool) -> list[dict]:
    # Never persist cookie values. Only keep attribute names and a short cookie-name label.
    raw = headers.get("set-cookie") or headers.get("Set-Cookie")
    if not raw:
        return []
    # aiohttp may combine multiple Set-Cookie headers depending on server; process each line cautiously.
    lines = raw.split("\n")[:10]
    findings = []
    for line in lines:
        if not line.strip():
            continue
        chunks = [c.strip() for c in line.split(";")]
        name = chunks[0].split("=", 1)[0][:80] if "=" in chunks[0] else "cookie"
        attrs = {c.split("=", 1)[0].strip().lower(): c.split("=", 1)[1].strip() if "=" in c else True for c in chunks[1:]}
        missing = []
        if is_https and "secure" not in attrs: missing.append("Secure")
        if "httponly" not in attrs: missing.append("HttpOnly")
        if "samesite" not in attrs: missing.append("SameSite")
        if missing:
            findings.append(make_finding(title=f"Cookie '{name}' is missing recommended attributes", category="cookies",
                severity="low", confidence="high", url=url,
                description="The Set-Cookie attributes were reviewed without storing the cookie value. Impact depends on the cookie's purpose and usage.",
                evidence={"cookie_name": name, "missing_attributes": missing},
                remediation="Consider Secure for HTTPS cookies, HttpOnly for cookies not needed by JavaScript, and an appropriate SameSite value."))
    return findings
