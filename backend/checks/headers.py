from __future__ import annotations

from ..scanner.findings import make_finding


def check_headers(url: str, headers: dict[str, str], *, is_https: bool) -> list[dict]:
    findings = []
    present = {k.lower(): v for k, v in headers.items()}
    required = [
        ("content-security-policy", "Content Security Policy is missing", "low", "A Content-Security-Policy can reduce the impact of some content-injection attacks when configured for the application.", "Define a policy appropriate for the application. Start with report-only mode if necessary."),
        ("x-content-type-options", "MIME-sniffing protection is missing", "low", "Without nosniff, some browsers may interpret responses using inferred MIME types.", "Set X-Content-Type-Options: nosniff."),
        ("referrer-policy", "Referrer-Policy is missing", "info", "A defined referrer policy helps control how much referrer information is sent to other origins.", "Choose a policy such as strict-origin-when-cross-origin based on application needs."),
        ("permissions-policy", "Permissions-Policy is missing", "info", "A Permissions-Policy can restrict access to selected browser features.", "Set a Permissions-Policy appropriate for the features the site uses."),
    ]
    for header, title, severity, desc, fix in required:
        if header not in present:
            findings.append(make_finding(title=title, category="security-headers", severity=severity,
                confidence="high", url=url, description=desc, evidence={"missing_header": header}, remediation=fix,
                references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers"]))
    if is_https and "strict-transport-security" not in present:
        findings.append(make_finding(title="HTTP Strict Transport Security is missing", category="security-headers",
            severity="low", confidence="high", url=url,
            description="The HTTPS response does not advertise HSTS. This check does not evaluate preload eligibility or the site's deployment requirements.",
            evidence={"missing_header": "strict-transport-security"}, remediation="Consider setting Strict-Transport-Security after confirming all relevant subdomains support HTTPS.",
            references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"]))
    if "x-frame-options" not in present and "content-security-policy" in present and "frame-ancestors" in present.get("content-security-policy", "").lower():
        pass
    elif "x-frame-options" not in present and "content-security-policy" not in present:
        findings.append(make_finding(title="Framing protection is not apparent", category="security-headers", severity="low",
            confidence="medium", url=url, description="Neither X-Frame-Options nor a CSP frame-ancestors directive was observed.",
            evidence={"missing_headers": ["x-frame-options", "content-security-policy frame-ancestors"]},
            remediation="Set a suitable Content-Security-Policy frame-ancestors directive or X-Frame-Options."))
    server = present.get("server", "")
    powered = present.get("x-powered-by", "")
    if server or powered:
        evidence = {k: v for k, v in (("server", server), ("x-powered-by", powered)) if v}
        findings.append(make_finding(title="Technology-identifying response headers are present", category="information-disclosure",
            severity="info", confidence="high", url=url,
            description="Response headers reveal server or framework identification. This is informational and does not establish a vulnerability.",
            evidence=evidence, remediation="Consider reducing unnecessary version details in response headers."))
    return findings
