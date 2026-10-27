from __future__ import annotations
from ..scanner.findings import make_finding


def check_cors(url: str, headers: dict[str, str]) -> list[dict]:
    lowered = {k.lower(): v for k, v in headers.items()}
    origin = lowered.get("access-control-allow-origin")
    creds = lowered.get("access-control-allow-credentials", "").lower() == "true"
    if origin == "*":
        # Wildcard ACAO alone is not necessarily a vulnerability; never inflate severity without context.
        return [make_finding(title="CORS allows any origin", category="cors", severity="info", confidence="high", url=url,
            description="The response advertises Access-Control-Allow-Origin: *. This may be intentional for public resources and does not by itself prove sensitive data exposure. Browsers do not permit credentialed CORS with a wildcard origin.",
            evidence={"access_control_allow_origin": "*", "allow_credentials": creds},
            remediation="Confirm that the endpoint contains only public data. Use an explicit origin allowlist for sensitive authenticated resources.",
            references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"])]
    if origin and creds and origin.lower() == "null":
        return [make_finding(title="CORS allows the null origin with credentials", category="cors", severity="medium", confidence="medium", url=url,
            description="The response appears to allow the opaque null origin while permitting credentials. Impact depends on authentication and the data exposed by this endpoint.",
            evidence={"access_control_allow_origin": "null", "allow_credentials": True},
            remediation="Avoid allowing the null origin for credentialed endpoints; use an explicit trusted-origin allowlist.",
            references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"])]
    return []
