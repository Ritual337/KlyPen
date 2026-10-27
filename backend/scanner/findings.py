from __future__ import annotations

import re
from typing import Any

_SECRET_PATTERNS = [
    re.compile(r"(?i)(authorization\s*[:=]\s*(?:bearer\s+)?)[^\s,;]+"),
    re.compile(r"(?i)(api[_-]?key\s*[:=]\s*)['\"]?[^'\"\s,;]+"),
    re.compile(r"(?i)(password\s*[:=]\s*)['\"]?[^'\"\s,;]+"),
    re.compile(r"(?i)(access[_-]?token\s*[:=]\s*)['\"]?[^'\"\s,;]+"),
    re.compile(r"(?i)(secret\s*[:=]\s*)['\"]?[^'\"\s,;]+"),
]


def redact(value: Any) -> Any:
    """Return safe display/storage content with common secrets redacted."""
    if isinstance(value, dict):
        return {str(k): ("[REDACTED]" if str(k).lower() in {"cookie", "set-cookie", "authorization", "password", "token", "secret", "api_key"} else redact(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    if isinstance(value, str):
        out = value[:2000]
        for pattern in _SECRET_PATTERNS:
            out = pattern.sub(r"\1[REDACTED]", out)
        return out
    return value


def make_finding(
    *, title: str, category: str, severity: str, confidence: str,
    url: str, description: str, evidence: Any, remediation: str,
    source: str = "local", references: list[str] | None = None,
) -> dict[str, Any]:
    severity = severity.lower()
    confidence = confidence.lower()
    if severity not in {"critical", "high", "medium", "low", "info"}:
        severity = "info"
    if confidence not in {"high", "medium", "low"}:
        confidence = "low"
    return {
        "title": title[:180], "category": category[:80], "severity": severity,
        "confidence": confidence, "url": url[:2048], "description": description[:1500],
        "evidence": redact(evidence), "remediation": remediation[:1500],
        "source": source, "references": (references or [])[:8],
    }


def deduplicate(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str, str]] = set()
    out = []
    for f in findings:
        key = (f.get("title", ""), f.get("url", ""), f.get("category", ""))
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


def score(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """A transparent risk indicator, not proof of security."""
    counts = {s: sum(1 for f in findings if f.get("severity") == s) for s in ("critical", "high", "medium", "low", "info")}
    penalty = counts["critical"] * 25 + counts["high"] * 15 + counts["medium"] * 7 + counts["low"] * 2
    rating = max(0, min(100, 100 - penalty))
    return {"score": rating, "label": "Risk indicator", "counts": counts,
            "explanation": "Starts at 100 and subtracts 25 per critical, 15 per high, 7 per medium, and 2 per low finding, capped at 0. This heuristic is not a certification or proof that a site is secure."}
