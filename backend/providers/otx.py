from __future__ import annotations

import os
import time
from typing import Any
from urllib.parse import quote

import aiohttp

_cache: dict[str, tuple[float, dict[str, Any]]] = {}


def status() -> dict[str, Any]:
    configured = bool(os.getenv("OTX_API_KEY", "").strip())
    enabled = os.getenv("KLYPEN_OTX_ENABLED", "false").lower() == "true"
    return {"name": "AlienVault OTX", "kind": "optional external threat intelligence", "enabled": enabled,
            "configured": configured, "authentication_required": True,
            "purpose": "Supplemental domain reputation context.",
            "source": "https://otx.alienvault.com/api", "last_success": None,
            "note": "No match is not proof of safety; a match is not automatic proof of malicious activity."}


async def lookup_domain(domain: str) -> dict[str, Any]:
    key = os.getenv("OTX_API_KEY", "").strip()
    if os.getenv("KLYPEN_OTX_ENABLED", "false").lower() != "true":
        raise RuntimeError("AlienVault OTX is disabled in configuration.")
    if not key:
        raise RuntimeError("Set OTX_API_KEY in your .env file to use this optional provider.")
    if not domain or len(domain) > 253 or any(c in domain for c in "/:@?# "):
        raise ValueError("Provide a hostname only, not a URL.")
    d = domain.strip().lower().rstrip(".")
    if not d or not all(label and len(label) <= 63 for label in d.split(".")):
        raise ValueError("Invalid hostname.")
    cached = _cache.get(d)
    if cached and cached[0] > time.time():
        return {**cached[1], "cached": True}
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{quote(d, safe='.')}/general"
    timeout = aiohttp.ClientTimeout(total=12, connect=4)
    async with aiohttp.ClientSession(timeout=timeout, trust_env=False) as session:
        async with session.get(url, headers={"X-OTX-API-KEY": key, "User-Agent": "KlyPen/1.0", "Accept": "application/json"}, allow_redirects=False) as response:
            if response.status != 200:
                raise RuntimeError(f"AlienVault OTX returned HTTP {response.status}.")
            raw = await response.content.read(500_001)
            if len(raw) > 500_000:
                raise RuntimeError("OTX response exceeded the safety limit.")
            import json
            data = json.loads(raw.decode("utf-8"))
    pulse_info = data.get("pulse_info") if isinstance(data.get("pulse_info"), dict) else {}
    result = {"provider": "AlienVault OTX", "domain": d, "pulse_count": int(pulse_info.get("count", 0) or 0),
              "pulses": [{"name": str(p.get("name", ""))[:200], "created": p.get("created"), "tags": [str(t)[:80] for t in p.get("tags", [])[:10]]}
                         for p in pulse_info.get("pulses", [])[:10] if isinstance(p, dict)],
              "source": "https://otx.alienvault.com/", "note": "Reputation information is supplemental, may be incomplete, and must be verified in context.", "cached": False}
    _cache[d] = (time.time() + 1800, result)
    return result
