from __future__ import annotations

import asyncio
import json
import time
from typing import Any

import aiohttp

OSV_URL = "https://api.osv.dev/v1/query"
ALLOWED_ECOSYSTEMS = {"PyPI", "npm", "Go", "Maven", "RubyGems", "crates.io", "NuGet", "Packagist", "Pub", "Hex", "SwiftURL", "OSS-Fuzz", "Linux"}
_cache: dict[tuple[str, str, str], tuple[float, dict[str, Any]]] = {}
_lock = asyncio.Lock()


async def query_package(name: str, version: str, ecosystem: str) -> dict[str, Any]:
    name, version, ecosystem = name.strip(), version.strip(), ecosystem.strip()
    if not name or not version or len(name) > 200 or len(version) > 100 or ecosystem not in ALLOWED_ECOSYSTEMS:
        raise ValueError("Provide a package name, exact version, and supported ecosystem.")
    if any(ord(c) < 32 for c in name + version):
        raise ValueError("Control characters are not allowed.")
    key = (name.lower(), version, ecosystem)
    cached = _cache.get(key)
    if cached and cached[0] > time.time():
        return {**cached[1], "cached": True}
    payload = {"package": {"name": name, "ecosystem": ecosystem}, "version": version}
    timeout = aiohttp.ClientTimeout(total=12, connect=4)
    async with aiohttp.ClientSession(timeout=timeout, trust_env=False) as session:
        async with session.post(OSV_URL, json=payload, headers={"User-Agent": "KlyPen/1.0", "Accept": "application/json"}, allow_redirects=False) as response:
            if response.status != 200:
                raise RuntimeError(f"OSV.dev returned HTTP {response.status}.")
            raw = await response.content.read(1_000_001)
            if len(raw) > 1_000_000:
                raise RuntimeError("OSV.dev response exceeded the safety limit.")
            data = json.loads(raw.decode("utf-8"))
    vulns = []
    for v in data.get("vulns", [])[:100]:
        refs = [r.get("url") for r in v.get("references", []) if isinstance(r, dict) and isinstance(r.get("url"), str)][:5]
        vulns.append({"id": str(v.get("id", ""))[:100], "summary": str(v.get("summary", "No summary provided"))[:500],
                      "modified": v.get("modified"), "published": v.get("published"), "references": refs})
    result = {"provider": "OSV.dev", "package": name, "version": version, "ecosystem": ecosystem,
              "vulnerabilities": vulns, "count": len(vulns), "source": "https://google.github.io/osv.dev/api/",
              "note": "A package/version database match is not proof that a deployed website uses or is affected by the package.", "cached": False}
    _cache[key] = (time.time() + 3600, result)
    return result


def status() -> dict[str, Any]:
    return {"name": "OSV.dev", "kind": "free external API", "enabled": True, "configured": True,
            "authentication_required": False, "purpose": "Look up known vulnerabilities for a specified package and version.",
            "source": "https://google.github.io/osv.dev/api/", "last_success": None,
            "note": "Only queried when the user submits a package and exact version; it is not guessed from site headers."}
