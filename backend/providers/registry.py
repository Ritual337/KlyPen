from __future__ import annotations
import os
from . import osv, otx


def all_statuses() -> list[dict]:
    statuses = [osv.status(), otx.status()]
    statuses.insert(0, {"name": "Local scanner", "kind": "local checks", "enabled": True, "configured": True,
        "authentication_required": False, "purpose": "Headers, cookies, TLS, forms, mixed content, redirects, and bounded same-origin crawling.",
        "source": None, "last_success": None, "note": "Operates without external API keys."})
    return statuses
