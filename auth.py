"""
Minimal API-key auth so every route (including the WebSocket and the
remediation-execute endpoint) requires a caller identity.

For real enterprise use, swap this for your SSO/OIDC layer — this is the
floor, not the ceiling. Keys are defined in .env as:

    API_KEYS=alice:ALICE_KEY_HERE,bob:BOB_KEY_HERE

Each request must send: X-API-Key: <key>
The matching label ("alice", "bob") is recorded as `actor` on every
audit-log row so HITL executions are attributable to a person.
"""
import os
from fastapi import Header, HTTPException, status, Query
from typing import Optional

def _load_keys() -> dict:
    raw = os.getenv("API_KEYS", "")
    keys = {}
    for pair in raw.split(","):
        pair = pair.strip()
        if not pair or ":" not in pair:
            continue
        label, key = pair.split(":", 1)
        keys[key.strip()] = label.strip()
    return keys


_API_KEYS = _load_keys()


def require_api_key(x_api_key: Optional[str] = Header(default=None)) -> str:
    """Dependency for regular HTTP routes. Returns the caller's label."""
    if not _API_KEYS:
        # No keys configured — fail closed rather than silently open.
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Server has no API_KEYS configured. Set API_KEYS in .env."
        )
    if not x_api_key or x_api_key not in _API_KEYS:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or missing X-API-Key")
    return _API_KEYS[x_api_key]


async def require_api_key_ws(api_key: Optional[str] = Query(default=None)) -> str:
    """Dependency for the WebSocket route (browsers can't set headers on ws connect easily)."""
    if not _API_KEYS or not api_key or api_key not in _API_KEYS:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or missing api_key")
    return _API_KEYS[api_key]
