"""Scoped keys: compare hashes, never retain the supplied key."""

import hashlib
import hmac
import json
import os
from typing import Any

from fastapi import HTTPException, Request

SCOPES = frozenset({"read", "alert-write", "admin", "ingest"})


def bindings() -> list[dict[str, Any]]:
    raw = os.environ.get("MINISIEM_KEYS", "[]")
    try:
        keys = json.loads(raw)
        if not isinstance(keys, list):
            raise ValueError()
        for k in keys:
            if (
                not isinstance(k, dict)
                or set(k) != {"sha256", "scopes"}
                or len(k["sha256"]) != 64
                or not set(k["scopes"]) <= SCOPES
            ):
                raise ValueError()
    except (ValueError, TypeError, KeyError):
        raise ValueError("invalid MINISIEM_KEYS metadata; values redacted") from None
    return keys


def authorize(request: Request, scope: str) -> str:
    """No query-string keys, cookies or browser storage."""
    supplied = request.headers.get("x-api-key", "")
    if not 32 <= len(supplied) <= 256:
        raise HTTPException(401, "API key required")
    digest = hashlib.sha256(supplied.encode()).hexdigest()
    for entry in bindings():
        if hmac.compare_digest(digest, entry["sha256"]):
            if scope not in entry["scopes"] and "admin" not in entry["scopes"]:
                raise HTTPException(403, "scope denied")
            request.state.key_id = digest[:16]
            return digest
    raise HTTPException(401, "invalid API key")
