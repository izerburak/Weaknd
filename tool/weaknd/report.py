"""Reporting helpers with mandatory secret redaction.

Artifacts are evidence for vendor reports, not a credential store.  Every
serialization path therefore passes through :func:`safe_data` before JSON is
written or returned by the local dashboard.
"""
from __future__ import annotations

import dataclasses
import json
import time
from collections.abc import Mapping
from pathlib import Path

ARTIFACTS = Path(__file__).resolve().parents[2] / "artifacts"

_SENSITIVE_KEYS = {
    "password", "passwords", "passwd", "passphrase", "root_pw",
    "root_password", "token", "access_token", "refresh_token",
    "private_key", "secret", "working_community", "derived", "shadow",
}


def _sensitive_key(key: object) -> bool:
    value = str(key).lower()
    return (value in _SENSITIVE_KEYS or value.endswith("_password") or
            value.endswith("_passphrase") or value.endswith("_secret") or
            value.endswith("_token") or value.endswith("_private_key"))


def safe_data(value):
    """Return a JSON-friendly copy with secret-bearing fields removed.

    This is deliberately allow-structure/deny-secret: evidence such as host,
    method, credential dictionary ID, and identity proof remains useful while
    credential material never reaches terminal summaries, APIs, or artifacts.
    """
    if dataclasses.is_dataclass(value):
        value = dataclasses.asdict(value)
    if isinstance(value, Mapping):
        return {str(key): safe_data(item) for key, item in value.items()
                if not _sensitive_key(key)}
    if isinstance(value, (list, tuple, set)):
        return [safe_data(item) for item in value]
    if isinstance(value, Path):
        return str(value)
    return value


def save(stage: str, host: str, data) -> Path:
    ARTIFACTS.mkdir(exist_ok=True)
    ts = time.strftime("%Y%m%d-%H%M%S")
    safe = host.replace(":", "_").replace("/", "_")
    path = ARTIFACTS / f"{safe}_{stage}_{ts}.json"
    path.write_text(json.dumps(safe_data(data), indent=2, ensure_ascii=False))
    return path
