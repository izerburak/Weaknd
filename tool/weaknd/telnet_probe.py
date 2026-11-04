"""Read-only Telnet exposure/banner probe; sends no username or password."""
from __future__ import annotations

import re
import socket
from dataclasses import dataclass, field


LOGIN_RE = re.compile(r"(?:login|username|user)\s*:\s*$", re.I | re.M)
PASSWORD_RE = re.compile(r"password\s*:\s*$", re.I | re.M)


@dataclass
class TelnetResult:
    host: str
    port: int = 23
    reachable: bool = False
    banner: str | None = None
    login_prompt: bool = False
    password_prompt: bool = False
    notes: list[str] = field(default_factory=list)


def run(host: str, port: int = 23, timeout: float = 6.0) -> TelnetResult:
    result = TelnetResult(host=host, port=port)
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            result.reachable = True
            sock.settimeout(2.0)
            try:
                data = sock.recv(2048)
            except socket.timeout:
                data = b""
    except OSError as exc:
        result.notes.append(f"Telnet not reachable: {type(exc).__name__}")
        return result

    # Strip the most common IAC negotiation bytes from display evidence.
    text = data.decode("latin-1", "replace")
    text = re.sub(r"[\xff\xfb-\xfe].", "", text).strip()
    result.banner = text[:500] or None
    result.login_prompt = bool(LOGIN_RE.search(text))
    result.password_prompt = bool(PASSWORD_RE.search(text))
    result.notes.append("banner-only probe; no username or password sent")
    return result

