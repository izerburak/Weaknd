"""SSH enumeration — banner, host-key / cipher algorithms, accepted auth methods.

No credentials are sent. We only read the banner and ask the server which auth
methods it will accept (via `ssh -o PreferredAuthentications=none`), which is the
enumeration step before any credential strategy.
"""
from __future__ import annotations

import re
import socket
import subprocess
from dataclasses import dataclass, field

# Legacy algos many CPEs still require.
LEGACY_OPTS = [
    "-oKexAlgorithms=+diffie-hellman-group14-sha1,diffie-hellman-group1-sha1",
    "-oHostKeyAlgorithms=+ssh-rsa,ssh-dss",
    "-oPubkeyAcceptedAlgorithms=+ssh-rsa",
    "-oCiphers=+aes128-cbc,aes256-cbc,3des-cbc",
    "-oMACs=+hmac-sha1,hmac-md5",
]


@dataclass
class SSHInfo:
    host: str
    port: int = 22
    banner: str | None = None
    auth_methods: list[str] = field(default_factory=list)
    reachable: bool = False
    notes: list[str] = field(default_factory=list)


def grab_banner(host: str, port: int = 22, timeout: float = 5.0) -> str | None:
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            data = s.recv(256)
        line = data.split(b"\r\n", 1)[0].decode("latin-1", "replace").strip()
        return line or None
    except OSError:
        return None


def probe_auth_methods(host: str, port: int = 22, user: str = "root") -> list[str]:
    """Ask the server which auth methods it accepts (sends no password)."""
    cmd = [
        "ssh", "-p", str(port),
        "-o", "PreferredAuthentications=none",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=6",
        "-o", "BatchMode=yes",
        *LEGACY_OPTS,
        f"{user}@{host}",
    ]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    except subprocess.TimeoutExpired:
        return []
    err = p.stderr
    m = re.search(r"Permission denied \(([^)]+)\)", err)
    if m:
        return [a.strip() for a in m.group(1).split(",")]
    if "No supported authentication methods" in err:
        return ["none"]
    return []


def run(host: str, port: int = 22, user: str = "root") -> SSHInfo:
    info = SSHInfo(host=host, port=port)
    info.banner = grab_banner(host, port)
    info.reachable = info.banner is not None
    if not info.reachable:
        info.notes.append("no SSH banner — port closed/filtered")
        return info
    if "-ssh" in (info.banner or "") and not re.search(r"ssh[-_]?\d", info.banner.lower().replace("ssh-2.0-ssh", "")):
        info.notes.append("version string masked — typical of hardened/vendor SSH (e.g. Zyxel)")
    info.auth_methods = probe_auth_methods(host, port, user)
    if "password" in info.auth_methods:
        info.notes.append("password auth accepted — credential strategy applies")
    if "publickey" in info.auth_methods and "password" not in info.auth_methods:
        info.notes.append("publickey only — need a key, not a password")
    return info
