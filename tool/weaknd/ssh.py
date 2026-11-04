"""Shared SSH exec helper — one lockout-aware, legacy-friendly SSH runner.

Used by the credential attack, privilege-escalation, and loot stages so there
is a single place that knows how to talk to old CPE SSH (legacy kex / host-key /
pubkey algorithms) non-interactively via sshpass.

SCOPE / SAFETY:
    * Own-lab use only — runs commands on a device you own, with a credential
      obtained through the creds/attack chain.
    * The helper itself is neutral: callers decide what command to run. The
      loot stage uses it for READ-ONLY recovery of your own stored secrets.
"""
from __future__ import annotations

import os
import shutil
import subprocess

from .ssh_probe import LEGACY_OPTS

# Non-interactive, legacy-tolerant SSH options shared by every exec caller.
COMMON_OPTS = [
    "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
    "-o", "ConnectTimeout=10", "-o", "PreferredAuthentications=password",
    "-o", "PubkeyAuthentication=no", "-o", "NumberOfPasswordPrompts=1",
    *LEGACY_OPTS,
]


def have_sshpass() -> bool:
    return shutil.which("sshpass") is not None


def execute(host: str, user: str, password: str, cmd: str,
            port: int = 22, timeout: int = 25) -> subprocess.CompletedProcess[str]:
    """Execute SSH without placing the password in argv or the environment."""
    if not have_sshpass():
        raise RuntimeError("sshpass not found")
    read_fd, write_fd = os.pipe()
    try:
        os.write(write_fd, (password + "\n").encode())
    finally:
        os.close(write_fd)
    full = ["sshpass", "-d", str(read_fd), "ssh", "-p", str(port), *COMMON_OPTS,
            f"{user}@{host}", cmd]
    try:
        return subprocess.run(full, capture_output=True, text=True, timeout=timeout,
                              pass_fds=(read_fd,))
    finally:
        os.close(read_fd)


def run(host: str, user: str, password: str, cmd: str,
        port: int = 22, timeout: int = 25) -> str:
    """Run one command over SSH; return combined stdout+stderr ('' on failure)."""
    try:
        p = execute(host, user, password, cmd, port, timeout)
    except subprocess.TimeoutExpired:
        return ""
    return (p.stdout or "") + (p.stderr or "")


def login_ok(host: str, user: str, password: str,
             port: int = 22, timeout: int = 15) -> bool:
    """True iff the credential yields a shell (uid= appears in `id`)."""
    return "uid=" in run(host, user, password, "id", port, timeout)
