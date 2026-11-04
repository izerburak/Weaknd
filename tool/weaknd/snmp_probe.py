"""SNMP default/weak community-string check (configuration test).

A device whose SNMP service answers to a default community string ("public",
"private", ...) leaks system information to anyone on the network — a very
common CPE misconfiguration. This module checks whether that's the case.

SCOPE / SAFETY:
    * Authorized use only — run this against your OWN home-lab devices.
    * READ-ONLY: we query a single standard OID, sysDescr (1.3.6.1.2.1.1.1.0),
      which is just the device's self-description string. No SET / no writes,
      nothing is changed on the device.
    * If no SNMP tooling is installed we simply report that and return.

Like the other stages, a run produces an SNMPResult dataclass and is saved as
JSON under ../artifacts/ via report.save().
"""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field

from . import report

# Community strings worth trying by default — the usual weak/default pair.
DEFAULT_COMMUNITIES = ["public", "private"]

# sysDescr.0 — a harmless, standard read: the device's own description text.
SYS_DESCR_OID = "1.3.6.1.2.1.1.1.0"

# stderr/stdout fragments that mean "no usable answer".
_NO_ANSWER = ("Timeout", "No Response", "No Such", "Unknown", "Cannot",
              "Authentication failure", "Reason: ")


@dataclass
class SNMPResult:
    host: str
    port: int = 161
    readable: bool = False
    working_community: str | None = None
    tested_communities: list[str] = field(default_factory=list)
    sample_data: str | None = None            # first bit of leaked info (sysDescr)
    notes: list[str] = field(default_factory=list)


def _snmp_tool() -> tuple[str, str] | None:
    """Prefer snmpget, fall back to snmpwalk. Return (name, path) or None."""
    for name in ("snmpget", "snmpwalk"):
        path = shutil.which(name)
        if path:
            return name, path
    return None


def _query(path: str, community: str, host: str, port: int,
           timeout: int = 4) -> tuple[str | None, str | None]:
    """Query sysDescr with one community. Return (value, error).

    (None, None) means the tool ran but the device gave no usable answer
    (filtered/closed, or the community was rejected).
    """
    cmd = [path, "-v2c", "-c", community, "-Ovq",
           "-t", str(timeout), "-r", "0", f"{host}:{port}", SYS_DESCR_OID]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 3)
    except subprocess.TimeoutExpired:
        return None, "subprocess timeout"
    except OSError as e:
        return None, f"{type(e).__name__}: {e}"
    out = (p.stdout or "").strip()
    both = out + "\n" + (p.stderr or "")
    if p.returncode == 0 and out and not any(s in out for s in _NO_ANSWER):
        return out, None
    if any(s in both for s in ("Timeout", "No Response")):
        return None, "no SNMP response (filtered/closed or wrong community)"
    return None, None


def probe_snmp(host: str, port: int = 161,
               communities: list[str] | None = None) -> SNMPResult:
    """Test whether SNMP is readable with a default/weak community string.

    Tries each community against sysDescr; stops at the first that answers.
    """
    communities = communities or list(DEFAULT_COMMUNITIES)
    res = SNMPResult(host=host, port=port, tested_communities=list(communities))

    tool = _snmp_tool()
    if not tool:
        res.notes.append("snmp tools not installed (snmpget/snmpwalk missing) — "
                         "`sudo apt install snmp`")
        return res
    name, path = tool
    res.notes.append(f"using {name}")

    for community in communities:
        value, err = _query(path, community, host, port)
        if err:
            res.notes.append(f"community {community!r}: {err}")
            continue
        if value:
            res.readable = True
            res.working_community = community
            res.sample_data = value.strip()[:300]
            res.notes.append(f"SNMP readable with community {community!r} — "
                             "sysDescr leaked (weak/default community)")
            return res
        res.notes.append(f"community {community!r}: no usable answer / rejected")

    if not res.readable:
        res.notes.append("no tested community returned data — SNMP closed or "
                         "properly restricted (good)")
    return res


def run(host: str, port: int = 161, save: bool = True) -> SNMPResult:
    """Probe + persist, mirroring the other stages' report.save() behavior."""
    res = probe_snmp(host, port)
    if save:
        report.save("snmp", res.host, res)
    return res


if __name__ == "__main__":
    # Standalone runner (run from the tool/ dir so package imports resolve):
    #   python -m weaknd.snmp_probe 192.168.1.1 --port 161
    import argparse

    ap = argparse.ArgumentParser(description="SNMP default/weak community check "
                                             "(own-device config test, read-only sysDescr).")
    ap.add_argument("host", help="device host/IP (own lab device)")
    ap.add_argument("--port", type=int, default=161)
    a = ap.parse_args()

    r = run(a.host, a.port)
    print(f"\n=== snmp-probe ===")
    print(f"  host:     {r.host}:{r.port}")
    print(f"  readable: {'YES' if r.readable else 'no'}")
    if r.readable:
        print(f"  community: {r.working_community}")
        print(f"  sysDescr:  {r.sample_data}")
    for n in r.notes:
        print(f"   - {n}")
