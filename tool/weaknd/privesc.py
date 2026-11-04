"""Stage 5 — post-auth privilege escalation check.

Given a working (user, password), log in and assess what this account can do
that it shouldn't — and whether we can become root/supervisor. Designed for
embedded CPEs (BusyBox), so it tolerates missing coreutils.

The point of the demo: "we logged in as admin; here is why admin == full
compromise on this box." Each finding is severity-tagged and vendor-reportable.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import ssh

# command -> (label, why it matters). Marker-wrapped so we can split output.
PROBES = {
    "id":                         ("identity", "current uid/gid"),
    "sudo -n -l 2>/dev/null":     ("sudo", "passwordless sudo = direct root"),
    "cat /etc/shadow 2>/dev/null | head -3": ("shadow", "readable password hashes = cred leak + offline crack"),
    "ls -ld /etc /etc/init.d 2>/dev/null": ("writable-etc", "world/group-writable system dirs = persistence"),
    "find / -perm -4000 -type f 2>/dev/null | head -10": ("suid", "SUID binaries = known privesc vectors"),
    "which busybox dropbear telnetd 2>/dev/null": ("busybox", "embedded toolset / extra daemons"),
    "cat /proc/version 2>/dev/null": ("kernel", "kernel version for CVE matching"),
}


@dataclass
class PrivescResult:
    host: str
    user: str
    uid: str | None = None
    is_root: bool = False
    escalation: bool = False
    findings: list[dict] = field(default_factory=list)   # {sev, label, detail}
    raw: dict = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def add(self, sev, label, detail):
        self.findings.append({"sev": sev, "label": label, "detail": detail})


def run_as(host, user, password, cmd, port=22, timeout=25) -> str:
    return ssh.run(host, user, password, cmd, port, timeout)


def _batch(host, user, password, port):
    """Run all probes in one session; return {label: output}."""
    parts = []
    for cmd, (label, _) in PROBES.items():
        parts.append(f"echo __K_{label}__; {cmd}")
    script = "; ".join(parts)
    out = run_as(host, user, password, script, port)
    res = {}
    cur = None
    for line in out.splitlines():
        m = line.strip()
        if m.startswith("__K_") and m.endswith("__"):
            cur = m[4:-2]
            res[cur] = []
        elif cur is not None:
            res[cur].append(line)
    return {k: "\n".join(v).strip() for k, v in res.items()}


def run(host: str, user: str, password: str, port: int = 22,
        root_pw_candidates: list[str] | None = None) -> PrivescResult:
    res = PrivescResult(host=host, user=user)
    data = _batch(host, user, password, port)
    res.raw = data

    idline = data.get("identity", "")
    res.uid = idline
    res.is_root = "uid=0" in idline
    if res.is_root:
        res.escalation = True
        res.add("CRITICAL", "admin==root",
                f"'{user}' login yields uid=0 — the management account IS root. "
                "No escalation needed; full device compromise on auth.")

    sudo = data.get("sudo", "")
    if sudo and "may run" in sudo.lower():
        res.escalation = True
        res.add("HIGH", "passwordless-sudo", f"sudo -l: {sudo[:200]}")

    shadow = data.get("shadow", "")
    if shadow and ":" in shadow and not res.is_root:
        res.add("HIGH", "shadow-readable",
                "/etc/shadow readable as non-root — password hashes leak (offline crack).")

    suid = data.get("suid", "")
    if suid:
        res.add("INFO", "suid-inventory", suid[:300])

    we = data.get("writable-etc", "")
    if we and ("rwxrwx" in we or "drwxrwxrwx" in we):
        res.add("MEDIUM", "writable-system-dir", we)

    kern = data.get("kernel", "")
    if kern:
        res.notes.append(kern[:120])

    # Do not interpolate a candidate secret into a remote command/argv.  A
    # future implementation may add a separate protected stdin channel.
    if root_pw_candidates and not res.is_root:
        res.notes.append(
            "candidate su test skipped: protected remote password input is not implemented"
        )

    if not res.findings:
        res.add("INFO", "no-obvious-privesc",
                "No obvious escalation from this account with current checks.")
    return res
