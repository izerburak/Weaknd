"""Reflected-XSS output-encoding probe.

Checks whether a web parameter's value is safely encoded when it is reflected
back into the HTML response. If a marker containing HTML metacharacters comes
back verbatim (unencoded), the output encoding is missing — the ingredient for
reflected XSS. If it comes back HTML-encoded (&lt;x&gt;), the field is safe.

SCOPE / SAFETY:
    * Authorized use only — run this against your OWN home-lab devices.
    * The markers are benign reflection probes — they do NOT execute anything
      and carry no real script logic; we only check how the value is echoed.
    * A couple of HTTP requests are sent and their responses read back; nothing
      is persisted or changed on the device.

Like the other stages, a run produces an XSSResult dataclass and is saved as
JSON under ../artifacts/ via report.save().
"""
from __future__ import annotations

import html
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

from . import report

# Unique, benign reflection markers containing HTML metacharacters.
# The first is a non-executing tag-shaped token; the second is the classic
# <script> shape — neither does anything, we only check how it is echoed back.
PAYLOADS = [
    "wknd<x>123",
    "<script>wknd123</script>",
]

_MAXREAD = 1 << 16  # cap response read at 64 KiB


@dataclass
class XSSResult:
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
    """Send one request with {param: value}. Return (body, error)."""
    ctx = _insecure_ctx() if url.lower().startswith("https") else None
    headers = {"User-Agent": "weaknd/0.1"}
    if method.upper() == "GET":
        sep = "&" if "?" in url else "?"
        req = urllib.request.Request(url + sep + urllib.parse.urlencode({param: value}),
                                     headers=headers)
    else:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        req = urllib.request.Request(url, data=urllib.parse.urlencode({param: value}).encode(),
                                     headers=headers, method="POST")
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


def _reflected_line(body: str, needle: str) -> str:
    for line in body.splitlines():
        if needle in line:
            return line.strip()[:200]
    return needle


def probe_xss(base_url: str, endpoint_path: str, param_name: str,
              http_method: str = "GET") -> XSSResult:
    """Test whether a reflected parameter is output-encoded.

    For each benign marker: if it comes back RAW (unencoded) → missing output
    encoding → vulnerable. If it comes back HTML-encoded → safe. Stops at the
    first unencoded reflection.
    """
    host = urllib.parse.urlparse(base_url).hostname or base_url
    url = base_url.rstrip("/") + "/" + endpoint_path.lstrip("/")
    res = XSSResult(host=host, endpoint=endpoint_path, parameter=param_name,
                    tested_payloads=list(PAYLOADS))

    for payload in PAYLOADS:
        body, err = _send(url, http_method, param_name, payload)
        if err:
            res.notes.append(f"{payload!r}: {err}")
            continue
        if payload in body:
            res.vulnerable = True
            res.payload_that_worked = payload
            res.evidence = _reflected_line(body, payload)
            res.notes.append(f"{payload!r} reflected RAW (unencoded) — output encoding missing")
            return res
        encoded = html.escape(payload)
        if encoded in body:
            res.notes.append(f"{payload!r} reflected but HTML-encoded ({encoded!r}) — safe")
        else:
            res.notes.append(f"{payload!r} not reflected in response")

    res.notes.append("no unencoded reflection seen — output encoding looks correct (good)")
    return res


def run(base_url: str, endpoint_path: str, param_name: str,
        http_method: str = "GET", save: bool = True) -> XSSResult:
    """Probe + persist, mirroring the other stages' report.save() behavior."""
    res = probe_xss(base_url, endpoint_path, param_name, http_method)
    if save:
        report.save("xss", res.host, res)
    return res


if __name__ == "__main__":
    # Standalone runner (run from the tool/ dir so package imports resolve):
    #   python -m weaknd.xss_probe 192.168.1.1 --endpoint /search --param q
    import argparse

    ap = argparse.ArgumentParser(description="Reflected-XSS output-encoding probe "
                                             "(own-device input-validation test).")
    ap.add_argument("host", help="device host/IP (own lab device)")
    ap.add_argument("--endpoint", required=True, help="endpoint path, e.g. /search")
    ap.add_argument("--param", required=True, help="parameter name to test")
    ap.add_argument("--method", default="GET", choices=["GET", "POST"])
    ap.add_argument("--scheme", default="http", choices=["http", "https"])
    a = ap.parse_args()

    base = f"{a.scheme}://{a.host}"
    r = run(base, a.endpoint, a.param, a.method)
    print(f"\n=== xss-probe ===")
    print(f"  host:       {r.host}")
    print(f"  endpoint:   {r.endpoint}  (param={r.parameter}, {a.method})")
    print(f"  vulnerable: {'YES' if r.vulnerable else 'no'}")
    if r.vulnerable:
        print(f"  payload:    {r.payload_that_worked}")
        print(f"  evidence:   {r.evidence}")
    for n in r.notes:
        print(f"   - {n}")
