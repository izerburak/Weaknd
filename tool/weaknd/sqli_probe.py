"""SQL-injection input-validation probe.

Checks whether a web management form (e.g. a login) or a single parameter
sanitizes its input, or passes it into a SQL query unescaped. Two low-touch
detection methods are used: error-based (the app leaks a SQL error) and
boolean-based (an always-true condition changes the response).

SCOPE / SAFETY:
    * Authorized use only — run this against your OWN home-lab devices.
    * This does NOT try to read or modify data. It only checks whether the
      form properly sanitizes input, using a handful of classic test strings.
    * A few HTTP requests are sent and their responses are read back; nothing
      is persisted or changed on the device.

Like the other stages, a run produces an SQLiResult dataclass and is saved as
JSON under ../artifacts/ via report.save().
"""
from __future__ import annotations

import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

from . import report

# A normal, harmless value for the baseline request.
BASELINE = "test"

# Classic input-validation test strings. Harmless — they probe quoting, not data.
PAYLOADS = [
    "test'",                 # single quote — tries to trigger a SQL error
    "test' OR '1'='1",       # always-true (single-quote context)
    'test" OR "1"="1',       # always-true (double-quote context)
    "test' --",              # comment-out the rest of the query
]

# Payloads whose point is a change in behavior (boolean-based), not an error.
_ALWAYS_TRUE = ("test' OR '1'='1", 'test" OR "1"="1')

# Typical SQL error signatures surfaced by a broken/unsanitized query.
SQL_ERROR_RE = re.compile(
    r"SQL syntax|syntax error|unclosed quotation|quoted string not properly terminated"
    r"|SQLSTATE|SQLException|ODBC|OLE DB|ORA-\d{4,5}"
    r"|you have an error in your sql|warning:\s*(?:mysqli?|pg|sqlite)"
    r"|mysql_fetch|mysqli?_|sqlite3?\.|psycopg2|PostgreSQL.*ERROR"
    r"|Microsoft SQL|native client|JDBC",
    re.I,
)

_MAXREAD = 1 << 16  # cap response read at 64 KiB


@dataclass
class SQLiResult:
    host: str
    endpoint: str
    parameter: str
    vulnerable: bool = False
    payload_that_worked: str | None = None
    detection_method: str | None = None     # "error-based" | "boolean-based"
    evidence: str | None = None
    tested_payloads: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def _insecure_ctx() -> ssl.SSLContext:
    """CPE mgmt pages use self-signed certs — don't fail on them."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _send(url: str, method: str, params: dict[str, str],
          timeout: float = 8.0) -> tuple[int | None, str, str | None]:
    """Send one request. Return (status, body, error).

    An HTTP error status still carries a body (the SQL error may be in it), so
    we read and return it instead of treating it as a hard failure.
    """
    ctx = _insecure_ctx() if url.lower().startswith("https") else None
    headers = {"User-Agent": "weaknd/0.1"}
    if method.upper() == "GET":
        sep = "&" if "?" in url else "?"
        req = urllib.request.Request(url + sep + urllib.parse.urlencode(params),
                                     headers=headers)
    else:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        req = urllib.request.Request(url, data=urllib.parse.urlencode(params).encode(),
                                     headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.getcode(), r.read(_MAXREAD).decode("utf-8", "replace"), None
    except urllib.error.HTTPError as e:
        try:
            body = e.read(_MAXREAD).decode("utf-8", "replace")
        except Exception:
            body = ""
        return e.code, body, None
    except (urllib.error.URLError, OSError, ValueError) as e:
        return None, "", f"{type(e).__name__}: {e}"


def _error_line(body: str, match: re.Match) -> str:
    hit = match.group(0)
    for line in body.splitlines():
        if hit in line:
            return line.strip()[:200]
    return hit[:200]


def probe_sqli(base_url: str, endpoint_path: str, param_name: str,
               http_method: str = "POST",
               extra_params: dict[str, str] | None = None) -> SQLiResult:
    """Test one parameter for SQL injection (error-based + boolean-based).

    Baseline first, then each test string. Stops at the first clear signal:
    a SQL error the baseline did not have (error-based), or an always-true
    condition that markedly changes the response (boolean-based).
    """
    extra = dict(extra_params or {})
    host = urllib.parse.urlparse(base_url).hostname or base_url
    url = base_url.rstrip("/") + "/" + endpoint_path.lstrip("/")
    res = SQLiResult(host=host, endpoint=endpoint_path, parameter=param_name,
                     tested_payloads=list(PAYLOADS))

    # Baseline — normal value.
    base_status, base_body, err = _send(url, http_method, {param_name: BASELINE, **extra})
    if err:
        res.notes.append(f"baseline request failed: {err}")
        return res
    base_len = len(base_body)
    base_has_err = bool(SQL_ERROR_RE.search(base_body))
    if base_has_err:
        res.notes.append("baseline already shows a SQL error signature — "
                         "error-based detection unreliable, using boolean only")
    res.notes.append(f"baseline: HTTP {base_status}, {base_len} bytes")

    for payload in PAYLOADS:
        status, body, err = _send(url, http_method, {param_name: payload, **extra})
        if err:
            res.notes.append(f"{payload!r}: {err}")
            continue

        # (a) error-based — a SQL error the baseline did not have.
        m = SQL_ERROR_RE.search(body)
        if m and not base_has_err:
            res.vulnerable = True
            res.payload_that_worked = payload
            res.detection_method = "error-based"
            res.evidence = _error_line(body, m)
            res.notes.append(f"error-based: {payload!r} surfaced a SQL error")
            return res

        # (b) boolean-based — always-true input changes the response markedly.
        if payload in _ALWAYS_TRUE:
            diff = abs(len(body) - base_len)
            big = base_len and diff > max(100, int(base_len * 0.3))
            if status != base_status or big:
                res.vulnerable = True
                res.payload_that_worked = payload
                res.detection_method = "boolean-based"
                res.evidence = (f"baseline HTTP {base_status}/{base_len}B vs "
                                f"payload HTTP {status}/{len(body)}B")
                res.notes.append(f"boolean-based: {payload!r} changed the response")
                return res
            res.notes.append(f"{payload!r}: HTTP {status}/{len(body)}B — no significant change")
        else:
            res.notes.append(f"{payload!r}: HTTP {status}/{len(body)}B — no SQL error")

    res.notes.append("no SQL error or boolean difference observed — "
                     "input appears sanitized (good)")
    return res


def run(base_url: str, endpoint_path: str, param_name: str,
        http_method: str = "POST", save: bool = True) -> SQLiResult:
    """Probe + persist, mirroring the other stages' report.save() behavior."""
    res = probe_sqli(base_url, endpoint_path, param_name, http_method)
    if save:
        report.save("sqli", res.host, res)
    return res


if __name__ == "__main__":
    # Standalone runner (run from the tool/ dir so package imports resolve):
    #   python -m weaknd.sqli_probe 192.168.1.1 --endpoint /login --param user
    import argparse

    ap = argparse.ArgumentParser(description="SQL-injection input-validation probe "
                                             "(own-device test, read-only).")
    ap.add_argument("host", help="device host/IP (own lab device)")
    ap.add_argument("--endpoint", required=True, help="form/endpoint path, e.g. /login")
    ap.add_argument("--param", required=True, help="parameter name to test")
    ap.add_argument("--method", default="POST", choices=["GET", "POST"])
    ap.add_argument("--scheme", default="http", choices=["http", "https"])
    a = ap.parse_args()

    base = f"{a.scheme}://{a.host}"
    r = run(base, a.endpoint, a.param, a.method)
    print(f"\n=== sqli-probe ===")
    print(f"  host:       {r.host}")
    print(f"  endpoint:   {r.endpoint}  (param={r.parameter}, {a.method})")
    print(f"  vulnerable: {'YES' if r.vulnerable else 'no'}")
    if r.vulnerable:
        print(f"  method:     {r.detection_method}")
        print(f"  payload:    {r.payload_that_worked}")
        print(f"  evidence:   {r.evidence}")
    for n in r.notes:
        print(f"   - {n}")
