"""Unauthenticated access-control check (auth-bypass probe).

Web management UIs are supposed to gate their internal pages (status, config,
system info, ...) behind a login. When one of those pages is reachable with no
credentials, that's a broken-access-control vulnerability — a common CPE flaw.
This module checks whether internal pages answer without authentication.

SCOPE / SAFETY:
    * Authorized use only — run this against your OWN home-lab devices.
    * READ-ONLY: every request is a plain HTTP GET. Nothing is submitted,
      changed, or saved on the device.
    * We send no credentials and we do not follow redirects, so we can tell a
      served page apart from a login redirect.

Like the other stages, a run produces an AuthBypassResult dataclass and is
saved as JSON under ../artifacts/ via report.save().
"""
from __future__ import annotations

import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

from . import report

# Common internal CPE pages that should require a login.
DEFAULT_PATHS = [
    "/admin/",
    "/status.html",
    "/system.html",
    "/config.html",
    "/info.html",
    "/network.html",
]

# A body that carries a password field / login form is itself a login page —
# serving it is NOT a bypass, so we treat it as protected.
LOGIN_RE = re.compile(
    r"type=['\"]?password|name=['\"]?(?:password|passwd|pwd)\b"
    r"|<form[^>]*login|loginform|j_security_check",
    re.I,
)

_MAXREAD = 1 << 16  # cap response read at 64 KiB
_REDIRECTS = {301, 302, 303, 307, 308}


@dataclass
class AuthBypassResult:
    host: str
    base_url: str
    accessible_pages: list[str] = field(default_factory=list)   # unprotected
    protected_pages: list[str] = field(default_factory=list)    # login/redirect/401/403
    tested_paths: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def _insecure_ctx() -> ssl.SSLContext:
    """CPE mgmt pages use self-signed certs — don't fail on them."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Don't follow redirects — surface them as HTTPError so we can inspect."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _get(url: str, timeout: float = 8.0) -> tuple[int | None, str | None, str, str | None]:
    """GET without following redirects. Return (status, location, body, error)."""
    opener = urllib.request.build_opener(
        _NoRedirect, urllib.request.HTTPSHandler(context=_insecure_ctx()))
    req = urllib.request.Request(url, headers={"User-Agent": "weaknd/0.1"})
    try:
        with opener.open(req, timeout=timeout) as r:
            body = r.read(_MAXREAD).decode("utf-8", "replace")
            return r.getcode(), r.headers.get("Location"), body, None
    except urllib.error.HTTPError as e:
        loc = e.headers.get("Location") if e.headers else None
        try:
            body = e.read(_MAXREAD).decode("utf-8", "replace")
        except Exception:
            body = ""
        return e.code, loc, body, None
    except (urllib.error.URLError, OSError, ValueError) as e:
        return None, None, "", f"{type(e).__name__}: {e}"


def _looks_like_login(body: str) -> bool:
    return bool(body) and bool(LOGIN_RE.search(body))


def probe_auth_bypass(base_url: str, paths: list[str] | None = None) -> AuthBypassResult:
    """Test whether internal pages answer without authentication.

    For each path, GET it with no credentials and classify:
        * 200 that is NOT a login form        -> accessible (unprotected)  [FINDING]
        * redirect to login / 401 / 403       -> protected
        * other (404/5xx/error)               -> noted, not classified
    """
    paths = paths or list(DEFAULT_PATHS)
    host = urllib.parse.urlparse(base_url).hostname or base_url
    res = AuthBypassResult(host=host, base_url=base_url.rstrip("/"),
                           tested_paths=list(paths))

    for path in paths:
        url = res.base_url + "/" + path.lstrip("/")
        status, loc, body, err = _get(url)
        if err:
            res.notes.append(f"{path}: {err}")
            continue

        if status in (401, 403):
            res.protected_pages.append(path)
            res.notes.append(f"{path}: HTTP {status} — protected")
        elif status in _REDIRECTS:
            dest = (loc or "").lower()
            tag = "redirect to login" if "login" in dest else f"redirect -> {loc or '?'}"
            res.protected_pages.append(path)
            res.notes.append(f"{path}: HTTP {status} {tag} — protected")
        elif status == 200:
            if _looks_like_login(body):
                res.protected_pages.append(path)
                res.notes.append(f"{path}: HTTP 200 but serves a login form — protected")
            else:
                res.accessible_pages.append(path)
                res.notes.append(f"{path}: HTTP 200, no login form — UNPROTECTED (reachable without auth)")
        else:
            res.notes.append(f"{path}: HTTP {status} — not classified (likely absent/error)")

    if not res.accessible_pages:
        res.notes.append("no internal page reachable without auth — access control looks enforced (good)")
    return res


def run(base_url: str, paths: list[str] | None = None, save: bool = True) -> AuthBypassResult:
    """Probe + persist, mirroring the other stages' report.save() behavior."""
    res = probe_auth_bypass(base_url, paths)
    if save:
        report.save("authbypass", res.host, res)
    return res


if __name__ == "__main__":
    # Standalone runner (run from the tool/ dir so package imports resolve):
    #   python -m weaknd.authbypass_probe 192.168.1.1 --scheme http
    import argparse

    ap = argparse.ArgumentParser(description="Unauthenticated access-control check "
                                             "(own-device test, GET-only, read-only).")
    ap.add_argument("host", help="device host/IP (own lab device)")
    ap.add_argument("--scheme", default="http", choices=["http", "https"])
    ap.add_argument("--paths", help="comma-separated paths to test (overrides defaults)")
    a = ap.parse_args()

    base = f"{a.scheme}://{a.host}"
    paths = [p.strip() for p in a.paths.split(",") if p.strip()] if a.paths else None
    r = run(base, paths)
    print(f"\n=== authbypass-probe ===")
    print(f"  base_url:   {r.base_url}")
    print(f"  accessible: {r.accessible_pages or 'none'}")
    print(f"  protected:  {r.protected_pages or 'none'}")
    for n in r.notes:
        print(f"   - {n}")
