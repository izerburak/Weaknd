"""Stage 1 — attack surface mapping.

Port/service enumeration + lightweight vendor fingerprint from the HTTP
management page. Wraps nmap when present, falls back to a TCP connect scan.
"""
from __future__ import annotations

import re
import shutil
import socket
import subprocess
import urllib.request
import ssl
from dataclasses import dataclass, field

# Common CPE management ports worth probing (LAN + typical WAN-exposed set).
DEFAULT_PORTS = [22, 23, 53, 80, 443, 161, 2222, 7547, 8080, 8443, 8443, 9000]

# Cheap vendor hints from the web management page.
VENDOR_SIGNS = {
    "zyxel": "Zyxel",
    "web-based configurator": "Zyxel",
    "arcadyan": "Arcadyan",
    "huawei": "Huawei",
    "zte": "ZTE",
    "sagem": "Sagemcom",
    "technicolor": "Technicolor",
    "tp-link": "TP-Link",
    "mikrotik": "MikroTik",
}


@dataclass
class SurfaceResult:
    host: str
    open_ports: list[int] = field(default_factory=list)
    services: dict[int, str] = field(default_factory=dict)
    vendor: str | None = None
    http_title: str | None = None
    hints: list[str] = field(default_factory=list)


def _tcp_open(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def scan_ports(host: str, ports: list[int] | None = None) -> dict[int, str]:
    """Return {port: service} for open ports. Uses nmap if available."""
    ports = sorted(set(ports or DEFAULT_PORTS))
    if shutil.which("nmap"):
        return _nmap(host, ports)
    return {p: "" for p in ports if _tcp_open(host, p)}


def _nmap(host: str, ports: list[int]) -> dict[int, str]:
    plist = ",".join(str(p) for p in ports)
    out = subprocess.run(
        ["nmap", "-Pn", "-n", "-T4", "-sV", "--version-intensity", "2",
         "--open", "--max-retries", "1", "--host-timeout", "40s",
         "-p", plist, host],
        capture_output=True, text=True, timeout=90,
    ).stdout
    found: dict[int, str] = {}
    for line in out.splitlines():
        m = re.match(r"^(\d+)/tcp\s+open\s+(\S+)", line)
        if m:
            found[int(m.group(1))] = m.group(2)
    return found


def http_fingerprint(host: str) -> tuple[str | None, str | None, list[str]]:
    """Fetch the mgmt page; return (vendor, title, hints)."""
    hints: list[str] = []
    body = ""
    for scheme, ctx in (("http", None), ("https", _insecure_ctx())):
        try:
            req = urllib.request.Request(f"{scheme}://{host}/",
                                         headers={"User-Agent": "weaknd/0.1"})
            with urllib.request.urlopen(req, timeout=6, context=ctx) as r:
                body = r.read(8192).decode("utf-8", "replace")
                if body:
                    break
        except Exception:
            continue
    if not body:
        return None, None, hints

    title = None
    m = re.search(r"<title>([^<]*)</title>", body, re.I)
    if m:
        title = m.group(1).strip()
    low = body.lower()
    vendor = next((v for sign, v in VENDOR_SIGNS.items() if sign in low), None)
    for model in re.findall(r"\b(EX\d{3,4}[A-Z0-9-]*|VMG\d{3,4}[A-Z0-9-]*|DX\d{3,4}[A-Z0-9-]*)\b", body):
        hints.append(f"model-candidate:{model}")
    return vendor, title, hints


def _insecure_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def run(host: str, ports: list[int] | None = None) -> SurfaceResult:
    services = scan_ports(host, ports)
    res = SurfaceResult(host=host, open_ports=sorted(services), services=services)
    if 80 in services or 443 in services or 8080 in services:
        res.vendor, res.http_title, res.hints = http_fingerprint(host)
    # surface-level WAN-risk annotations
    if 7547 in services:
        res.hints.append("TR-069/CWMP reachable — check ACS auth & connection-request")
    if 23 in services:
        res.hints.append("telnet open — legacy mgmt, likely weak/default creds")
    return res
