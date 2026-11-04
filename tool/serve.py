#!/usr/bin/env python3
"""weaknd demo backend — tiny stdlib HTTP server that drives the real harness.

Serves the dashboard (web/index.html) and exposes a JSON API that runs the
actual weaknd modules against a target, stage by stage, so the frontend can
animate a real scan. No third-party deps.

    python serve.py            # -> http://127.0.0.1:8777
    python serve.py --port 9000

Demo safety: if a stage raises or a host is unreachable, the API returns a
structured error the UI can show instead of crashing. Pass ?demo=1 to replay
fictional documentation-only sample data.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from weaknd import (discovery, surface, ssh_probe, default_audit, cwmp_probe,
                    telnet_probe, wan_scan, pentest, creds,
                    credential_testing, nikto_scan, attack, privesc, report)

WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")
ARTIFACT_DIR = Path(__file__).resolve().parent.parent / "artifacts"

# Generic canned replay data for the LAN workflow.
DEMO = {
    "discovery": {
        "context": {
            "vantage": "lan", "interface": "wlp0s20f3",
            "address": "192.0.2.50", "prefixlen": 24,
            "network": "192.0.2.0/24", "gateway": "192.0.2.1",
            "ssid": "CPE-LAB", "bssid": "00:11:22:33:44:66",
        },
        "scan_profile": "top", "service_detection": True, "udp_profile": "none",
        "hosts": [
            {"address": "192.0.2.1", "state": "up",
             "mac": "00:11:22:33:44:55", "vendor": None,
             "is_self": False, "is_gateway": True,
             "display_name": "Gateway · CPE-LAB", "role": "gateway/router",
             "matched_ssids": ["CPE-LAB"], "identity_confidence": "confirmed-role",
             "identity_notes": [],
             "ports": [
                 {"port": 22, "protocol": "tcp", "service": "ssh",
                  "product": None, "version": None, "extra_info": None},
                 {"port": 53, "protocol": "tcp", "service": "domain",
                  "product": None, "version": None, "extra_info": None},
                 {"port": 80, "protocol": "tcp", "service": "http",
                  "product": None, "version": None, "extra_info": None},
                 {"port": 443, "protocol": "tcp", "service": "https",
                  "product": None, "version": None, "extra_info": None},
             ]},
            {"address": "192.0.2.50", "state": "up",
             "mac": None, "vendor": None, "is_self": True,
             "is_gateway": False, "ports": [], "display_name": "This laptop",
             "role": "scanner laptop", "matched_ssids": [],
             "identity_confidence": "confirmed", "identity_notes": []},
        ],
        "wifi_networks": [
            {"ssid": "CPE-LAB", "bssid": "00:11:22:33:44:66",
             "signal": 86, "channel": 48, "security": "WPA2", "active": True},
            {"ssid": "CPE-WAN-LAB", "bssid": "00:11:22:33:44:77",
             "signal": 67, "channel": 6, "security": "WPA2", "active": False},
        ],
        "notes": ["replay data; no authentication was attempted"],
    },
    "surface": {
        "host": "192.0.2.1", "open_ports": [22, 53, 80, 443],
        "services": {"22": "ssh", "53": "domain", "80": "http", "443": "https"},
        "vendor": None,
        "http_title": "Example CPE Management", "hints": [],
    },
    "ssh": {
        "host": "192.0.2.1", "port": 22, "banner": "SSH-2.0-ssh",
        "auth_methods": ["publickey", "password"], "reachable": True,
        "notes": ["version string masked by the device SSH service",
                  "password auth accepted — credential strategy applies"],
    },
    "default_audit": {
        "host": "192.0.2.1", "port": 22, "profile": "minimal",
        "in_connected_lan": True, "ssh_banner": "SSH-2.0-dropbear",
        "auth_methods": ["password"],
        "legacy_ssh_options": [
            "-oKexAlgorithms=+diffie-hellman-group14-sha1,diffie-hellman-group1-sha1",
            "-oHostKeyAlgorithms=+ssh-rsa,ssh-dss",
            "-oPubkeyAcceptedAlgorithms=+ssh-rsa"
        ],
        "attempts": [
            {"credential_id": "generic-admin-admin", "label": "admin/admin",
             "username": "admin", "status": "success"}
        ],
        "found": True, "credential_id": "generic-admin-admin",
        "credential_label": "admin/admin", "username": "admin",
        "proof": "uid=0(root) gid=0(root)", "is_root": True,
        "notes": ["replay: bounded sequential audit stopped on first success"]
    },
    "creds": {
        "host": "192.0.2.1", "port": 22, "service": "ssh", "derived": [],
        "defaults": [["admin", "admin"], ["admin", "1234"], ["admin", "password"],
                     ["supervisor", "supervisor"], ["root", "root"], ["user", "user"]],
        "notes": ["manufacturer-specific derivation is not configured for this sample",
                  "hydra not installed — `sudo apt install hydra` for brute-force arm",
                  "order: derive -> defaults -> brute (lockout-aware)"],
    },
    # Generic replay outcome: the bounded default profile does not match.
    "attack": {
        "host": "192.0.2.1", "port": 22, "found": False, "user": None,
        "via": None, "attempts": 6,
        "tried": ["credential dictionary entry (redacted)"],
        "notes": ["no derived candidate yet (serial unknown / keygen unvalidated)",
                  "defaults failed → brute/derive required",
                  "next: LFI serial leak (CVE-2023-28770) or hydra wordlist"],
    },
    # Illustrative privesc on a reference BusyBox CPE (admin login == root path).
    "privesc": {
        "host": "reference-cpe", "user": "admin", "uid": "uid=0(root) gid=0(root)",
        "is_root": True, "escalation": True,
        "findings": [
            {"sev": "CRITICAL", "label": "admin==root",
             "detail": "'admin' login yields uid=0 — management account IS root. Full compromise on auth."},
            {"sev": "HIGH", "label": "shadow-readable",
             "detail": "/etc/shadow readable — password hashes leak (offline crack)."},
            {"sev": "INFO", "label": "suid-inventory", "detail": "/bin/busybox (multicall) ..."},
        ],
        "notes": ["Linux 4.1.51 armv7l / BusyBox v1.22.1"],
    },
}


def _asdict(o):
    return report.safe_data(o)


def _latest_lan_results():
    discoveries = sorted(ARTIFACT_DIR.glob("*_discover_*.json"),
                         key=lambda path: path.stat().st_mtime, reverse=True)
    if not discoveries:
        return {"discovery": None, "default_audits": {}}
    discovery_data = json.loads(discoveries[0].read_text())
    audits = {}
    audit_paths = sorted(ARTIFACT_DIR.glob("*_default-audit_*.json"),
                         key=lambda path: path.stat().st_mtime, reverse=True)
    for path in audit_paths:
        data = json.loads(path.read_text())
        host = data.get("host")
        if host and host not in audits:
            audits[host] = data
    return {"discovery": discovery_data, "default_audits": audits}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # quiet
        pass

    def _send(self, code, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else json.dumps(body, default=_asdict,
                                                                ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        host = (q.get("host") or [""])[0]
        demo = q.get("demo", ["0"])[0] == "1"

        if u.path in ("/", "/index.html"):
            return self._file("index.html", "text/html; charset=utf-8")
        if u.path.startswith("/static/"):
            return self._file(u.path[len("/static/"):], None)

        try:
            if u.path == "/api/latest-lan":
                return self._send(200, _latest_lan_results())
            if u.path == "/api/interfaces":
                return self._send(200, {"interfaces": wan_scan.available_interfaces()})
            if u.path == "/api/wan-scan":
                profile = (q.get("profile") or ["quick"])[0]
                manufacturer = (q.get("manufacturer") or [""])[0].strip()[:80]
                model = (q.get("model") or [""])[0].strip()[:80]
                job_id = (q.get("job_id") or [""])[0].strip()[:80]
                interface = (q.get("interface") or [""])[0].strip()[:80]
                if profile not in wan_scan.PROFILES:
                    return self._send(400, {"error": "bad_scan_profile"})
                if demo:
                    res = wan_scan.demo_result(profile, manufacturer, model)
                else:
                    res = wan_scan.run(host, profile, manufacturer, model, job_id, interface)
                    report.save("wan-scan", host, res)
                return self._send(200, res)
            if u.path == "/api/wan-cancel":
                job_id = (q.get("job_id") or [""])[0].strip()[:80]
                return self._send(200, {"cancelled": wan_scan.cancel(job_id)})
            if u.path == "/api/pentest-cancel":
                job_id = (q.get("job_id") or [""])[0].strip()[:80]
                return self._send(200, {"cancelled": pentest.cancel(job_id)})
            if u.path == "/api/credential-cancel":
                job_id = (q.get("job_id") or [""])[0].strip()[:80]
                return self._send(200, {"cancelled": credential_testing.cancel(job_id)})
            if u.path == "/api/nikto-options":
                return self._send(200, nikto_scan.options())
            if u.path == "/api/nikto-cancel":
                job_id = (q.get("job_id") or [""])[0].strip()[:80]
                return self._send(200, {"cancelled": nikto_scan.cancel(job_id)})
            if u.path == "/api/discover":
                if demo:
                    return self._send(200, DEMO["discovery"])
                vantage = (q.get("vantage") or ["lan"])[0]
                scan_profile = (q.get("scan") or ["top"])[0]
                udp_profile = (q.get("udp") or ["none"])[0]
                if vantage not in {"current", "lan", "wan"}:
                    return self._send(400, {"error": "bad_vantage"})
                if scan_profile not in {"none", "common", "top", "all"}:
                    return self._send(400, {"error": "bad_scan_profile"})
                if udp_profile not in {"none", "common"}:
                    return self._send(400, {"error": "bad_udp_profile"})
                full_gateway = (q.get("full_gateway") or ["0"])[0] == "1"
                assume_up = (q.get("assume_up") or ["0"])[0] == "1"
                res = discovery.run(vantage=vantage, scan_profile=scan_profile,
                                    full_gateway=full_gateway, assume_up=assume_up,
                                    udp_profile=udp_profile)
                report.save("discover", res.context.network, res)
                return self._send(200, res)
            if u.path == "/api/surface":
                res = DEMO["surface"] if demo else surface.run(host)
                return self._send(200, res)
            if u.path == "/api/ssh":
                res = DEMO["ssh"] if demo else ssh_probe.run(host, 22, "root")
                return self._send(200, res)
            if u.path == "/api/default-audit":
                profile = (q.get("profile") or ["minimal"])[0]
                if profile not in {"minimal", "common"}:
                    return self._send(400, {"error": "bad_credential_profile"})
                res = (DEMO["default_audit"] if demo
                       else default_audit.run(host, profile=profile))
                report.save("default-audit", host, res)
                return self._send(200, res)
            if u.path == "/api/cwmp":
                res = cwmp_probe.run(host)
                report.save("cwmp", host, res)
                return self._send(200, res)
            if u.path == "/api/telnet":
                res = telnet_probe.run(host)
                report.save("telnet", host, res)
                return self._send(200, res)
            if u.path == "/api/creds":
                vendor = (q.get("vendor") or [None])[0]
                serial = (q.get("serial") or [None])[0]
                res = DEMO["creds"] if demo else creds.plan(host, vendor=vendor, serial=serial)
                return self._send(200, res)
            if u.path == "/api/attack":
                vendor = (q.get("vendor") or [None])[0]
                serial = (q.get("serial") or [None])[0]
                brute = q.get("brute", ["0"])[0] == "1"   # off by default (lockout-safe)
                res = (DEMO["attack"] if demo
                       else attack.attack(host, vendor=vendor, serial=serial, use_brute=brute))
                return self._send(200, res)
            if u.path == "/api/privesc":
                if demo:
                    return self._send(200, DEMO["privesc"])
                user = (q.get("user") or [None])[0]
                pw = (q.get("password") or [None])[0]
                if not user or pw is None:
                    return self._send(200, {"skipped": True,
                                            "reason": "no credential yet — run attack first"})
                return self._send(200, privesc.run(host, user, pw))
        except Exception as e:  # demo safety
            return self._send(200, {"error": type(e).__name__, "detail": str(e)})

        self._send(404, {"error": "not_found", "path": u.path})

    def do_POST(self):
        u = urlparse(self.path)
        if u.path in {"/api/pentest-checks", "/api/pentest-run",
                      "/api/credential-options", "/api/credential-run",
                      "/api/nikto-run"}:
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                return self._send(400, {"error": "invalid_content_length"})
            if length <= 0 or length > 2 * 1024 * 1024:
                return self._send(400, {"error": "invalid_json_payload_size"})
            try:
                payload = json.loads(self.rfile.read(length))
                target = str(payload.get("target") or "")
                recon = payload.get("recon") or {}
                if u.path == "/api/nikto-run":
                    result = nikto_scan.run(
                        target=target,
                        protocol=str(payload.get("protocol") or ""),
                        port=int(payload.get("port") or 0),
                        categories=payload.get("categories") or [],
                        disruptive_confirmed=payload.get("disruptive_confirmed") is True,
                        job_id=str(payload.get("job_id") or "nikto")[:80],
                    )
                    report.save(f"nikto-{result.scan_id}", result.target, result)
                    return self._send(200, result)
                if u.path == "/api/credential-options":
                    return self._send(200, credential_testing.options(recon))
                if recon.get("sample_data"):
                    return self._send(400, {"error": "live_recon_required",
                                            "detail": "Pentest engines do not run against simulated Recon data."})
                if u.path == "/api/credential-run":
                    result = credential_testing.run(
                        target=target,
                        protocol=str(payload.get("protocol") or ""),
                        port=int(payload.get("port") or 0),
                        mode=str(payload.get("mode") or ""),
                        username=(str(payload.get("username"))
                                  if payload.get("username") is not None else None),
                        password=(str(payload.get("password"))
                                  if payload.get("password") is not None else None),
                        selected_default_ids=[str(item) for item in
                                              payload.get("selected_default_ids", [])],
                        authorized=payload.get("authorized") is True,
                        job_id=str(payload.get("job_id") or "credential-test")[:80],
                    )
                    report.save("credential-test", result.target, result)
                    return self._send(200, result)
                manufacturer = str(payload.get("manufacturer") or "")[:80]
                model = str(payload.get("model") or "")[:80]
                if u.path == "/api/pentest-checks":
                    return self._send(200, pentest.availability(
                        target, recon, manufacturer, model))
                engines = [item for item in payload.get("engines", [])
                           if item in {"nmap", "nuclei", "routersploit"}]
                selected_checks = [str(item)[:300] for item in payload.get("selected_checks", [])]
                interface = str(payload.get("interface") or "")[:80]
                job_id = str(payload.get("job_id") or "pentest")[:80]
                result = pentest.run(target, recon, engines, selected_checks,
                                     manufacturer, model, interface, job_id)
                report.save("pentest", target, result)
                return self._send(200, result)
            except Exception as error:
                return self._send(200, {"status": "error", "error": type(error).__name__,
                                        "detail": str(error)})
        return self._send(404, {"error": "not_found", "path": u.path})

    def _file(self, name, ctype):
        path = os.path.normpath(os.path.join(WEB_DIR, name))
        if not path.startswith(WEB_DIR) or not os.path.isfile(path):
            return self._send(404, {"error": "no_file", "name": name})
        if ctype is None:
            ext = os.path.splitext(path)[1]
            ctype = {".css": "text/css", ".js": "text/javascript",
                     ".svg": "image/svg+xml"}.get(ext, "application/octet-stream")
        with open(path, "rb") as f:
            self._send(200, f.read(), ctype)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8777)
    ap.add_argument("--host", default="127.0.0.1")
    a = ap.parse_args()
    srv = ThreadingHTTPServer((a.host, a.port), Handler)
    print(f"weaknd dashboard → http://{a.host}:{a.port}  (Ctrl-C to stop)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nbye")


if __name__ == "__main__":
    main()
