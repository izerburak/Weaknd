#!/usr/bin/env python3
"""weaknd — CPE penetration testing harness (CLI).

Usage:
    python weaknd.py discover [CIDR] [--vantage current|lan|wan]
                                        [--scan none|common|top|all]
                                        [--udp none|common]
                                        [--full-gateway] [--assume-up]
    python weaknd.py scan       <host> [--ports 22,80,443]
    python weaknd.py ssh-probe  <host> [--port 22] [--user root]
    python weaknd.py default-audit <host> [--profile minimal|common]
                                        # bounded SSH factory-default audit; no Hydra
    python weaknd.py cwmp-probe <host> [--port 7547]
    python weaknd.py telnet-probe <host> [--port 23]
    python weaknd.py creds      <host> [--service ssh] [--port 22]
                                        [--vendor zyxel] [--serial S210Y...]
    python weaknd.py recon      <host>     # scan + ssh-probe + creds plan, one shot
    python weaknd.py enum       <host> [--user root --password PW] [--port 22]
                                        # on-device recon of my own box (needs shell)
    python weaknd.py inject     <host> --endpoint <path> --param <name>
                                        [--method GET|POST] [--scheme http|https]
    python weaknd.py snmp       <host> [--port 161]   # default/weak community check
    python weaknd.py authbypass <host> [--scheme http|https] [--paths /a,/b]
    python weaknd.py sqli       <host> --endpoint <path> --param <name>
                                        [--method GET|POST] [--scheme http|https]
    python weaknd.py xss        <host> --endpoint <path> --param <name>
                                        [--method GET|POST] [--scheme http|https]
    python weaknd.py traversal  <host> --endpoint <path> --param <name>
                                        [--method GET|POST] [--scheme http|https]
    python weaknd.py webaudit   <host> [--endpoint <path> --param <name>]
                                        [--method GET|POST] [--scheme http|https]

Every run is saved as JSON under ../artifacts/.
"""
from __future__ import annotations

import argparse
import getpass
import sys

from weaknd import (discovery, surface, ssh_probe, default_audit, cwmp_probe,
                    telnet_probe, creds, attack, privesc, enum,
                    injection_probe, snmp_probe, authbypass_probe, sqli_probe,
                    xss_probe, traversal_probe, report)


def _ports(s: str | None):
    return [int(p) for p in s.split(",")] if s else None


def _show(title: str, obj) -> None:
    print(f"\n=== {title} ===")
    values = report.safe_data(obj)
    for k, v in values.items():
        print(f"  {k}: {v}")


def _read_password(args) -> str:
    if getattr(args, "password_stdin", False):
        return sys.stdin.readline().rstrip("\r\n")
    return getpass.getpass("Password: ")


def cmd_discover(a) -> object:
    """Map what this laptop can see; never attempts authentication."""
    res = discovery.run(
        cidr=a.cidr,
        interface=a.interface,
        vantage=a.vantage,
        scan_profile=a.scan,
        service_detection=not a.no_service_detect,
        include_self=a.include_self,
        full_gateway=a.full_gateway,
        allow_large=a.allow_large,
        assume_up=a.assume_up,
        udp_profile=a.udp,
    )
    print("\n" + "\n".join(discovery.summary_lines(res)))
    path = report.save("discover", res.context.network, res)
    print(f"\nreport: {path}")
    return res


def cmd_scan(a) -> object:
    res = surface.run(a.host, _ports(a.ports))
    _show("surface", res)
    report.save("surface", a.host, res)
    return res


def cmd_ssh_probe(a) -> object:
    res = ssh_probe.run(a.host, a.port, a.user)
    _show("ssh", res)
    report.save("ssh", a.host, res)
    return res


def cmd_default_audit(a) -> object:
    res = default_audit.run(a.host, a.port, a.profile, a.delay)
    _show("ssh-default-audit", res)
    path = report.save("default-audit", a.host, res)
    print(f"\n  result: {'CONFIRMED DEFAULT' if res.found else 'no confirmed default'}")
    if res.found:
        print(f"  credential profile hit: {res.credential_label} ({res.credential_id})")
        print(f"  proof: {res.proof}")
    print(f"  report: {path}")
    return res


def cmd_cwmp_probe(a) -> object:
    res = cwmp_probe.run(a.host, a.port)
    _show("cwmp-probe", res)
    path = report.save("cwmp", a.host, res)
    print(f"\n  verdict: {res.verdict}")
    print(f"  report: {path}")
    return res


def cmd_telnet_probe(a) -> object:
    res = telnet_probe.run(a.host, a.port)
    _show("telnet-probe", res)
    path = report.save("telnet", a.host, res)
    print(f"\n  reachable: {'YES' if res.reachable else 'no'}")
    print(f"  report: {path}")
    return res


def cmd_creds(a) -> object:
    res = creds.plan(a.host, a.port, a.service, a.vendor, a.serial)
    _show("creds-plan", res)
    report.save("creds", a.host, res)
    return res


def cmd_attack(a) -> object:
    res = attack.attack(a.host, a.port, a.vendor, a.serial, use_brute=not a.no_brute)
    _show("cred-attack", res)
    report.save("attack", a.host, res)
    if res.found:
        print(f"\n  >>> VALID credential for {res.user} (via {res.via}; secret redacted)")
    return res


def cmd_privesc(a) -> object:
    res = privesc.run(a.host, a.user, _read_password(a), a.port)
    _show("privesc", res)
    print("\n  escalation:", "YES" if res.escalation else "no")
    for f in res.findings:
        print(f"   [{f['sev']}] {f['label']}: {f['detail'][:120]}")
    report.save("privesc", a.host, res)
    return res


def cmd_pwn(a) -> object:
    """Full realistic chain: scan -> ssh-probe -> attack -> login -> privesc."""
    s = surface.run(a.host); _show("surface", s)
    if 22 not in s.open_ports:
        print("\n  no SSH — stopping."); return s
    sp = ssh_probe.run(a.host, 22, "root"); _show("ssh", sp)
    print("\n--- Stage 3: credential attack (derive -> default -> brute) ---")
    at = attack.attack(a.host, 22, s.vendor, a.serial, use_brute=not a.no_brute)
    _show("cred-attack", at)
    if not at.found:
        print("\n  no credential found — stopping before login."); return at
    print(f"\n  >>> VALID credential for {at.user} (via {at.via}; secret redacted)")
    print("\n--- Stage 5: privilege escalation ---")
    pe = privesc.run(a.host, at.user, at.password, 22)
    _show("privesc", pe)
    print("\n  escalation:", "YES" if pe.escalation else "no")
    for f in pe.findings:
        print(f"   [{f['sev']}] {f['label']}: {f['detail'][:120]}")
    report.save("pwn", a.host, {"surface": s, "attack": at, "privesc": pe})
    return pe


def cmd_enum(a) -> object:
    """On-device recon of my own test box: inventory firmware/services/network/
    TR-069/capabilities and list where secrets live (feeds the loot stage)."""
    res = enum.run(a.host, a.user, _read_password(a), a.port)
    print("\n" + "\n".join(enum.summary_lines(res)))
    path = report.save("enum", a.host, res)
    print(f"\n  report: {path}")
    return res


def cmd_inject(a) -> object:
    base = f"{a.scheme}://{a.host}"
    res = injection_probe.run(base, a.endpoint, a.param, a.method)
    _show("inject", res)
    print("\n  vulnerable:", "YES" if res.vulnerable else "no")
    if res.vulnerable:
        print(f"   payload: {res.payload_that_worked}")
        print(f"   evidence: {res.evidence}")
    return res


def cmd_snmp(a) -> object:
    res = snmp_probe.run(a.host, a.port)
    _show("snmp", res)
    print("\n  readable:", "YES" if res.readable else "no")
    if res.readable:
        print(f"   community: {res.working_community}")
        print(f"   sysDescr: {res.sample_data}")
    return res


def cmd_sqli(a) -> object:
    base = f"{a.scheme}://{a.host}"
    res = sqli_probe.run(base, a.endpoint, a.param, a.method)
    _show("sqli", res)
    print("\n  vulnerable:", "YES" if res.vulnerable else "no")
    if res.vulnerable:
        print(f"   method: {res.detection_method}")
        print(f"   payload: {res.payload_that_worked}")
        print(f"   evidence: {res.evidence}")
    return res


def cmd_xss(a) -> object:
    base = f"{a.scheme}://{a.host}"
    res = xss_probe.run(base, a.endpoint, a.param, a.method)
    _show("xss", res)
    print("\n  vulnerable:", "YES" if res.vulnerable else "no")
    if res.vulnerable:
        print(f"   payload: {res.payload_that_worked}")
        print(f"   evidence: {res.evidence}")
    return res


def cmd_traversal(a) -> object:
    base = f"{a.scheme}://{a.host}"
    res = traversal_probe.run(base, a.endpoint, a.param, a.method)
    _show("traversal", res)
    print("\n  vulnerable:", "YES" if res.vulnerable else "no")
    if res.vulnerable:
        print(f"   payload: {res.payload_that_worked}")
        print(f"   evidence: {res.evidence}")
    return res


def cmd_webaudit(a) -> object:
    """Combined web audit: authbypass always, + inject/sqli/xss/traversal if a
    target endpoint/param is given. One summary block, one JSON artifact."""
    base = f"{a.scheme}://{a.host}"
    results: dict = {}

    ab = authbypass_probe.run(base, None, save=False)
    results["authbypass"] = ab

    have_target = bool(a.endpoint and a.param)
    if have_target:
        results["inject"] = injection_probe.run(base, a.endpoint, a.param, a.method, save=False)
        results["sqli"] = sqli_probe.run(base, a.endpoint, a.param, a.method, save=False)
        results["xss"] = xss_probe.run(base, a.endpoint, a.param, a.method, save=False)
        results["traversal"] = traversal_probe.run(base, a.endpoint, a.param, a.method, save=False)

    # --- summary block ---
    print(f"\n=== webaudit {a.host} ({a.scheme}) ===")
    acc = ab.accessible_pages or []
    print(f"  authbypass : {'VULNERABLE' if acc else 'ok'}"
          f"  — {len(acc)} unprotected page(s): {acc or 'none'}")
    if have_target:
        print(f"  target     : {a.endpoint} (param={a.param}, {a.method})")
        ij, sq, xs, tr = (results["inject"], results["sqli"],
                          results["xss"], results["traversal"])
        print(f"  inject     : {'VULNERABLE' if ij.vulnerable else 'ok'}"
              + (f"  — {ij.payload_that_worked}" if ij.vulnerable else ""))
        print(f"  sqli       : {'VULNERABLE' if sq.vulnerable else 'ok'}"
              + (f"  — {sq.detection_method}: {sq.payload_that_worked}" if sq.vulnerable else ""))
        print(f"  xss        : {'VULNERABLE' if xs.vulnerable else 'ok'}"
              + (f"  — {xs.payload_that_worked}" if xs.vulnerable else ""))
        print(f"  traversal  : {'VULNERABLE' if tr.vulnerable else 'ok'}"
              + (f"  — {tr.payload_that_worked}" if tr.vulnerable else ""))
    else:
        print("  (no --endpoint/--param → authbypass only; pass both to also run "
              "inject/sqli/xss/traversal)")

    vuln = [name for name, r in results.items()
            if getattr(r, "vulnerable", False) or getattr(r, "accessible_pages", None)]
    print(f"\n  => findings: {', '.join(vuln) if vuln else 'none'}")
    report.save("webaudit", a.host, results)
    return results


def cmd_authbypass(a) -> object:
    base = f"{a.scheme}://{a.host}"
    paths = [p.strip() for p in a.paths.split(",") if p.strip()] if a.paths else None
    res = authbypass_probe.run(base, paths)
    _show("authbypass", res)
    print("\n  accessible (unprotected):", res.accessible_pages or "none")
    return res


def cmd_recon(a) -> object:
    s = surface.run(a.host)
    _show("surface", s)
    vendor = s.vendor
    if 22 in s.open_ports:
        sp = ssh_probe.run(a.host, 22, "root")
        _show("ssh", sp)
    cp = creds.plan(a.host, vendor=vendor, serial=a.serial)
    _show("creds-plan", cp)
    report.save("recon", a.host, {"surface": s, "vendor": vendor})
    return cp


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="weaknd", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser(
        "discover",
        help="auto-detect the current subnet, find hosts, and map TCP services",
    )
    sp.add_argument("cidr", nargs="?", help="target CIDR; default: current IPv4 subnet")
    sp.add_argument("--interface", help="network interface; default: IPv4 default route")
    sp.add_argument("--vantage", default="current", choices=["current", "lan", "wan"],
                    help="label the observation point for later LAN/WAN comparison")
    sp.add_argument("--scan", default="top", choices=["none", "common", "top", "all"],
                    help="TCP profile: discovery-only, CPE common, top 1000, or all ports")
    sp.add_argument("--no-service-detect", action="store_true",
                    help="skip nmap -sV service fingerprinting")
    sp.add_argument("--udp", default="none", choices=["none", "common"],
                    help="optional bounded UDP profile on the gateway; default: none")
    sp.add_argument("--include-self", action="store_true",
                    help="also port-scan this laptop")
    sp.add_argument("--full-gateway", action="store_true",
                    help="add a full 1-65535 TCP scan for the detected gateway")
    sp.add_argument("--allow-large", action="store_true",
                    help="allow an explicitly supplied network larger than /20")
    sp.add_argument("--assume-up", action="store_true",
                    help="scan every address with -Pn; useful for WAN firewalls hiding discovery")
    sp.set_defaults(fn=cmd_discover)

    sp = sub.add_parser("scan"); sp.add_argument("host"); sp.add_argument("--ports")
    sp.set_defaults(fn=cmd_scan)

    sp = sub.add_parser("ssh-probe"); sp.add_argument("host")
    sp.add_argument("--port", type=int, default=22); sp.add_argument("--user", default="root")
    sp.set_defaults(fn=cmd_ssh_probe)

    sp = sub.add_parser("default-audit",
                        help="bounded, sequential SSH factory-default audit (no Hydra)")
    sp.add_argument("host"); sp.add_argument("--port", type=int, default=22)
    sp.add_argument("--profile", choices=["minimal", "common"], default="minimal")
    sp.add_argument("--delay", type=float, default=1.0,
                    help="seconds between attempts; clamped to 0.5-10")
    sp.set_defaults(fn=cmd_default_audit)

    sp = sub.add_parser("cwmp-probe", help="read-only CWMP HEAD/GET/OPTIONS exposure check")
    sp.add_argument("host"); sp.add_argument("--port", type=int, default=7547)
    sp.set_defaults(fn=cmd_cwmp_probe)

    sp = sub.add_parser("telnet-probe", help="read-only Telnet reachability/banner check")
    sp.add_argument("host"); sp.add_argument("--port", type=int, default=23)
    sp.set_defaults(fn=cmd_telnet_probe)

    sp = sub.add_parser("creds"); sp.add_argument("host")
    sp.add_argument("--service", default="ssh"); sp.add_argument("--port", type=int, default=22)
    sp.add_argument("--vendor"); sp.add_argument("--serial")
    sp.set_defaults(fn=cmd_creds)

    sp = sub.add_parser("recon"); sp.add_argument("host"); sp.add_argument("--serial")
    sp.set_defaults(fn=cmd_recon)

    sp = sub.add_parser("attack"); sp.add_argument("host")
    sp.add_argument("--port", type=int, default=22); sp.add_argument("--vendor")
    sp.add_argument("--serial"); sp.add_argument("--no-brute", action="store_true")
    sp.set_defaults(fn=cmd_attack)

    sp = sub.add_parser("privesc"); sp.add_argument("host")
    sp.add_argument("user")
    sp.add_argument("--password-stdin", action="store_true",
                    help="read one password line from stdin; default: protected prompt")
    sp.add_argument("--port", type=int, default=22)
    sp.set_defaults(fn=cmd_privesc)

    sp = sub.add_parser("enum"); sp.add_argument("host")
    sp.add_argument("--user", default="root")
    sp.add_argument("--password-stdin", action="store_true",
                    help="read one password line from stdin; default: protected prompt")
    sp.add_argument("--port", type=int, default=22)
    sp.set_defaults(fn=cmd_enum)

    sp = sub.add_parser("pwn"); sp.add_argument("host"); sp.add_argument("--serial")
    sp.add_argument("--no-brute", action="store_true")
    sp.set_defaults(fn=cmd_pwn)

    sp = sub.add_parser("inject"); sp.add_argument("host")
    sp.add_argument("--endpoint", required=True); sp.add_argument("--param", required=True)
    sp.add_argument("--method", default="POST", choices=["GET", "POST"])
    sp.add_argument("--scheme", default="http", choices=["http", "https"])
    sp.set_defaults(fn=cmd_inject)

    sp = sub.add_parser("snmp"); sp.add_argument("host")
    sp.add_argument("--port", type=int, default=161)
    sp.set_defaults(fn=cmd_snmp)

    sp = sub.add_parser("authbypass"); sp.add_argument("host")
    sp.add_argument("--scheme", default="http", choices=["http", "https"])
    sp.add_argument("--paths")
    sp.set_defaults(fn=cmd_authbypass)

    sp = sub.add_parser("sqli"); sp.add_argument("host")
    sp.add_argument("--endpoint", required=True); sp.add_argument("--param", required=True)
    sp.add_argument("--method", default="POST", choices=["GET", "POST"])
    sp.add_argument("--scheme", default="http", choices=["http", "https"])
    sp.set_defaults(fn=cmd_sqli)

    sp = sub.add_parser("xss"); sp.add_argument("host")
    sp.add_argument("--endpoint", required=True); sp.add_argument("--param", required=True)
    sp.add_argument("--method", default="GET", choices=["GET", "POST"])
    sp.add_argument("--scheme", default="http", choices=["http", "https"])
    sp.set_defaults(fn=cmd_xss)

    sp = sub.add_parser("traversal"); sp.add_argument("host")
    sp.add_argument("--endpoint", required=True); sp.add_argument("--param", required=True)
    sp.add_argument("--method", default="GET", choices=["GET", "POST"])
    sp.add_argument("--scheme", default="http", choices=["http", "https"])
    sp.set_defaults(fn=cmd_traversal)

    sp = sub.add_parser("webaudit"); sp.add_argument("host")
    sp.add_argument("--endpoint"); sp.add_argument("--param")
    sp.add_argument("--method", default="GET", choices=["GET", "POST"])
    sp.add_argument("--scheme", default="http", choices=["http", "https"])
    sp.set_defaults(fn=cmd_webaudit)

    a = p.parse_args(argv)
    a.fn(a)
    return 0


if __name__ == "__main__":
    sys.exit(main())
