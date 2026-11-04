#!/usr/bin/env python3
"""
(a) Analyze a WAN bring-up capture for an insecure update/telemetry channel.

Answers one question: during bring-up, does the device pull a script/binary over
PLAINTEXT HTTP (the Odido/Lifemote pattern)? Also surfaces DNS targets and HTTPS
SNI hosts so you know which endpoints to test for broken TLS validation in step (b).

Pure wrapper around tshark -- read-only, touches nothing but the pcap you pass.

usage: python3 analyze_capture.py <capture.pcapng> [--carve]
  --carve   export HTTP response objects and flag any that look like shell scripts
"""
import argparse
import os
import re
import subprocess
import sys
import tempfile
from collections import Counter

# URI / content-type that smell like "executable payload fetched over the wire"
SCRIPTY_URI = re.compile(r"\.(sh|bash|bin|img|cgi|pl|py|tar|gz|ipk|rbi)(\?|$)"
                         r"|/(scripts?|update|upgrade|firmware|provision|cwmp)\b", re.I)
SCRIPTY_CT = re.compile(r"x-sh|shellscript|octet-stream|x-executable|plain", re.I)


def tshark(pcap, display_filter, fields):
    cmd = ["tshark", "-r", pcap, "-Q", "-Y", display_filter, "-T", "fields",
           "-E", "separator=\t", "-E", "occurrence=f"]
    for f in fields:
        cmd += ["-e", f]
    out = subprocess.run(cmd, capture_output=True, text=True)
    if out.returncode != 0:
        sys.stderr.write(out.stderr)
    rows = []
    for line in out.stdout.splitlines():
        if line.strip():
            rows.append(line.split("\t"))
    return rows


def hdr(t):
    print(f"\n{'='*72}\n{t}\n{'='*72}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    ap.add_argument("--carve", action="store_true")
    args = ap.parse_args()
    if not os.path.isfile(args.pcap):
        sys.exit(f"no such file: {args.pcap}")

    findings = []

    # 1. DNS — which hostnames did the device look up?
    hdr("1. DNS queries (where is the device reaching out?)")
    dns = tshark(args.pcap, "dns.flags.response==0 and dns.qry.name", ["dns.qry.name"])
    names = Counter(r[0] for r in dns if r and r[0])
    if names:
        for name, n in names.most_common():
            print(f"  {n:4d}x  {name}")
    else:
        print("  (none)")

    # 2. Cleartext HTTP requests — the core of (a)
    hdr("2. Cleartext HTTP requests")
    reqs = tshark(args.pcap, "http.request",
                  ["frame.number", "ip.dst", "http.request.method",
                   "http.host", "http.request.full_uri", "http.user_agent"])
    if not reqs:
        print("  (no plaintext HTTP requests seen)")
    for r in reqs:
        r += [""] * (6 - len(r))
        frame, dst, method, host, uri, ua = r[:6]
        scripty = bool(SCRIPTY_URI.search(uri or host or ""))
        flag = "  <== SCRIPT/BINARY FETCH OVER PLAINTEXT" if scripty else ""
        print(f"  #{frame:<6} {method:<5} {uri or ('http://'+host)}{flag}")
        if ua:
            print(f"          UA: {ua}")
        if scripty:
            findings.append(f"plaintext HTTP fetch: {method} {uri or host} (frame {frame})")

    # 3. Cleartext HTTP responses that look like scripts/binaries
    hdr("3. Cleartext HTTP responses (content-type of what came back)")
    resps = tshark(args.pcap, "http.response",
                   ["frame.number", "http.response.code",
                    "http.content_type", "http.response_for.uri"])
    if not resps:
        print("  (no plaintext HTTP responses seen)")
    for r in resps:
        r += [""] * (4 - len(r))
        frame, code, ct, foruri = r[:4]
        scripty = bool(SCRIPTY_CT.search(ct or "")) or bool(SCRIPTY_URI.search(foruri or ""))
        flag = "  <== payload-like body in cleartext" if scripty else ""
        print(f"  #{frame:<6} {code:<4} {ct or '?':<28} {foruri}{flag}")

    # 4. TFTP (another common cleartext provisioning channel)
    hdr("4. TFTP read requests")
    tftp = tshark(args.pcap, "tftp.opcode==1", ["frame.number", "tftp.source_file"])
    if tftp:
        for r in tftp:
            r += [""] * (2 - len(r))
            print(f"  #{r[0]:<6} RRQ {r[1]}")
            findings.append(f"TFTP fetch: {r[1]} (frame {r[0]})")
    else:
        print("  (none)")

    # 5. HTTPS SNI — telemetry/update endpoints to test for broken TLS validation in (b)
    hdr("5. HTTPS endpoints (TLS SNI) -- candidates for step (b) cert-validation test")
    sni = tshark(args.pcap, "tls.handshake.extensions_server_name",
                 ["tls.handshake.extensions_server_name"])
    snis = Counter(r[0] for r in sni if r and r[0])
    if snis:
        for name, n in snis.most_common():
            print(f"  {n:4d}x  {name}")
    else:
        print("  (none)")

    # 6. Optional: carve HTTP objects and flag shell scripts by shebang
    if args.carve:
        hdr("6. Carved HTTP objects (bodies starting with a shebang)")
        outdir = os.path.join(os.path.dirname(os.path.abspath(args.pcap)),
                              "carved-" + os.path.basename(args.pcap))
        os.makedirs(outdir, exist_ok=True)
        subprocess.run(["tshark", "-r", args.pcap, "-Q",
                        "--export-objects", f"http,{outdir}"],
                       capture_output=True, text=True)
        hits = 0
        for root, _, files in os.walk(outdir):
            for fn in files:
                p = os.path.join(root, fn)
                try:
                    with open(p, "rb") as fh:
                        head = fh.read(4)
                except OSError:
                    continue
                if head.startswith(b"#!"):
                    hits += 1
                    print(f"  SHELL SCRIPT: {p}")
                    findings.append(f"carved shell script body: {p}")
        if not hits:
            print(f"  (no shebang bodies; objects in {outdir})")

    # Verdict for (a)
    hdr("VERDICT (a): insecure plaintext update/telemetry fetch?")
    if findings:
        print("  FINDING -- device pulls executable content over a cleartext channel:")
        for f in findings:
            print(f"    - {f}")
        print("\n  => in-path injection is viable; proceed to (b) broken-TLS test on the")
        print("     HTTPS SNI hosts above, then the full MITM->config-read chain.")
    else:
        print("  No cleartext script/binary fetch seen in THIS capture.")
        print("  Either the channel is clean, or the capture didn't see the WAN side")
        print("  (wrong position) or didn't cover a real bring-up (re-run during reboot).")


if __name__ == "__main__":
    main()
