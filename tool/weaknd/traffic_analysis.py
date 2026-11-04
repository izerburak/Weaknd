"""Lightweight, device-independent PCAP analysis for the WAN demo."""
from __future__ import annotations

import ipaddress
import shutil
import subprocess
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path


MAX_PACKETS = 10_000


@dataclass
class TrafficFinding:
    title: str
    severity: str
    description: str
    evidence: str


@dataclass
class TrafficAnalysisResult:
    filename: str
    status: str
    packets_analyzed: int = 0
    protocol_statistics: list[dict] = field(default_factory=list)
    dns: dict = field(default_factory=dict)
    http: dict = field(default_factory=dict)
    tls: dict = field(default_factory=dict)
    external_connections: list[dict] = field(default_factory=list)
    findings: list[TrafficFinding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    error: str | None = None


def _run(command: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, capture_output=True, text=True, timeout=timeout)


def _validate_capture(path: Path) -> None:
    if not shutil.which("tcpdump"):
        raise RuntimeError("tcpdump is not installed")
    check = _run(["tcpdump", "-nn", "-r", str(path), "-c", "1"], 10)
    if check.returncode != 0:
        detail = (check.stderr or "capture validation failed").strip()[-400:]
        raise ValueError(detail)


def _is_external(address: str) -> bool:
    try:
        return ipaddress.ip_address(address).is_global
    except ValueError:
        return False


def _tls_name(value: str) -> str:
    return {
        "0x0300": "SSL 3.0", "0x0301": "TLS 1.0", "0x0302": "TLS 1.1",
        "0x0303": "TLS 1.2", "0x0304": "TLS 1.3",
    }.get(value.lower(), value)


def analyze(path: str | Path, filename: str) -> TrafficAnalysisResult:
    capture = Path(path)
    _validate_capture(capture)
    if not shutil.which("tshark"):
        raise RuntimeError("tshark is not installed")

    fields = [
        "frame.number", "_ws.col.Protocol", "ip.src", "ipv6.src", "ip.dst",
        "ipv6.dst", "dns.qry.name", "dns.flags.rcode", "http.request.method",
        "http.host", "http.request.uri", "tls.handshake.extensions_server_name",
        "tls.handshake.version", "tcp.dstport", "udp.dstport",
    ]
    command = [
        "tshark", "-r", str(capture), "-n", "-c", str(MAX_PACKETS),
        "-T", "fields", "-E", "separator=/t", "-E", "quote=n",
        "-E", "occurrence=f",
    ]
    for field_name in fields:
        command.extend(["-e", field_name])
    scan = _run(command, 45)
    if scan.returncode != 0:
        detail = (scan.stderr or "tshark analysis failed").strip()[-500:]
        raise RuntimeError(detail)

    protocols: Counter[str] = Counter()
    dns_names: Counter[str] = Counter()
    dns_codes: Counter[str] = Counter()
    http_methods: Counter[str] = Counter()
    http_hosts: Counter[str] = Counter()
    http_urls: Counter[str] = Counter()
    tls_names: Counter[str] = Counter()
    tls_versions: Counter[str] = Counter()
    connections: Counter[tuple[str, str]] = Counter()
    destination_ports: Counter[tuple[str, str]] = Counter()
    packets = 0

    for line in scan.stdout.splitlines():
        columns = line.split("\t")
        columns.extend([""] * (len(fields) - len(columns)))
        (number, protocol, ip4_src, ip6_src, ip4_dst, ip6_dst, dns_name,
         dns_code, http_method, http_host, http_uri, tls_sni, tls_version,
         tcp_dst, udp_dst) = columns[:len(fields)]
        if not number:
            continue
        packets += 1
        protocols[protocol or "Unknown"] += 1
        source, destination = ip4_src or ip6_src, ip4_dst or ip6_dst
        if source and destination and (_is_external(source) or _is_external(destination)):
            connections[(source, destination)] += 1
        if tcp_dst:
            destination_ports[("tcp", tcp_dst)] += 1
        if udp_dst:
            destination_ports[("udp", udp_dst)] += 1
        if dns_name:
            dns_names[dns_name] += 1
        if dns_code:
            dns_codes[dns_code] += 1
        if http_method:
            http_methods[http_method] += 1
            if http_host:
                http_hosts[http_host] += 1
                http_urls[f"{http_host}{http_uri or '/'}"] += 1
        if tls_sni:
            tls_names[tls_sni] += 1
        if tls_version:
            tls_versions[_tls_name(tls_version)] += 1

    protocol_stats = [
        {"protocol": name, "packets": count,
         "percent": round(count * 100 / packets, 1) if packets else 0.0}
        for name, count in protocols.most_common()
    ]
    external = [
        {"source": source, "destination": destination, "packets": count}
        for (source, destination), count in connections.most_common(50)
    ]
    dns = {
        "queries": sum(dns_names.values()),
        "unique_names": len(dns_names),
        "top_names": [{"name": name, "count": count}
                      for name, count in dns_names.most_common(30)],
        "response_codes": dict(dns_codes),
    }
    http = {
        "requests": sum(http_methods.values()),
        "methods": dict(http_methods),
        "hosts": [{"host": host, "count": count}
                  for host, count in http_hosts.most_common(30)],
        "urls": [{"url": url, "count": count}
                 for url, count in http_urls.most_common(30)],
    }
    tls = {
        "server_names": [{"name": name, "count": count}
                         for name, count in tls_names.most_common(30)],
        "versions": dict(tls_versions),
    }

    findings: list[TrafficFinding] = []
    if http["requests"]:
        findings.append(TrafficFinding(
            "Cleartext HTTP Traffic", "MEDIUM",
            "Unencrypted HTTP requests were observed in the capture.",
            f"{http['requests']} HTTP request(s)",
        ))
    if dns["queries"]:
        findings.append(TrafficFinding(
            "Plaintext DNS Metadata", "INFO",
            "DNS query names were visible in the capture. Consider encrypted DNS where appropriate.",
            f"{dns['queries']} query observation(s), {dns['unique_names']} unique name(s)",
        ))
    legacy_tls = [name for name in tls_versions if name in {"SSL 3.0", "TLS 1.0", "TLS 1.1"}]
    if legacy_tls:
        findings.append(TrafficFinding(
            "Legacy TLS Observed", "MEDIUM",
            "The capture contains handshakes advertising obsolete TLS protocol versions.",
            ", ".join(legacy_tls),
        ))
    if destination_ports.get(("tcp", "23")):
        findings.append(TrafficFinding(
            "Telnet Traffic", "HIGH", "Plaintext Telnet traffic was observed.",
            f"{destination_ports[('tcp', '23')]} packet(s) destined for TCP/23",
        ))
    if destination_ports.get(("tcp", "21")):
        findings.append(TrafficFinding(
            "FTP Control Traffic", "MEDIUM", "Plaintext FTP control traffic was observed.",
            f"{destination_ports[('tcp', '21')]} packet(s) destined for TCP/21",
        ))

    notes = [f"Analyzed up to {MAX_PACKETS} packets using TShark."]
    if packets == MAX_PACKETS:
        notes.append("Packet limit reached; results represent the beginning of the capture.")
    return TrafficAnalysisResult(
        filename=Path(filename).name, status="completed", packets_analyzed=packets,
        protocol_statistics=protocol_stats, dns=dns, http=http, tls=tls,
        external_connections=external, findings=findings, notes=notes,
    )
