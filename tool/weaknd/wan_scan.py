"""Generic, vendor-neutral WAN scanning for the dashboard."""
from __future__ import annotations

import ipaddress
import json
import os
import re
import shlex
import shutil
import socket
import stat
import subprocess
import threading
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field


QUICK_TCP_PORTS = [21, 22, 23, 53, 80, 443, 8080, 8443, 7547, 2323]
COMMON_UDP_PORTS = [53, 67, 68, 69, 123, 161, 500, 1900, 4500, 5353]
PROFILES = {"quick", "full", "udp", "vulnerability"}
HOST_TIMEOUT_SECONDS = {"full": 360, "udp": 120, "vulnerability": 180}

VENDOR_SIGNATURES = (
    (("zyxel", "web-based configurator", "zyxelcert"), "Zyxel"),
    (("sagemcom", "sagem"), "Sagemcom"),
    (("technicolor",), "Technicolor"),
    (("tp-link", "tplink"), "TP-Link"),
    (("huawei",), "Huawei"),
    (("zte",), "ZTE"),
    (("mikrotik", "routeros"), "MikroTik"),
    (("netgear",), "Netgear"),
    (("d-link", "dlink"), "D-Link"),
)
MODEL_PATTERNS = (
    re.compile(r"\b(?:EX|DX|VMG|PMG|NR|NWA|USG|ATP)\d{2,5}(?:-[A-Z0-9]+)*\b", re.I),
    re.compile(r"\bFAST\d{4,6}[A-Z0-9-]*\b", re.I),
)
KEYED_MODEL_RE = re.compile(
    r"\bmodel(?:\s+(?:name|number|descr(?:iption)?))?\s*[:=]\s*"
    r"([A-Z0-9][A-Z0-9._/-]{2,63})",
    re.I,
)
KEYED_FIRMWARE_RE = re.compile(
    r"\b(?:firmware|software)(?:\s+(?:version|revision))?\s*[:=]\s*"
    r"([A-Z0-9][A-Z0-9()._+-]{2,79})",
    re.I,
)
ZYXEL_FIRMWARE_RE = re.compile(
    r"\bV\d+\.\d+\([A-Z0-9.]+\)[A-Z0-9._-]*\b",
    re.I,
)


@dataclass
class PortObservation:
    port: int
    protocol: str
    state: str
    service: str
    product: str | None = None
    version: str | None = None
    extra_info: str | None = None
    service_method: str | None = None
    service_confidence: int | None = None
    tunnel: str | None = None
    scripts: dict[str, str] = field(default_factory=dict)


@dataclass
class Finding:
    title: str
    severity: str
    description: str
    evidence: str
    confirmed: bool = False


@dataclass
class WanScanResult:
    target: str
    profile: str
    mode: str
    status: str
    manufacturer: str | None = None
    model: str | None = None
    requested_interface: str | None = None
    interface_used: str | None = None
    firmware: str | None = None
    identity_evidence: list[str] = field(default_factory=list)
    sample_data: bool = False
    ports: list[PortObservation] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    error: str | None = None
    executed_command: str | None = None
    commands_executed: list[str] = field(default_factory=list)
    exit_code: int | None = None
    stderr: str = ""
    duration_seconds: float = 0.0
    discovered_port_count: int = 0
    scan_method: str | None = None
    privilege_mode: str | None = None


_jobs: dict[str, subprocess.Popen[str]] = {}
_cancelled: set[str] = set()
_jobs_lock = threading.Lock()


def available_interfaces() -> list[dict]:
    records = {name: {"name": name, "addresses": [], "up": False}
               for _, name in socket.if_nameindex()}
    if shutil.which("ip"):
        try:
            command = subprocess.run(
                ["ip", "-j", "addr", "show"], capture_output=True, text=True,
                timeout=5, check=True,
            )
            for item in json.loads(command.stdout):
                name = item.get("ifname")
                if not name:
                    continue
                record = records.setdefault(name, {"name": name, "addresses": [], "up": False})
                record["up"] = "UP" in item.get("flags", [])
                record["addresses"] = [address.get("local") for address in item.get("addr_info", [])
                                       if address.get("local")]
        except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
            pass
    return sorted(records.values(), key=lambda item: (item["name"] == "lo", not item["up"], item["name"]))


def _validate_target(target: str) -> str:
    if not target.strip():
        raise ValueError("target IP address is required")
    address = ipaddress.ip_address(target.strip())
    if address.is_unspecified or address.is_multicast:
        raise ValueError("target must be a unicast IP address")
    return str(address)


def _route_interface(target: str) -> str | None:
    if not shutil.which("ip"):
        return None
    address = ipaddress.ip_address(target)
    command = ["ip", "-j"] + (["-6"] if address.version == 6 else []) + ["route", "get", target]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=5, check=True)
        routes = json.loads(result.stdout)
        return routes[0].get("dev") if routes else None
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError, IndexError):
        return None


def _select_interface(target: str, requested: str | None) -> tuple[str | None, str | None]:
    requested = (requested or "").strip()
    names = {item["name"] for item in available_interfaces()}
    if requested and requested not in names:
        raise ValueError("selected network interface is unavailable")
    route_interface = _route_interface(target)
    if requested and route_interface and requested != route_interface:
        raise ValueError(
            f"selected interface {requested} does not match the OS route via {route_interface}; "
            "select Automatic routing or configure the route first"
        )
    return requested or None, route_interface or requested or None


def _syn_scan_available() -> tuple[bool, str]:
    nmap = shutil.which("nmap")
    if os.geteuid() == 0:
        return True, "root process"
    if nmap:
        try:
            mode = os.stat(nmap).st_mode
            if mode & stat.S_ISUID:
                return True, "setuid nmap executable"
            getcap = shutil.which("getcap")
            if getcap:
                result = subprocess.run([getcap, nmap], capture_output=True, text=True, timeout=3)
                if "cap_net_raw" in result.stdout:
                    return True, "nmap has cap_net_raw"
        except (OSError, subprocess.SubprocessError):
            pass
    return False, "unprivileged process; TCP connect fallback"


def _command(target: str, profile: str, interface: str | None,
             tcp_scan: str = "-sT") -> tuple[list[str], int]:
    common = ["nmap", "-Pn", "-n", "--open", "--reason", "--max-retries", "2"]
    interface_args = ["-e", interface] if interface else []
    tcp_ports = ",".join(str(port) for port in QUICK_TCP_PORTS)
    if profile == "quick":
        return [
            "nmap", "-Pn", "-n", "-sT", "-p", tcp_ports,
            "--reason", "--max-retries", "2", "-oX", "-", target,
        ], 45
    if profile == "full":
        args = common + [tcp_scan, "-sV", "--version-light", "--max-rate", "500",
                         "--host-timeout", "360s", "--script-timeout", "15s", "--script",
                         "http-title,http-headers,http-server-header,ssl-cert", "-p-"]
        return args + interface_args + ["-oX", "-", target], 390
    if profile == "udp":
        udp_ports = ",".join(str(port) for port in COMMON_UDP_PORTS)
        args = common + ["-sU", "-sV", "--version-light", "--max-rate", "20",
                         "--host-timeout", "120s", "--script-timeout", "15s",
                         "--script", "upnp-info",
                         "-p", udp_ports]
        return args + interface_args + ["-oX", "-", target], 150
    args = common + [tcp_scan, "-sV", "--version-light", "--max-rate", "20"]
    if profile == "vulnerability":
        scripts = ("ssh2-enum-algos,ssl-enum-ciphers,ssl-cert,http-title,"
                   "http-headers,http-server-header,dns-recursion")
        args += ["--host-timeout", "180s", "--script-timeout", "15s",
                 "--script", scripts, "-p", tcp_ports]
        return args + interface_args + ["-oX", "-", target], 210
    raise ValueError("unknown scan profile")


def _parse_xml(xml_text: str) -> list[PortObservation]:
    root = ET.fromstring(xml_text)
    observations: list[PortObservation] = []
    for port_node in root.findall(".//host/ports/port"):
        state_node = port_node.find("state")
        state = state_node.get("state", "unknown") if state_node is not None else "unknown"
        if not state.startswith("open"):
            continue
        service_node = port_node.find("service")
        service = service_node.get("name", "unknown") if service_node is not None else "unknown"
        observations.append(PortObservation(
            port=int(port_node.get("portid", "0")), protocol=port_node.get("protocol", "tcp"),
            state=state, service=service,
            product=service_node.get("product") if service_node is not None else None,
            version=service_node.get("version") if service_node is not None else None,
            extra_info=service_node.get("extrainfo") if service_node is not None else None,
            service_method=service_node.get("method") if service_node is not None else None,
            service_confidence=(int(service_node.get("conf"))
                                if service_node is not None and
                                (service_node.get("conf") or "").isdigit() else None),
            tunnel=service_node.get("tunnel") if service_node is not None else None,
            scripts={node.get("id", "script"): node.get("output", "")
                     for node in port_node.findall("script")},
        ))
    return sorted(observations, key=lambda item: (item.protocol, item.port))


def infer_identity(ports: list[PortObservation], manufacturer: str | None = None,
                   model: str | None = None) -> tuple[str | None, str | None,
                                                       str | None, list[str]]:
    """Derive public device metadata from service and safe NSE evidence.

    Caller-supplied manufacturer/model values win. Firmware is never guessed
    from a generic service version; it must be explicitly labelled or match a
    vendor firmware format.
    """
    resolved_manufacturer = (manufacturer or "").strip() or None
    resolved_model = (model or "").strip() or None
    firmware = None
    evidence: list[str] = []

    for observation in ports:
        source_prefix = f"{observation.port}/{observation.protocol}"
        sources = [
            ("service fingerprint", " ".join(filter(None, (
                observation.service, observation.product, observation.version,
                observation.extra_info,
            )))),
            *((script_id, output) for script_id, output in observation.scripts.items()),
        ]
        for source, text in sources:
            if not text:
                continue
            lowered = text.lower()
            if resolved_manufacturer is None:
                for signs, vendor in VENDOR_SIGNATURES:
                    if any(sign in lowered for sign in signs):
                        resolved_manufacturer = vendor
                        evidence.append(
                            f"manufacturer={vendor} ({source_prefix} {source})")
                        break
            if resolved_model is None:
                keyed = KEYED_MODEL_RE.search(text)
                candidate = keyed.group(1) if keyed else None
                if candidate is None:
                    candidate = next((match.group(0) for pattern in MODEL_PATTERNS
                                      if (match := pattern.search(text))), None)
                if candidate:
                    resolved_model = candidate.upper()
                    evidence.append(
                        f"model={resolved_model} ({source_prefix} {source})")
            if firmware is None:
                keyed = KEYED_FIRMWARE_RE.search(text)
                match = keyed or ZYXEL_FIRMWARE_RE.search(text)
                if match:
                    firmware = match.group(1) if keyed else match.group(0)
                    evidence.append(
                        f"firmware={firmware} ({source_prefix} {source})")

    return resolved_manufacturer, resolved_model, firmware, evidence


def completion_status(profile: str, duration: float,
                      ports: list[PortObservation]) -> str:
    """Do not present a host-budget exhaustion as a conclusive empty scan."""
    budget = HOST_TIMEOUT_SECONDS.get(profile)
    if budget and not ports and duration >= budget - 1:
        return "incomplete"
    return "completed"


def derive_findings(ports: list[PortObservation]) -> list[Finding]:
    findings: list[Finding] = []
    for observation in ports:
        if observation.state != "open":
            continue
        endpoint = f"{observation.port}/{observation.protocol}"
        service_text = " ".join(filter(None, [observation.service, observation.product,
                                                observation.version, observation.extra_info])).lower()
        script_text = "\n".join(observation.scripts.values()).lower()
        service_confirmed = bool(
            observation.service not in {"", "unknown", "tcpwrapped"} and
            (observation.product or observation.service_method in {None, "probed"} or
             (observation.service_confidence is not None and observation.service_confidence >= 7))
        )
        if service_confirmed and "telnet" in service_text:
            findings.append(Finding(
                "Insecure Remote Management", "HIGH",
                "A plaintext Telnet service is reachable. Disable it or restrict access.",
                f"{endpoint} positively identified as {observation.service}",
            ))
        if service_confirmed and "ssh" in service_text:
            findings.append(Finding(
                "SSH Management Exposure", "INFO",
                "An SSH service is reachable. Review source restrictions and authentication policy.",
                f"{endpoint} positively identified as {observation.service}",
            ))
        is_http = observation.service.startswith("http") or "http" in service_text
        is_tls = observation.service in {"https", "ssl/http", "https-alt"} or "ssl" in service_text
        if service_confirmed and is_http:
            findings.append(Finding(
                "Web Service Exposure", "INFO" if is_tls else "MEDIUM",
                ("An HTTPS service is reachable. Confirm whether it is a management interface and "
                 "review authentication and access controls." if is_tls else
                 "An unencrypted HTTP service is reachable. Confirm whether it is a management "
                 "interface and require HTTPS or restrict access."),
                f"{endpoint} identified as {observation.service}",
            ))
        if service_confirmed and ("cwmp" in service_text or "tr-069" in service_text or
                                  "tr069" in service_text):
            findings.append(Finding(
                "CWMP Exposure", "INFO",
                "A possible TR-069/CWMP endpoint is reachable. Exposure alone is not a vulnerability; "
                "review authentication and ACS restrictions.",
                f"{endpoint} identified as {observation.service}",
            ))
        if service_confirmed and ("domain" in service_text or "dns" in service_text):
            findings.append(Finding(
                "DNS Service Exposure", "INFO",
                "A DNS service is reachable. Review recursion, amplification controls, and intended scope.",
                f"{endpoint} identified as {observation.service}",
            ))
            if "recursion appears to be enabled" in script_text:
                findings.append(Finding(
                    "Open DNS Recursion", "HIGH",
                    "The DNS recursion check indicates that recursive queries may be accepted.",
                    f"dns-recursion response on {endpoint}",
                ))
        if service_confirmed and "snmp" in service_text:
            findings.append(Finding(
                "SNMP Exposure", "INFO",
                "SNMP is reachable. Verify version, community or user policy, and source restrictions.",
                f"{endpoint} identified as {observation.service}",
            ))
        if ((service_confirmed and ("upnp" in service_text or "ssdp" in service_text)) or
                "upnp-info" in observation.scripts):
            findings.append(Finding(
                "Potential UPnP/SSDP Exposure", "MEDIUM",
                "UPnP or SSDP appears reachable. Confirm interface binding and disable external exposure "
                "when it is not required.",
                f"{endpoint} returned UPnP/SSDP indicators",
            ))
        weak_ssh = [token for token in (
            "diffie-hellman-group1-sha1", "ssh-dss", "3des-cbc", "arcfour", "hmac-md5",
        ) if token in script_text]
        if weak_ssh:
            findings.append(Finding(
                "Weak SSH Configuration", "MEDIUM",
                "SSH advertised legacy cryptographic algorithms. Retain modern algorithms only.",
                ", ".join(weak_ssh),
            ))
        weak_tls = [token for token in ("sslv2", "sslv3", "tlsv1.0", "tlsv1.1", "rc4", "3des")
                    if token in script_text]
        if weak_tls:
            findings.append(Finding(
                "Weak TLS Configuration", "MEDIUM",
                "TLS enumeration observed legacy protocol or cipher support.",
                ", ".join(weak_tls),
            ))
    unique: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for finding in findings:
        key = (finding.title, finding.evidence)
        if key not in seen:
            seen.add(key)
            unique.append(finding)
    return unique


def demo_result(profile: str, manufacturer: str | None = None,
                model: str | None = None) -> WanScanResult:
    if profile not in PROFILES:
        raise ValueError("unknown scan profile")
    if profile == "udp":
        ports = [
            PortObservation(53, "udp", "open", "domain", "Example DNS service"),
            PortObservation(161, "udp", "open", "snmp", "Example SNMP agent"),
            PortObservation(1900, "udp", "open", "upnp", "Example UPnP service"),
        ]
    else:
        ports = [
            PortObservation(22, "tcp", "open", "ssh", "Example SSH service", "1.0", scripts={
                "ssh2-enum-algos": "kex_algorithms: diffie-hellman-group1-sha1; "
                                    "server_host_key_algorithms: ssh-dss",
            }),
            PortObservation(80, "tcp", "open", "http", "Example HTTP service", "1.0"),
            PortObservation(443, "tcp", "open", "https", "Example HTTPS service", "1.0", scripts={
                "ssl-enum-ciphers": "TLSv1.0: TLS_RSA_WITH_3DES_EDE_CBC_SHA",
            }),
            PortObservation(7547, "tcp", "open", "http", "Example CWMP service", "1.0"),
        ]
    return WanScanResult(
        target="203.0.113.10", profile=profile, mode="demo", status="completed",
        manufacturer=manufacturer or None, model=model or None,
        requested_interface=None, interface_used="simulated", sample_data=True,
        ports=ports, findings=derive_findings(ports),
        notes=["Simulated sample data; no network scan was executed.",
               "Potential findings are not proof of exploitability."],
        executed_command="not executed (Demo Mode)", discovered_port_count=len(ports),
        scan_method="simulated", privilege_mode="not applicable",
    )


def run(target: str, profile: str, manufacturer: str | None = None,
        model: str | None = None, job_id: str | None = None,
        interface: str | None = None) -> WanScanResult:
    if profile not in PROFILES:
        raise ValueError("unknown scan profile")
    target = _validate_target(target)
    if not shutil.which("nmap"):
        raise RuntimeError("nmap is not installed")
    requested_interface, interface_used = _select_interface(target, interface)
    syn_available, privilege_mode = _syn_scan_available()
    if profile == "quick":
        scan_method, privilege_mode = "-sT", "fixed Quick TCP connect scan"
    else:
        scan_method = "-sU" if profile == "udp" else ("-sS" if syn_available else "-sT")
    commands_executed: list[str] = []
    stderr_chunks: list[str] = []
    started = time.monotonic()

    def execute(command: list[str], timeout: int) -> tuple[str, str, int | None, bool]:
        commands_executed.append(shlex.join(command))
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True, start_new_session=True)
        if job_id:
            with _jobs_lock:
                _jobs[job_id] = process
        try:
            stdout, stderr = process.communicate(timeout=timeout)
            return stdout, stderr, process.returncode, False
        except subprocess.TimeoutExpired:
            process.terminate()
            try:
                stdout, stderr = process.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate()
            return stdout, stderr, process.returncode, True
        finally:
            if job_id:
                with _jobs_lock:
                    if _jobs.get(job_id) is process:
                        _jobs.pop(job_id, None)

    if job_id:
        with _jobs_lock:
            _cancelled.discard(job_id)
    command, timeout = _command(target, profile, requested_interface, scan_method)
    stdout, stderr, exit_code, timed_out = execute(command, timeout)
    if stderr.strip():
        stderr_chunks.append(stderr.strip())

    privilege_error = any(token in stderr.lower() for token in (
        "requires root privileges", "operation not permitted", "failed to open device",
        "couldn't open a raw socket", "requires privileged",
    ))
    with _jobs_lock:
        cancelled_before_fallback = bool(job_id and job_id in _cancelled)
    fallback_used = False
    if (scan_method == "-sS" and exit_code and privilege_error and not timed_out
            and not cancelled_before_fallback):
        fallback_used = True
        scan_method = "-sT"
        fallback_command, fallback_timeout = _command(
            target, profile, requested_interface, scan_method)
        stdout, fallback_stderr, exit_code, timed_out = execute(
            fallback_command, fallback_timeout)
        if fallback_stderr.strip():
            stderr_chunks.append("TCP connect fallback:\n" + fallback_stderr.strip())

    duration = round(time.monotonic() - started, 3)
    combined_stderr = "\n".join(stderr_chunks)[-4000:]
    with _jobs_lock:
        was_cancelled = bool(job_id and job_id in _cancelled)
        if job_id:
            _cancelled.discard(job_id)
    debug = {
        "executed_command": commands_executed[-1] if commands_executed else None,
        "commands_executed": commands_executed,
        "exit_code": exit_code,
        "stderr": combined_stderr,
        "duration_seconds": duration,
        "scan_method": scan_method,
        "privilege_mode": privilege_mode,
    }
    if was_cancelled:
        return WanScanResult(
            target, profile, "live", "cancelled", manufacturer or None, model or None,
            requested_interface, interface_used, **debug)
    if timed_out:
        return WanScanResult(
            target, profile, "live", "error", manufacturer or None, model or None,
            requested_interface, interface_used,
            error=f"scan exceeded the {timeout}-second execution limit", **debug)
    if exit_code != 0:
        detail = (combined_stderr or "nmap exited with an error").strip()[-500:]
        return WanScanResult(
            target, profile, "live", "error", manufacturer or None, model or None,
            requested_interface, interface_used, error=detail, **debug)
    try:
        ports = _parse_xml(stdout)
    except ET.ParseError as error:
        return WanScanResult(
            target, profile, "live", "error", manufacturer or None, model or None,
            requested_interface, interface_used,
            error=f"invalid Nmap XML output: {error}", **debug)
    detected_manufacturer, detected_model, firmware, identity_evidence = infer_identity(
        ports, manufacturer, model)
    notes = ["Results reflect the current scanner location and routing path.",
             "Potential findings are not proof of exploitability."]
    if profile == "quick":
        notes.append("Quick Recon reports port state only; port-table service names are unverified.")
    elif fallback_used or (profile != "udp" and not syn_available):
        notes.append("SYN scan was unavailable; Nmap used TCP connect scanning (-sT).")
    if profile == "udp" and any(port.state == "open|filtered" for port in ports):
        notes.append("UDP open|filtered means Nmap received no definitive response.")
    scan_status = completion_status(profile, duration, ports)
    if scan_status == "incomplete":
        notes.append(
            "The scan exhausted its per-host budget without a complete port result; "
            "zero displayed ports is inconclusive."
        )
    return WanScanResult(
        target, profile, "live", scan_status, detected_manufacturer, detected_model,
        requested_interface, interface_used, ports=ports, findings=derive_findings(ports),
        firmware=firmware, identity_evidence=identity_evidence,
        notes=notes, discovered_port_count=len(ports), **debug,
    )


def cancel(job_id: str) -> bool:
    if not job_id:
        return False
    with _jobs_lock:
        process = _jobs.get(job_id)
        if process is None or process.poll() is not None:
            return False
        _cancelled.add(job_id)
        process.terminate()
        return True
