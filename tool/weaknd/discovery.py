"""Vantage-aware LAN/WAN recon orchestration.

Detect the active IPv4 subnet, discover live hosts, and optionally map their
open TCP ports and services. No authentication is attempted.
"""
from __future__ import annotations

import ipaddress
import json
import os
import shutil
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path


COMMON_TCP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 554, 631,
    1723, 1883, 2323, 2601, 5000, 5001, 5003, 5683, 7547, 8000,
    8080, 8081, 8291, 8443, 8883, 9000, 10000, 20443, 49152,
    49153, 58000,
]
COMMON_UDP_PORTS = [
    53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 1900, 3478, 4500,
    5353, 5683,
]
MAX_DEFAULT_ADDRESSES = 4096  # /20; prevents accidental Internet-scale scans


@dataclass
class NetworkContext:
    vantage: str
    interface: str
    address: str
    prefixlen: int
    network: str
    gateway: str | None = None
    ssid: str | None = None
    bssid: str | None = None


@dataclass
class PortInfo:
    port: int
    protocol: str = "tcp"
    service: str | None = None
    product: str | None = None
    version: str | None = None
    extra_info: str | None = None


@dataclass
class HostInfo:
    address: str
    state: str = "up"
    mac: str | None = None
    vendor: str | None = None
    is_self: bool = False
    is_gateway: bool = False
    ports: list[PortInfo] = field(default_factory=list)
    display_name: str | None = None
    role: str | None = None
    matched_ssids: list[str] = field(default_factory=list)
    identity_confidence: str | None = None
    identity_notes: list[str] = field(default_factory=list)


@dataclass
class WifiNetwork:
    ssid: str
    bssid: str
    signal: int | None = None
    channel: int | None = None
    security: str | None = None
    active: bool = False


@dataclass
class DiscoveryResult:
    context: NetworkContext
    scan_profile: str
    service_detection: bool
    udp_profile: str = "none"
    assume_up: bool = False
    hosts: list[HostInfo] = field(default_factory=list)
    wifi_networks: list[WifiNetwork] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def _command(args: list[str], timeout: int = 30) -> str:
    proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout).strip()
        raise RuntimeError(f"{' '.join(args)} failed: {detail}")
    return proc.stdout


def _default_route() -> dict:
    routes = json.loads(_command(["ip", "-j", "-4", "route", "show", "default"]))
    if not routes:
        raise RuntimeError("no IPv4 default route found; pass --interface/--cidr explicitly")
    return min(routes, key=lambda route: route.get("metric", 0))


def _optional_command(args: list[str], timeout: int = 15) -> str | None:
    try:
        return _command(args, timeout)
    except (OSError, RuntimeError, subprocess.TimeoutExpired):
        return None


def _wifi_identity(interface: str) -> tuple[str | None, str | None]:
    if not shutil.which("iwgetid"):
        return None, None
    ssid = _optional_command(["iwgetid", interface, "--raw"])
    bssid = _optional_command(["iwgetid", interface, "--ap", "--raw"])
    return ((ssid or "").strip() or None, (bssid or "").strip().upper() or None)


def _split_nmcli(line: str) -> list[str]:
    """Split nmcli terse output while honoring its backslash escaping."""
    fields: list[str] = []
    current: list[str] = []
    escaped = False
    for char in line:
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == ":":
            fields.append("".join(current))
            current = []
        else:
            current.append(char)
    if escaped:
        current.append("\\")
    fields.append("".join(current))
    return fields


def wifi_inventory(interface: str) -> list[WifiNetwork]:
    """Refresh visible SSIDs through NetworkManager; never connects to one."""
    if not shutil.which("nmcli"):
        return []
    output = _optional_command([
        "nmcli", "-t", "--escape", "yes",
        "-f", "IN-USE,SSID,BSSID,SIGNAL,CHAN,SECURITY",
        "device", "wifi", "list", "ifname", interface, "--rescan", "yes",
    ])
    if not output:
        return []
    networks: list[WifiNetwork] = []
    seen: set[str] = set()
    for line in output.splitlines():
        fields = _split_nmcli(line)
        if len(fields) < 6:
            continue
        active, ssid, bssid, signal, channel = fields[:5]
        security = ":".join(fields[5:])
        key = bssid.upper()
        if not bssid or key in seen:
            continue
        seen.add(key)
        networks.append(WifiNetwork(
            ssid=ssid or "(hidden)", bssid=key,
            signal=int(signal) if signal.isdigit() else None,
            channel=int(channel) if channel.isdigit() else None,
            security=security or None, active=active.strip() == "*",
        ))
    return sorted(networks, key=lambda network: (not network.active, -(network.signal or 0)))


@lru_cache(maxsize=1)
def _oui_vendors() -> dict[str, str]:
    path = Path("/usr/share/nmap/nmap-mac-prefixes")
    if not path.is_file():
        return {}
    vendors: dict[str, str] = {}
    try:
        for line in path.read_text(errors="replace").splitlines():
            if not line or line.startswith("#"):
                continue
            prefix, _, vendor = line.partition(" ")
            if prefix and vendor:
                vendors[prefix.upper()] = vendor.strip()
    except OSError:
        return {}
    return vendors


def _mac_vendor(mac: str | None) -> str | None:
    if not mac:
        return None
    prefix = "".join(char for char in mac if char.isalnum())[:6].upper()
    return _oui_vendors().get(prefix)


def _mac_octets(mac: str | None) -> list[str]:
    if not mac:
        return []
    return [part.upper() for part in mac.replace("-", ":").split(":") if part]


def _same_device_mac_family(mac: str | None, bssid: str | None) -> bool:
    """Heuristic: Ethernet and Wi-Fi interfaces often differ only at byte 6."""
    left, right = _mac_octets(mac), _mac_octets(bssid)
    return len(left) == 6 and len(right) == 6 and left[:5] == right[:5]


def enrich_identities(hosts: list[HostInfo], wifi: list[WifiNetwork],
                      context: NetworkContext) -> None:
    """Attach human-friendly roles and SSID correlations without claiming proof."""
    for host in hosts:
        matched = sorted({network.ssid for network in wifi
                          if network.ssid != "(hidden)" and
                          _same_device_mac_family(host.mac, network.bssid)})
        host.matched_ssids = matched

        ports = {port.port for port in host.ports}
        if host.is_self:
            host.role = "scanner laptop"
            host.display_name = "This laptop"
            host.identity_confidence = "confirmed"
        elif host.is_gateway:
            host.role = "gateway/router"
            label = matched[0] if matched else context.ssid
            host.display_name = "Gateway" + (f" · {label}" if label else "")
            host.identity_confidence = "confirmed-role"
        elif matched:
            host.role = ("CPE WAN interface candidate" if context.vantage == "wan"
                         else "Wi-Fi AP/bridge candidate")
            prefix = host.vendor or "Wi-Fi device"
            host.display_name = f"{prefix} · {', '.join(matched)}"
            host.identity_confidence = "probable"
        elif host.vendor:
            host.role = "network host"
            host.display_name = host.vendor
            host.identity_confidence = "vendor-only"
        elif ports.intersection({53, 80, 443, 7547, 8080, 8443}):
            host.role = "network service device"
            host.display_name = "Unidentified network device"
            host.identity_confidence = "low"
        else:
            host.role = "host"
            host.display_name = "Unidentified host"
            host.identity_confidence = "low"

        if matched:
            host.identity_notes.append(
                "SSID association is inferred from a five-byte MAC/BSSID prefix match; "
                "confirm with HTTP/UPnP/model fingerprinting"
            )


def detect_context(cidr: str | None = None, interface: str | None = None,
                   vantage: str = "current") -> NetworkContext:
    """Detect active IPv4 interface, address, gateway, and scan network."""
    route = _default_route()
    dev = interface or route.get("dev")
    if not dev:
        raise RuntimeError("default route has no interface")

    links = json.loads(_command(["ip", "-j", "-4", "addr", "show", "dev", dev]))
    candidates = [address for link in links for address in link.get("addr_info", [])
                  if address.get("family") == "inet" and address.get("scope") == "global"]
    if not candidates:
        raise RuntimeError(f"no global IPv4 address found on {dev}")

    chosen = candidates[0]
    local = chosen["local"]
    prefixlen = int(chosen["prefixlen"])
    detected = ipaddress.ip_network(f"{local}/{prefixlen}", strict=False)
    network = ipaddress.ip_network(cidr, strict=False) if cidr else detected
    if network.version != 4:
        raise ValueError("discover currently accepts an IPv4 CIDR")

    ssid, bssid = _wifi_identity(dev)

    return NetworkContext(
        vantage=vantage,
        interface=dev,
        address=local,
        prefixlen=prefixlen,
        network=str(network),
        gateway=route.get("gateway"),
        ssid=ssid,
        bssid=bssid,
    )


def _nmap_xml(arguments: list[str], timeout: int) -> str:
    if not shutil.which("nmap"):
        raise RuntimeError("nmap is required (`sudo apt install nmap`)")
    # No shell: each target is a separate argv element.
    return _command(["nmap", "-n", *arguments, "-oX", "-"], timeout=timeout)


def parse_nmap_xml(document: str) -> list[HostInfo]:
    """Parse nmap XML into the tool's stable host/port model."""
    root = ET.fromstring(document)
    results: list[HostInfo] = []
    for node in root.findall("host"):
        status = node.find("status")
        state = status.get("state", "unknown") if status is not None else "unknown"
        addresses = node.findall("address")
        ipv4 = next((address.get("addr") for address in addresses
                     if address.get("addrtype") == "ipv4"), None)
        if not ipv4:
            continue
        mac_node = next((address for address in addresses
                         if address.get("addrtype") == "mac"), None)
        host = HostInfo(
            address=ipv4,
            state=state,
            mac=mac_node.get("addr") if mac_node is not None else None,
            vendor=mac_node.get("vendor") if mac_node is not None else None,
        )
        for port_node in node.findall("./ports/port"):
            state_node = port_node.find("state")
            if state_node is None or state_node.get("state") != "open":
                continue
            service = port_node.find("service")
            host.ports.append(PortInfo(
                port=int(port_node.get("portid", "0")),
                protocol=port_node.get("protocol", "tcp"),
                service=service.get("name") if service is not None else None,
                product=service.get("product") if service is not None else None,
                version=service.get("version") if service is not None else None,
                extra_info=service.get("extrainfo") if service is not None else None,
            ))
        host.ports.sort(key=lambda port: (port.protocol, port.port))
        results.append(host)
    return results


def _neighbors(interface: str, network: ipaddress.IPv4Network) -> dict[str, str]:
    """Return IP->MAC from the neighbor table (fills non-root nmap gaps)."""
    try:
        output = _command(["ip", "neigh", "show", "dev", interface])
    except (OSError, RuntimeError, subprocess.TimeoutExpired):
        return {}
    found: dict[str, str] = {}
    for line in output.splitlines():
        parts = line.split()
        if not parts:
            continue
        try:
            address = ipaddress.ip_address(parts[0])
        except ValueError:
            continue
        if address.version != 4 or address not in network or "lladdr" not in parts:
            continue
        index = parts.index("lladdr")
        if index + 1 < len(parts):
            found[str(address)] = parts[index + 1].upper()
    return found


def _merge_hosts(base: list[HostInfo], update: list[HostInfo]) -> list[HostInfo]:
    by_ip = {host.address: host for host in base}
    for incoming in update:
        current = by_ip.get(incoming.address)
        if current is None:
            by_ip[incoming.address] = incoming
            continue
        current.state = incoming.state or current.state
        current.mac = incoming.mac or current.mac
        current.vendor = incoming.vendor or current.vendor
        if incoming.ports:
            known = {(port.protocol, port.port): port for port in current.ports}
            for port in incoming.ports:
                known[(port.protocol, port.port)] = port
            current.ports = sorted(known.values(), key=lambda port: (port.protocol, port.port))
    return sorted(by_ip.values(), key=lambda host: ipaddress.ip_address(host.address))


def _port_arguments(profile: str, service_detection: bool) -> list[str]:
    args = ["-sT", "-T3", "--open", "--max-retries", "2", "--host-timeout", "180s"]
    if profile == "common":
        args += ["-p", ",".join(str(port) for port in COMMON_TCP_PORTS)]
    elif profile == "top":
        args += ["--top-ports", "1000"]
    elif profile == "all":
        args += ["-p-"]
    elif profile != "none":
        raise ValueError(f"unknown scan profile: {profile}")
    if service_detection and profile != "none":
        args += ["-sV", "--version-light"]
    return args


def _udp_arguments(profile: str, service_detection: bool) -> list[str]:
    """Build a bounded UDP scan for CPE control/discovery protocols."""
    if profile == "none":
        return []
    if profile != "common":
        raise ValueError(f"unknown UDP scan profile: {profile}")
    args = [
        "-sU", "-T3", "-Pn", "--open", "--max-retries", "1",
        "--host-timeout", "120s", "-p",
        ",".join(str(port) for port in COMMON_UDP_PORTS),
    ]
    if service_detection:
        args += ["-sV", "--version-light"]
    return args


def run(cidr: str | None = None, interface: str | None = None,
        vantage: str = "current", scan_profile: str = "top",
        service_detection: bool = True, include_self: bool = False,
        full_gateway: bool = False, allow_large: bool = False,
        assume_up: bool = False, udp_profile: str = "none") -> DiscoveryResult:
    """Discover hosts and TCP services from the declared observation point."""
    if udp_profile not in {"none", "common"}:
        raise ValueError(f"unknown UDP scan profile: {udp_profile}")
    context = detect_context(cidr, interface, vantage)
    network = ipaddress.ip_network(context.network)
    if network.num_addresses > MAX_DEFAULT_ADDRESSES and not allow_large:
        raise ValueError(
            f"refusing {network} ({network.num_addresses} addresses); "
            "use /20 or smaller, or pass --allow-large explicitly"
        )

    result = DiscoveryResult(context=context, scan_profile=scan_profile,
                             service_detection=service_detection,
                             udp_profile=udp_profile, assume_up=assume_up)
    discovered = parse_nmap_xml(_nmap_xml(["-sn", context.network], timeout=180))

    known = {host.address for host in discovered}
    for address in (context.address, context.gateway):
        if address and ipaddress.ip_address(address) in network and address not in known:
            discovered.append(HostInfo(address=address))
            known.add(address)

    neighbors = _neighbors(context.interface, network)
    for host in discovered:
        host.is_self = host.address == context.address
        host.is_gateway = host.address == context.gateway
        host.mac = host.mac or neighbors.get(host.address)
        host.vendor = host.vendor or _mac_vendor(host.mac)
    discovered.sort(key=lambda host: ipaddress.ip_address(host.address))

    targets = [host.address for host in discovered if include_self or not host.is_self]
    if scan_profile != "none" and (targets or assume_up):
        scan_targets = [context.network] if assume_up else targets
        # Forced subnet scans use two passes: quick port discovery over the
        # CIDR, then service detection only on hosts that exposed a port.
        arguments = _port_arguments(scan_profile, service_detection and not assume_up)
        if assume_up:
            arguments.append("-Pn")
        arguments += scan_targets
        scanned = parse_nmap_xml(_nmap_xml(arguments, timeout=max(300, 210 * len(targets))))
        if assume_up:
            # With -Pn nmap calls every address "up"; retain only hosts that
            # actually exposed a selected port, then merge ordinary discovery.
            scanned = [host for host in scanned
                       if host.ports and (include_self or host.address != context.address)]
            if service_detection and scanned:
                detail_targets = [host.address for host in scanned]
                detail_args = (_port_arguments(scan_profile, True) + ["-Pn"] + detail_targets)
                detailed = parse_nmap_xml(_nmap_xml(
                    detail_args, timeout=max(300, 210 * len(detail_targets))))
                scanned = _merge_hosts(scanned, detailed)
        discovered = _merge_hosts(discovered, scanned)
        if assume_up:
            result.notes.append(
                "forced edge scan used -Pn; service detection ran only on hosts exposing a selected port"
            )

    gateway_in_scope = (context.gateway is not None and
                        ipaddress.ip_address(context.gateway) in network)
    if full_gateway and gateway_in_scope:
        gateway_scan = parse_nmap_xml(_nmap_xml(
            _port_arguments("all", service_detection) + [context.gateway], timeout=600))
        discovered = _merge_hosts(discovered, gateway_scan)
        result.notes.append("gateway received an additional full 1-65535 TCP scan")
    elif full_gateway:
        result.notes.append("full gateway scan skipped: gateway is outside target CIDR")

    if udp_profile == "common":
        if not gateway_in_scope:
            result.notes.append("common UDP scan skipped: gateway is outside target CIDR")
        elif getattr(os, "geteuid", lambda: 1)() != 0:
            result.notes.append(
                "common UDP scan skipped: raw UDP discovery requires root; "
                "rerun the CLI explicitly with sufficient privileges"
            )
        else:
            try:
                udp_scan = parse_nmap_xml(_nmap_xml(
                    _udp_arguments("common", service_detection) + [context.gateway],
                    timeout=180,
                ))
                discovered = _merge_hosts(discovered, udp_scan)
                result.notes.append(
                    "gateway received a bounded common UDP scan; only confirmed open ports are retained"
                )
            except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
                result.notes.append(
                    f"common UDP scan could not complete: {type(exc).__name__}"
                )

    for host in discovered:
        host.is_self = host.address == context.address
        host.is_gateway = host.address == context.gateway
        host.mac = host.mac or neighbors.get(host.address)
        host.vendor = host.vendor or _mac_vendor(host.mac)
    result.wifi_networks = wifi_inventory(context.interface)
    enrich_identities(discovered, result.wifi_networks, context)
    result.hosts = discovered
    result.notes.append("discovery/port checks only; no authentication was attempted")
    return result


def summary_lines(result: DiscoveryResult) -> list[str]:
    context = result.context
    lines = [
        f"=== discover ({context.vantage}) ===",
        f"interface : {context.interface}",
        f"self      : {context.address}/{context.prefixlen}",
        f"network   : {context.network}",
        f"gateway   : {context.gateway or '-'}",
        f"ssid      : {context.ssid or '-'}",
        f"bssid     : {context.bssid or '-'}",
        f"profile   : {result.scan_profile}",
        f"udp       : {result.udp_profile}",
        f"hosts     : {len(result.hosts)}",
        "",
    ]
    for host in result.hosts:
        tags = []
        if host.is_gateway:
            tags.append("gateway")
        if host.is_self:
            tags.append("self")
        tag = f" [{' '.join(tags)}]" if tags else ""
        identity = " ".join(value for value in (host.mac, host.vendor) if value)
        lines.append(f"{host.display_name or host.address} · {host.address}{tag}" +
                     (f"  {identity}" if identity else ""))
        if host.ports:
            for port in host.ports:
                detail = " ".join(value for value in
                                  (port.service, port.product, port.version, port.extra_info)
                                  if value)
                lines.append(f"  {port.port}/{port.protocol} open" +
                             (f"  {detail}" if detail else ""))
        elif not host.is_self and result.scan_profile != "none":
            lines.append("  no open ports found in selected profile")
    for note in result.notes:
        lines.append(f"note: {note}")
    return lines

