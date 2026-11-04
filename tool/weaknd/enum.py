"""On-device recon — inventory one of my own test-lab CPE boxes over SSH.

Given a shell on a device I own (credential from the creds/attack chain), walk
the box and write down what it *is*: firmware, who I am on it, which daemons
listen, how the network is wired, where the TR-069/ACS client points, which
tools ship on the box, and — the bridge to the loot stage — where config and
secrets actually live.

This is "know my own device" work, not post-exploitation: every probe is a
read (uname/id/ps/netstat/ip/cat/which/find). Nothing is changed on the box.

SCOPE / SAFETY:
    * Own-lab only — runs read-only commands on my own test CPE devices, with a
      credential I already hold.
    * One SSH session: every probe is batched behind markers (like privesc), so
      we touch the box once and stay lockout-friendly.
    * `candidate_secret_stores` is the hand-off to loot discovery: it lists the
      locations worth reading for secrets, it does NOT read the secrets here.

Design note: `run()` is the only part that talks to the device. It hands the raw
command output to `build()`, which is pure — every section parser and the
config-store discovery run on strings, so they are testable without a device.
"""
from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass, field

from . import ssh

# ---------------------------------------------------------------------------
# Probes — label -> command. All read-only. Batched into one SSH session and
# split back apart by the __K_<label>__ markers (same trick as privesc._batch).
# Labels are dotted (section.name) purely for readability.
# ---------------------------------------------------------------------------
PROBES: dict[str, str] = {
    # --- system / firmware ---
    "system.uname":    "uname -a",
    "system.release":  "cat /etc/os-release 2>/dev/null || cat /etc/*release* 2>/dev/null",
    "system.busybox":  "busybox 2>&1 | head -1",
    "system.cpuinfo":  "cat /proc/cpuinfo 2>/dev/null",
    "system.meminfo":  "grep -i memtotal /proc/meminfo 2>/dev/null",
    "system.nvram":    "nvram show 2>/dev/null | grep -iE 'model|firmware|fw_?ver|hw_?ver|prod|boardname'",
    # --- identity / privilege ---
    "id":              "id",
    "whoami":          "whoami",
    "writable":        'for d in /tmp /var /etc /etc/config /www /overlay /jffs /data; do [ -w "$d" ] && echo "W:$d"; done',
    # --- services / listening ---
    "ps":              "ps w 2>/dev/null || ps 2>/dev/null",
    "listen":          "netstat -ltnup 2>/dev/null || ss -ltnup 2>/dev/null",
    # --- network ---
    "net.addr":        "ip addr 2>/dev/null || ifconfig 2>/dev/null",
    "net.route":       "ip route 2>/dev/null || route -n 2>/dev/null",
    "net.wanget":      "ip route get 8.8.8.8 2>/dev/null",
    "net.dns":         "cat /etc/resolv.conf 2>/dev/null",
    "net.bridge":      "brctl show 2>/dev/null; ls /sys/class/net 2>/dev/null",
    # --- TR-069 / ACS ---
    "tr069.nvram":     "nvram show 2>/dev/null | grep -iE 'acs|cwmp|tr.?069|inform|conn.?req|connection.?request'",
    "tr069.uci":       "uci show 2>/dev/null | grep -iE 'cwmp|tr069|acs'; cat /etc/config/cwmp 2>/dev/null; cat /etc/config/tr069 2>/dev/null",
    "tr069.files":     "cat /etc/tr069/*.conf /etc/cwmp/*.conf /etc/cwmp.conf /var/cwmp* 2>/dev/null",
    "tr069.find":      r"find /etc /var /tmp /data -maxdepth 3 \( -iname '*cwmp*' -o -iname '*tr069*' -o -iname '*tr-069*' -o -iname '*datamodel*' \) 2>/dev/null | head -30",
    # --- capabilities ---
    "cap.which":       "which nvram bcmnvram sendcmd hostapd_cli tcpdump nc 2>/dev/null",
    "cap.applets":     "busybox --list 2>/dev/null",
    # --- config / secret stores (feeds candidate_secret_stores) ---
    "store.etcconfig": "ls -1 /etc/config 2>/dev/null",
    "store.hostapd":   "ls -1 /tmp/*hapd*.conf /tmp/*hostapd* /var/run/hostapd* 2>/dev/null",
    "store.db":        r"find /etc /var /tmp /data /jffs -maxdepth 3 \( -iname '*.db' -o -iname '*.sqlite' -o -iname '*.xml' \) 2>/dev/null | head -40",
}

# daemon basename -> what it is. Used to label listening ports and ps lines.
DAEMON_SIGNS = {
    "httpd": "http-mgmt", "uhttpd": "http-mgmt", "lighttpd": "http-mgmt",
    "mini_httpd": "http-mgmt", "boa": "http-mgmt", "goahead": "http-mgmt",
    "dropbear": "ssh", "sshd": "ssh",
    "telnetd": "telnet", "utelnetd": "telnet",
    "upnpd": "upnp", "miniupnpd": "upnp", "wscd": "wps",
    "cwmp": "tr-069/acs-client", "cwmpd": "tr-069/acs-client",
    "tr069": "tr-069/acs-client", "tr-069": "tr-069/acs-client",
    "snmpd": "snmp", "dnsmasq": "dns/dhcp", "hostapd": "wifi-ap",
}


# ---------------------------------------------------------------------------
# Section dataclasses
# ---------------------------------------------------------------------------
@dataclass
class SystemInfo:
    uname: str | None = None
    kernel: str | None = None
    arch: str | None = None
    cpu_model: str | None = None
    ram_total_kb: int | None = None
    busybox_version: str | None = None
    os_release: dict[str, str] = field(default_factory=dict)
    nvram_model: str | None = None
    nvram_firmware: str | None = None
    notes: list[str] = field(default_factory=list)


@dataclass
class IdentityInfo:
    whoami: str | None = None
    id: str | None = None
    is_root: bool = False
    writable_dirs: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass
class Service:
    proto: str                       # tcp / udp
    local: str                       # listen address:port as reported
    port: int | None = None
    process: str | None = None       # daemon basename, if the OS told us
    role: str | None = None          # recognized role (http-mgmt, ssh, ...)


@dataclass
class ServicesInfo:
    listening: list[Service] = field(default_factory=list)
    daemons: list[str] = field(default_factory=list)   # recognized roles seen
    ps_sample: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass
class NetworkInfo:
    interfaces: list[str] = field(default_factory=list)   # "eth0 192.168.1.1/24"
    routes: list[str] = field(default_factory=list)
    wan_iface: str | None = None
    default_gateway: str | None = None
    dns: list[str] = field(default_factory=list)
    bridges: list[str] = field(default_factory=list)
    vlans: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass
class Tr069Info:
    acs_url: str | None = None
    connection_request_url: str | None = None
    connection_request_port: int | None = None
    periodic_inform_interval: str | None = None
    datamodel_store: str | None = None
    source: str | None = None        # where we read it (nvram / uci / files)
    notes: list[str] = field(default_factory=list)


@dataclass
class Capabilities:
    tools: dict[str, str] = field(default_factory=dict)      # basename -> path
    busybox_applets: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass
class ReconResult:
    host: str
    user: str
    system: SystemInfo = field(default_factory=SystemInfo)
    identity: IdentityInfo = field(default_factory=IdentityInfo)
    services: ServicesInfo = field(default_factory=ServicesInfo)
    network: NetworkInfo = field(default_factory=NetworkInfo)
    tr069: Tr069Info = field(default_factory=Tr069Info)
    capabilities: Capabilities = field(default_factory=Capabilities)
    # bridge to the loot stage: {path, kind, note}
    candidate_secret_stores: list[dict] = field(default_factory=list)
    raw: dict = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# SSH collection (the only device-touching part)
# ---------------------------------------------------------------------------
def _split_markers(out: str) -> dict[str, str]:
    """Split one batched run back into {label: output} by __K_<label>__ lines."""
    res: dict[str, list[str]] = {}
    cur: str | None = None
    for line in out.splitlines():
        m = line.strip()
        if m.startswith("__K_") and m.endswith("__"):
            cur = m[4:-2]
            res[cur] = []
        elif cur is not None:
            res[cur].append(line)
    return {k: "\n".join(v).strip() for k, v in res.items()}


def collect(host: str, user: str, password: str, port: int = 22,
            timeout: int = 45) -> dict[str, str]:
    """Run every probe in one SSH session; return {label: raw output}."""
    script = "; ".join(f"echo __K_{label}__; {cmd}" for label, cmd in PROBES.items())
    out = ssh.run(host, user, password, script, port, timeout)
    return _split_markers(out)


# ---------------------------------------------------------------------------
# Pure parsers — each takes raw strings, never a device. Unit-testable.
# ---------------------------------------------------------------------------
_ARCH_RE = re.compile(r"\b(armv\d\w*|aarch64|mips(?:el|64)?|i[3-6]86|x86_64|ppc\w*)\b")


def _first_line(s: str) -> str:
    for line in (s or "").splitlines():
        if line.strip():
            return line.strip()
    return ""


def parse_system(raw: dict[str, str]) -> SystemInfo:
    s = SystemInfo()
    uname = _first_line(raw.get("system.uname", ""))
    if uname:
        s.uname = uname
        parts = uname.split()
        if len(parts) >= 3:
            s.kernel = parts[2]
        m = _ARCH_RE.search(uname)
        if m:
            s.arch = m.group(1)
    else:
        s.notes.append("uname empty — host unreachable or no shell?")

    rel = raw.get("system.release", "")
    for line in rel.splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            s.os_release[k.strip()] = v.strip().strip('"').strip("'")

    bb = _first_line(raw.get("system.busybox", ""))
    m = re.search(r"BusyBox\s+(v[\d.]+)", bb)
    if m:
        s.busybox_version = m.group(1)

    for line in raw.get("system.cpuinfo", "").splitlines():
        key, _, val = line.partition(":")
        key = key.strip().lower()
        val = val.strip()
        # "processor" is the model on some ARM builds but just an index ("0")
        # on x86/SMP — skip the numeric form.
        if key in ("model name", "hardware", "processor", "system type",
                   "machine", "cpu model") and val and not val.isdigit():
            s.cpu_model = val
            break
    if not s.arch and s.cpu_model:
        m = _ARCH_RE.search(s.cpu_model)
        if m:
            s.arch = m.group(1)

    m = re.search(r"MemTotal:\s*(\d+)\s*kB", raw.get("system.meminfo", ""), re.I)
    if m:
        s.ram_total_kb = int(m.group(1))

    for line in raw.get("system.nvram", "").splitlines():
        k, _, v = line.partition("=")
        kl, v = k.strip().lower(), v.strip()
        if not v:
            continue
        if s.nvram_model is None and "model" in kl:
            s.nvram_model = v
        if s.nvram_firmware is None and ("firmware" in kl or "fwver" in kl
                                         or "fw_ver" in kl):
            s.nvram_firmware = v
    return s


def parse_identity(raw: dict[str, str]) -> IdentityInfo:
    i = IdentityInfo()
    idline = _first_line(raw.get("id", ""))
    if idline:
        i.id = idline
        i.is_root = "uid=0" in idline
    i.whoami = _first_line(raw.get("whoami", "")) or None
    for line in raw.get("writable", "").splitlines():
        line = line.strip()
        if line.startswith("W:"):
            i.writable_dirs.append(line[2:])
    if i.is_root:
        i.notes.append("uid=0 — full read of every config/secret store.")
    elif i.writable_dirs:
        i.notes.append("non-root but writable: " + ", ".join(i.writable_dirs))
    return i


def _process_name(line: str) -> str | None:
    """Pull a daemon name from a netstat (`1234/httpd`) or ss (`users:((...))`) line."""
    m = re.search(r"\d+/([A-Za-z0-9_\-./]+)", line)
    if m:
        return posixpath.basename(m.group(1))
    m = re.search(r'\(\("([^"]+)"', line)
    if m:
        return m.group(1)
    return None


def parse_services(raw: dict[str, str]) -> ServicesInfo:
    sv = ServicesInfo()
    roles: set[str] = set()

    for line in raw.get("listen", "").splitlines():
        toks = line.split()
        if not toks or not toks[0].lower().startswith(("tcp", "udp")):
            continue
        proto = "udp" if toks[0].lower().startswith("udp") else "tcp"
        local, port = None, None
        for t in toks[1:]:
            m = re.match(r"^(.+):(\d+)$", t)      # skips foreign "0.0.0.0:*"
            if m:
                local, port = t, int(m.group(2))
                break
        if local is None:
            continue
        proc = _process_name(line)
        role = DAEMON_SIGNS.get((proc or "").lower())
        if role:
            roles.add(role)
        sv.listening.append(Service(proto=proto, local=local, port=port,
                                    process=proc, role=role))

    ps = raw.get("ps", "")
    sv.ps_sample = [l for l in ps.splitlines() if l.strip()][:40]
    for line in ps.splitlines():
        low = line.lower()
        for name, role in DAEMON_SIGNS.items():
            if re.search(rf"\b{re.escape(name)}\b", low):
                roles.add(role)
    sv.daemons = sorted(roles)
    return sv


def parse_network(raw: dict[str, str]) -> NetworkInfo:
    n = NetworkInfo()

    addr = raw.get("net.addr", "")
    cur_if = None
    if_addr: dict[str, list[str]] = {}
    for line in addr.splitlines():
        # `ip addr`: "2: eth0: <...>"      ;  "    inet 192.168.1.1/24 ..."
        m = re.match(r"^\d+:\s+([^:@]+)[:@]", line)
        if m:
            cur_if = m.group(1).strip()
            if_addr.setdefault(cur_if, [])
            continue
        # `ifconfig`: "eth0      Link encap:..."
        m = re.match(r"^(\S+)\s+Link encap", line)
        if m:
            cur_if = m.group(1)
            if_addr.setdefault(cur_if, [])
            continue
        # `ip addr` -> "inet 192.168.1.1/24"; ifconfig -> "inet addr:10.0.0.1"
        m = re.search(r"inet\s+(?:addr:)?\s*(\d+\.\d+\.\d+\.\d+(?:/\d+)?)", line)
        if m and cur_if:
            if_addr[cur_if].append(m.group(1))
    for iface, addrs in if_addr.items():
        n.interfaces.append(f"{iface} {' '.join(addrs)}".strip())
        if iface.startswith("br") or iface.startswith("bridge"):
            n.bridges.append(iface)
        if "." in iface and iface not in ("lo",):
            n.vlans.append(iface)

    route = raw.get("net.route", "")
    n.routes = [l.strip() for l in route.splitlines() if l.strip()]

    wanget = raw.get("net.wanget", "")
    m = re.search(r"\bdev\s+(\S+)", wanget)
    if m:
        n.wan_iface = m.group(1)
    m = re.search(r"\bvia\s+(\d+\.\d+\.\d+\.\d+)", wanget)
    if m:
        n.default_gateway = m.group(1)
    if not n.wan_iface or not n.default_gateway:          # fall back to route table
        for line in n.routes:
            toks = line.split()
            if not (line.startswith("default") or (toks and toks[0] == "0.0.0.0")):
                continue
            m = re.search(r"\bdev\s+(\S+)", line)          # `ip route` form
            if not n.wan_iface:
                n.wan_iface = m.group(1) if m else (toks[-1] if toks else None)
            m = re.search(r"\b(?:via|gateway)\s+(\d+\.\d+\.\d+\.\d+)", line)
            if not n.default_gateway:
                if m:
                    n.default_gateway = m.group(1)
                elif toks[0] == "0.0.0.0" and len(toks) > 1 and \
                        re.match(r"\d+\.\d+\.\d+\.\d+$", toks[1]):  # `route -n` col 2
                    n.default_gateway = toks[1]

    for line in raw.get("net.dns", "").splitlines():
        m = re.match(r"\s*nameserver\s+(\S+)", line)
        if m:
            n.dns.append(m.group(1))

    for line in raw.get("net.bridge", "").splitlines():
        tok = line.split()
        if tok and (tok[0].startswith("br") or tok[0].startswith("bridge")) \
                and tok[0] not in n.bridges and tok[0] != "bridge":
            n.bridges.append(tok[0])
    n.bridges = sorted(set(n.bridges))
    n.vlans = sorted(set(n.vlans))
    return n


def parse_tr069(raw: dict[str, str]) -> Tr069Info:
    t = Tr069Info()
    # Combine the config sources; remember which one actually carried data.
    sources = [("nvram", raw.get("tr069.nvram", "")),
               ("uci", raw.get("tr069.uci", "")),
               ("files", raw.get("tr069.files", ""))]
    blob = "\n".join(text for _, text in sources)

    def find(pat: str) -> str | None:
        m = re.search(pat, blob, re.I)
        return m.group(1).strip().strip('"').strip("'") if m else None

    t.acs_url = (find(r"(?:acs[_.]?url|ManagementServer\.URL|\bURL)\s*[=:]\s*(\S+)")
                 or find(r"(https?://\S*acs\S*)"))
    t.connection_request_url = find(
        r"(?:conn(?:ection)?[_.]?req(?:uest)?[_.]?url|ConnectionRequestURL)\s*[=:]\s*(\S+)")
    t.periodic_inform_interval = find(
        r"(?:periodic[_.]?inform[_.]?interval|PeriodicInformInterval)\s*[=:]\s*(\S+)")

    cr_port = find(r"(?:conn(?:ection)?[_.]?req(?:uest)?[_.]?port)\s*[=:]\s*(\d+)")
    if cr_port:
        t.connection_request_port = int(cr_port)
    elif t.connection_request_url:
        m = re.search(r"://[^/:]+:(\d+)", t.connection_request_url)
        if m:
            t.connection_request_port = int(m.group(1))

    for name, text in sources:
        if text.strip() and (t.acs_url or t.connection_request_url
                             or t.periodic_inform_interval):
            t.source = name
            break

    # datamodel store: a cwmp/datamodel file surfaced by the find probe
    for line in (raw.get("tr069.find", "") + "\n"
                 + raw.get("store.db", "")).splitlines():
        p = line.strip()
        if not p:
            continue
        low = p.lower()
        if ("cwmp" in low or "tr069" in low or "tr-069" in low
                or "datamodel" in low) and p.startswith("/"):
            t.datamodel_store = p
            break

    if not blob.strip():
        t.notes.append("no TR-069 config found in nvram/uci/files — client may be "
                       "off, or config lives somewhere else.")
    return t


def parse_capabilities(raw: dict[str, str]) -> Capabilities:
    c = Capabilities()
    for line in raw.get("cap.which", "").splitlines():
        p = line.strip()
        if p.startswith("/"):
            c.tools[posixpath.basename(p)] = p
    applets = raw.get("cap.applets", "")
    c.busybox_applets = sorted({a.strip() for a in re.split(r"[\s,]+", applets)
                                if a.strip()})
    return c


# command names we'd want for the loot/capture stages
_USEFUL = ("tcpdump", "nc", "hostapd_cli", "sendcmd")


def discover_secret_stores(raw: dict[str, str], caps: Capabilities,
                           system: SystemInfo, tr069: Tr069Info) -> list[dict]:
    """The bridge to loot: list where config/secrets live. Read nothing here."""
    stores: list[dict] = []
    seen: set[str] = set()

    def add(path: str, kind: str, note: str) -> None:
        if path and path not in seen:
            seen.add(path)
            stores.append({"path": path, "kind": kind, "note": note})

    # nvram — either the tool is present or the earlier nvram probe returned rows
    if ("nvram" in caps.tools or "bcmnvram" in caps.tools
            or system.nvram_model or system.nvram_firmware
            or raw.get("system.nvram", "").strip()
            or raw.get("tr069.nvram", "").strip()):
        add("nvram", "nvram",
            "key/value store — wifi PSK, admin + ACS creds; dump via `nvram show`")

    # OpenWrt-style /etc/config (uci)
    etc = [l.strip() for l in raw.get("store.etcconfig", "").splitlines() if l.strip()]
    if etc:
        add("/etc/config", "uci", "uci config tree")
        for f in etc:
            if f.lower() in ("wireless", "cwmp", "tr069", "network", "system",
                             "dropbear", "firewall"):
                add(f"/etc/config/{f}", "uci-file", f"uci: {f} (creds/keys likely)")

    # hostapd runtime configs (plaintext PSK)
    for line in raw.get("store.hostapd", "").splitlines():
        p = line.strip()
        if p.startswith("/"):
            add(p, "hostapd-conf", "wifi PSK in plaintext")

    # the cwmp datamodel store, if TR-069 parsing found one — add before the
    # generic db loop so the more specific kind wins the dedup.
    if tr069.datamodel_store:
        add(tr069.datamodel_store, "cwmp-datamodel",
            "TR-069 parameter store — ACS + connection-request creds")

    # sqlite/xml/db stores
    for line in raw.get("store.db", "").splitlines():
        p = line.strip()
        if not p.startswith("/"):
            continue
        ext = posixpath.splitext(p)[1].lower()
        kind = {".db": "sqlite", ".sqlite": "sqlite", ".xml": "xml"}.get(ext, "db")
        add(p, kind, f"{kind} store — grep for password/psk/acs")

    return stores


# ---------------------------------------------------------------------------
# Assembly
# ---------------------------------------------------------------------------
def build(raw: dict[str, str], host: str, user: str) -> ReconResult:
    """Pure: turn collected command output into a ReconResult. No device."""
    res = ReconResult(host=host, user=user, raw=raw)
    res.system = parse_system(raw)
    res.identity = parse_identity(raw)
    res.services = parse_services(raw)
    res.network = parse_network(raw)
    res.tr069 = parse_tr069(raw)
    res.capabilities = parse_capabilities(raw)
    res.candidate_secret_stores = discover_secret_stores(
        raw, res.capabilities, res.system, res.tr069)

    if not any(raw.get(k, "").strip() for k in ("system.uname", "id")):
        res.notes.append("no output from the box — check host/creds/sshpass.")
    missing = [t for t in _USEFUL if t not in res.capabilities.tools]
    if missing:
        res.capabilities.notes.append("not on box: " + ", ".join(missing))
    return res


def run(host: str, user: str, password: str, port: int = 22) -> ReconResult:
    """Collect over SSH, then build. The one call the CLI makes."""
    raw = collect(host, user, password, port)
    return build(raw, host, user)


# ---------------------------------------------------------------------------
# Human-readable summary (shared by the CLI and the tests)
# ---------------------------------------------------------------------------
def summary_lines(res: ReconResult) -> list[str]:
    sy, idn, sv = res.system, res.identity, res.services
    net, tr, cap = res.network, res.tr069, res.capabilities
    out: list[str] = []
    out.append(f"=== enum {res.host} (as {res.user}) ===")

    out.append("[system]")
    out.append(f"  firmware : {sy.uname or '-'}")
    fw = sy.nvram_firmware or sy.os_release.get("VERSION") or "-"
    model = sy.nvram_model or sy.os_release.get("PRETTY_NAME") or "-"
    out.append(f"  model/fw : {model} / {fw}")
    ram = f"{sy.ram_total_kb // 1024} MB" if sy.ram_total_kb else "-"
    out.append(f"  arch/cpu : {sy.arch or '-'} / {sy.cpu_model or '-'}   ram:{ram}"
               f"   busybox:{sy.busybox_version or '-'}")

    out.append("[identity]")
    out.append(f"  {idn.id or '-'}   root:{'YES' if idn.is_root else 'no'}")
    out.append(f"  writable : {', '.join(idn.writable_dirs) or 'none'}")

    out.append("[services] listening:")
    if sv.listening:
        for s in sv.listening:
            tag = f" {s.process}" if s.process else ""
            role = f" ({s.role})" if s.role else ""
            out.append(f"    {s.proto:<3} {s.local:<22}{tag}{role}")
    else:
        out.append("    none parsed")
    out.append(f"  daemons  : {', '.join(sv.daemons) or 'none recognized'}")

    out.append("[network]")
    for iface in net.interfaces:
        out.append(f"    {iface}")
    out.append(f"  wan      : {net.wan_iface or '-'}  gw:{net.default_gateway or '-'}"
               f"  dns:{', '.join(net.dns) or '-'}")
    if net.bridges or net.vlans:
        out.append(f"  bridge/vlan: {', '.join(net.bridges) or '-'} / "
                   f"{', '.join(net.vlans) or '-'}")

    out.append("[tr-069]")
    out.append(f"  acs url  : {tr.acs_url or '-'}   (src: {tr.source or '-'})")
    out.append(f"  conn-req : {tr.connection_request_url or '-'}"
               f"  port:{tr.connection_request_port or '-'}")
    out.append(f"  inform   : {tr.periodic_inform_interval or '-'}"
               f"   datamodel:{tr.datamodel_store or '-'}")

    out.append("[capabilities]")
    out.append(f"  tools    : {', '.join(sorted(cap.tools)) or 'none of interest'}")
    out.append(f"  applets  : {len(cap.busybox_applets)} busybox applets")

    out.append(f"[secret stores] {len(res.candidate_secret_stores)} candidate(s) "
               "-> loot:")
    for st in res.candidate_secret_stores:
        out.append(f"    {st['kind']:<14} {st['path']}")

    for note in res.notes:
        out.append(f"  ! {note}")
    return out
