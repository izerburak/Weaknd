# Weak&

`Weak&` is a lightweight, vendor-agnostic CPE (router/modem) security assessment
harness. It combines LAN discovery, WAN-facing reconnaissance, service-aware
security checks, bounded credential testing, and evidence-oriented reporting in
one local web dashboard and a Python CLI.

> **Authorized use only.** Run this project only against devices and networks
> you own or have explicit permission to test. Some checks generate active
> traffic, may trigger account lockouts, and may affect device availability.

## What it does

### LAN Audit

- Detects the active interface, local subnet, gateway, SSID, and BSSID.
- Discovers hosts and maps TCP services with Nmap.
- Supports optional bounded UDP discovery and full gateway TCP scanning.
- Identifies likely gateway/router management interfaces.
- Probes SSH authentication methods without sending a password.
- Checks Telnet and CWMP/TR-069 reachability when those services are observed.
- Runs a bounded, sequential SSH/Telnet default-credential assessment.
- Stores observations and confirmed results in the LAN Findings view.

### WAN Audit

The WAN workflow is split into three views:

1. **Recon** — maps explicitly supplied WAN targets using Quick, Full TCP, UDP,
   or vulnerability-oriented scan profiles. Quick Recon uses a small CPE port
   set and reports port-table service names as unverified until validated.
2. **Pentest** — derives applicable checks from Recon evidence and can run:
   - conservative Nmap NSE checks;
   - service-validated Nuclei HTTP/HTTPS and TLS checks;
   - bounded generic SSH/Telnet credential tests;
   - conservatively allowlisted RouterSploit checks when an optional compatible
     RouterSploit installation is configured;
   - category-selectable Nikto HTTP/HTTPS assessments.
3. **Findings** — consolidates observations and validated findings and exports a
   standalone HTML report.

WAN scans run from the machine hosting `weaknd`. To compare real LAN and WAN
exposure, run the assessments from the appropriate network vantage points.

### Nikto categories

The Nikto panel builds `-Tuning` dynamically from the selected categories. The
default selection is:

- `2` — Misconfiguration / Default Files
- `3` — Information Disclosure
- `b` — Software Identification

Denial-of-service category `6` is disabled by default and requires explicit
confirmation. Command-execution category `8` displays an additional warning.
The exact subprocess argument list, scan ID, PID, timestamps, return code, and
raw output are retained in the corresponding JSON artifact.

## Safety controls

- No scan starts automatically.
- Targets must be entered manually or inherited from the current Recon session.
- Credential checks use one worker, a short delay, attempt limits, and
  stop-on-success/rate-limit behavior.
- Passwords are not written to findings, logs, or exported reports.
- Successful authentication is sufficient evidence; no command is executed
  after a generic credential test succeeds.
- Scanner processes can be cancelled from the UI.
- Open ports are observations, not automatic vulnerability claims.
- Incomplete and failed scans are not reported as secure results.

## Requirements

- Linux (Ubuntu is the primary development platform)
- Python 3.10 or newer
- Nmap for discovery and service scanning

The application itself currently uses only the Python standard library. Install
the Python environment with:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

System tools are detected at runtime. Install only the integrations you intend
to use:

| Tool | Used for | Required? |
|---|---|---|
| `nmap` | LAN/WAN discovery, service detection, NSE | Core scanning |
| `nikto` | Category-selectable HTTP/HTTPS assessment | Optional |
| `nuclei` | Conservative HTTP/TLS template checks | Optional |
| `ssh`, `sshpass` | SSH probes and bounded authentication helpers | Optional |
| `snmpget` / `snmpwalk` | Read-only SNMP assessment | Optional |
| `tcpdump`, `tshark` | PCAP validation and traffic analysis module | Optional |
| `hydra` | Legacy CLI credential attack path | Optional, lockout risk |
| RouterSploit | Allowlisted module checks and credential runtime | Optional |

Example Ubuntu packages:

```bash
sudo apt update
sudo apt install nmap nikto openssh-client sshpass snmp tcpdump tshark \
  iproute2 network-manager wireless-tools
```

Nuclei and RouterSploit should be installed from their respective upstream
projects. They are intentionally not installed by `requirements.txt`.

## Quick start

Start the local dashboard:

```bash
cd tool
python serve.py
```

Then open `http://127.0.0.1:8777`.

The server binds to localhost by default. Restart the Python process after
updating the backend; the UI rejects an outdated Nikto backend instead of
running a command that differs from its preview.

## Optional integrations

RouterSploit paths can be configured without changing source code:

```bash
export ROUTERSPLOIT_PATH=/path/to/routersploit
export ROUTERSPLOIT_PYTHON=/path/to/routersploit/.venv/bin/python
```

For Nuclei, point the application at an existing templates directory:

```bash
export NUCLEI_TEMPLATES_PATH=/path/to/nuclei-templates
```

## CLI examples

Run CLI commands from the `tool` directory:

```bash
python weaknd.py --help
python weaknd.py discover --vantage lan --scan common
python weaknd.py scan 192.0.2.1 --ports 22,23,80,443
python weaknd.py ssh-probe 192.0.2.1
python weaknd.py telnet-probe 192.0.2.1
python weaknd.py cwmp-probe 192.0.2.1
python weaknd.py default-audit 192.0.2.1 --profile minimal
python weaknd.py snmp 192.0.2.1
python weaknd.py webaudit 192.0.2.1 --scheme https
```

Some legacy CLI commands perform authentication, brute-force,
post-authentication, or privilege checks. Review `python weaknd.py --help` and
the relevant module before using them. Prefer the bounded dashboard workflows
for routine testing.

## Main modules

| Module | Purpose |
|---|---|
| `discovery.py` | Interface/subnet detection, host discovery, TCP/UDP mapping |
| `wan_scan.py` | WAN scan profiles, XML parsing, cancellation, interface checks |
| `surface.py` | Targeted service/version and HTTP fingerprinting |
| `pentest.py` | Applicable-check selection, Nmap NSE, Nuclei, RouterSploit |
| `credential_testing.py` | Bounded generic SSH/Telnet authentication testing |
| `nikto_scan.py` | Nikto category validation, subprocess execution, diagnostics |
| `ssh_probe.py` | SSH banner, algorithms, and authentication-method discovery |
| `telnet_probe.py` | Telnet reachability and banner probe |
| `cwmp_probe.py` | Read-only CWMP exposure checks |
| `snmp_probe.py` | Read-only default-community SNMP check |
| `traffic_analysis.py` | Bounded PCAP analysis with tcpdump/TShark |
| `report.py` | Secret-redacted JSON artifact serialization |

## Output and reporting

- Machine-readable evidence is written to `artifacts/` as JSON.
- LAN and WAN findings can be exported from the dashboard as standalone HTML.
- Nikto artifacts use a unique server-generated scan ID in the filename.
- Results retain vantage point, target, engine, timestamps, evidence, and
  validation status where available.

Before publishing a fork, review `artifacts/`, `findings/`, `data/`, and local
logs for device identifiers, customer information, or other private evidence.
Do not commit recovered credentials or unredacted device configuration.

## Project layout

```text
.
├── README.md
├── requirements.txt
├── tool/
│   ├── serve.py              # local dashboard backend
│   ├── weaknd.py             # CLI entry point
│   ├── web/index.html        # single-page dashboard
│   └── weaknd/               # assessment modules
├── data/                     # bounded dictionaries and local research data
├── artifacts/                # generated JSON evidence
├── findings/                 # analyst-maintained finding notes
└── resources/                # research references
```

## Limitations

- This is a lightweight proof-of-concept, not a replacement for a complete
  penetration-testing platform.
- Service names from fast port-table scans are unverified until a protocol
  probe confirms them.
- Tool availability and privileges affect scan coverage.
- A negative authentication result does not prove that a device is secure.
- Excluding disruptive Nikto categories does not guarantee a non-disruptive
  assessment.

