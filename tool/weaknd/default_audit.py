"""Bounded SSH factory-default credential audit for authorized LAN CPEs.

This is intentionally not a brute-force engine. It tries exact username/
password pairs from one small named profile, sequentially, with a delay, and
stops at the first confirmed shell. Passwords never appear in process argv,
result objects, or artifacts; results reference public dictionary IDs/labels.
"""
from __future__ import annotations

import ipaddress
import json
import re
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import discovery, ssh, ssh_probe


DICTIONARY = Path(__file__).resolve().parents[2] / "data" / "common_cpe_credentials.json"
UID_RE = re.compile(r"uid=\d+(?:\([^)]*\))?[^\r\n]*")
PROOF_COMMAND = "printf 'WEAKND_OK\\n'; id"


@dataclass(frozen=True)
class DefaultCredential:
    id: str
    username: str
    password: str
    label: str


@dataclass
class CredentialAttempt:
    credential_id: str
    label: str
    username: str
    status: str  # success | failed | timeout | error


@dataclass
class DefaultAuditResult:
    host: str
    port: int
    profile: str
    in_connected_lan: bool = False
    ssh_banner: str | None = None
    auth_methods: list[str] = field(default_factory=list)
    legacy_ssh_options: list[str] = field(default_factory=lambda: list(ssh_probe.LEGACY_OPTS))
    attempts: list[CredentialAttempt] = field(default_factory=list)
    found: bool = False
    credential_id: str | None = None
    credential_label: str | None = None
    username: str | None = None
    proof: str | None = None
    is_root: bool = False
    notes: list[str] = field(default_factory=list)


def load_profile(profile: str) -> list[DefaultCredential]:
    data = json.loads(DICTIONARY.read_text())
    profile_ids = data.get("profiles", {}).get(profile)
    if not isinstance(profile_ids, list):
        raise ValueError(f"unknown credential profile: {profile}")
    by_id = {item["id"]: item for item in data.get("credentials", [])}
    credentials: list[DefaultCredential] = []
    for credential_id in profile_ids:
        item = by_id.get(credential_id)
        if not item:
            raise ValueError(f"profile {profile} references missing credential {credential_id}")
        credentials.append(DefaultCredential(**item))
    return credentials


def validate_connected_lan_target(host: str) -> discovery.NetworkContext:
    """Require a concrete host inside the laptop's directly connected IPv4 LAN."""
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ValueError("default audit requires an IPv4 address, not a hostname") from exc
    if address.version != 4:
        raise ValueError("default audit currently supports connected-LAN IPv4 targets")
    context = discovery.detect_context(vantage="lan")
    network = ipaddress.ip_network(context.network)
    if address not in network or address in {network.network_address, network.broadcast_address}:
        raise ValueError(f"target {host} is outside connected LAN {network}")
    if str(address) == context.address:
        raise ValueError("refusing to credential-audit the scanner laptop")
    return context


def _proof_line(output: str) -> str | None:
    match = UID_RE.search(output)
    return match.group(0)[:300] if match else None


def run(host: str, port: int = 22, profile: str = "minimal",
        delay: float = 1.0) -> DefaultAuditResult:
    delay = min(max(float(delay), 0.5), 10.0)
    credentials = load_profile(profile)
    result = DefaultAuditResult(host=host, port=port, profile=profile)
    context = validate_connected_lan_target(host)
    result.in_connected_lan = True
    result.notes.append(f"scope confirmed: {host} is inside {context.network}")
    result.notes.append(
        f"bounded sequential audit: {len(credentials)} exact pair(s), {delay:.1f}s delay, stop on success"
    )

    info = ssh_probe.run(host, port, "root")
    result.ssh_banner = info.banner
    result.auth_methods = info.auth_methods
    if not info.reachable:
        result.notes.append("SSH is not reachable; no credential was sent")
        return result
    if info.auth_methods and "password" not in info.auth_methods:
        result.notes.append("SSH does not advertise password auth; no credential was sent")
        return result
    if not ssh.have_sshpass():
        result.notes.append("sshpass is not installed; audit cannot run")
        return result

    for index, credential in enumerate(credentials):
        try:
            proc = ssh.execute(host, credential.username, credential.password,
                               PROOF_COMMAND, port=port, timeout=18)
            combined = (proc.stdout or "") + (proc.stderr or "")
            proof = _proof_line(combined)
            success = proc.returncode == 0 and "WEAKND_OK" in combined and proof is not None
            status = "success" if success else "failed"
        except subprocess.TimeoutExpired:
            proof = None
            success = False
            status = "timeout"
        except (OSError, RuntimeError) as exc:
            proof = None
            success = False
            status = "error"
            result.notes.append(f"SSH execution error: {type(exc).__name__}")

        result.attempts.append(CredentialAttempt(
            credential_id=credential.id,
            label=credential.label,
            username=credential.username,
            status=status,
        ))
        if success:
            result.found = True
            result.credential_id = credential.id
            result.credential_label = credential.label
            result.username = credential.username
            result.proof = proof
            result.is_root = bool(proof and "uid=0" in proof)
            result.notes.append("default credential produced a confirmed shell; audit stopped")
            return result
        if index + 1 < len(credentials):
            time.sleep(delay)

    result.notes.append("no profile credential produced a confirmed shell")
    return result

