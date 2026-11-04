"""Bounded, vendor-independent SSH/Telnet credential testing."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import subprocess
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import default_audit
from .pentest import SecurityFinding, _finding


ROUTERSPLOIT_PATH = Path(os.environ.get("ROUTERSPLOIT_PATH", "/home/burak/routersploit"))
ROUTERSPLOIT_PYTHON = Path(os.environ.get(
    "ROUTERSPLOIT_PYTHON", str(ROUTERSPLOIT_PATH / ".venv" / "bin" / "python")))
RUNNER = Path(__file__).resolve().parents[1] / "credential_check_runner.py"
SUPPORTED_PROTOCOLS = {"ssh": 22, "telnet": 23}
MAX_DEFAULT_ATTEMPTS = 3
DEFAULT_DELAY_SECONDS = 1.0
ATTEMPT_TIMEOUT_SECONDS = 8.0
ENGINE = "Generic Protocol Adapter (RouterSploit runtime)"


@dataclass
class CredentialAttemptResult:
    username: str
    credential_reference: str
    status: str
    evidence: str
    duration_seconds: float


@dataclass
class CredentialTestResult:
    target: str
    protocol: str
    port: int
    test_type: str
    status: str
    final_result: str
    attempted_credentials: int = 0
    successful_authentications: int = 0
    failed_authentications: int = 0
    duration_seconds: float = 0.0
    detection_engine: str = ENGINE
    evidence: str = ""
    timestamp: str = ""
    attempts: list[CredentialAttemptResult] = field(default_factory=list)
    finding: SecurityFinding | None = None
    stopped_on_success: bool = False
    stopped_on_rate_limit: bool = False


_jobs: dict[str, subprocess.Popen[str]] = {}
_active_jobs: set[str] = set()
_cancelled: set[str] = set()
_jobs_lock = threading.Lock()


def runtime_available() -> bool:
    return (ROUTERSPLOIT_PYTHON.is_file() and RUNNER.is_file() and
            (ROUTERSPLOIT_PATH / "routersploit").is_dir())


def default_options() -> list[dict]:
    """Return review metadata only; passwords remain in the dedicated dictionary."""
    options = []
    for credential in default_audit.load_profile("credential-test"):
        options.append({
            "id": credential.id,
            "username": credential.username,
            "label": credential.label,
        })
    return options


def discovered_services(recon: dict) -> list[dict]:
    """Return confirmed services and explicit Quick Recon table candidates."""
    services: list[dict] = []
    for port in (recon or {}).get("ports", []):
        if port.get("state") != "open":
            continue
        method = port.get("service_method")
        confidence = port.get("service_confidence")
        confirmed = bool(port.get("product") or method == "probed" or
                         (isinstance(confidence, int) and confidence >= 7))
        if not confirmed and method != "table":
            continue
        text = " ".join(str(port.get(key) or "") for key in
                        ("service", "product", "version", "extra_info")).lower()
        protocol = next((name for name in SUPPORTED_PROTOCOLS
                         if re.search(rf"\b{re.escape(name)}\b", text)), None)
        if protocol:
            services.append({
                "protocol": protocol,
                "port": int(port["port"]),
                "service": port.get("service"),
                "confirmed": confirmed,
                "evidence": ("confirmed Recon service fingerprint" if confirmed else
                             "unverified Nmap port-table candidate"),
            })
    return services


def options(recon: dict | None = None) -> dict:
    return {
        "available": runtime_available(),
        "router_sploit_path": str(ROUTERSPLOIT_PATH),
        "router_sploit_python": str(ROUTERSPLOIT_PYTHON),
        "protocols": [{"name": name, "default_port": port}
                      for name, port in SUPPORTED_PROTOCOLS.items()],
        "default_credentials": default_options(),
        "max_default_attempts": MAX_DEFAULT_ATTEMPTS,
        "delay_seconds": DEFAULT_DELAY_SECONDS,
        "discovered_services": discovered_services(recon or {}),
    }


def _validate_target(target: str) -> str:
    address = ipaddress.ip_address((target or "").strip())
    if address.is_unspecified or address.is_multicast:
        raise ValueError("target must be a unicast IP address")
    return str(address)


def _validate_text(value: str, name: str, maximum: int, allow_empty: bool = False) -> str:
    value = str(value)
    if (not value and not allow_empty) or len(value) > maximum:
        raise ValueError(f"invalid {name}")
    if any(character in value for character in ("\r", "\n", "\x00")):
        raise ValueError(f"invalid {name}")
    return value


def _credential_reference(identifier: str) -> str:
    return "default-" + hashlib.sha256(identifier.encode()).hexdigest()[:10]


def _selected_defaults(selected_ids: list[str]) -> list[tuple[str, str, str]]:
    if not isinstance(selected_ids, list):
        raise ValueError("selected default credentials must be a list")
    selected_ids = list(dict.fromkeys(str(item) for item in selected_ids))
    if not selected_ids or len(selected_ids) > MAX_DEFAULT_ATTEMPTS:
        raise ValueError(f"select between 1 and {MAX_DEFAULT_ATTEMPTS} default credentials")
    by_id = {item.id: item for item in default_audit.load_profile("credential-test")}
    selected = []
    for identifier in selected_ids:
        credential = by_id.get(identifier)
        if credential is None:
            raise ValueError("unknown default credential selection")
        selected.append((credential.username, credential.password,
                         _credential_reference(identifier)))
    return selected


def _runner_attempt(target: str, protocol: str, port: int, username: str,
                    password: str, job_id: str) -> dict:
    command = [str(ROUTERSPLOIT_PYTHON), str(RUNNER)]
    payload = json.dumps({
        "target": target, "protocol": protocol, "port": port,
        "username": username, "password": password,
        "timeout": ATTEMPT_TIMEOUT_SECONDS,
    })
    process = subprocess.Popen(
        command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, start_new_session=True,
    )
    with _jobs_lock:
        _jobs[job_id] = process
    try:
        stdout, _ = process.communicate(input=payload, timeout=ATTEMPT_TIMEOUT_SECONDS * 3 + 3)
    except subprocess.TimeoutExpired:
        process.terminate()
        try:
            process.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
        return {
            "status": "timeout", "evidence": "The authentication runner timed out.",
            "duration_seconds": ATTEMPT_TIMEOUT_SECONDS * 3 + 3,
        }
    finally:
        with _jobs_lock:
            if _jobs.get(job_id) is process:
                _jobs.pop(job_id, None)
    marker = next((line for line in reversed(stdout.splitlines())
                   if line.startswith("WEAKND_CREDENTIAL_JSON=")), None)
    if marker is None:
        return {
            "status": "inconclusive",
            "evidence": "The authentication runner returned no structured result.",
            "duration_seconds": 0.0,
        }
    try:
        result = json.loads(marker.partition("=")[2])
    except json.JSONDecodeError:
        return {
            "status": "inconclusive",
            "evidence": "The authentication runner returned an invalid result.",
            "duration_seconds": 0.0,
        }
    allowed = {
        "authentication_successful", "authentication_failed", "connection_failed",
        "timeout", "authentication_method_unsupported", "inconclusive", "rate_limited",
    }
    if result.get("status") not in allowed:
        result["status"] = "inconclusive"
    result["evidence"] = str(result.get("evidence") or "No protocol evidence returned.")[:500]
    result["duration_seconds"] = round(float(result.get("duration_seconds") or 0.0), 3)
    return result


def _cancelled_job(job_id: str) -> bool:
    with _jobs_lock:
        return job_id in _cancelled


def _delay(job_id: str, seconds: float) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if _cancelled_job(job_id):
            return False
        time.sleep(min(0.1, max(0.0, deadline - time.monotonic())))
    return True


def _final_result(attempts: list[CredentialAttemptResult], cancelled: bool) -> str:
    statuses = [attempt.status for attempt in attempts]
    if cancelled:
        return "Inconclusive"
    if "authentication_successful" in statuses:
        return "Authentication Successful"
    if "rate_limited" in statuses:
        return "Inconclusive"
    if statuses and all(status == "authentication_failed" for status in statuses):
        return "Authentication Failed"
    if statuses and all(status == "connection_failed" for status in statuses):
        return "Connection Failed"
    if statuses and all(status == "timeout" for status in statuses):
        return "Timeout"
    if statuses and all(status == "authentication_method_unsupported" for status in statuses):
        return "Authentication Method Unsupported"
    return "Inconclusive"


def _build_finding(result: CredentialTestResult) -> SecurityFinding:
    success = result.successful_authentications > 0
    default_success = success and result.test_type == "small_default_check"
    if default_success:
        title = "Validated Default Credential Weakness"
        description = ("A user-selected generic default credential was accepted. "
                       "No command or post-authentication action was performed.")
        severity, validation = "HIGH", "VALIDATED"
        remediation = ("Require a unique credential during provisioning, remove factory defaults, "
                       "and review source restrictions and lockout controls.")
    elif success:
        title = "Authentication Successful with User-Supplied Credential"
        description = ("The supplied credential authenticated successfully. This confirms access "
                       "but is not by itself evidence of a default-credential weakness.")
        severity, validation = "INFO", "VALIDATED"
        remediation = "Confirm that the accepted account and remote exposure are intended and appropriately restricted."
    else:
        title = ("Failed Test — Authentication Failed"
                 if result.final_result == "Authentication Failed" else
                 f"Credential Test Result — {result.final_result}")
        description = ("The bounded credential test did not validate a weakness. Rejection or an "
                       "inconclusive result does not establish that the service is secure.")
        severity = "INFO"
        validation = "ERROR" if result.status == "error" else "INCONCLUSIVE"
        remediation = "Review authentication policy, rate limiting, source restrictions, and device logs."
    evidence = (
        f"target={result.target}; protocol={result.protocol}; port={result.port}; "
        f"test_type={result.test_type}; attempts={result.attempted_credentials}; "
        f"successful={result.successful_authentications}; failed={result.failed_authentications}; "
        f"result={result.final_result}; duration={result.duration_seconds:.3f}s; "
        "no command executed; credential material omitted"
    )
    return _finding(
        result.target, result.port, "tcp", result.protocol, title, description,
        severity, ENGINE, f"credential-test:{result.protocol}:{result.test_type}",
        None, evidence, validation, remediation,
    )


def run(target: str, protocol: str, port: int, mode: str,
        username: str | None = None, password: str | None = None,
        selected_default_ids: list[str] | None = None,
        authorized: bool = False, job_id: str = "credential-test") -> CredentialTestResult:
    if not authorized:
        raise ValueError("explicit authorized-target confirmation is required")
    if not runtime_available():
        raise RuntimeError("RouterSploit Python runtime or credential runner is unavailable")
    target = _validate_target(target)
    protocol = str(protocol or "").lower()
    if protocol not in SUPPORTED_PROTOCOLS:
        raise ValueError("unsupported credential-test protocol")
    port = int(port)
    if not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")
    if mode == "single":
        if password is None:
            raise ValueError("password field is required")
        credentials = [(
            _validate_text(username or "", "username", 128),
            _validate_text(password, "password", 256, allow_empty=True),
            "user-supplied",
        )]
        test_type = "single_credential"
    elif mode == "defaults":
        credentials = _selected_defaults(selected_default_ids or [])
        test_type = "small_default_check"
    else:
        raise ValueError("unknown credential test mode")

    started = time.monotonic()
    timestamp = datetime.now(timezone.utc).isoformat()
    attempts: list[CredentialAttemptResult] = []
    with _jobs_lock:
        _cancelled.discard(job_id)
        _active_jobs.add(job_id)
    try:
        for index, (attempt_user, attempt_password, reference) in enumerate(credentials):
            if _cancelled_job(job_id):
                break
            outcome = _runner_attempt(
                target, protocol, port, attempt_user, attempt_password, job_id)
            attempts.append(CredentialAttemptResult(
                username=attempt_user, credential_reference=reference,
                status=outcome["status"], evidence=outcome["evidence"],
                duration_seconds=outcome["duration_seconds"],
            ))
            if outcome["status"] in {"authentication_successful", "rate_limited"}:
                break
            if index + 1 < len(credentials) and not _delay(job_id, DEFAULT_DELAY_SECONDS):
                break
    finally:
        with _jobs_lock:
            cancelled = job_id in _cancelled
            _active_jobs.discard(job_id)
            _jobs.pop(job_id, None)
            _cancelled.discard(job_id)

    success_count = sum(item.status == "authentication_successful" for item in attempts)
    failed_count = sum(item.status == "authentication_failed" for item in attempts)
    final_result = _final_result(attempts, cancelled)
    result = CredentialTestResult(
        target=target, protocol=protocol, port=port, test_type=test_type,
        status="cancelled" if cancelled else "completed", final_result=final_result,
        attempted_credentials=len(attempts), successful_authentications=success_count,
        failed_authentications=failed_count,
        duration_seconds=round(time.monotonic() - started, 3), timestamp=timestamp,
        attempts=attempts, stopped_on_success=bool(success_count),
        stopped_on_rate_limit=any(item.status == "rate_limited" for item in attempts),
    )
    result.evidence = (
        f"{protocol.upper()} {test_type}: {len(attempts)} bounded attempt(s); "
        f"result={final_result}; credential material omitted"
    )
    result.finding = _build_finding(result)
    return result


def cancel(job_id: str) -> bool:
    if not job_id:
        return False
    with _jobs_lock:
        active = job_id in _active_jobs
        if not active:
            return False
        _cancelled.add(job_id)
        process = _jobs.get(job_id)
        if process is not None and process.poll() is None:
            process.terminate()
        return True
