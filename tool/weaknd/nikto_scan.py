"""Small, cancellable Nikto adapter for authorized WAN web assessments."""
from __future__ import annotations

import json
import re
import shlex
import shutil
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from . import wan_scan
from .pentest import SecurityFinding, _finding


REQUEST_TIMEOUT = 3
API_VERSION = 2
CATEGORIES = {
    "0": ("File Upload", "Check for potentially unsafe file upload functionality."),
    "1": ("Interesting Files", "Look for interesting or potentially sensitive files."),
    "2": ("Misconfiguration / Default Files", "Check for default files and web server misconfigurations."),
    "3": ("Information Disclosure", "Look for potentially exposed information."),
    "4": ("Injection", "Test for XSS, script and HTML injection patterns."),
    "5": ("Remote File Retrieval (Web Root)", "Check for unintended file access inside the web root."),
    "6": ("Denial of Service", "Potentially disruptive availability checks."),
    "7": ("Remote File Retrieval (Server Wide)", "Check for unintended file access outside the web root."),
    "8": ("Command Execution", "Check for potential command execution vulnerabilities."),
    "9": ("SQL Injection", "Check for SQL injection vulnerabilities."),
    "a": ("Authentication Bypass", "Check for potential authentication bypass conditions."),
    "b": ("Software Identification", "Identify web server software and components."),
    "c": ("Remote Source Inclusion", "Check for unsafe inclusion of external resources."),
}
DEFAULT_CATEGORIES = ("2", "3", "b")


@dataclass
class NiktoObservation:
    classification: str
    description: str
    reference: str | None = None


@dataclass
class NiktoResult:
    target: str
    protocol: str
    port: int
    status: str
    final_result: str
    scan_id: str = ""
    job_id: str = ""
    argv: list[str] = field(default_factory=list)
    process_id: int | None = None
    started_at: str | None = None
    ended_at: str | None = None
    categories: list[str] = field(default_factory=list)
    tuning: str = ""
    output: str = ""
    stderr: str = ""
    exit_code: int | None = None
    duration_seconds: float = 0.0
    command: str | None = None
    findings: list[SecurityFinding] = field(default_factory=list)
    observations: list[NiktoObservation] = field(default_factory=list)


_jobs: dict[str, subprocess.Popen[str]] = {}
_cancelled: set[str] = set()
_jobs_lock = threading.Lock()

_METADATA = ("target ip:", "target hostname:", "target port:", "start time:",
             "end time:", "server:", "nikto v", "host(s) tested", "requests:")
_INFO = ("uncommon header", "retrieved", "allowed http methods", "server banner")
_SECURITY = ("vulnerab", "cross site scripting", "xss", "sql injection",
             "command injection", "remote code", "file inclusion", "path traversal",
             "directory indexing", "authentication bypass", "default credential",
             "outdated", "end of life", "information disclosure", "not present",
             "not defined", "not set", "exposed")
_REFERENCE = re.compile(r"\b(?:CVE-\d{4}-\d+|OSVDB-\d+)\b", re.I)


def _log_process(event: str, **fields) -> None:
    print(json.dumps({"component": "nikto", "event": event, **fields},
                     ensure_ascii=True), flush=True)


def options() -> dict:
    executable = shutil.which("nikto")
    return {"available": bool(executable), "executable": executable,
            "api_version": API_VERSION,
            "request_timeout": REQUEST_TIMEOUT,
            "default_categories": list(DEFAULT_CATEGORIES),
            "categories": [
                {"code": code, "name": value[0], "description": value[1]}
                for code, value in CATEGORIES.items()
            ]}


def _parse(target: str, protocol: str, port: int, output: str):
    findings: list[SecurityFinding] = []
    observations: list[NiktoObservation] = []
    seen: set[str] = set()
    for raw in output.splitlines():
        line = raw.strip()
        if not line.startswith("+"):
            continue
        line = line.lstrip("+").strip()
        lowered = line.lower()
        if not line or lowered.startswith(_METADATA) or re.match(r"^\d+\s+requests?:", line, re.I):
            continue
        key = re.sub(r"\s+", " ", lowered)
        if key in seen:
            continue
        seen.add(key)
        match = _REFERENCE.search(line)
        reference = match.group(0).upper() if match else None
        security = bool(reference or any(marker in lowered for marker in _SECURITY))
        informational = "header" in lowered or any(marker in lowered for marker in _INFO)
        if security and not informational:
            findings.append(_finding(
                target, port, "tcp", protocol, "Nikto Security Finding", line,
                "INFO", "Nikto", reference or f"nikto:{key[:160]}",
                reference, line, "DETECTED",
                "Review the Nikto evidence and apply the appropriate web-service remediation.",
            ))
        else:
            observations.append(NiktoObservation("Informational Observation", line, reference))
    return findings, observations


def run(target: str, protocol: str, port: int, categories: list[str],
        disruptive_confirmed: bool = False, job_id: str = "nikto") -> NiktoResult:
    target = wan_scan._validate_target(target)
    protocol = str(protocol or "").lower()
    if protocol not in {"http", "https"}:
        raise ValueError("Nikto protocol must be HTTP or HTTPS")
    port = int(port)
    if not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")
    if not isinstance(categories, list):
        raise ValueError("Nikto categories must be a list")
    unknown = sorted({str(code) for code in categories} - set(CATEGORIES))
    if unknown:
        raise ValueError(f"unsupported Nikto categories: {', '.join(unknown)}")
    selected = [code for code in CATEGORIES if code in categories]
    if not selected:
        raise ValueError("select at least one Nikto category")
    if "6" in selected and not disruptive_confirmed:
        raise PermissionError("Denial of Service category requires explicit confirmation")
    executable = shutil.which("nikto")
    if not executable:
        raise RuntimeError("nikto executable was not found in PATH")

    url_host = f"[{target}]" if ":" in target else target
    tuning = "".join(selected)
    command = [executable, "-h", f"{protocol}://{url_host}:{port}",
               "-Tuning", tuning, "-timeout", str(REQUEST_TIMEOUT)]
    scan_id = uuid.uuid4().hex
    job_id = str(job_id or f"nikto-{scan_id}")[:80]
    started_at = datetime.now(timezone.utc).isoformat()
    started = time.monotonic()
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, start_new_session=True)
    _log_process("started", scan_id=scan_id, job_id=job_id, argv=command,
                 process_id=process.pid, started_at=started_at)
    with _jobs_lock:
        _cancelled.discard(job_id)
        _jobs[job_id] = process
    try:
        stdout, stderr = process.communicate()
    finally:
        with _jobs_lock:
            cancelled = job_id in _cancelled
            if _jobs.get(job_id) is process:
                _jobs.pop(job_id, None)
            _cancelled.discard(job_id)

    output, error_output = stdout or "", stderr or ""
    ended_at = datetime.now(timezone.utc).isoformat()
    _log_process("finished", scan_id=scan_id, job_id=job_id,
                 process_id=process.pid, ended_at=ended_at,
                 return_code=process.returncode)
    findings, observations = _parse(target, protocol, port, output)
    combined = (output + "\n" + error_output).lower()
    scan_error = ((process.returncode not in (0, None)) or
                  any(marker in combined for marker in (
                      "no web server found", "unable to connect", "error limit reached")))
    if cancelled:
        status, final_result = "incomplete", "Incomplete"
    elif scan_error:
        status, final_result = "error", "Error"
    elif findings:
        status, final_result = "completed", "Security Finding"
    else:
        status, final_result = "completed", "Informational Observation"
    return NiktoResult(
        target=target, protocol=protocol, port=port, status=status,
        final_result=final_result, scan_id=scan_id, job_id=job_id,
        argv=command.copy(), process_id=process.pid,
        started_at=started_at, ended_at=ended_at,
        categories=selected, tuning=tuning,
        output=output, stderr=error_output,
        exit_code=process.returncode, duration_seconds=round(time.monotonic() - started, 3),
        command=shlex.join(command), findings=findings, observations=observations,
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
