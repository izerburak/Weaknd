"""Read-only CWMP/TR-069 WAN exposure probe.

The probe sends unauthenticated HEAD, GET, and OPTIONS requests to the selected
port. It does not send SOAP actions, credentials, configuration changes, or
exploit payloads. The goal is to establish exposure and authentication posture.
"""
from __future__ import annotations

import http.client
from dataclasses import dataclass, field


@dataclass
class HTTPObservation:
    method: str
    status: int | None = None
    reason: str | None = None
    server: str | None = None
    www_authenticate: str | None = None
    allow: str | None = None
    content_type: str | None = None
    error: str | None = None


@dataclass
class CWMPResult:
    host: str
    port: int = 7547
    reachable: bool = False
    observations: list[HTTPObservation] = field(default_factory=list)
    authentication_challenge: bool = False
    auth_schemes: list[str] = field(default_factory=list)
    unauthenticated_2xx: bool = False
    server: str | None = None
    verdict: str = "not-reachable"  # not-reachable | protected | exposed-review
    notes: list[str] = field(default_factory=list)


def _request(host: str, port: int, method: str, timeout: float = 6.0) -> HTTPObservation:
    observation = HTTPObservation(method=method)
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request(method, "/", headers={"User-Agent": "weaknd/0.2", "Connection": "close"})
        response = conn.getresponse()
        observation.status = response.status
        observation.reason = response.reason
        observation.server = response.getheader("Server")
        observation.www_authenticate = response.getheader("WWW-Authenticate")
        observation.allow = response.getheader("Allow")
        observation.content_type = response.getheader("Content-Type")
        response.read(4096)
    except (OSError, http.client.HTTPException) as exc:
        observation.error = f"{type(exc).__name__}: {exc}"
    finally:
        conn.close()
    return observation


def run(host: str, port: int = 7547) -> CWMPResult:
    result = CWMPResult(host=host, port=port)
    result.observations = [_request(host, port, method) for method in ("HEAD", "GET", "OPTIONS")]
    successful_transport = [item for item in result.observations if item.status is not None]
    result.reachable = bool(successful_transport)
    result.server = next((item.server for item in successful_transport if item.server), None)
    challenges = [item.www_authenticate for item in successful_transport
                  if item.www_authenticate]
    result.authentication_challenge = bool(challenges)
    result.auth_schemes = sorted({challenge.split(None, 1)[0] for challenge in challenges})
    result.unauthenticated_2xx = any(item.status is not None and 200 <= item.status < 300
                                    for item in successful_transport)

    if not result.reachable:
        result.verdict = "not-reachable"
        result.notes.append("CWMP endpoint did not complete an HTTP response")
    elif result.authentication_challenge and not result.unauthenticated_2xx:
        result.verdict = "protected"
        result.notes.append("endpoint is exposed but challenges unauthenticated requests")
    else:
        result.verdict = "exposed-review"
        result.notes.append(
            "endpoint is WAN-reachable without a clear auth challenge; protocol-specific review required"
        )
    result.notes.append("read-only probe: HEAD/GET/OPTIONS only; no SOAP action or credential sent")
    return result

