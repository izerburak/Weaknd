"""One-shot SSH/Telnet authentication runner.

The runner is executed with RouterSploit's Python interpreter so it can reuse
the installed Paramiko runtime. Credentials arrive only on stdin and are never
returned, printed, placed in argv, or used to execute a remote command.
"""
from __future__ import annotations

import ipaddress
import json
import re
import socket
import sys
import telnetlib
import time

import paramiko


MARKER = "WEAKND_CREDENTIAL_JSON="
LOCKOUT_RE = re.compile(
    r"(?:account\s+(?:is\s+)?locked|too many|rate.?limit|try again later|temporarily blocked)",
    re.I,
)


def _result(status: str, evidence: str, started: float) -> dict:
    return {
        "status": status,
        "evidence": evidence[:500],
        "duration_seconds": round(time.monotonic() - started, 3),
    }


def _ssh(target: str, port: int, username: str, password: str,
         timeout: float, started: float) -> dict:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            target, port=port, username=username, password=password,
            timeout=timeout, banner_timeout=timeout, auth_timeout=timeout,
            look_for_keys=False, allow_agent=False,
        )
        return _result("authentication_successful",
                       "SSH password authentication was accepted; no command was executed.",
                       started)
    except paramiko.BadAuthenticationType:
        return _result("authentication_method_unsupported",
                       "The SSH service did not accept password authentication.", started)
    except paramiko.AuthenticationException:
        return _result("authentication_failed",
                       "The SSH service rejected the supplied credential.", started)
    except (socket.timeout, TimeoutError):
        return _result("timeout", "The SSH authentication attempt timed out.", started)
    except (paramiko.ssh_exception.NoValidConnectionsError, ConnectionError, OSError):
        return _result("connection_failed", "The SSH connection could not be established.", started)
    except paramiko.SSHException as error:
        if LOCKOUT_RE.search(str(error)):
            return _result("rate_limited",
                           "The SSH service indicated lockout or rate limiting; testing stopped.",
                           started)
        return _result("inconclusive", "The SSH authentication result was inconclusive.", started)
    finally:
        client.close()


def _telnet(target: str, port: int, username: str, password: str,
            timeout: float, started: float) -> dict:
    client = None
    try:
        client = telnetlib.Telnet(target, port, timeout=timeout)
        login_patterns = [re.compile(pattern, re.I) for pattern in (
            rb"login\s*:\s*$", rb"username\s*:\s*$", rb"user\s+name\s*:\s*$",
        )]
        login_index, _, login_data = client.expect(login_patterns, timeout=timeout)
        if login_index < 0:
            if LOCKOUT_RE.search(login_data.decode("latin-1", "replace")):
                return _result("rate_limited",
                               "The Telnet service indicated lockout or rate limiting; testing stopped.",
                               started)
            return _result("authentication_method_unsupported",
                           "A supported Telnet username prompt was not observed.", started)
        client.write(username.encode("utf-8") + b"\r\n")
        password_index, _, password_data = client.expect(
            [re.compile(rb"password\s*:\s*$", re.I)], timeout=timeout)
        if password_index < 0:
            if LOCKOUT_RE.search(password_data.decode("latin-1", "replace")):
                return _result("rate_limited",
                               "The Telnet service indicated lockout or rate limiting; testing stopped.",
                               started)
            return _result("authentication_method_unsupported",
                           "A supported Telnet password prompt was not observed.", started)
        client.write(password.encode("utf-8") + b"\r\n")
        patterns = [
            re.compile(rb"(?:incorrect|authentication failed|login failed|access denied|invalid)", re.I),
            re.compile(rb"(?:account\s+(?:is\s+)?locked|too many|rate.?limit|try again later|temporarily blocked)", re.I),
            re.compile(rb"(?:^|[\r\n])[^\r\n]{0,80}[#$>]\s*$", re.M),
        ]
        outcome, _, _ = client.expect(patterns, timeout=timeout)
        if outcome == 0:
            return _result("authentication_failed",
                           "The Telnet service rejected the supplied credential.", started)
        if outcome == 1:
            return _result("rate_limited",
                           "The Telnet service indicated lockout or rate limiting; testing stopped.",
                           started)
        if outcome == 2:
            return _result("authentication_successful",
                           "Telnet authentication reached a command prompt; no command was executed.",
                           started)
        return _result("inconclusive",
                       "The Telnet service returned no reliable success or failure marker.", started)
    except (socket.timeout, TimeoutError, EOFError):
        return _result("timeout", "The Telnet authentication attempt timed out.", started)
    except (ConnectionError, OSError):
        return _result("connection_failed", "The Telnet connection could not be established.", started)
    except Exception:
        return _result("inconclusive", "The Telnet authentication result was inconclusive.", started)
    finally:
        if client is not None:
            try:
                client.close()
            except OSError:
                pass


def main() -> int:
    started = time.monotonic()
    try:
        payload = json.loads(sys.stdin.read(8192))
        target = str(ipaddress.ip_address(str(payload.get("target") or "")))
        protocol = str(payload.get("protocol") or "").lower()
        port = int(payload.get("port"))
        username = str(payload.get("username") or "")
        password = str(payload.get("password") if "password" in payload else "")
        timeout = min(max(float(payload.get("timeout", 8.0)), 2.0), 15.0)
        if protocol not in {"ssh", "telnet"}:
            raise ValueError("unsupported protocol")
        if not 1 <= port <= 65535:
            raise ValueError("invalid port")
        if not username or len(username) > 128 or len(password) > 256:
            raise ValueError("invalid credential length")
        if any(character in username or character in password for character in ("\r", "\n", "\x00")):
            raise ValueError("credential contains a forbidden control character")
        handler = {"ssh": _ssh, "telnet": _telnet}[protocol]
        result = handler(target, port, username, password, timeout, started)
    except (ValueError, TypeError, json.JSONDecodeError):
        result = _result("inconclusive", "The credential test request was invalid.", started)
    sys.stdout.write(MARKER + json.dumps(result, ensure_ascii=True) + "\n")
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
