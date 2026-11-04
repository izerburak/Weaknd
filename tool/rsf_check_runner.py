"""Isolated RouterSploit check() runner; executed with RouterSploit's Python."""
from __future__ import annotations

import argparse
import contextlib
import importlib
import io
import json
import re
import sys
import traceback
from pathlib import Path


MARKER = "WEAKND_RSF_JSON="


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--module", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--ssl", choices=("true", "false"), default="false")
    args = parser.parse_args()

    if not re.fullmatch(r"exploits\.[a-zA-Z0-9_.]+", args.module):
        raise SystemExit("invalid module path")
    root = Path(args.root).resolve()
    if not (root / "routersploit" / "modules").is_dir():
        raise SystemExit("invalid RouterSploit root")
    sys.path.insert(0, str(root))

    captured_out, captured_err = io.StringIO(), io.StringIO()
    payload: dict
    try:
        with contextlib.redirect_stdout(captured_out), contextlib.redirect_stderr(captured_err):
            module = importlib.import_module("routersploit.modules." + args.module)
            check = module.Exploit()
            check.target = args.target
            if "port" in getattr(check, "options", []):
                check.port = args.port
            if "ssl" in getattr(check, "options", []):
                check.ssl = args.ssl
            if "verbosity" in getattr(check, "options", []):
                check.verbosity = "false"
            result = check.check()
        payload = {
            "status": "completed",
            "result": True if result is True else False if result is False else None,
            "stdout": captured_out.getvalue()[-4000:],
            "stderr": captured_err.getvalue()[-4000:],
        }
    except Exception as error:
        payload = {
            "status": "error", "result": None,
            "error": f"{type(error).__name__}: {error}",
            "traceback": traceback.format_exc()[-4000:],
            "stdout": captured_out.getvalue()[-4000:],
            "stderr": captured_err.getvalue()[-4000:],
        }
    sys.__stdout__.write(MARKER + json.dumps(payload, ensure_ascii=True) + "\n")
    sys.__stdout__.flush()
    return 0 if payload["status"] == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
