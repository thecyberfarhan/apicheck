"""python -m apicheck URL [options]"""
from __future__ import annotations

import argparse
import ipaddress
import json
import socket
import sys
from pathlib import Path

from . import checks

NOTE = "apicheck: only test systems you own or have written permission to test."


def in_scope(host: str, authorized: bool) -> None:
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror as exc:
        raise SystemExit(f"error: cannot resolve {host}: {exc}")
    a = ipaddress.ip_address(ip)
    if not (a.is_private or a.is_loopback or a.is_link_local) and not authorized:
        raise SystemExit(f"error: {host} resolves to the public address {ip}. Repeat with --authorized only if you have written permission.")


def to_markdown(base: str, findings: list, requests: int) -> str:
    lines = [f"# apicheck report: {base}", "", f"Requests sent: {requests}. Findings: {len(findings)}.", "",
             "Findings are indicators to verify by hand, not proof of exploitability.", ""]
    if not findings:
        lines.append("No findings.")
    for f in findings:
        lines += [f"## [{f['severity'].upper()}] {f['title']}", "", f"- Check: {f['check']}", f"- Detail: {f['detail']}", f"- Fix: {f['fix']}", ""]
    return "\n".join(lines)


def run(argv=None) -> int:
    p = argparse.ArgumentParser(prog="apicheck", description="Small web and API misconfiguration checker. " + NOTE)
    p.add_argument("url", help="base URL, for example http://192.168.1.10:8080")
    p.add_argument("--token", help="bearer token, used to compare authenticated and anonymous responses")
    p.add_argument("--endpoints", help="file with one path per line to test for missing authentication")
    p.add_argument("--timeout", type=float, default=5.0)
    p.add_argument("--authorized", action="store_true", help="confirm written permission for a public target")
    p.add_argument("-o", "--out", help="write report to .md or .json")
    a = p.parse_args(argv)
    try:
        t = checks.Target(a.url, a.timeout, a.token)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    in_scope(t.host, a.authorized)
    print(NOTE, file=sys.stderr)
    found: list = []
    for fn in checks.ALL_CHECKS:
        found += fn(t)
    eps = [e.strip() for e in Path(a.endpoints).read_text().splitlines() if e.strip().startswith("/")] if a.endpoints else checks.endpoints_from_openapi(t)
    if eps:
        found += checks.check_auth(t, eps)
    found.sort(key=lambda f: checks.SEVERITY_ORDER[f.severity])
    rows = [f.to_dict() for f in found]
    text = json.dumps({"target": t.base, "requests": t.requests, "findings": rows}, indent=2) if (a.out or "").endswith(".json") else to_markdown(t.base, rows, t.requests)
    if a.out:
        Path(a.out).write_text(text)
        print(f"report written to {a.out}", file=sys.stderr)
    else:
        print(text)
    return 0


def main() -> None:
    sys.exit(run())


if __name__ == "__main__":
    main()
