#!/usr/bin/env python3
"""Summarise honeypot logs (JSON Lines) into a readable report."""
import argparse
import json
import re
from collections import Counter

URL_RE = re.compile(r"https?://[^\s'\"]+|(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?/[^\s'\"]+")


def load(path):
    events = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue  # skip a partially written line
    return events


def table(title, counter, n):
    lines = [f"\n## {title}\n", "| Value | Count |", "|---|---|"]
    for value, count in counter.most_common(n):
        safe = str(value).replace("|", "\\|") or "(empty)"
        lines.append(f"| `{safe}` | {count} |")
    return "\n".join(lines)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("logfile", nargs="?", default="logs/honeypot.jsonl")
    p.add_argument("--top", type=int, default=10)
    p.add_argument("--out", help="write the report to this markdown file")
    args = p.parse_args()

    events = load(args.logfile)
    auth = [e for e in events if e.get("event") == "auth_attempt"]
    cmds = [e for e in events if e.get("event") in ("command", "exec_command")]
    conns = [e for e in events if e.get("event") == "connection"]

    ips = Counter(e.get("ip", "(unknown)") for e in auth)
    hours = Counter(e.get("ts", "unknown")[:13] for e in conns)  # YYYY-MM-DDTHH
    urls = Counter(u for e in cmds for u in URL_RE.findall(e.get("command", "")))

    out = ["# Honeypot report"]
    if events:
        first_ts = events[0].get("ts", "unknown")
        last_ts = events[-1].get("ts", "unknown")
        out.append(f"\nPeriod: {first_ts} to {last_ts}")
    out.append(f"\n- Connections: **{len(conns)}** from **{len({e['ip'] for e in conns})}** unique IPs")
    out.append(f"- Password attempts: **{len(auth)}**")
    out.append(f"- Commands captured: **{len(cmds)}**")

    out.append(table("Top source IPs (by auth attempts)", ips, args.top))
    out.append(table("Top usernames", Counter(e.get("username", "(unknown)") for e in auth), args.top))
    out.append("\n> Password values are intentionally excluded from this report. "
               "The raw honeypot log may contain attempted passwords; keep it private "
               "and never commit it to a public repository.")
    out.append(table("Top commands", Counter(e.get("command", "(unknown)") for e in cmds), args.top))
    out.append(table("Payload URLs seen in commands", urls, args.top))
    out.append(table("SSH client versions",
                     Counter(e.get("version", "(unknown)") for e in events if e.get("event") == "client_version"),
                     args.top))
    out.append(table("Connections per hour (UTC)", hours, 24))

    report = "\n".join(out) + "\n"
    print(report)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(report)


if __name__ == "__main__":
    main()
