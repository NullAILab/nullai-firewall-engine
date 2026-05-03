#!/usr/bin/env python3
"""
main.py — Firewall Rule Engine CLI.

Commands:
  parse     Parse and display an iptables-save file
  simulate  Simulate a packet against a named chain
  audit     Detect security issues and shadow rules

Usage examples:
  python src/main.py parse examples/web_server.iptables
  python src/main.py simulate --chain INPUT --src 10.0.0.1 --dport 80 examples/web_server.iptables
  python src/main.py audit examples/corporate.iptables
"""

from __future__ import annotations

import argparse
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from model import Packet
from parser import parse_iptables_save
from simulator import simulate
from analyzer import find_shadow_rules, audit_security


# ─── Colour helpers ──────────────────────────────────────────────────────────

_USE_COLOR = sys.stdout.isatty()
_RED    = "\033[31m" if _USE_COLOR else ""
_YELLOW = "\033[33m" if _USE_COLOR else ""
_GREEN  = "\033[32m" if _USE_COLOR else ""
_BOLD   = "\033[1m"  if _USE_COLOR else ""
_RESET  = "\033[0m"  if _USE_COLOR else ""

_SEV_COLOR = {"HIGH": _RED, "MEDIUM": _YELLOW, "LOW": ""}


def _load(path: str) -> dict:
    try:
        text = open(path).read()
    except OSError as e:
        print(f"[!] Cannot open file: {e}", file=sys.stderr)
        sys.exit(1)
    return parse_iptables_save(text)


def cmd_parse(args: argparse.Namespace) -> None:
    chains = _load(args.file)
    if not chains:
        print("No filter-table chains found.")
        return
    for name, chain in chains.items():
        print(f"\n{_BOLD}Chain {name}{_RESET} (policy {chain.policy})")
        if not chain.rules:
            print("  (empty)")
        for i, rule in enumerate(chain.rules):
            comment = f"  # {rule.comment}" if rule.comment else ""
            print(f"  [{i+1:2d}] src={rule.src} dst={rule.dst} "
                  f"dport={rule.dport} proto={rule.proto} → {rule.target}{comment}")


def cmd_simulate(args: argparse.Namespace) -> None:
    chains = _load(args.file)
    if args.chain not in chains:
        print(f"[!] Chain '{args.chain}' not found. Available: {list(chains.keys())}")
        sys.exit(1)

    pkt = Packet(
        src_ip=args.src, dst_ip=args.dst,
        src_port=args.sport, dst_port=args.dport,
        proto=args.proto,
    )
    result = simulate(pkt, chains[args.chain])

    print(f"\n[*] Simulating: {pkt.src_ip}:{pkt.src_port} → {pkt.dst_ip}:{pkt.dport} ({pkt.proto})")
    print(f"    Chain: {args.chain}\n")

    for i, rule in enumerate(chains[args.chain].rules):
        matched = rule.matches(pkt)
        marker = "→ MATCH" if matched else "  miss "
        print(f"  Rule {i+1:2d}: {marker}  {rule.raw.strip() or repr(rule)}")
        if matched and rule.target in ("ACCEPT", "DROP", "REJECT"):
            break

    dec_color = _GREEN if result.decision == "ACCEPT" else _RED
    rule_info = f"rule {result.rule_index + 1}" if result.rule_index is not None else "default policy"
    print(f"\n  Decision: {dec_color}{_BOLD}{result.decision}{_RESET} (via {rule_info})\n")


def cmd_audit(args: argparse.Namespace) -> None:
    chains = _load(args.file)
    found_any = False

    for name, chain in chains.items():
        shadows  = find_shadow_rules(chain)
        security = audit_security(chain)
        all_issues = shadows + security

        if not all_issues:
            continue
        found_any = True
        print(f"\n{_BOLD}Chain {name}{_RESET} — {len(all_issues)} issue(s):")
        for issue in sorted(all_issues, key=lambda i: ["HIGH", "MEDIUM", "LOW"].index(i.severity)):
            color = _SEV_COLOR.get(issue.severity, "")
            print(f"  {color}[{issue.severity}]{_RESET} {issue.description}")
            print(f"         {issue.detail}")

    if not found_any:
        print(f"\n{_GREEN}[OK]{_RESET} No issues found in filter chains.\n")
    else:
        print()


def main() -> None:
    p = argparse.ArgumentParser(description="Firewall Rule Engine — NullAI Lab")
    sub = p.add_subparsers(dest="command")

    # parse
    pp = sub.add_parser("parse", help="Parse and display rules")
    pp.add_argument("file", help="iptables-save file")

    # simulate
    sp = sub.add_parser("simulate", help="Simulate packet traversal")
    sp.add_argument("file", help="iptables-save file")
    sp.add_argument("--chain", default="INPUT", help="Chain to simulate (default: INPUT)")
    sp.add_argument("--src",   default="0.0.0.0")
    sp.add_argument("--dst",   default="0.0.0.0")
    sp.add_argument("--sport", type=int, default=12345)
    sp.add_argument("--dport", type=int, default=80)
    sp.add_argument("--proto", default="tcp")

    # audit
    ap = sub.add_parser("audit", help="Detect security issues and shadow rules")
    ap.add_argument("file", help="iptables-save file")

    args = p.parse_args()

    if args.command == "parse":
        cmd_parse(args)
    elif args.command == "simulate":
        cmd_simulate(args)
    elif args.command == "audit":
        cmd_audit(args)
    else:
        p.print_help()


if __name__ == "__main__":
    main()
