"""
parser.py — Parse iptables-save format into Chain / Rule objects.

Handles the output of ``iptables-save`` / ``iptables-restore``.

Supported rule components:
  -s / --source       source CIDR
  -d / --destination  destination CIDR
  --sport             source port or range
  --dport             destination port or range
  -p / --protocol     protocol
  -j / --jump         target (ACCEPT, DROP, REJECT, LOG, ...)
  -m comment --comment  rule comment
"""

from __future__ import annotations

import re
import shlex
from typing import Optional

from model import Chain, Rule


def parse_iptables_save(text: str) -> dict[str, Chain]:
    """
    Parse the output of ``iptables-save`` and return a mapping of
    chain name → :class:`~model.Chain`.

    Only the ``filter`` table is considered.  NAT / mangle tables are skipped.
    """
    chains: dict[str, Chain] = {}
    in_filter = False

    for raw_line in text.splitlines():
        line = raw_line.strip()

        # Table markers
        if line.startswith("*"):
            table = line[1:].strip()
            in_filter = table == "filter"
            continue
        if line == "COMMIT":
            in_filter = False
            continue

        if not in_filter:
            continue

        # Chain policy line: :INPUT ACCEPT [0:0]
        if line.startswith(":"):
            parts = line[1:].split()
            if len(parts) >= 2:
                name, policy = parts[0], parts[1]
                chains[name] = Chain(name=name, policy=policy)
            continue

        # Rule line: -A CHAIN [options]
        if line.startswith("-A "):
            rule, chain_name = _parse_rule_line(line)
            if rule and chain_name:
                if chain_name not in chains:
                    chains[chain_name] = Chain(name=chain_name)
                chains[chain_name].rules.append(rule)
            continue

    return chains


def parse_rule_line(line: str) -> Optional[tuple[Rule, str]]:
    """Public entry point for parsing a single rule line (for tests)."""
    return _parse_rule_line(line)


def _parse_rule_line(line: str) -> tuple[Optional[Rule], Optional[str]]:
    try:
        tokens = shlex.split(line)
    except ValueError:
        return None, None

    if len(tokens) < 3 or tokens[0] != "-A":
        return None, None

    chain_name = tokens[1]
    rule = Rule(raw=line)
    i = 2
    while i < len(tokens):
        t = tokens[i]
        if t in ("-s", "--source") and i + 1 < len(tokens):
            rule.src = tokens[i + 1]; i += 2
        elif t in ("-d", "--destination") and i + 1 < len(tokens):
            rule.dst = tokens[i + 1]; i += 2
        elif t in ("-p", "--protocol") and i + 1 < len(tokens):
            rule.proto = tokens[i + 1]; i += 2
        elif t == "--sport" and i + 1 < len(tokens):
            rule.sport = tokens[i + 1]; i += 2
        elif t == "--dport" and i + 1 < len(tokens):
            rule.dport = tokens[i + 1]; i += 2
        elif t in ("-j", "--jump") and i + 1 < len(tokens):
            rule.target = tokens[i + 1]; i += 2
        elif t == "--comment" and i + 1 < len(tokens):
            rule.comment = tokens[i + 1]; i += 2
        else:
            i += 1

    return rule, chain_name
