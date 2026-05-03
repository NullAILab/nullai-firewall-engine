"""
model.py — Data model for firewall rules, chains, and packets.

Intentionally simple — no external dependencies, pure Python dataclasses.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Packet:
    """A simulated network packet."""
    src_ip:   str = "0.0.0.0"
    dst_ip:   str = "0.0.0.0"
    src_port: int = 0
    dst_port: int = 0
    proto:    str = "tcp"   # tcp | udp | icmp | all


@dataclass
class Rule:
    """One iptables rule (``-A CHAIN [matches] -j TARGET``)."""
    src:     str = "0.0.0.0/0"   # CIDR or "any"
    dst:     str = "0.0.0.0/0"
    sport:   str = "any"          # "any", "80", "1024:65535"
    dport:   str = "any"
    proto:   str = "all"          # tcp | udp | icmp | all
    target:  str = "ACCEPT"       # ACCEPT | DROP | REJECT | RETURN | LOG
    comment: str = ""
    raw:     str = ""             # original iptables line

    def matches(self, pkt: Packet) -> bool:
        """Return True if *pkt* matches every criterion of this rule."""
        return (
            _ip_matches(pkt.src_ip, self.src)
            and _ip_matches(pkt.dst_ip, self.dst)
            and _port_matches(pkt.src_port, self.sport)
            and _port_matches(pkt.dst_port, self.dport)
            and _proto_matches(pkt.proto, self.proto)
        )


@dataclass
class Chain:
    """A named rule chain (INPUT, FORWARD, OUTPUT, or custom)."""
    name:   str
    policy: str = "ACCEPT"   # default policy when no rule matches
    rules:  list[Rule] = field(default_factory=list)


# ─── Matching helpers ─────────────────────────────────────────────────────────

def _ip_matches(ip: str, spec: str) -> bool:
    """Return True if *ip* falls within the CIDR *spec* (or spec is 'any')."""
    if spec in ("any", "0.0.0.0/0"):
        return True
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(spec, strict=False)
    except ValueError:
        return False


def _port_matches(port: int, spec: str) -> bool:
    """Return True if *port* matches the spec ('any', single, or 'low:high')."""
    if spec == "any":
        return True
    if ":" in spec:
        lo, hi = spec.split(":", 1)
        return int(lo) <= port <= int(hi)
    return port == int(spec)


def _proto_matches(pkt_proto: str, rule_proto: str) -> bool:
    if rule_proto == "all":
        return True
    return pkt_proto.lower() == rule_proto.lower()
