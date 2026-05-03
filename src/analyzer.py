"""
analyzer.py — Static analysis of firewall rule chains.

Detects:
  - Shadow rules: rules that can never be reached because a preceding rule
    always matches first.
  - Security issues: overly permissive rules, missing default-deny policy,
    SSH exposed to the internet, etc.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from model import Chain, Rule, Packet, _ip_matches, _port_matches, _proto_matches


@dataclass
class Issue:
    severity: str    # HIGH | MEDIUM | LOW
    rule_idx: int    # 0-based index in chain.rules (-1 = chain-level)
    description: str
    detail: str


def find_shadow_rules(chain: Chain) -> list[Issue]:
    """
    Find rules that are unreachable because an earlier rule is a superset.

    A rule R[j] is shadowed by R[i] (i < j) if R[i] matches every packet
    that R[i] would match and both have the same (or R[i] has a terminal) target.

    This is an approximation — we check structural supersets, not full
    semantic equivalence.
    """
    issues: list[Issue] = []
    for j in range(1, len(chain.rules)):
        candidate = chain.rules[j]
        for i in range(j):
            earlier = chain.rules[i]
            if _is_superset(earlier, candidate) and earlier.target in ("ACCEPT", "DROP", "REJECT"):
                issues.append(Issue(
                    severity="MEDIUM",
                    rule_idx=j,
                    description=f"Shadow rule — rule {j+1} is unreachable",
                    detail=(
                        f"Rule {i+1} ({earlier.src or 'any'} → {earlier.dst or 'any'}, "
                        f"target={earlier.target}) is a superset of rule {j+1}"
                    ),
                ))
                break  # report once per shadowed rule
    return issues


def audit_security(chain: Chain) -> list[Issue]:
    """
    Check for common security misconfigurations.
    """
    issues: list[Issue] = []

    # Default-allow policy is permissive
    if chain.policy == "ACCEPT":
        issues.append(Issue(
            severity="LOW",
            rule_idx=-1,
            description=f"Default policy for chain '{chain.name}' is ACCEPT",
            detail="Consider setting default policy to DROP for defence-in-depth",
        ))

    for idx, rule in enumerate(chain.rules):
        # SSH open to the world
        if (rule.dport in ("22", "22:22") and rule.target == "ACCEPT"
                and rule.src in ("any", "0.0.0.0/0", "")):
            issues.append(Issue(
                severity="HIGH",
                rule_idx=idx,
                description=f"Rule {idx+1}: SSH exposed to all source IPs",
                detail="Consider restricting -s to known management CIDR ranges",
            ))

        # Any-port accept from any source
        if (rule.src in ("any", "0.0.0.0/0", "")
                and rule.dport == "any"
                and rule.target == "ACCEPT"
                and rule.proto == "all"):
            issues.append(Issue(
                severity="HIGH",
                rule_idx=idx,
                description=f"Rule {idx+1}: Unconditional ACCEPT from any source",
                detail="This rule allows all traffic — review whether it is intentional",
            ))

        # Telnet open
        if (rule.dport in ("23", "23:23") and rule.target == "ACCEPT"):
            issues.append(Issue(
                severity="HIGH",
                rule_idx=idx,
                description=f"Rule {idx+1}: Telnet (port 23) allowed",
                detail="Telnet transmits credentials in plaintext — disable and use SSH",
            ))

        # Log-only rule without a subsequent block (informational)
        if rule.target == "LOG":
            issues.append(Issue(
                severity="LOW",
                rule_idx=idx,
                description=f"Rule {idx+1}: LOG rule — verify a DROP follows",
                detail="LOG is non-terminal; ensure the logged traffic is also blocked",
            ))

    return issues


# ─── Structural superset check ────────────────────────────────────────────────

def _is_superset(earlier: Rule, later: Rule) -> bool:
    """
    Return True if *earlier* structurally matches every packet *later* would match.
    Uses CIDR containment and port range containment.
    """
    return (
        _cidr_contains(earlier.src, later.src)
        and _cidr_contains(earlier.dst, later.dst)
        and _range_contains(earlier.sport, later.sport)
        and _range_contains(earlier.dport, later.dport)
        and _proto_superset(earlier.proto, later.proto)
    )


def _cidr_contains(outer: str, inner: str) -> bool:
    """Return True if every IP in *inner* is also in *outer*."""
    if outer in ("any", "0.0.0.0/0", ""):
        return True
    if inner in ("any", "0.0.0.0/0", ""):
        return outer in ("any", "0.0.0.0/0", "")
    try:
        o = ipaddress.ip_network(outer, strict=False)
        i = ipaddress.ip_network(inner, strict=False)
        return i.subnet_of(o)
    except ValueError:
        return False


def _range_contains(outer: str, inner: str) -> bool:
    """Return True if port range *inner* is fully contained in *outer*."""
    if outer == "any":
        return True
    if inner == "any":
        return outer == "any"
    o_lo, o_hi = _parse_range(outer)
    i_lo, i_hi = _parse_range(inner)
    return o_lo <= i_lo and i_hi <= o_hi


def _parse_range(spec: str) -> tuple[int, int]:
    if ":" in spec:
        lo, hi = spec.split(":", 1)
        return int(lo), int(hi)
    v = int(spec)
    return v, v


def _proto_superset(outer: str, inner: str) -> bool:
    if outer == "all":
        return True
    return outer.lower() == inner.lower()
