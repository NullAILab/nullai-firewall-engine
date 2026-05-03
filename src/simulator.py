"""
simulator.py — Simulate packet traversal through a rule chain.

Evaluates rules top-to-bottom and returns the first matching terminal target
(ACCEPT, DROP, REJECT) or the chain's default policy if no rule matches.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from model import Chain, Packet, Rule


@dataclass
class SimResult:
    decision: str           # ACCEPT | DROP | REJECT
    rule_index: Optional[int]   # 0-based index of the matching rule (None = default policy)
    rule: Optional[Rule]
    chain: str


_TERMINAL_TARGETS = {"ACCEPT", "DROP", "REJECT"}


def simulate(pkt: Packet, chain: Chain) -> SimResult:
    """
    Walk *chain*'s rules for *pkt* and return the first terminal decision.

    - RETURN in a custom chain is treated as a miss (continue to policy).
    - LOG is non-terminal — matching continues.
    - Unknown targets are treated as non-terminal.
    """
    for idx, rule in enumerate(chain.rules):
        if rule.matches(pkt):
            target = rule.target.upper()
            if target in _TERMINAL_TARGETS:
                return SimResult(decision=target, rule_index=idx,
                                 rule=rule, chain=chain.name)
            # LOG and other non-terminal targets: continue
    # Default policy
    return SimResult(decision=chain.policy, rule_index=None,
                     rule=None, chain=chain.name)
