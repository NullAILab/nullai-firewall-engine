# Firewall Rule Engine

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)
![Tests](https://img.shields.io/badge/tests-34%20passing-brightgreen)
![License](https://img.shields.io/badge/license-MIT%20%2B%20Responsible%20Use-blue)

Misconfigured firewall rules are among the most common causes of unintended exposure — a rule that should block SSH to the internet instead accepts it because an earlier catch-all rule shadows it, and no one noticed. This engine parses real `iptables-save` output, simulates how specific packets traverse a rule chain step by step, and runs static analysis to detect shadow rules (unreachable rules caused by superset predecessors) and security misconfigurations such as SSH exposed to the world, Telnet allowed, and permissive default-accept policies. It gives firewall operators a fast, scriptable way to audit rulesets without needing a live packet to discover a misconfiguration.

## Features

- **Parser** — reads `iptables-save` / `iptables-restore` format; handles CIDR, port ranges, protocols, and inline comments
- **Simulator** — traces a synthetic packet through a named chain rule by rule, showing each match/miss
- **Shadow-rule detector** — finds rules that can never be reached because an earlier rule is a structural superset (CIDR containment + port range containment)
- **Security auditor** — flags SSH/Telnet/unconditional-ACCEPT rules and default-allow policies
- **Clean Python** — pure stdlib except `ipaddress` (built in since Python 3.3); no root required, runs on any OS

## Tech Stack

| Component | Technology |
|-----------|------------|
| Language | Python 3.10+ |
| CIDR matching | `ipaddress` (stdlib) |
| Rule tokenisation | `shlex` (stdlib) |
| Testing | `pytest` |

## Project Structure

```
22-firewall-rule-engine/
├── src/
│   ├── model.py       # Packet, Rule, Chain dataclasses + matching helpers
│   ├── parser.py      # iptables-save parser
│   ├── simulator.py   # Packet simulation engine
│   ├── analyzer.py    # Shadow-rule detection + security audit
│   └── main.py        # CLI entry point
├── tests/
│   └── test_engine.py # 34 unit tests
├── examples/
│   ├── web_server.iptables   # Typical web server ruleset
│   └── corporate.iptables    # Corporate edge firewall with shadow rules
├── docs/
│   └── NOTES.md       # Design notes and architecture decisions
└── README.md
```

## Quick Start

```bash
git clone https://github.com/NullAILab/nullai-firewall-engine.git
cd nullai-firewall-engine

# Install test dependency (no runtime dependencies beyond stdlib)
pip install pytest

# Run tests
pytest tests/ -v

# Parse a ruleset and display it
python src/main.py parse examples/web_server.iptables

# Simulate a packet through the INPUT chain
python src/main.py simulate --chain INPUT --src 10.0.0.5 --dport 22 examples/web_server.iptables

# Full security + shadow-rule audit
python src/main.py audit examples/corporate.iptables
```

## Usage

### `parse` — Display rules

```
python src/main.py parse <iptables-save-file>
```

Prints all filter-table chains with their default policies and each rule's parsed fields.

### `simulate` — Trace a packet

```
python src/main.py simulate [options] <iptables-save-file>

Options:
  --chain CHAIN   Chain to simulate (default: INPUT)
  --src IP        Source IP address (default: 0.0.0.0)
  --dst IP        Destination IP address (default: 0.0.0.0)
  --sport PORT    Source port (default: 12345)
  --dport PORT    Destination port (default: 80)
  --proto PROTO   Protocol: tcp | udp | all (default: tcp)
```

Example output:

```
[*] Simulating: 10.0.0.5:12345 → 0.0.0.0:22 (tcp)
    Chain: INPUT

  Rule  1: → MATCH  -A INPUT -s 10.0.0.0/8 -p tcp --dport 22 -j ACCEPT

  Decision: ACCEPT (via rule 1)
```

### `audit` — Security analysis

```
python src/main.py audit <iptables-save-file>
```

Reports findings sorted by severity (HIGH → MEDIUM → LOW):

```
Chain INPUT — 2 issue(s):
  [HIGH] Rule 3: SSH exposed to all source IPs
         Consider restricting -s to known management CIDR ranges
  [MEDIUM] Shadow rule — rule 4 is unreachable
         Rule 2 (any → any, target=DROP) is a superset of rule 4
```

## How Shadow Detection Works

A rule `R[j]` is considered **shadowed** by an earlier rule `R[i]` if `R[i]` structurally matches every packet that `R[j]` would also match:

- **CIDR containment**: `10.0.0.0/8` is a superset of `10.0.1.0/24`
- **Port range containment**: `1024:65535` is a superset of `8080`
- **Protocol matching**: `all` is a superset of `tcp`

If `R[i]` has a terminal target (`ACCEPT`, `DROP`, `REJECT`) and is a superset of `R[j]`, then `R[j]` can never fire — it is a shadow rule and will be flagged `MEDIUM`.

## Extending the Engine

**Add a new audit rule** in `src/analyzer.py`:

```python
# Inside audit_security():
if rule.dport in ("3389", "3389:3389") and rule.target == "ACCEPT":
    issues.append(Issue(
        severity="HIGH",
        rule_idx=idx,
        description=f"Rule {idx+1}: RDP (port 3389) exposed",
        detail="RDP is a common brute-force target — restrict to VPN ranges",
    ))
```

**Use as a library**:

```python
from parser import parse_iptables_save
from simulator import simulate
from analyzer import audit_security
from model import Packet

chains = parse_iptables_save(open("my.iptables").read())
pkt = Packet(src_ip="1.2.3.4", dst_port=22, proto="tcp")
result = simulate(pkt, chains["INPUT"])
print(result.decision)  # ACCEPT or DROP

for issue in audit_security(chains["INPUT"]):
    print(f"[{issue.severity}] {issue.description}")
```

## Running Tests

```bash
pytest tests/ -v
# 34 passed in 0.26s
```

Tests cover: IP/port/protocol matching, parser edge cases (empty input, non-filter tables, direct rule-line parsing), packet simulation (first-match-wins, default policy, non-terminal LOG), shadow detection, and all five security audit rules.

## Responsible Use

This tool is designed for **defensive security** — auditing your own firewall rulesets or infrastructure you are explicitly authorised to test.

- Do **not** use this tool to analyse rulesets you do not own or have explicit permission to audit
- Shadow-rule and security findings are heuristic — treat them as starting points for manual review, not authoritative verdicts
- **Always test rule changes in a staging environment before applying to production**

## License

MIT License + Responsible Use Guidelines. See [LICENSE](LICENSE) for full terms.
