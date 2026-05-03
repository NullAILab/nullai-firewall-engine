# Design Notes — Firewall Rule Engine

## Architecture

The engine is split into four independent modules so each layer can be tested or swapped without touching the others:

```
model.py      ← Data types and primitive matching
parser.py     ← Text → model objects
simulator.py  ← model objects → decision
analyzer.py   ← model objects → list of issues
```

`main.py` only imports from these four; it contains no business logic.

---

## Model Decisions

### `Rule` defaults to wildcard

Every field in `Rule` defaults to "match anything" (`src="0.0.0.0/0"`, `dport="any"`, `proto="all"`).
This means a bare `Rule()` is the implicit default-accept rule, which is correct and lets test code construct minimal rules.

### `Packet` uses concrete defaults

`Packet` defaults to `0.0.0.0` / port 0 / proto `tcp`. These are deliberately "do-nothing" values — tests that only care about the destination port can construct `Packet(dst_port=443)` without filling every field.

### `_ip_matches` uses `ipaddress.ip_network`

`ipaddress.ip_network(addr, strict=False)` handles hosts inside subnets gracefully (e.g., `10.0.0.1/24` is normalised to `10.0.0.0/24`). `strict=True` would raise `ValueError` for host bits set, which is not the behaviour we want when parsing real iptables output that may contain such addresses.

---

## Parser Decisions

### Only `*filter` table is processed

NAT and mangle rules are skipped entirely. The engine's audience is INPUT/FORWARD/OUTPUT chain analysts; NAT rules require a different semantic model (pre-routing address rewriting) that is out of scope.

### `shlex.split` for tokenisation

iptables rule lines can have quoted strings (`--comment "allow web"`). A naive `line.split()` would split inside the comment. `shlex.split` handles quoting correctly at the cost of raising `ValueError` on malformed input, which we catch and ignore.

### Unknown flags are skipped

The token-walking loop calls `i += 1` for unrecognised tokens (`-m`, `-i`, `-o`, `--state`, etc.). This means the parser gracefully degrades on rules with conntrack or interface matches — it extracts what it understands and ignores the rest. A future version could store unknown flags in `Rule.extras: list[str]` for display purposes.

---

## Simulator Decisions

### LOG is non-terminal

`LOG` logs the packet and then continues to the next rule. The simulator skips it and keeps walking. This matches real iptables behaviour.

### RETURN in a custom chain

If `RETURN` appears in a user-defined chain the packet returns to the calling chain. The simulator treats `RETURN` as non-terminal (continues to the default policy). For single-chain simulation this is a safe approximation.

---

## Shadow Rule Detection

The `_is_superset(earlier, later)` check uses three structural tests:

1. **CIDR containment** (`ipaddress.ip_network.subnet_of`): The inner network must be a subnet of the outer. `"any"` / `""` / `"0.0.0.0/0"` are treated as matching everything.
2. **Port range containment**: Parse `lo:hi` ranges; a single port `N` is `(N, N)`. Earlier range must fully contain the later range.
3. **Protocol superset**: `"all"` contains any protocol; otherwise exact case-insensitive match.

This is a structural approximation. A full semantic equivalence check would require SAT/SMT solving across all fields simultaneously, which is overkill for a practical audit tool. False positives (incorrectly flagged shadows) are unlikely given the structural strictness; false negatives (missed shadows involving negated matches or `!-s`) are the known limitation.

---

## Security Audit Heuristics

| Rule | Severity | Rationale |
|------|----------|-----------|
| SSH to world | HIGH | Port 22 from `0.0.0.0/0` is the single most common attack vector on Linux servers |
| Telnet | HIGH | Plaintext protocol; any allowed Telnet rule is a misconfiguration regardless of source |
| Unconditional ACCEPT | HIGH | Allows all protocols from all sources — almost certainly a mistake |
| LOG without DROP | LOW | Non-terminal; the packet still passes. Informational — may be intentional |
| Default ACCEPT policy | LOW | A single missed rule exposes the entire chain |

SSH restricted to a non-zero source CIDR (e.g., `10.0.0.0/8`) is **not** flagged — that is the desired pattern.

---

## Known Limitations

- **Single-chain simulation**: Chains that jump to user-defined sub-chains (e.g., `-j DOCKER`) are not followed; the jump target is treated as a non-terminal and simulation continues.
- **Negated matches** (`! -s 10.0.0.0/8`): Not parsed; the `!` token is skipped, so the rule is treated as a positive match. This can cause false-negative shadow detections.
- **Interface flags** (`-i eth0`, `-o lo`): Ignored during parsing. Rules that differ only by interface will not be distinguished.
- **IPv6** (`ip6tables`): The model uses `ipaddress.ip_network` which supports IPv6, but the parser only sees `*filter` from an `iptables-save` file. `ip6tables-save` output would need to be fed separately.
