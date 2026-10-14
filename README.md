<p align="center"><img src="docs/logo.svg" width="96" alt="" /></p>

# aclvet

aclvet is an offline command-line auditor for ordered IPv4 allow/deny rule lists, such as security-group, firewall, or ACL exports. It is intended for people reviewing policy changes. It checks rules for shadowing and redundancy, evaluates flows, and counts exact verdict changes without enumerating the enormous flow space. It never changes its input.

[![CI](https://github.com/Gulliby-development/aclvet/actions/workflows/ci.yml/badge.svg)](https://github.com/Gulliby-development/aclvet/actions/workflows/ci.yml) [![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## Install

Build a local binary with:

```sh
go build -o aclvet .
```

Or run it directly with `go run . ARGS`.

## Usage

```
usage: aclvet check FILE
       aclvet eval RULES FLOWS
       aclvet diff OLD NEW
```

Each file argument is a path, or `-` to read standard input. `check` reports rules that decide no traffic or can be removed without changing verdicts. `eval` prints the verdict for each flow. `diff` counts the traffic whose verdict changes between two rule lists.

### Worked example

The rule list `edge.rules`:

```
# edge firewall
allow tcp 10.0.0.0/8 -> 10.1.0.0/16 443
deny  tcp any -> 10.1.0.0/16 22
allow tcp 10.2.0.0/16 -> 10.1.0.0/16 22
deny  tcp 10.0.0.0/9 -> any 1-1023
deny  tcp 10.128.0.0/9 -> any 1-1023
allow tcp 10.0.0.0/8 -> any 80
allow icmp 10.0.0.0/8 -> any
deny  udp any -> any 53
deny  any any -> any
```

`aclvet check edge.rules` prints:

```
edge.rules:4: AV001 shadowed by line 3
edge.rules:7: AV001 shadowed by lines 5, 6
edge.rules:9: AV002 redundant: removing it changes no verdict
```

The flow list `flows.txt`:

```
tcp 10.0.0.5 10.1.2.3 443
tcp 10.2.0.9 10.1.0.7 22
udp 10.9.9.9 10.1.0.53 53
icmp 10.0.0.1 10.1.0.1
tcp 192.168.1.1 10.1.0.1 22
```

`aclvet eval edge.rules flows.txt` prints:

```
tcp 10.0.0.5 -> 10.1.2.3 443: allow (line 2)
tcp 10.2.0.9 -> 10.1.0.7 22: deny (line 3)
udp 10.9.9.9 -> 10.1.0.53 53: deny (line 9)
icmp 10.0.0.1 -> 10.1.0.1: allow (line 8)
tcp 192.168.1.1 -> 10.1.0.1 22: deny (line 3)
```

The revised list `new.rules`:

```
# edge firewall, revised
allow tcp 10.0.0.0/8 -> 10.1.0.0/16 443
allow tcp 10.0.0.0/8 -> 10.1.0.0/16 8443
deny  tcp any -> 10.1.0.0/16 22
allow tcp 10.2.0.0/16 -> 10.1.0.0/16 22
allow icmp 10.0.0.0/16 -> any
deny  any any -> any
```

`aclvet diff edge.rules new.rules` prints:

```
allow -> deny (old line 8, new line 7): 71776119061217280 flows
deny -> allow (old line 10, new line 3): 1099511627776 flows
71777218572845056 flows change verdict
```

## Rule file

A rule file has one rule per physical line:

```
ACTION PROTO SRC -> DST [PORTS]
```

Actions are `allow` and `deny`. Protocols are `tcp`, `udp`, `icmp`, and `any`; `any` covers all three protocols. An address is an IPv4 address or a network in CIDR notation. `any` is equivalent to `0.0.0.0/0`. Network host bits must be zero. TCP and UDP rules may specify destination ports as `any`, one port, or an inclusive range; omitted ports mean the full range. ICMP rules do not take ports.

Blank lines and lines beginning with `#` are ignored. Tokens are separated by spaces or tabs. Input is UTF-8; a leading BOM is accepted, and LF or CRLF line endings are supported.

A flow file has one flow per line:

```
PROTO SRC DST [PORT]
```

Flow protocols are `tcp`, `udp`, and `icmp`. Source and destination are single IPv4 addresses. TCP and UDP flows require a destination port; ICMP flows have no port.

## Findings

Rules are applied in order: the first matching rule decides the verdict, and unmatched traffic is denied by default. aclvet represents traffic as protocol-specific address and port boxes and computes exact regions, rather than iterating over flows.

- **AV001 — shadowed:** the rule decides no traffic because earlier rules already match all of it. The finding names the first earlier rule that alone covers it, or lists every earlier partial matcher in file order.
- **AV002 — redundant:** the rule decides traffic, but removing it leaves that traffic with the same verdict from later rules. The default deny is not counted as a later rule, so a final deny-all rule is not reported as redundant. A shadowed rule receives AV001 only.

`diff` compares the regions decided by each rule (and the default region) in the old and new lists. It reports an exact count for each old/new decider pair whose actions differ, then the total number of flows whose verdict changes. Counts use arbitrary-precision integers.

## Exit codes

- `0`: success; no check findings, every evaluated flow is allowed, or no diff verdict changes.
- `1`: check findings, one or more denied evaluated flows, or changed diff verdicts.
- `2`: usage or input error.

## Development

Run the project checks with:

```sh
go vet ./...
gofmt -l .
go test ./...
```

## License

MIT, see [LICENSE](LICENSE).

---

Built with BAKED, an open-source coding agent.
