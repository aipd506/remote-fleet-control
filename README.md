# remote-fleet-control (`fleetctl`)

[![CI](https://github.com/aipd506/remote-fleet-control/actions/workflows/ci.yml/badge.svg)](https://github.com/aipd506/remote-fleet-control/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

Production-grade, zero-external-dependency remote fleet execution agent, cryptographically signed command dispatcher, multiplexed reverse tunnel over asyncio, and tamper-evident SHA-256 rolling hash audit trail.

Part of the **IT Enterprise Infrastructure and Cybersecurity Suite**.

---

## Architecture & Features

1. **HMAC-SHA256 Signed Command Dispatcher (`fleetctl/dispatcher.py`)**:
   - Canonical JSON payload serialization.
   - Constant-time HMAC-SHA256 verification (`hmac.compare_digest`).
   - Anti-replay protection via sliding LRU nonce cache and UTC timestamp drift checks.
2. **Execution Agent Daemon (`fleetctl/agent.py`)**:
   - Outbound agent node with process execution and timeout control.
   - Comprehensive stdout, stderr, exit code, and execution duration capture.
3. **Multiplexed Reverse Tunnel (`fleetctl/tunnel.py`)**:
   - 11-byte binary framed wire protocol (`!H B I I`: Magic `0xFC01`, Message Type, Stream ID, Payload Length).
   - Asyncio-powered reverse tunnel server and client for agents behind NAT or firewalls.
4. **Tamper-Evident Rolling Hash Audit Trail (`fleetctl/audit.py`)**:
   - Cryptographically linked SHA-256 hash chain: $\text{ChainHash}_i = \text{SHA256}(\text{ChainHash}_{i-1} \parallel \text{Event}_i)$.
   - Audit integrity verification with automatic detection of modified, deleted, or injected records.

---

## Installation

```bash
pip install -e .
```

Zero external runtime dependencies. Requires only Python 3.10+.

---

## CLI Usage

```bash
# Start an agent
fleetctl agent --agent-id node-01 --secret "shared-secret-key"

# Dispatch a signed command
fleetctl dispatch --target node-01 --cmd "uptime" --secret "shared-secret-key" --local-exec

# Verify rolling audit hash chain
fleetctl audit --verify-chain --log-file fleet_audit.jsonl

# Manage tunnel controller
fleetctl tunnel --listen 0.0.0.0:9050 --secret "shared-secret-key" --status
```

---

## Testing

```bash
python -m pytest tests/ -v
```

---

## License

MIT License. Copyright (c) 2026 aipd506.
