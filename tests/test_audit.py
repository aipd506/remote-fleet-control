"""Tests for fleetctl.audit (rolling SHA-256 hash chain and verification)."""

import json
import os
import pytest
from fleetctl.audit import (
    GENESIS_HASH,
    append_audit_record,
    read_audit_records,
    verify_audit_chain,
)


def test_append_audit_records_and_verify(tmp_path):
    log_file = str(tmp_path / "fleet_audit.jsonl")
    
    # 1. Empty file verification
    is_valid, count, err = verify_audit_chain(log_file)
    assert is_valid is True
    assert count == 0

    # 2. Append records
    r1 = append_audit_record(log_file, "node-1", "uname -a", 0, 12.5)
    assert r1["index"] == 1
    assert r1["prev_hash"] == GENESIS_HASH
    assert len(r1["hash"]) == 64

    r2 = append_audit_record(log_file, "node-2", "df -h", 0, 8.2)
    assert r2["index"] == 2
    assert r2["prev_hash"] == r1["hash"]

    r3 = append_audit_record(log_file, "node-1", "cat /etc/hosts", 1, 4.0)
    assert r3["index"] == 3
    assert r3["prev_hash"] == r2["hash"]

    # 3. Verify valid chain
    is_valid, count, err = verify_audit_chain(log_file)
    assert is_valid is True
    assert count == 3
    assert err is None


def test_audit_detects_tampered_payload(tmp_path):
    log_file = str(tmp_path / "fleet_audit.jsonl")
    append_audit_record(log_file, "node-1", "whoami", 0)
    append_audit_record(log_file, "node-1", "uptime", 0)

    # Tamper with record 1
    with open(log_file, "r", encoding="utf-8") as f:
        lines = f.readlines()

    rec1 = json.loads(lines[0])
    rec1["command"] = "malicious_command"
    lines[0] = json.dumps(rec1) + "\n"

    with open(log_file, "w", encoding="utf-8") as f:
        f.writelines(lines)

    is_valid, count, err = verify_audit_chain(log_file)
    assert is_valid is False
    assert "Tampered record detected" in err


def test_audit_detects_broken_chain(tmp_path):
    log_file = str(tmp_path / "fleet_audit.jsonl")
    append_audit_record(log_file, "node-1", "cmd1", 0)
    append_audit_record(log_file, "node-1", "cmd2", 0)
    append_audit_record(log_file, "node-1", "cmd3", 0)

    # Delete record 2
    with open(log_file, "r", encoding="utf-8") as f:
        lines = f.readlines()
    del lines[1]
    with open(log_file, "w", encoding="utf-8") as f:
        f.writelines(lines)

    is_valid, count, err = verify_audit_chain(log_file)
    assert is_valid is False
    assert "Hash chain broken" in err or "Index mismatch" in err


def test_read_and_filter_records(tmp_path):
    log_file = str(tmp_path / "fleet_audit.jsonl")
    append_audit_record(log_file, "agent-A", "cmd1", 0, timestamp=100.0)
    append_audit_record(log_file, "agent-B", "cmd2", 0, timestamp=200.0)
    append_audit_record(log_file, "agent-A", "cmd3", 0, timestamp=300.0)

    all_recs = read_audit_records(log_file)
    assert len(all_recs) == 3

    agent_a_recs = read_audit_records(log_file, agent_id="agent-A")
    assert len(agent_a_recs) == 2

    since_recs = read_audit_records(log_file, since=150.0)
    assert len(since_recs) == 2
