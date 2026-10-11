"""
Tamper-evident SHA-256 rolling hash chain audit trail for command execution.
"""

import hashlib
import json
import os
import time
from typing import Any, Dict, List, Optional, Tuple

from fleetctl.dispatcher import canonical_serialize

GENESIS_SEED = b"GENESIS"
GENESIS_HASH = hashlib.sha256(GENESIS_SEED).hexdigest()


def compute_record_hash(prev_hash: str, event_data: Dict[str, Any]) -> str:
    """
    Calculate SHA-256 rolling hash combining prev_hash and canonical event data.
    """
    canonical_bytes = canonical_serialize(event_data)
    combined = prev_hash.encode("utf-8") + b":" + canonical_bytes
    return hashlib.sha256(combined).hexdigest()


def append_audit_record(
    log_path: str,
    target_id: str,
    command: str,
    exit_code: int,
    duration_ms: float = 0.0,
    timestamp: Optional[float] = None,
) -> Dict[str, Any]:
    """
    Append an execution event to the rolling hash audit log.
    Creates log file with genesis baseline if not existing.
    """
    if timestamp is None:
        timestamp = time.time()

    last_hash = GENESIS_HASH
    next_index = 1

    if os.path.exists(log_path) and os.path.getsize(log_path) > 0:
        with open(log_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        rec = json.loads(line)
                        if "hash" in rec and "index" in rec:
                            last_hash = rec["hash"]
                            next_index = rec["index"] + 1
                    except json.JSONDecodeError:
                        pass

    event_data = {
        "index": next_index,
        "timestamp": float(timestamp),
        "target_id": str(target_id),
        "command": str(command),
        "exit_code": int(exit_code),
        "duration_ms": float(duration_ms),
        "prev_hash": last_hash,
    }

    current_hash = compute_record_hash(last_hash, event_data)
    record = dict(event_data)
    record["hash"] = current_hash

    os.makedirs(os.path.dirname(os.path.abspath(log_path)), exist_ok=True)
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, sort_keys=True) + "\n")

    return record


def verify_audit_chain(log_path: str) -> Tuple[bool, int, Optional[str]]:
    """
    Verify integrity of rolling SHA-256 hash chain in audit log file.
    Returns: (is_valid, record_count, error_description)
    """
    if not os.path.exists(log_path):
        return True, 0, None

    expected_prev_hash = GENESIS_HASH
    record_count = 0

    with open(log_path, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue

            try:
                record = json.loads(line)
            except json.JSONDecodeError as e:
                return False, record_count, f"Line {line_num}: Malformed JSON ({e})"

            required = {"index", "timestamp", "target_id", "command", "exit_code", "prev_hash", "hash"}
            missing = required - set(record.keys())
            if missing:
                return False, record_count, f"Line {line_num}: Missing fields {sorted(list(missing))}"

            expected_index = record_count + 1
            if record["index"] != expected_index:
                return False, record_count, (
                    f"Line {line_num}: Index mismatch (expected {expected_index}, got {record['index']})"
                )

            if record["prev_hash"] != expected_prev_hash:
                return False, record_count, (
                    f"Line {line_num}: Hash chain broken (expected prev_hash {expected_prev_hash[:12]}..., "
                    f"got {record['prev_hash'][:12]}...)"
                )

            # Recalculate hash
            event_data = {k: v for k, v in record.items() if k != "hash"}
            recalculated = compute_record_hash(expected_prev_hash, event_data)
            if recalculated != record["hash"]:
                return False, record_count, (
                    f"Line {line_num}: Tampered record detected (recalculated {recalculated[:12]}..., "
                    f"stored {record['hash'][:12]}...)"
                )

            expected_prev_hash = record["hash"]
            record_count += 1

    return True, record_count, None


def read_audit_records(
    log_path: str,
    agent_id: Optional[str] = None,
    since: Optional[float] = None,
) -> List[Dict[str, Any]]:
    """Read and filter audit records."""
    if not os.path.exists(log_path):
        return []

    records = []
    with open(log_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                if agent_id and rec.get("target_id") != agent_id:
                    continue
                if since is not None and rec.get("timestamp", 0) < since:
                    continue
                records.append(rec)
            except json.JSONDecodeError:
                continue
    return records
