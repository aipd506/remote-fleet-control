"""Tests for fleetctl.dispatcher (HMAC signature & anti-replay nonce cache)."""

import time
import pytest
from fleetctl.dispatcher import (
    NonceCache,
    canonical_serialize,
    create_signed_payload,
    sign_payload,
    verify_signed_payload,
)


def test_canonical_serialize_order_invariant():
    d1 = {"b": 2, "a": 1, "c": [3, 2, 1]}
    d2 = {"c": [3, 2, 1], "a": 1, "b": 2}
    assert canonical_serialize(d1) == canonical_serialize(d2)


def test_sign_and_verify_valid_payload():
    secret = "super-secret-key-12345"
    payload = create_signed_payload(target="agent-01", cmd="echo hello", secret=secret, timeout=15)
    
    assert "signature" in payload
    assert payload["target"] == "agent-01"
    assert payload["cmd"] == "echo hello"
    
    cache = NonceCache()
    is_valid, err = verify_signed_payload(payload, secret, nonce_cache=cache)
    assert is_valid is True
    assert err is None


def test_verify_rejects_wrong_secret():
    secret = "correct-secret"
    wrong_secret = "wrong-secret"
    payload = create_signed_payload(target="agent-01", cmd="echo hello", secret=secret)
    
    cache = NonceCache()
    is_valid, err = verify_signed_payload(payload, wrong_secret, nonce_cache=cache)
    assert is_valid is False
    assert "Invalid HMAC signature" in err


def test_verify_rejects_tampered_payload():
    secret = "correct-secret"
    payload = create_signed_payload(target="agent-01", cmd="echo hello", secret=secret)
    
    payload["cmd"] = "rm -rf /"  # Tamper with command
    cache = NonceCache()
    is_valid, err = verify_signed_payload(payload, secret, nonce_cache=cache)
    assert is_valid is False
    assert "Invalid HMAC signature" in err


def test_anti_replay_nonce_cache():
    secret = "correct-secret"
    payload = create_signed_payload(target="agent-01", cmd="echo hello", secret=secret)
    
    cache = NonceCache()
    # First time: valid
    is_valid1, err1 = verify_signed_payload(payload, secret, nonce_cache=cache)
    assert is_valid1 is True
    
    # Second time (replay with same nonce): rejected!
    is_valid2, err2 = verify_signed_payload(payload, secret, nonce_cache=cache)
    assert is_valid2 is False
    assert "Replay detected" in err2


def test_timestamp_drift_rejection():
    secret = "correct-secret"
    # Create payload from 10 minutes ago
    old_timestamp = time.time() - 600
    payload = create_signed_payload(
        target="agent-01",
        cmd="echo hello",
        secret=secret,
        timestamp=old_timestamp,
    )
    
    cache = NonceCache()
    is_valid, err = verify_signed_payload(payload, secret, nonce_cache=cache, max_drift=300.0)
    assert is_valid is False
    assert "Timestamp drift exceeds tolerance" in err


def test_nonce_cache_pruning():
    cache = NonceCache(ttl=0.1, max_size=5)
    cache.add("nonce1")
    assert cache.has_seen("nonce1") is True
    time.sleep(0.15)
    assert cache.has_seen("nonce1") is False  # Expired
