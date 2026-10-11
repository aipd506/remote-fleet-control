"""
Cryptographically signed command dispatcher with HMAC-SHA256 and anti-replay nonce cache.
"""

import hashlib
import hmac
import json
import secrets
import time
from typing import Any, Dict, Optional, Tuple


def canonical_serialize(data: Dict[str, Any]) -> bytes:
    """Canonical JSON serialization for deterministic cryptographic hashing."""
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


class NonceCache:
    """
    In-memory anti-replay cache with sliding time window and maximum capacity.
    """

    def __init__(self, ttl: float = 600.0, max_size: int = 10000) -> None:
        self.ttl = ttl
        self.max_size = max_size
        self._cache: Dict[str, float] = {}

    def _prune(self, now: float) -> None:
        expired = [nonce for nonce, expiry in self._cache.items() if expiry <= now]
        for nonce in expired:
            del self._cache[nonce]
        # If still over max_size, prune oldest
        if len(self._cache) > self.max_size:
            sorted_items = sorted(self._cache.items(), key=lambda x: x[1])
            excess = len(self._cache) - self.max_size
            for k, _ in sorted_items[:excess]:
                del self._cache[k]

    def has_seen(self, nonce: str) -> bool:
        now = time.time()
        self._prune(now)
        return nonce in self._cache

    def add(self, nonce: str) -> bool:
        """
        Record a nonce. Returns True if successfully added (new nonce),
        or False if nonce was already seen (replay attempt).
        """
        now = time.time()
        self._prune(now)
        if nonce in self._cache:
            return False
        self._cache[nonce] = now + self.ttl
        return True

    def clear(self) -> None:
        self._cache.clear()


# Default singleton nonce cache
DEFAULT_NONCE_CACHE = NonceCache()


def sign_payload(data: Dict[str, Any], secret: str) -> str:
    """Calculate HMAC-SHA256 signature for payload."""
    secret_bytes = secret.encode("utf-8") if isinstance(secret, str) else secret
    canonical_bytes = canonical_serialize(data)
    return hmac.new(secret_bytes, canonical_bytes, hashlib.sha256).hexdigest()


def create_signed_payload(
    target: str,
    cmd: str,
    secret: str,
    timeout: int = 30,
    command_id: Optional[str] = None,
    nonce: Optional[str] = None,
    timestamp: Optional[float] = None,
) -> Dict[str, Any]:
    """
    Construct and sign a command dispatch payload.
    """
    if command_id is None:
        command_id = secrets.token_hex(8)
    if nonce is None:
        nonce = secrets.token_hex(16)
    if timestamp is None:
        timestamp = time.time()

    payload_data = {
        "command_id": command_id,
        "target": target,
        "cmd": cmd,
        "timeout": int(timeout),
        "timestamp": float(timestamp),
        "nonce": nonce,
    }

    signature = sign_payload(payload_data, secret)
    full_payload = dict(payload_data)
    full_payload["signature"] = signature
    return full_payload


def verify_signed_payload(
    payload: Dict[str, Any],
    secret: str,
    nonce_cache: Optional[NonceCache] = None,
    max_drift: float = 300.0,
) -> Tuple[bool, Optional[str]]:
    """
    Verify HMAC-SHA256 signature and anti-replay properties.
    Returns (True, None) if valid, or (False, reason) if invalid.
    """
    if not isinstance(payload, dict):
        return False, "Payload must be a dictionary"

    required_keys = {"command_id", "target", "cmd", "timeout", "timestamp", "nonce", "signature"}
    missing = required_keys - set(payload.keys())
    if missing:
        return False, f"Missing required payload fields: {sorted(list(missing))}"

    signature = payload["signature"]
    if not isinstance(signature, str):
        return False, "Invalid signature format"

    # Check timestamp drift
    timestamp = payload["timestamp"]
    now = time.time()
    if abs(now - timestamp) > max_drift:
        return False, f"Timestamp drift exceeds tolerance ({abs(now - timestamp):.1f}s > {max_drift}s)"

    # Check anti-replay nonce
    nonce = payload["nonce"]
    cache = nonce_cache if nonce_cache is not None else DEFAULT_NONCE_CACHE
    if cache.has_seen(nonce):
        return False, f"Replay detected: nonce {nonce} has already been processed"

    # Verify signature
    data_to_verify = {k: v for k, v in payload.items() if k != "signature"}
    expected_sig = sign_payload(data_to_verify, secret)

    if not hmac.compare_digest(signature, expected_sig):
        return False, "Invalid HMAC signature"

    # Record nonce once verified
    cache.add(nonce)
    return True, None
