import os
import json
import hmac
import hashlib
import secrets
import time
from pathlib import Path

def _get_hmac_key() -> bytes:
    """Retrieve the alert-signing key; never silently use a public default."""
    key = os.environ.get("BRDS_ALERT_HMAC_KEY")
    if not key and os.environ.get("BRDS_ALLOW_INSECURE_DEV_HMAC") == "1":
        key = "BRDS_TEST_ONLY_HMAC_KEY"
    if not key:
        raise RuntimeError(
            "BRDS_ALERT_HMAC_KEY must be set before signing or verifying alerts. "
            "The test-only BRDS_ALLOW_INSECURE_DEV_HMAC override is not for deployment."
        )
    return key.encode("utf-8")

def sign_alerts(alerts: list) -> str:
    """Serialize alerts list and append an HMAC-SHA256 signature string."""
    payload_str = json.dumps(alerts, separators=(',', ':'), sort_keys=True)
    key = _get_hmac_key()
    signature = hmac.new(key, payload_str.encode("utf-8"), hashlib.sha256).hexdigest()
    
    signed_container = {
        "alerts": alerts,
        "sig": signature
    }
    return json.dumps(signed_container, indent=2)

def verify_and_load(alerts_path: Path | str, allow_unsigned_legacy: bool = False) -> list:
    """Read alerts file, verify HMAC-SHA256 signature, and return alerts list.
    
    Raises:
        ValueError: If file is malformed JSON, unsigned list (and legacy not permitted),
                    or missing container fields.
        RuntimeError: If HMAC key is missing, or if signature mismatch is detected (tampered alerts).
    """
    path = Path(alerts_path)
    if not path.exists():
        return []
        
    content = path.read_text(encoding="utf-8").strip()
    if not content:
        return []
        
    try:
        data = json.loads(content)
    except Exception as e:
        raise ValueError(f"Invalid JSON format in alerts file: {e}")
        
    # Isolate backward-compatible handling for raw arrays behind an EXPLICIT test-only flag
    if isinstance(data, list):
        if allow_unsigned_legacy or os.environ.get("BRDS_ALLOW_UNSIGNED_ALERTS_TEST_ONLY") == "1":
            return data
        raise ValueError(
            f"SECURITY REJECTION: Alerts file {path} is an unsigned raw array. "
            "Signed container format {'alerts': [...], 'sig': '...'} is strictly required on the production/containment path."
        )
        
    if not isinstance(data, dict):
        raise ValueError("Alerts file format invalid: root element must be a JSON object containing 'alerts' and 'sig'.")

    if "alerts" not in data or "sig" not in data:
        raise ValueError("Alerts file format invalid: missing 'alerts' or 'sig' container fields.")
        
    alerts = data["alerts"]
    provided_sig = data["sig"]
    
    if not isinstance(alerts, list):
        raise ValueError("Alerts container format invalid: 'alerts' field must be a list.")
        
    if not isinstance(provided_sig, str) or not provided_sig.strip():
        raise ValueError("Alerts container format invalid: 'sig' field must be a non-empty string.")
    
    payload_str = json.dumps(alerts, separators=(',', ':'), sort_keys=True)
    key = _get_hmac_key()
    expected_sig = hmac.new(key, payload_str.encode("utf-8"), hashlib.sha256).hexdigest()
    
    if not hmac.compare_digest(provided_sig, expected_sig):
        raise RuntimeError(
            f"SECURITY ALERT: HMAC signature verification failed for {path}! "
            f"Alert file has been modified or tampered with."
        )
        
    return alerts

def create_arm_token(token_path: Path | str | None = None) -> str:
    """Generate a time-limited, single-use, cryptographically signed arm token.

    Token format (JSON):
        {
            "payload":   "BRDS_ACTIVE_ARMED_STATE_2026",
            "timestamp": "<ISO-8601 UTC>",
            "nonce":     "<32 hex chars, cryptographically random>",
            "sig":       "<HMAC-SHA256 over canonical JSON of payload+timestamp+nonce>"
        }

    If token_path is provided the token is written there.  Always returns the
    JSON string so callers can inspect or pass it without re-reading the file.
    """
    payload = "BRDS_ACTIVE_ARMED_STATE_2026"
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    nonce = secrets.token_hex(16)  # 32 hex chars = 128 bits entropy
    key = _get_hmac_key()
    # Sign the canonical JSON of the three identity fields to prevent field-
    # omission or field-reuse attacks.
    signing_input = json.dumps(
        {"nonce": nonce, "payload": payload, "timestamp": timestamp},
        sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    sig = hmac.new(key, signing_input, hashlib.sha256).hexdigest()
    token = json.dumps(
        {"payload": payload, "timestamp": timestamp, "nonce": nonce, "sig": sig},
        indent=2
    )
    if token_path is not None:
        Path(token_path).write_text(token, encoding="utf-8")
    return token


def verify_arm_token(
    token_path: Path | str,
    *,
    max_age_seconds: int = 300,
    consume: bool = True,
) -> bool:
    """Verify and optionally consume a single-use arm token.

    Checks performed (all must pass):
      1. Token file exists and parses as valid JSON.
      2. Required fields present: payload, timestamp, nonce, sig (all strings).
      3. Payload string matches the expected constant.
      4. HMAC-SHA256 signature is cryptographically valid.
      5. Token has not expired (timestamp within max_age_seconds of UTC now).
      6. Token has not already been consumed (no adjacent .consumed sidecar).

    If consume=True (default), the token file is atomically renamed to
    <token_path>.consumed on success, preventing replay even after process
    restart.  Path.replace() is used for the rename, which is atomic on both
    POSIX and Windows (within the same filesystem volume).

    Returns:
        True  -- token valid, unexpired, unconsumed (and consumed if consume=True).
        False -- any check fails; never raises so callers get a simple bool gate.
    """
    path = Path(token_path)
    consumed_path = path.with_suffix(path.suffix + ".consumed")

    # Replay check: a .consumed sidecar means the token was already used.
    # Check this BEFORE checking whether the original file exists, so a
    # restored or re-written token file cannot bypass the replay guard.
    if consumed_path.exists():
        return False

    if not path.exists():
        return False

    try:
        data = json.loads(path.read_text(encoding="utf-8").strip())
    except Exception:
        return False

    # Field presence and type validation
    for field in ("payload", "timestamp", "nonce", "sig"):
        if field not in data or not isinstance(data[field], str) or not data[field]:
            return False

    if data["payload"] != "BRDS_ACTIVE_ARMED_STATE_2026":
        return False

    # Signature verification
    key = _get_hmac_key()
    signing_input = json.dumps(
        {"nonce": data["nonce"], "payload": data["payload"], "timestamp": data["timestamp"]},
        sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    expected_sig = hmac.new(key, signing_input, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(data["sig"], expected_sig):
        return False

    # Expiry check -- parse ISO-8601 UTC timestamp
    try:
        # time.strptime + calendar.timegm is the portable UTC-safe parser
        import calendar
        token_utc = calendar.timegm(time.strptime(data["timestamp"], "%Y-%m-%dT%H:%M:%SZ"))
    except (ValueError, OverflowError):
        return False

    if time.time() - token_utc > max_age_seconds:
        return False

    # Atomic single-use consumption
    if consume:
        try:
            path.replace(consumed_path)
        except OSError:
            # If rename fails (e.g., concurrent consumer already renamed it),
            # treat as already consumed to prevent double-use.
            return False

    return True
