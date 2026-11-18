"""Stage C tests: lab containment mode.

Covers:
  - trigger_daemon dual gate: live only when BRDS_LIVE_CONTAINMENT=1 AND valid arm token
  - trigger_daemon passes -Armed to PS1 only when armed; -DryRunOverride otherwise
  - trigger_daemon writes containment audit log entry per action
  - trigger_daemon skips pre-existing alerts on startup
  - POST /api/containment/status updates Incident.status in DB
  - POST /api/containment/status rejects invalid status values
  - POST /api/containment/status returns 404 for unknown incident
  - PS1 DryRunOverride path (no actual network/process changes)
"""

from __future__ import annotations

import json
import os
import joblib
import numpy as np
import pandas as pd
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from scripts.train_baseline import train


# ── Helpers ───────────────────────────────────────────────────────────────────

FEATURE_NAMES = ["event_count", "file_activity_count", "registry_activity_count"]


def _build_baseline(tmp_path: Path) -> Path:
    rows = []
    for label, prefix, offset in ((0, "benign", 0), (1, "attack", 10)):
        for si in range(3):
            for ri in range(4):
                rows.append({
                    "source": f"{prefix}-{si}", "label": label,
                    "computer": "host-a", "process_key": f"p-{ri}",
                    "window_start": f"2026-01-01T00:00:{ri:02d}Z",
                    "event_count": offset + ri,
                    "file_activity_count": offset + ri,
                    "registry_activity_count": ri,
                })
    artifacts, _ = train(pd.DataFrame(rows))
    path = tmp_path / "baseline_models.joblib"
    joblib.dump(artifacts, path)
    return path


def _make_signed_alert(tmp_path: Path, window_start: str = "2026-01-01T00:00:00Z") -> Path:
    """Write a single HMAC-signed alert file and return its path."""
    os.environ["BRDS_ALLOW_INSECURE_DEV_HMAC"] = "1"
    from containment.alert_integrity import sign_alerts
    alert = {
        "computer": "host-a",
        "process_key": "wannacry.exe:1234",
        "window_start": window_start,
        "timestamp": window_start,
        "risk_score": 0.97,
        "technique_id": "T1486",
    }
    path = tmp_path / "alerts.json"
    path.write_text(sign_alerts([alert]), encoding="utf-8")
    return path


def _make_arm_token(path: Path) -> None:
    os.environ["BRDS_ALLOW_INSECURE_DEV_HMAC"] = "1"
    from containment.alert_integrity import create_arm_token
    path.write_text(create_arm_token(), encoding="utf-8")


@pytest.fixture(autouse=True)
def _insecure_hmac(monkeypatch):
    monkeypatch.setenv("BRDS_ALLOW_INSECURE_DEV_HMAC", "1")


# ── Dual-gate tests ───────────────────────────────────────────────────────────

def test_c1_no_live_containment_env_means_dry_run(tmp_path, monkeypatch):
    """Without BRDS_LIVE_CONTAINMENT=1, dual gate must return False."""
    monkeypatch.setenv("BRDS_LAB_ENVIRONMENT_APPROVED", "1")
    monkeypatch.delenv("BRDS_LIVE_CONTAINMENT", raising=False)
    arm = tmp_path / ".arm_token"
    _make_arm_token(arm)

    from containment.trigger_daemon import _is_live_containment_allowed
    assert _is_live_containment_allowed(arm) is False


def test_c2_no_arm_token_means_dry_run(tmp_path, monkeypatch):
    """Without a valid arm token, dual gate must return False even with env set."""
    monkeypatch.setenv("BRDS_LAB_ENVIRONMENT_APPROVED", "1")
    monkeypatch.setenv("BRDS_LIVE_CONTAINMENT", "1")
    missing_token = tmp_path / ".arm_token"  # does not exist

    from containment.trigger_daemon import _is_live_containment_allowed
    assert _is_live_containment_allowed(missing_token) is False


def test_c2b_no_lab_environment_means_dry_run(tmp_path, monkeypatch):
    """Without BRDS_LAB_ENVIRONMENT_APPROVED=1, dual gate must return False."""
    monkeypatch.delenv("BRDS_LAB_ENVIRONMENT_APPROVED", raising=False)
    monkeypatch.setenv("BRDS_LIVE_CONTAINMENT", "1")
    arm = tmp_path / ".arm_token"
    _make_arm_token(arm)

    from containment.trigger_daemon import _is_live_containment_allowed
    assert _is_live_containment_allowed(arm) is False


def test_c3_both_conditions_met_means_armed(tmp_path, monkeypatch):
    """When ALL conditions met (LAB + LIVE + TOKEN), gate returns True."""
    monkeypatch.setenv("BRDS_LAB_ENVIRONMENT_APPROVED", "1")
    monkeypatch.setenv("BRDS_LIVE_CONTAINMENT", "1")
    arm = tmp_path / ".arm_token"
    _make_arm_token(arm)

    from containment.trigger_daemon import _is_live_containment_allowed
    assert _is_live_containment_allowed(arm) is True


def test_c4_daemon_passes_dry_run_override_when_not_armed(tmp_path, monkeypatch):
    """In dry-run mode the daemon must pass -DryRunOverride (not -Armed) to PS1."""
    monkeypatch.delenv("BRDS_LIVE_CONTAINMENT", raising=False)
    alerts_path = _make_signed_alert(tmp_path)
    arm = tmp_path / ".arm_token"  # missing
    audit_log = tmp_path / "audit.jsonl"
    processed: set[str] = set()

    ps_calls: list[list[str]] = []

    def fake_run_ps(script_path, args, timeout=30):
        ps_calls.append(list(args))
        return 0, "[DRY-RUN] logged"

    from containment import trigger_daemon
    with patch.object(trigger_daemon, "run_powershell", side_effect=fake_run_ps):
        with patch.object(trigger_daemon, "_notify_backend"):
            trigger_daemon.poll_alerts(alerts_path, arm, audit_log, processed)

    assert len(ps_calls) >= 1
    for call_args in ps_calls:
        assert "-DryRunOverride" in call_args
        assert "-Armed" not in call_args


def test_c5_daemon_passes_armed_flag_when_gate_open(tmp_path, monkeypatch):
    """In live mode the daemon must pass -Armed (not -DryRunOverride) to PS1."""
    monkeypatch.setenv("BRDS_LAB_ENVIRONMENT_APPROVED", "1")
    monkeypatch.setenv("BRDS_LIVE_CONTAINMENT", "1")
    alerts_path = _make_signed_alert(tmp_path)
    arm = tmp_path / ".arm_token"
    _make_arm_token(arm)
    audit_log = tmp_path / "audit.jsonl"
    processed: set[str] = set()

    ps_calls: list[list[str]] = []

    def fake_run_ps(script_path, args, timeout=30):
        ps_calls.append(list(args))
        return 0, "[CONTAINMENT] done"

    from containment import trigger_daemon
    with patch.object(trigger_daemon, "run_powershell", side_effect=fake_run_ps):
        with patch.object(trigger_daemon, "_notify_backend"):
            trigger_daemon.poll_alerts(alerts_path, arm, audit_log, processed)

    assert len(ps_calls) >= 1
    for call_args in ps_calls:
        assert "-Armed" in call_args
        assert "-DryRunOverride" not in call_args


def test_c6_audit_log_written_per_action(tmp_path, monkeypatch):
    """trigger_daemon must write a JSONL audit entry for every processed alert."""
    monkeypatch.delenv("BRDS_LIVE_CONTAINMENT", raising=False)
    alerts_path = _make_signed_alert(tmp_path, "2026-01-01T01:00:00Z")
    arm = tmp_path / ".arm_token"
    audit_log = tmp_path / "audit.jsonl"
    processed: set[str] = set()

    from containment import trigger_daemon
    with patch.object(trigger_daemon, "run_powershell", return_value=(0, "ok")):
        with patch.object(trigger_daemon, "_notify_backend"):
            trigger_daemon.poll_alerts(alerts_path, arm, audit_log, processed)

    assert audit_log.exists(), "Audit log must be created"
    lines = audit_log.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["alert_id"] == "2026-01-01T01:00:00Z"
    assert record["computer"] == "host-a"
    assert "actions" in record
    assert record["mode"] == "DRY-RUN"


def test_c7_pre_existing_alerts_skipped(tmp_path, monkeypatch):
    """Alerts already in processed_alerts at startup must not trigger containment."""
    monkeypatch.delenv("BRDS_LIVE_CONTAINMENT", raising=False)
    alerts_path = _make_signed_alert(tmp_path, "2026-01-01T02:00:00Z")
    arm = tmp_path / ".arm_token"
    audit_log = tmp_path / "audit.jsonl"
    # Pre-seed the alert ID as already processed
    processed = {"2026-01-01T02:00:00Z"}

    from containment import trigger_daemon
    with patch.object(trigger_daemon, "run_powershell", return_value=(0, "ok")) as mock_ps:
        with patch.object(trigger_daemon, "_notify_backend"):
            trigger_daemon.poll_alerts(alerts_path, arm, audit_log, processed)

    mock_ps.assert_not_called()
    assert not audit_log.exists()


# ── Backend containment status endpoint ───────────────────────────────────────

@pytest.fixture
def app_with_incident(tmp_path):
    """App with one ACTIVE incident pre-seeded."""
    from backend.app import create_app
    from backend.models import db
    from backend.models.incidents import Incident

    baseline_path = _build_baseline(tmp_path)
    app = create_app({
        "TESTING": True,
        "MODEL_PATH": baseline_path,
        "LSTM_MODEL_PATH": tmp_path / "missing.pth",
        "ALERTS_PATH": tmp_path / "alerts.json",
        "TELEMETRY_PATH": tmp_path / "telemetry.csv",
        "REPORT_PATH": tmp_path / "report.json",
    })
    with app.app_context():
        inc = Incident(
            timestamp="2026-01-01T00:00:30Z",
            computer="host-lab",
            ransomware_family="T1486",
            risk_score=0.97,
            process_id=1234,
            status="ACTIVE",
        )
        db.session.add(inc)
        db.session.commit()

    os.environ["BRDS_API_KEY"] = "test-key"
    yield app
    os.environ.pop("BRDS_API_KEY", None)


def test_c8_containment_status_endpoint_updates_incident(app_with_incident):
    """POST /api/containment/status must flip Incident.status in the database."""
    from backend.models.incidents import Incident

    app = app_with_incident
    with app.test_client() as client:
        res = client.post(
            "/api/containment/status",
            json={
                "window_start": "2026-01-01T00:00:30Z",
                "computer": "host-lab",
                "status": "CONTAINED",
            },
            headers={"X-BRDS-API-Key": "test-key"},
        )
    assert res.status_code == 200
    body = res.get_json()
    assert body["new_status"] == "CONTAINED"

    with app.app_context():
        inc = Incident.query.filter_by(computer="host-lab").one()
        assert inc.status == "CONTAINED"


def test_c9_containment_status_rejects_invalid_status(app_with_incident):
    app = app_with_incident
    with app.test_client() as client:
        res = client.post(
            "/api/containment/status",
            json={
                "window_start": "2026-01-01T00:00:30Z",
                "computer": "host-lab",
                "status": "HACKED",
            },
            headers={"X-BRDS-API-Key": "test-key"},
        )
    assert res.status_code == 400
    assert "Invalid status" in res.get_json()["error"]


def test_c10_containment_status_returns_404_for_unknown_incident(app_with_incident):
    app = app_with_incident
    with app.test_client() as client:
        res = client.post(
            "/api/containment/status",
            json={
                "window_start": "2099-01-01T00:00:00Z",
                "computer": "ghost-host",
                "status": "CONTAINED",
            },
            headers={"X-BRDS-API-Key": "test-key"},
        )
    assert res.status_code == 404


# ── HMAC alert verification tests (Phase 1) ────────────────────────────────────

def test_hmac_valid_signed_alert_accepted(tmp_path, monkeypatch):
    """Valid HMAC signed alerts container must be successfully loaded."""
    from containment.alert_integrity import sign_alerts, verify_and_load
    monkeypatch.setenv("BRDS_ALLOW_INSECURE_DEV_HMAC", "1")
    alert = [{"computer": "host-test", "risk_score": 0.95, "window_start": "2026-01-01T00:00:00Z"}]
    path = tmp_path / "signed_alerts.json"
    path.write_text(sign_alerts(alert), encoding="utf-8")

    loaded = verify_and_load(path)
    assert len(loaded) == 1
    assert loaded[0]["computer"] == "host-test"


def test_hmac_invalid_signature_rejected(tmp_path, monkeypatch):
    """Alerts container with tampered/invalid signature must raise RuntimeError."""
    from containment.alert_integrity import sign_alerts, verify_and_load
    monkeypatch.setenv("BRDS_ALLOW_INSECURE_DEV_HMAC", "1")
    alert = [{"computer": "host-test", "risk_score": 0.95, "window_start": "2026-01-01T00:00:00Z"}]
    path = tmp_path / "tampered_alerts.json"
    container = json.loads(sign_alerts(alert))
    container["sig"] = "0000000000000000000000000000000000000000000000000000000000000000"
    path.write_text(json.dumps(container), encoding="utf-8")

    with pytest.raises(RuntimeError, match="HMAC signature verification failed"):
        verify_and_load(path)


def test_hmac_missing_signature_rejected(tmp_path, monkeypatch):
    """Container missing 'sig' key must raise ValueError."""
    from containment.alert_integrity import verify_and_load
    monkeypatch.setenv("BRDS_ALLOW_INSECURE_DEV_HMAC", "1")
    path = tmp_path / "missing_sig.json"
    path.write_text(json.dumps({"alerts": [{"computer": "host-test"}]}), encoding="utf-8")

    with pytest.raises(ValueError, match="missing 'alerts' or 'sig'"):
        verify_and_load(path)


def test_hmac_malformed_payload_rejected(tmp_path, monkeypatch):
    """Malformed container (invalid json or bad alerts field type) must raise ValueError."""
    from containment.alert_integrity import verify_and_load
    monkeypatch.setenv("BRDS_ALLOW_INSECURE_DEV_HMAC", "1")
    
    # 1. Non-JSON text
    bad_json = tmp_path / "bad.json"
    bad_json.write_text("NOT JSON CONTENT", encoding="utf-8")
    with pytest.raises(ValueError, match="Invalid JSON format"):
        verify_and_load(bad_json)

    # 2. alerts field is not a list
    bad_container = tmp_path / "bad_container.json"
    bad_container.write_text(json.dumps({"alerts": "not a list", "sig": "abc"}), encoding="utf-8")
    with pytest.raises(ValueError, match="'alerts' field must be a list"):
        verify_and_load(bad_container)


def test_hmac_raw_unsigned_list_rejected_by_default(tmp_path, monkeypatch):
    """Raw unsigned JSON list MUST be rejected by default on the production path."""
    from containment.alert_integrity import verify_and_load
    monkeypatch.setenv("BRDS_ALLOW_INSECURE_DEV_HMAC", "1")
    monkeypatch.delenv("BRDS_ALLOW_UNSIGNED_ALERTS_TEST_ONLY", raising=False)
    
    raw_path = tmp_path / "raw_unsigned.json"
    raw_path.write_text(json.dumps([{"computer": "host-test", "risk_score": 0.99}]), encoding="utf-8")

    with pytest.raises(ValueError, match="unsigned raw array"):
        verify_and_load(raw_path)


def test_hmac_raw_unsigned_list_allowed_with_explicit_test_flag(tmp_path, monkeypatch):
    """Raw unsigned JSON list is permitted ONLY when explicit test override flag is set."""
    from containment.alert_integrity import verify_and_load
    monkeypatch.setenv("BRDS_ALLOW_INSECURE_DEV_HMAC", "1")
    
    raw_path = tmp_path / "raw_unsigned_test.json"
    raw_path.write_text(json.dumps([{"computer": "host-test", "risk_score": 0.99}]), encoding="utf-8")

    # 1. Via allow_unsigned_legacy parameter
    loaded1 = verify_and_load(raw_path, allow_unsigned_legacy=True)
    assert len(loaded1) == 1

    # 2. Via environment variable override
    monkeypatch.setenv("BRDS_ALLOW_UNSIGNED_ALERTS_TEST_ONLY", "1")
    loaded2 = verify_and_load(raw_path)
    assert len(loaded2) == 1



# ── Arm token security tests (Phase 3) ────────────────────────────────────────
# These tests exercise the new time-limited, single-use, nonce-bearing token
# introduced to replace the permanently reusable static HMAC token.

import time as _time_module


def test_arm_token_valid_token_accepted(tmp_path, monkeypatch):
    """A freshly created token with correct HMAC must be accepted."""
    monkeypatch.setenv("BRDS_ALLOW_INSECURE_DEV_HMAC", "1")
    from containment.alert_integrity import create_arm_token, verify_arm_token

    token_path = tmp_path / ".arm_token_valid"
    create_arm_token(token_path)
    assert verify_arm_token(token_path, consume=False) is True


def test_arm_token_replay_rejected(tmp_path, monkeypatch):
    """A consumed token (renamed to .consumed) must be rejected on second use."""
    monkeypatch.setenv("BRDS_ALLOW_INSECURE_DEV_HMAC", "1")
    from containment.alert_integrity import create_arm_token, verify_arm_token

    token_path = tmp_path / ".arm_token_replay"
    create_arm_token(token_path)

    # First verification consumes the token (default consume=True)
    result1 = verify_arm_token(token_path, consume=True)
    assert result1 is True, "First verification should succeed"

    # Token file is now renamed to .arm_token_replay.consumed; re-verification must fail
    result2 = verify_arm_token(token_path, consume=True)
    assert result2 is False, "Second verification (replay) must be rejected"


def test_arm_token_replay_rejected_even_if_token_file_restored(tmp_path, monkeypatch):
    """Replay guard must hold even if the original token file is recreated with identical content."""
    monkeypatch.setenv("BRDS_ALLOW_INSECURE_DEV_HMAC", "1")
    from containment.alert_integrity import create_arm_token, verify_arm_token

    token_path = tmp_path / ".arm_token_restore"
    token_text = create_arm_token(token_path)

    # Consume the token
    verify_arm_token(token_path, consume=True)

    # Attacker restores the original token file
    token_path.write_text(token_text, encoding="utf-8")

    # Must still be rejected because .consumed sidecar exists
    result = verify_arm_token(token_path, consume=False)
    assert result is False, "Restored token file must be rejected due to .consumed sidecar"


def test_arm_token_expired_token_rejected(tmp_path, monkeypatch):
    """A token with a timestamp older than max_age_seconds must be rejected."""
    monkeypatch.setenv("BRDS_ALLOW_INSECURE_DEV_HMAC", "1")
    from containment.alert_integrity import create_arm_token, verify_arm_token
    import json
    import hmac as _hmac
    import hashlib as _hl

    token_text = create_arm_token()  # get fresh token string
    data = json.loads(token_text)

    # Backdate the timestamp by 10 minutes
    past_time = _time_module.gmtime(_time_module.time() - 600)
    data["timestamp"] = _time_module.strftime("%Y-%m-%dT%H:%M:%SZ", past_time)

    # Re-sign with the test key so HMAC is valid for the backdated timestamp
    key = b"BRDS_TEST_ONLY_HMAC_KEY"
    signing_input = json.dumps(
        {"nonce": data["nonce"], "payload": data["payload"], "timestamp": data["timestamp"]},
        sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    data["sig"] = _hmac.new(key, signing_input, _hl.sha256).hexdigest()

    token_path = tmp_path / ".arm_token_expired"
    token_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    result = verify_arm_token(token_path, max_age_seconds=300, consume=False)
    assert result is False, "Expired token (10 min old, TTL=5 min) must be rejected"


def test_arm_token_tampered_hmac_rejected(tmp_path, monkeypatch):
    """A token with a forged/corrupted HMAC signature must be rejected."""
    monkeypatch.setenv("BRDS_ALLOW_INSECURE_DEV_HMAC", "1")
    from containment.alert_integrity import create_arm_token, verify_arm_token
    import json

    token_text = create_arm_token()
    data = json.loads(token_text)
    data["sig"] = "0" * 64  # zeroed-out signature

    token_path = tmp_path / ".arm_token_tampered"
    token_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    result = verify_arm_token(token_path, consume=False)
    assert result is False, "Token with forged HMAC must be rejected"


def test_arm_token_missing_nonce_rejected(tmp_path, monkeypatch):
    """Old-format token without nonce field must be rejected."""
    monkeypatch.setenv("BRDS_ALLOW_INSECURE_DEV_HMAC", "1")
    from containment.alert_integrity import verify_arm_token
    import json
    import hmac as _hmac
    import hashlib as _hl

    # Simulate a legacy token: payload + sig only (no nonce, no timestamp)
    key = b"BRDS_TEST_ONLY_HMAC_KEY"
    payload = "BRDS_ACTIVE_ARMED_STATE_2026"
    sig = _hmac.new(key, payload.encode("utf-8"), _hl.sha256).hexdigest()

    token_path = tmp_path / ".arm_token_no_nonce"
    token_path.write_text(
        json.dumps({"payload": payload, "sig": sig}, indent=2),
        encoding="utf-8"
    )

    result = verify_arm_token(token_path, consume=False)
    assert result is False, "Legacy token without nonce/timestamp must be rejected"


def test_arm_token_wrong_payload_rejected(tmp_path, monkeypatch):
    """Token with wrong payload string must be rejected even with valid HMAC."""
    monkeypatch.setenv("BRDS_ALLOW_INSECURE_DEV_HMAC", "1")
    from containment.alert_integrity import verify_arm_token
    import json
    import hmac as _hmac
    import hashlib as _hl

    key = b"BRDS_TEST_ONLY_HMAC_KEY"
    payload = "ATTACKER_CONTROLLED_PAYLOAD"
    timestamp = _time_module.strftime("%Y-%m-%dT%H:%M:%SZ", _time_module.gmtime())
    nonce = "aaaa" * 8

    signing_input = json.dumps(
        {"nonce": nonce, "payload": payload, "timestamp": timestamp},
        sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    sig = _hmac.new(key, signing_input, _hl.sha256).hexdigest()

    token_path = tmp_path / ".arm_token_wrong_payload"
    token_path.write_text(
        json.dumps({"payload": payload, "timestamp": timestamp, "nonce": nonce, "sig": sig}, indent=2),
        encoding="utf-8"
    )

    result = verify_arm_token(token_path, consume=False)
    assert result is False, "Token with wrong payload must be rejected"


def test_arm_token_nonexistent_file_returns_false(tmp_path, monkeypatch):
    """Missing token file must return False, not raise an exception."""
    monkeypatch.setenv("BRDS_ALLOW_INSECURE_DEV_HMAC", "1")
    from containment.alert_integrity import verify_arm_token

    missing = tmp_path / ".arm_token_does_not_exist"
    result = verify_arm_token(missing, consume=False)
    assert result is False


def test_arm_token_trigger_daemon_gate_accepts_new_format(tmp_path, monkeypatch):
    """The trigger_daemon dual gate must accept the new time-limited token format."""
    monkeypatch.setenv("BRDS_ALLOW_INSECURE_DEV_HMAC", "1")
    monkeypatch.setenv("BRDS_LAB_ENVIRONMENT_APPROVED", "1")
    monkeypatch.setenv("BRDS_LIVE_CONTAINMENT", "1")

    from containment.alert_integrity import create_arm_token
    from containment import trigger_daemon

    arm = tmp_path / ".arm_token_gate"
    create_arm_token(arm)

    result = trigger_daemon._is_live_containment_allowed(arm)
    assert result is True, "Dual gate must accept a freshly created new-format token"

def test_arm_token_simultaneous_verification_permits_exactly_one_consumer(tmp_path, monkeypatch):
    """8 simultaneous workers synchronized via a barrier across 10 rounds must allow exactly 1 consumer per round."""
    import concurrent.futures
    import threading
    monkeypatch.setenv("BRDS_ALLOW_INSECURE_DEV_HMAC", "1")
    from containment.alert_integrity import create_arm_token, verify_arm_token

    num_workers = 8
    num_rounds = 10

    for round_idx in range(num_rounds):
        round_dir = tmp_path / f"round_{round_idx}"
        round_dir.mkdir()
        token_path = round_dir / ".arm_token_concurrent"
        create_arm_token(token_path)

        barrier = threading.Barrier(num_workers)

        def _worker():
            barrier.wait()  # synchronize all 8 workers to attempt consumption simultaneously
            return verify_arm_token(token_path, consume=True)

        with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as executor:
            futures = [executor.submit(_worker) for _ in range(num_workers)]
            results = [f.result() for f in futures]

        assert results.count(True) == 1, (
            f"Round {round_idx}: expected exactly 1 successful consumer, got {results.count(True)}"
        )
        assert results.count(False) == num_workers - 1, (
            f"Round {round_idx}: expected {num_workers - 1} rejected consumers, got {results.count(False)}"
        )


def test_rollback_host_state_validation_fail_closed(tmp_path):
    """RollbackHost.ps1 must fail closed (exit 1) on missing, malformed, missing-property, or wrong-type state."""
    import shutil
    import subprocess

    if shutil.which("powershell") is None:
        pytest.skip("powershell not available")

    script = Path(__file__).resolve().parent.parent / "containment" / "RollbackHost.ps1"
    assert script.exists(), "RollbackHost.ps1 script must exist"

    # Case 1: Missing state file -> exit 1
    missing = tmp_path / "missing_state.json"
    res1 = subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script), "-StateFilePath", str(missing)],
        capture_output=True, text=True
    )
    assert res1.returncode == 1, f"Missing state file must exit 1, got {res1.returncode}"

    # Case 2: Malformed JSON -> exit 1
    malformed = tmp_path / "malformed.json"
    malformed.write_text("{not valid json", encoding="utf-8")
    res2 = subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script), "-StateFilePath", str(malformed)],
        capture_output=True, text=True
    )
    assert res2.returncode == 1, f"Malformed state file must exit 1, got {res2.returncode}"

    # Case 3: Incomplete state (missing disabled_by_containment property) -> exit 1
    missing_prop = tmp_path / "missing_prop.json"
    missing_prop.write_text(json.dumps({"timestamp": "2026-01-01T00:00:00Z", "dry_run": False}), encoding="utf-8")
    res3 = subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script), "-StateFilePath", str(missing_prop)],
        capture_output=True, text=True
    )
    assert res3.returncode == 1, f"State missing disabled_by_containment must exit 1, got {res3.returncode}"

    # Case 4: Wrong type (e.g. integer instead of array) -> exit 1
    wrong_type = tmp_path / "wrong_type.json"
    wrong_type.write_text(json.dumps({"timestamp": "2026-01-01T00:00:00Z", "disabled_by_containment": 123}), encoding="utf-8")
    res4 = subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script), "-StateFilePath", str(wrong_type)],
        capture_output=True, text=True
    )
    assert res4.returncode == 1, f"Wrong-type disabled_by_containment must exit 1, got {res4.returncode}"


def test_rollback_host_state_zero_adapters_and_dryrun_success(tmp_path):
    """RollbackHost.ps1 must distinguish valid zero adapters (exit 0) and dryrun restore (exit 0)."""
    import shutil
    import subprocess

    if shutil.which("powershell") is None:
        pytest.skip("powershell not available")

    script = Path(__file__).resolve().parent.parent / "containment" / "RollbackHost.ps1"

    # Case 1: Valid state recording 0 adapters -> exit 0
    zero_state = tmp_path / "zero_state.json"
    zero_state.write_text(json.dumps({"timestamp": "2026-01-01T00:00:00Z", "disabled_by_containment": []}), encoding="utf-8")
    res1 = subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script), "-StateFilePath", str(zero_state)],
        capture_output=True, text=True
    )
    assert res1.returncode == 0, f"Valid zero adapters state must exit 0, got {res1.returncode}"
    assert "0 adapters disabled by containment" in res1.stdout or "Nothing to restore" in res1.stdout

    # Case 2: Valid state with adapter in dry-run mode -> exit 0 without modifying adapters
    valid_state = tmp_path / "valid_state.json"
    valid_state.write_text(json.dumps({"timestamp": "2026-01-01T00:00:00Z", "disabled_by_containment": ["MockAdapterNonExistent"]}), encoding="utf-8")
    res2 = subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script), "-StateFilePath", str(valid_state), "-DryRunOverride"],
        capture_output=True, text=True
    )
    assert res2.returncode == 0, f"Valid dry-run state must exit 0, got {res2.returncode}"
    assert "DRY-RUN" in res2.stdout

