import os
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

os.environ.setdefault("AGENTAPI_TOKEN", "test-token")
os.environ.setdefault("AGENTAPI_ALLOWED_CALLERS", "127.0.0.1")

import main
import security


def test_block_returns_results_wrapper_and_confirms_scheduler(monkeypatch):
    monkeypatch.setattr(main.firewall, "block_ip", lambda ip: None)
    monkeypatch.setattr(main.state, "add_blocked", lambda *args, **kwargs: None)
    monkeypatch.setattr(main.state, "is_blocked", lambda ip: False)
    monkeypatch.setattr(main.audit, "record", lambda *args, **kwargs: None)
    monkeypatch.setattr(security, "verify_caller_ip", lambda request: None)

    client = TestClient(main.app)
    response = client.post(
        "/block",
        json={
            "attacker_ip": "203.0.113.10",
            "victim_ip": "10.0.0.4",
            "victim_mode": "confirm",
            "incident_id": "inc-1",
            "reason": "unit test",
        },
        headers={"X-API-Key": "test-token"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert "results" in payload
    assert payload["results"][0]["ip"] == "203.0.113.10"
