# infra/firewall-controller/test_app.py
#
# Tests unitaires du service firewall-controller. L'exécution réelle
# d'iptables est mockée ici pour ne pas dépendre de la capability NET_ADMIN
# en environnement de test (CI) — mais le code applicatif appelé est le code
# de production réel, sans branche de simulation.
#
# Exécution : cd infra/firewall-controller && python3 -m pytest test_app.py -v
# (nécessite : pip install fastapi httpx pytest)

import subprocess
from unittest.mock import patch, MagicMock

import pytest
from fastapi.testclient import TestClient

from app import app, _blocked_ips


@pytest.fixture(autouse=True)
def _reset_state():
    _blocked_ips.clear()
    yield
    _blocked_ips.clear()


client = TestClient(app)


def test_block_rejects_invalid_ip():
    resp = client.post("/block", json={"ip": "not-an-ip", "reason": "test"})
    assert resp.status_code == 422


def test_block_calls_real_iptables_command_and_returns_blocked():
    fake_result = MagicMock(returncode=0, stdout="", stderr="")
    with patch("subprocess.run", return_value=fake_result) as mock_run:
        resp = client.post("/block", json={"ip": "203.0.113.5", "reason": "brute force"})

    assert resp.status_code == 200
    body = resp.json()
    assert body == {"status": "blocked", "ip": "203.0.113.5"}
    mock_run.assert_called_once_with(
        ["iptables", "-I", "INPUT", "-s", "203.0.113.5", "-j", "DROP"],
        capture_output=True, text=True, timeout=5,
    )


def test_block_returns_failure_when_iptables_denies_permission():
    """Sans NET_ADMIN, iptables échoue — le service doit relayer l'erreur réelle,
    jamais un faux succès."""
    fake_result = MagicMock(returncode=1, stdout="", stderr="iptables: Permission denied (you must be root).")
    with patch("subprocess.run", return_value=fake_result):
        resp = client.post("/block", json={"ip": "203.0.113.6", "reason": "test"})

    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "failure"
    assert "Permission denied" in body["error"]


def test_block_returns_failure_when_iptables_binary_missing():
    with patch("subprocess.run", side_effect=FileNotFoundError("iptables: not found")):
        resp = client.post("/block", json={"ip": "203.0.113.7", "reason": "test"})

    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "failure"
    assert "introuvable" in body["error"]


def test_block_is_idempotent_on_second_call():
    fake_result = MagicMock(returncode=0, stdout="", stderr="")
    with patch("subprocess.run", return_value=fake_result) as mock_run:
        client.post("/block", json={"ip": "203.0.113.8", "reason": "first"})
        resp2 = client.post("/block", json={"ip": "203.0.113.8", "reason": "second"})

    assert resp2.json()["status"] == "blocked"
    # Un seul appel iptables réel : le deuxième blocage est court-circuité (déjà bloquée)
    assert mock_run.call_count == 1


def test_health_reports_iptables_availability():
    fake_result = MagicMock(returncode=0)
    with patch("subprocess.run", return_value=fake_result):
        resp = client.get("/health")

    assert resp.status_code == 200
    assert resp.json()["iptables_available"] is True


def test_health_reports_degraded_when_iptables_unavailable():
    with patch("subprocess.run", side_effect=FileNotFoundError()):
        resp = client.get("/health")

    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "degraded"
    assert body["iptables_available"] is False


def test_list_blocked_reflects_real_state():
    fake_result = MagicMock(returncode=0, stdout="", stderr="")
    with patch("subprocess.run", return_value=fake_result):
        client.post("/block", json={"ip": "203.0.113.9", "reason": "test"})
        resp = client.get("/blocked")

    body = resp.json()
    assert body["total"] == 1
    assert "203.0.113.9" in body["blocked"]


def test_unblock_removes_rule_and_state():
    fake_result = MagicMock(returncode=0, stdout="", stderr="")
    with patch("subprocess.run", return_value=fake_result) as mock_run:
        client.post("/block", json={"ip": "203.0.113.10", "reason": "test"})
        resp = client.delete("/block/203.0.113.10")

    assert resp.status_code == 200
    assert resp.json() == {"status": "unblocked", "ip": "203.0.113.10"}
    mock_run.assert_any_call(
        ["iptables", "-D", "INPUT", "-s", "203.0.113.10", "-j", "DROP"],
        capture_output=True, text=True, timeout=5,
    )


def test_unblock_unknown_ip_returns_404():
    resp = client.delete("/block/203.0.113.99")
    assert resp.status_code == 404
