"""API smoke tests."""
from __future__ import annotations

from fastapi.testclient import TestClient

from sentry.api.main import app


def test_healthz():
    with TestClient(app) as c:
        r = c.get("/healthz")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"


def test_metrics_endpoint():
    with TestClient(app) as c:
        r = c.get("/metrics")
        assert r.status_code == 200


def test_login_and_protected_route():
    with TestClient(app) as c:
        r = c.post("/api/auth/login", json={"username": "admin", "password": "test-password-123"})
        assert r.status_code == 200, r.text
        data = r.json()
        assert "access_token" in data
        assert data["user"]["role"] == "admin"

        r2 = c.get("/api/alerts")
        assert r2.status_code == 200
        assert "items" in r2.json()

        r3 = c.get("/api/sentry/status")
        assert r3.status_code == 200
        assert r3.json()["mode"] in ("monitoring", "training", "active", "booting")

        r4 = c.get("/api/hosts")
        assert r4.status_code == 200


def test_unauthenticated_is_rejected():
    with TestClient(app) as c:
        r = c.get("/api/alerts")
        assert r.status_code == 401


def test_iam_guards_the_last_administrator():
    with TestClient(app) as c:
        r = c.post("/api/auth/login", json={"username": "admin", "password": "test-password-123"})
        assert r.status_code == 200
        users = c.get("/api/users").json()
        admin = next(user for user in users if user["role"] == "admin")
        demote = c.patch(f"/api/users/{admin['id']}", json={"role": "analyst"})
        assert demote.status_code == 400

        created = c.post("/api/users", json={
            "email": "analyst@example.test", "username": "analyst1",
            "password": "analyst-password-123", "role": "analyst",
        })
        assert created.status_code == 200, created.text
        analyst = created.json()
        assert analyst["role"] == "analyst"
        disabled = c.patch(f"/api/users/{analyst['id']}", json={"is_active": False})
        assert disabled.status_code == 200
        assert disabled.json()["is_active"] is False
