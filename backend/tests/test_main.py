import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from main import app
from database import get_db, Base
import models
from auth import get_password_hash

# Setup in-memory SQLite for testing
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db

@pytest.fixture()
def test_db():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)

@pytest.fixture()
def client(test_db):
    return TestClient(app)

def test_read_root(client):
    response = client.get("/")
    assert response.status_code == 200


# ── helpers ────────────────────────────────────────────────────────────────────

def _register_and_login(client, email="u@test.com", password="pass123"):
    client.post("/users/", json={"email": email, "password": password})
    r = client.post("/token", data={"username": email, "password": password})
    return r.json()["access_token"]

def test_create_user(client):
    response = client.post(
        "/users/",
        json={"email": "test@example.com", "password": "testpassword"}
    )
    assert response.status_code == 201
    data = response.json()
    assert data["email"] == "test@example.com"
    assert "id" in data

def test_login_for_access_token(client):
    # First create a user
    client.post(
        "/users/",
        json={"email": "login@example.com", "password": "loginpass"}
    )
    # Then try to login
    response = client.post(
        "/token",
        data={"username": "login@example.com", "password": "loginpass"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"

def test_get_cves_empty(client):
    response = client.get("/cves/")
    assert response.status_code == 200
    assert response.json() == []

def test_get_cves_pagination(client):
    db = TestingSessionLocal()
    # Add some mock CVEs
    for i in range(25):
        cve = models.CVE(
            cve_id=f"CVE-2024-00{i:02d}",
            title=f"Test Vulnerability {i}",
            description="Test description",
            severity="HIGH"
        )
        db.add(cve)
    db.commit()
    db.close()

    response = client.get("/cves/?skip=0&limit=10")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 10

    response2 = client.get("/cves/?skip=20&limit=10")
    assert response2.status_code == 200
    data2 = response2.json()
    assert len(data2) == 5


# ── Auth guard tests ────────────────────────────────────────────────────────────

def test_sync_requires_auth(client):
    r = client.post("/sync/", json={"feeds": [], "scrapers": []})
    assert r.status_code == 401


def test_clear_checkpoint_requires_auth(client):
    r = client.delete("/cves/clear-checkpoint")
    assert r.status_code == 401


def test_discord_notif_requires_auth(client):
    r = client.post("/notifications/discord", json={
        "webhook_url": "https://discord.com/api/webhooks/123/abc",
        "title": "T", "severity": "high", "cve_id": "CVE-2024-0001"
    })
    assert r.status_code == 401


def test_telegram_notif_requires_auth(client):
    r = client.post("/notifications/telegram", json={
        "bot_token": "tok", "chat_id": "123",
        "title": "T", "severity": "high", "cve_id": "CVE-2024-0001"
    })
    assert r.status_code == 401


# ── Trigger CRUD tests ─────────────────────────────────────────────────────────

def test_create_and_list_trigger(client):
    token = _register_and_login(client, "trigger@test.com")
    headers = {"Authorization": f"Bearer {token}"}

    r = client.post("/triggers/", json={"min_severity": "critical"}, headers=headers)
    assert r.status_code == 201
    assert r.json()["min_severity"] == "critical"

    r2 = client.get("/triggers/", headers=headers)
    assert r2.status_code == 200
    assert len(r2.json()) == 1


def test_trigger_requires_at_least_one_condition(client):
    token = _register_and_login(client, "t2@test.com")
    headers = {"Authorization": f"Bearer {token}"}
    r = client.post("/triggers/", json={}, headers=headers)
    assert r.status_code == 422


def test_delete_trigger(client):
    token = _register_and_login(client, "t3@test.com")
    headers = {"Authorization": f"Bearer {token}"}
    r = client.post("/triggers/", json={"keyword": "apache"}, headers=headers)
    tid = r.json()["id"]
    r2 = client.delete(f"/triggers/{tid}", headers=headers)
    assert r2.status_code == 204
    assert client.get("/triggers/", headers=headers).json() == []


def test_delete_trigger_not_found(client):
    token = _register_and_login(client, "t4@test.com")
    headers = {"Authorization": f"Bearer {token}"}
    r = client.delete("/triggers/00000000-0000-0000-0000-000000000000", headers=headers)
    assert r.status_code == 404


# ── Discord URL validation ────────────────────────────────────────────────────

def test_discord_rejects_bad_url(client):
    token = _register_and_login(client, "d@test.com")
    headers = {"Authorization": f"Bearer {token}"}
    r = client.post("/notifications/discord", json={
        "webhook_url": "https://evil.com/hook",
        "title": "T", "severity": "high", "cve_id": "CVE-2024-0001"
    }, headers=headers)
    assert r.status_code == 422
