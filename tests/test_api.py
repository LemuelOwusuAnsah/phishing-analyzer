import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from app import app as flask_app


@pytest.fixture
def client():
    flask_app.config["TESTING"] = True
    with flask_app.test_client() as c:
        yield c


def test_index_loads(client):
    res = client.get("/")
    assert res.status_code == 200
    assert b"phishing" in res.data.lower()


def test_analyze_missing_url(client):
    res = client.post("/api/analyze", json={})
    assert res.status_code == 400


def test_analyze_empty_url(client):
    res = client.post("/api/analyze", json={"url": ""})
    assert res.status_code == 400


def test_analyze_safe_url(client):
    res = client.post("/api/analyze", json={"url": "https://www.google.com"})
    assert res.status_code == 200
    data = res.get_json()
    assert "score" in data
    assert "verdict" in data
    assert "findings" in data
    assert isinstance(data["findings"], list)
    assert data["score"] < 40


def test_analyze_phishing_url(client):
    res = client.post("/api/analyze", json={"url": "http://paypa1-secure-login.tk/verify"})
    assert res.status_code == 200
    data = res.get_json()
    assert data["score"] > 40
    assert data["verdict"] in ("MEDIUM", "DANGEROUS", "HIGH")


def test_analyze_ip_host(client):
    res = client.post("/api/analyze", json={"url": "http://192.168.1.1/account/update"})
    assert res.status_code == 200
    data = res.get_json()
    titles = [f["title"] for f in data["findings"]]
    assert any("IP" in t or "ip" in t for t in titles)
