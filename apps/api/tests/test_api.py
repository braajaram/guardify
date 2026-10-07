from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_health():
    assert client.get("/api/v1/health").status_code == 200

def test_ssrf_urls_rejected():
    for url in ("http://localhost", "http://127.0.0.1", "http://169.254.169.254", "http://10.0.0.1", "file:///etc/passwd", "javascript:alert(1)"):
        assert client.post("/api/v1/analyze/url", json={"url": url}).status_code == 422

def test_file_hash_is_deterministic():
    response = client.post("/api/v1/analyze/file", files={"file": ("x.txt", b"hello", "text/plain")})
    assert response.status_code == 200
    assert response.json()["data"]["analyst"]["sha256"] == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"

def test_email_shape():
    response = client.post("/api/v1/analyze/email", json={"sender": "a@example.com", "recipient": "b@example.com"})
    assert response.status_code == 200
    assert response.json()["data"]["verdict"] == "UNKNOWN"
