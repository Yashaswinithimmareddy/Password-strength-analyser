"""
Integration Tests - REST API Endpoints & Security Headers
---------------------------------------------------------
Validates Flask endpoints, payload limits, CSPRNG generator, and security headers.
"""
import pytest
from backend.app import create_app

@pytest.fixture
def client():
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client

def test_26_api_analyze_valid_response(client):
    """Test 26: POST /api/analyze returns 200 with structured analysis."""
    resp = client.post("/api/analyze", json={
        "password": "Correct-Horse-Battery-Staple-2026!",
        "context": {},
        "persist_analytics": False
    })
    assert resp.status_code == 200
    data = resp.get_json()
    assert "score" in data
    assert "classification" in data
    assert "findings" in data
    assert "suggestions" in data
    assert "privacy_audit" in data

def test_27_api_generate_secure_password(client):
    """Test 27: POST /api/generate-password returns cryptographically secure credential."""
    resp = client.post("/api/generate-password", json={
        "length": 24,
        "include_uppercase": True,
        "include_lowercase": True,
        "include_digits": True,
        "include_symbols": True,
        "avoid_ambiguous": True
    })
    assert resp.status_code == 200
    data = resp.get_json()
    assert "password" in data
    assert len(data["password"]) == 24
    assert data["entropy_source"] == "os_urandom_via_secrets_csprng"

def test_33_api_generate_passphrase(client):
    """Test 33: POST /api/generate-passphrase generates multi-word phrase."""
    resp = client.post("/api/generate-passphrase", json={
        "word_count": 5,
        "delimiter": "-"
    })
    assert resp.status_code == 200
    data = resp.get_json()
    words = data["passphrase"].split("-")
    assert len(words) == 5
    assert data["word_count"] == 5

def test_34_api_policy_check(client):
    """Test 34: POST /api/check-policy correctly evaluates policy compliance."""
    # Test short password failing policy
    resp_fail = client.post("/api/check-policy", json={"password": "short"})
    assert resp_fail.status_code == 200
    assert resp_fail.get_json()["status"] == "POLICY FAIL"

    # Test solid password passing policy
    resp_pass = client.post("/api/check-policy", json={"password": "valid-enterprise-passphrase-2026"})
    assert resp_pass.status_code == 200
    assert resp_pass.get_json()["status"] == "POLICY PASS"

def test_35_api_hashing_demo(client):
    """Test 35: GET /api/hashing-demo returns comparative benchmarks."""
    resp = client.get("/api/hashing-demo?sample=DemoSyntheticPassword123!")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "fast_hash" in data
    assert "slow_salted_hash" in data
    assert "salt_demonstration" in data
    assert data["salt_demonstration"]["hashes_differ"] is True
    assert data["verification_test"]["correct_password_verified"] is True

def test_36_api_dashboard_stats(client):
    """Test 36: GET /api/dashboard/stats returns aggregate metrics without passwords."""
    resp = client.get("/api/dashboard/stats")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "total_analyses" in data
    assert "classification_distribution" in data
    assert "length_distribution" in data

def test_37_api_health_endpoint(client):
    """Test 37: GET /api/health confirms operational status."""
    resp = client.get("/api/health")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "HEALTHY"

def test_38_security_headers_present(client):
    """Test 38: Verify defensive security headers on HTTP responses."""
    resp = client.get("/api/health")
    assert resp.headers.get("X-Content-Type-Options") == "nosniff"
    assert resp.headers.get("X-Frame-Options") == "DENY"
    assert "no-store" in resp.headers.get("Cache-Control", "")

def test_39_oversized_payload_rejected(client):
    """Test 39: Oversized candidate password (>256 chars) is rejected to mitigate DoS."""
    oversized = "A" * 300
    resp = client.post("/api/analyze", json={"password": oversized})
    assert resp.status_code == 400
    assert "safety limit" in resp.get_json()["error"]
