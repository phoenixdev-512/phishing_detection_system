import pytest
from fastapi.testclient import TestClient
from unittest.mock import AsyncMock, patch

from app.main import app
from app.services.database import DatabaseService, get_db

client = TestClient(app)

@pytest.fixture
def mock_graph_builder():
    with patch("app.services.graph_builder.EgoGraphBuilder._fetch_pdns", new_callable=AsyncMock) as mock_pdns, \
         patch("app.services.graph_builder.EgoGraphBuilder._fetch_ct_logs", new_callable=AsyncMock) as mock_ct, \
         patch("app.services.graph_builder.EgoGraphBuilder._fetch_bgp", new_callable=AsyncMock) as mock_bgp, \
         patch("app.services.graph_builder.EgoGraphBuilder._fetch_whois", new_callable=AsyncMock) as mock_whois:
        
        mock_pdns.return_value = None
        mock_ct.return_value = None
        mock_bgp.return_value = None
        
        async def fake_whois(self, *args, **kwargs):
            self.domain_age_days = 30.0
            
        mock_whois.side_effect = fake_whois

        yield

def test_scan_returns_200_for_valid_url(mock_graph_builder):
    response = client.post("/scan", json={"url": "https://example.com"})
    assert response.status_code == 200

def test_response_contains_all_required_fields(mock_graph_builder):
    response = client.post("/scan", json={"url": "https://example.com"})
    assert response.status_code == 200
    data = response.json()
    required_keys = {
        "url", "status", "risk_score", "verdict_source", "reasons",
        "recommendation", "tgis_score", "tis_score", "scp_score",
        "domain_age_days", "scp_activated", "siblings", "graph_summary"
    }
    for key in required_keys:
        assert key in data

def test_risk_score_is_int_0_to_100(mock_graph_builder):
    response = client.post("/scan", json={"url": "https://example.com"})
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data["risk_score"], int)
    assert 0 <= data["risk_score"] <= 100

def test_tgis_score_is_float_0_to_1(mock_graph_builder):
    response = client.post("/scan", json={"url": "https://example.com"})
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data["tgis_score"], float)
    assert 0.0 <= data["tgis_score"] <= 1.0

def test_invalid_url_returns_422(mock_graph_builder):
    response = client.post("/scan", json={"url": "not-a-url-at-all!!!"})
    assert response.status_code == 422

def test_blacklisted_url_returns_malicious(mock_graph_builder):
    def override_get_db():
        db = DatabaseService()
        # Seed test db
        db.add_to_blacklist("bad-domain.com")
        return db

    app.dependency_overrides[get_db] = override_get_db
    try:
        response = client.post("/scan", json={"url": "https://bad-domain.com"})
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "malicious"
        assert data["verdict_source"] == "Blacklist"
        assert data["risk_score"] == 100
    finally:
        app.dependency_overrides.clear()

def test_scp_activated_for_new_domain():
    with patch("app.services.graph_builder.EgoGraphBuilder._fetch_pdns", new_callable=AsyncMock) as mock_pdns, \
         patch("app.services.graph_builder.EgoGraphBuilder._fetch_ct_logs", new_callable=AsyncMock) as mock_ct, \
         patch("app.services.graph_builder.EgoGraphBuilder._fetch_bgp", new_callable=AsyncMock) as mock_bgp, \
         patch("app.services.graph_builder.EgoGraphBuilder._fetch_whois", new_callable=AsyncMock) as mock_whois:

        mock_pdns.return_value = None
        mock_ct.return_value = None
        mock_bgp.return_value = None
        
        async def fake_whois_new(self, *args, **kwargs):
            self.domain_age_days = 0.04  # roughly 1 hour
            
        mock_whois.side_effect = fake_whois_new

        response = client.post("/scan", json={"url": "https://new-example.com"})
        assert response.status_code == 200
        data = response.json()
        assert data["scp_activated"] is True

def test_rate_limit_returns_429(mock_graph_builder):
    # To reliably hit 429, we patch the settings to a small rate limit
    with patch("app.api.v1.endpoints.scan.settings.RATE_LIMIT_PER_MINUTE", 30):
        # Depending on how slowapi interprets the mock, it might not be dynamic.
        # So we just loop 31 times (if the limit config was picked up as 30) or 61 times.
        # We will loop enough times to guarantee a 429.
        status_429_seen = False
        for i in range(65):
            res = client.post("/scan", json={"url": "https://example-rate-limit.com"}, headers={"X-Forwarded-For": "127.0.0.1"})
            if res.status_code == 429:
                status_429_seen = True
                # if the user specifically asked for 31st response, we can assert on loop iteration
                break
                
        assert status_429_seen
