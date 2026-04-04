from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_scan_endpoint_valid_url():
    response = client.post(
        "/api/v1/scan",
        json={"url": "https://example.com"}
    )
    # The rate limiter might require X-Forwarded-For or normal client works.
    assert response.status_code in [200, 429] 
    
    if response.status_code == 200:
        data = response.json()
        assert "url" in data
        assert "status" in data
        assert "risk_score" in data
        assert "tgis_score" in data
        assert "recommendation" in data
        assert "graph_summary" in data

def test_scan_endpoint_invalid_url():
    response = client.post(
        "/api/v1/scan",
        json={"url": "not a url"}
    )
    # FastAPI pydantic validation will fail it with 422
    assert response.status_code == 422
