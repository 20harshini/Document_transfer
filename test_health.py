def test_root_endpoint(client):
    """
    Verify the root endpoint responds with basic metadata and API links.
    """
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "operational"
    assert "version" in data
    assert data["health"] == "/api/v1/health"
    assert data["docs"] == "/docs"


def test_health_check_endpoint(client):
    """
    Verify the health check endpoint returns 200 and expected status fields.
    """
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["app"] == "TrustVault API"
    assert "version" in data
    assert "environment" in data
    assert "timestamp" in data
    assert "services" in data
    assert data["services"]["api"] == "healthy"


def test_nonexistent_endpoint_returns_404(client):
    """
    Verify nonexistent routes return a standard 404 response.
    """
    response = client.get("/api/v1/nonexistent-route")
    assert response.status_code == 404
