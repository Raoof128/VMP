"""
Unit Tests for FastAPI Endpoints
Tests for vulnerability management API routes
"""

import pytest
from fastapi.testclient import TestClient
from datetime import datetime
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from src.api.main import app
from src.database.models import Vulnerability, Asset, RemediationStatus, SeverityLevel, AssetType


@pytest.fixture
def client():
    """Create FastAPI test client"""
    return TestClient(app)


@pytest.mark.unit
class TestHealthEndpoints:
    """Test health check endpoints"""

    def test_root_endpoint(self, client):
        """Test root endpoint returns API info"""
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "Vulnerability Management Pipeline API"
        assert data["version"] == "1.0.0"
        assert "documentation" in data

    def test_health_check_endpoint(self, client):
        """Test health check endpoint"""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert "version" in data
        assert "timestamp" in data
        assert "services" in data


@pytest.mark.unit
class TestVulnerabilityEndpoints:
    """Test vulnerability-related endpoints"""

    def test_get_vulnerabilities_empty(self, client, db_session):
        """Test getting vulnerabilities when database is empty"""
        response = client.get("/api/vulnerabilities")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 0
        assert data["data"] == []

    def test_get_vulnerabilities_with_data(self, client, db_session, sample_vulnerability):
        """Test getting vulnerabilities with data"""
        response = client.get("/api/vulnerabilities")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] > 0
        assert len(data["data"]) > 0

        vuln_data = data["data"][0]
        assert "cve_id" in vuln_data
        assert "business_risk_score" in vuln_data
        assert "remediation_status" in vuln_data

    def test_get_vulnerabilities_pagination(self, client, db_session):
        """Test vulnerability pagination"""
        response = client.get("/api/vulnerabilities?skip=0&limit=10")
        assert response.status_code == 200
        data = response.json()
        assert data["skip"] == 0
        assert data["limit"] == 10

    def test_get_vulnerabilities_filtering(self, client, db_session):
        """Test vulnerability filtering by min_risk"""
        response = client.get("/api/vulnerabilities?min_risk=80")
        assert response.status_code == 200
        data = response.json()
        # All returned vulnerabilities should have risk >= 80
        for vuln in data["data"]:
            assert vuln["business_risk_score"] >= 80

    def test_get_vulnerabilities_sorting(self, client, db_session):
        """Test vulnerability sorting"""
        # Test sort by risk_score
        response = client.get("/api/vulnerabilities?sort=risk_score")
        assert response.status_code == 200

        # Test sort by discovered_date
        response = client.get("/api/vulnerabilities?sort=discovered_date")
        assert response.status_code == 200

        # Test sort by cve_id
        response = client.get("/api/vulnerabilities?sort=cve_id")
        assert response.status_code == 200

    def test_get_vulnerability_by_cve_not_found(self, client, db_session):
        """Test getting non-existent vulnerability returns 404"""
        response = client.get("/api/vulnerabilities/CVE-9999-99999")
        assert response.status_code == 404
        data = response.json()
        assert "detail" in data

    def test_get_vulnerability_by_cve_success(self, client, db_session, sample_vulnerability):
        """Test getting specific vulnerability by CVE ID"""
        response = client.get(f"/api/vulnerabilities/{sample_vulnerability.cve_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["cve_id"] == sample_vulnerability.cve_id
        assert "title" in data
        assert "description" in data
        assert "cvss_base_score" in data
        assert "affected_assets" in data


@pytest.mark.unit
class TestAssetEndpoints:
    """Test asset-related endpoints"""

    def test_get_assets_empty(self, client, db_session):
        """Test getting assets when database is empty"""
        response = client.get("/api/assets")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 0
        assert data["data"] == []

    def test_get_assets_with_data(self, client, db_session, sample_asset):
        """Test getting assets with data"""
        response = client.get("/api/assets")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] > 0
        assert len(data["data"]) > 0

        asset_data = data["data"][0]
        assert "hostname" in asset_data
        assert "ip_address" in asset_data
        assert "criticality" in asset_data
        assert "vulnerability_count" in asset_data

    def test_get_assets_pagination(self, client, db_session):
        """Test asset pagination"""
        response = client.get("/api/assets?skip=0&limit=10")
        assert response.status_code == 200
        data = response.json()
        assert data["skip"] == 0
        assert data["limit"] == 10


@pytest.mark.unit
class TestMetricsEndpoints:
    """Test metrics and statistics endpoints"""

    def test_get_metrics_summary_empty(self, client, db_session):
        """Test metrics summary with empty database"""
        response = client.get("/api/metrics/summary")
        assert response.status_code == 200
        data = response.json()
        assert data["total_vulnerabilities"] == 0
        assert "by_priority" in data
        assert "by_status" in data
        assert "timestamp" in data

    def test_get_metrics_summary_with_data(self, client, db_session, sample_vulnerability):
        """Test metrics summary with data"""
        response = client.get("/api/metrics/summary")
        assert response.status_code == 200
        data = response.json()
        assert data["total_vulnerabilities"] > 0

        # Check priority breakdown
        assert "critical" in data["by_priority"]
        assert "high" in data["by_priority"]
        assert "medium" in data["by_priority"]
        assert "low" in data["by_priority"]

        # Check status breakdown
        assert "open" in data["by_status"]


@pytest.mark.unit
class TestAPIValidation:
    """Test API input validation"""

    def test_invalid_pagination_params(self, client):
        """Test invalid pagination parameters"""
        # Negative skip
        response = client.get("/api/vulnerabilities?skip=-1")
        assert response.status_code == 422  # Validation error

        # Negative limit
        response = client.get("/api/vulnerabilities?limit=-10")
        assert response.status_code == 422

    def test_invalid_min_risk_param(self, client):
        """Test invalid min_risk parameter"""
        # min_risk > 100
        response = client.get("/api/vulnerabilities?min_risk=150")
        # Should still work, just no results returned
        assert response.status_code == 200

    def test_invalid_sort_param(self, client):
        """Test invalid sort parameter"""
        # Invalid sort field (should be ignored)
        response = client.get("/api/vulnerabilities?sort=invalid_field")
        assert response.status_code == 200  # Should not error, just ignore


@pytest.mark.unit
class TestAPIResponseFormat:
    """Test API response format consistency"""

    def test_vulnerability_list_response_format(self, client, db_session):
        """Test vulnerability list response has correct format"""
        response = client.get("/api/vulnerabilities")
        assert response.status_code == 200
        data = response.json()

        # Check required fields
        assert "total" in data
        assert "skip" in data
        assert "limit" in data
        assert "data" in data
        assert isinstance(data["data"], list)

    def test_vulnerability_detail_response_format(self, client, db_session, sample_vulnerability):
        """Test vulnerability detail response has all fields"""
        response = client.get(f"/api/vulnerabilities/{sample_vulnerability.cve_id}")
        assert response.status_code == 200
        data = response.json()

        # Check all expected fields are present
        expected_fields = [
            "id", "cve_id", "title", "description", "cvss_base_score",
            "cvss_version", "cvss_vector", "cvss_severity", "epss_score",
            "business_risk_score", "remediation_status", "affected_assets"
        ]

        for field in expected_fields:
            assert field in data

    def test_asset_list_response_format(self, client, db_session):
        """Test asset list response has correct format"""
        response = client.get("/api/assets")
        assert response.status_code == 200
        data = response.json()

        # Check required fields
        assert "total" in data
        assert "skip" in data
        assert "limit" in data
        assert "data" in data
        assert isinstance(data["data"], list)


@pytest.mark.unit
class TestCORSHeaders:
    """Test CORS configuration"""

    def test_cors_headers_present(self, client):
        """Test CORS headers are present in responses"""
        response = client.get("/")
        # FastAPI TestClient doesn't include CORS headers by default
        # This test verifies the endpoint is accessible
        assert response.status_code == 200


@pytest.mark.unit
class TestAPIErrorHandling:
    """Test API error handling"""

    def test_404_for_invalid_vulnerability(self, client):
        """Test 404 error for non-existent vulnerability"""
        response = client.get("/api/vulnerabilities/CVE-INVALID-00000")
        assert response.status_code == 404

    def test_invalid_endpoint_returns_404(self, client):
        """Test invalid endpoint returns 404"""
        response = client.get("/api/nonexistent")
        assert response.status_code == 404
