"""
PyTest Configuration and Fixtures
Shared test fixtures for unit and integration tests
"""

import pytest
import os
import sys
from datetime import datetime

# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.database.engine import get_engine, SessionLocal, Base
from src.database.models import Vulnerability, Asset, Patch, RemediationStatus, AssetType, SeverityLevel


@pytest.fixture(scope="session")
def test_db_engine():
    """Create test database engine"""
    # Use in-memory SQLite for testing
    from sqlalchemy import create_engine
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(engine)
    yield engine
    Base.metadata.drop_all(engine)


@pytest.fixture(scope="function")
def db_session(test_db_engine):
    """Create a new database session for a test"""
    from sqlalchemy.orm import sessionmaker
    Session = sessionmaker(bind=test_db_engine)
    session = Session()

    yield session

    session.rollback()
    session.close()


@pytest.fixture
def sample_asset(db_session):
    """Create a sample asset for testing"""
    asset = Asset(
        hostname="test-server-01",
        ip_address="192.168.1.100",
        asset_type=AssetType.SERVER,
        criticality=8,
        operating_system="Ubuntu 22.04",
        owner_team="Engineering",
        environment="PRODUCTION",
        is_active=True
    )
    db_session.add(asset)
    db_session.commit()
    return asset


@pytest.fixture
def sample_vulnerability(db_session, sample_asset):
    """Create a sample vulnerability for testing"""
    vuln = Vulnerability(
        cve_id="CVE-2024-TEST",
        title="Test Vulnerability",
        description="This is a test vulnerability for unit testing",
        cvss_base_score=8.5,
        cvss_version="3.1",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        cvss_severity=SeverityLevel.HIGH,
        epss_score=0.65,
        epss_percentile=85.0,
        cwe_ids=["CWE-79"],
        business_risk_score=72.5,
        remediation_status=RemediationStatus.OPEN,
        discovered_date=datetime.utcnow(),
        data_source="TEST"
    )
    vuln.affected_assets = [sample_asset]
    db_session.add(vuln)
    db_session.commit()
    return vuln


@pytest.fixture
def sample_patch(db_session, sample_vulnerability):
    """Create a sample patch for testing"""
    patch = Patch(
        patch_id="TEST-PATCH-001",
        name="Test Security Patch",
        vendor="Test Vendor",
        product="Test Product",
        version="1.0.0",
        release_date=datetime.utcnow(),
        deployment_difficulty=2,
        requires_reboot=False,
        estimated_deployment_hours=4.0,
        vulnerabilities_fixed_count=1,
        high_risk_vulns_fixed=1
    )
    patch.vulnerabilities = [sample_vulnerability]
    patch.roi_score = 1 / 4.0  # 0.25
    db_session.add(patch)
    db_session.commit()
    return patch


# Pytest markers
def pytest_configure(config):
    """Register custom markers"""
    config.addinivalue_line(
        "markers", "unit: mark test as a unit test"
    )
    config.addinivalue_line(
        "markers", "integration: mark test as an integration test"
    )
    config.addinivalue_line(
        "markers", "performance: mark test as a performance test"
    )
    config.addinivalue_line(
        "markers", "slow: mark test as slow running (>1 second)"
    )
