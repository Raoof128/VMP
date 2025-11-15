"""
Integration Tests for Database Models
Tests ORM relationships and database operations
"""

import pytest
from datetime import datetime
from src.database.models import (
    Vulnerability, Asset, Scan, Patch, RemediationTicket,
    ScanResult, ComplianceMapping, RiskHistory,
    RemediationStatus, AssetType, SeverityLevel, ScanType, TicketPriority
)


@pytest.mark.integration
class TestVulnerabilityAssetRelationship:
    """Test many-to-many relationship between Vulnerability and Asset"""

    def test_create_vulnerability_with_assets(self, db_session):
        """Create vulnerability with multiple assets"""
        # Create assets
        asset1 = Asset(
            hostname="server-01",
            ip_address="10.0.1.10",
            asset_type=AssetType.SERVER,
            criticality=9
        )
        asset2 = Asset(
            hostname="server-02",
            ip_address="10.0.1.11",
            asset_type=AssetType.SERVER,
            criticality=8
        )
        db_session.add_all([asset1, asset2])
        db_session.commit()

        # Create vulnerability
        vuln = Vulnerability(
            cve_id="CVE-2024-INT-001",
            title="Integration Test Vulnerability",
            cvss_base_score=8.5,
            cvss_severity=SeverityLevel.HIGH
        )
        vuln.affected_assets = [asset1, asset2]
        db_session.add(vuln)
        db_session.commit()

        # Verify relationship
        assert len(vuln.affected_assets) == 2
        assert asset1 in vuln.affected_assets
        assert asset2 in vuln.affected_assets

    def test_asset_vulnerability_bidirectional(self, db_session):
        """Test bidirectional relationship works"""
        asset = Asset(
            hostname="test-asset",
            ip_address="10.0.1.50",
            asset_type=AssetType.SERVER,
            criticality=7
        )
        db_session.add(asset)
        db_session.commit()

        vuln1 = Vulnerability(
            cve_id="CVE-2024-INT-002",
            title="Test Vuln 1",
            cvss_base_score=7.0
        )
        vuln2 = Vulnerability(
            cve_id="CVE-2024-INT-003",
            title="Test Vuln 2",
            cvss_base_score=6.0
        )

        vuln1.affected_assets = [asset]
        vuln2.affected_assets = [asset]

        db_session.add_all([vuln1, vuln2])
        db_session.commit()

        # Reload asset from database
        db_session.expire(asset)
        reloaded_asset = db_session.query(Asset).filter_by(hostname="test-asset").first()

        # Verify asset can see its vulnerabilities
        assert len(reloaded_asset.vulnerabilities) == 2


@pytest.mark.integration
class TestPatchVulnerabilityRelationship:
    """Test many-to-many relationship between Patch and Vulnerability"""

    def test_patch_fixes_multiple_vulnerabilities(self, db_session):
        """Patch should be linked to multiple vulnerabilities"""
        vuln1 = Vulnerability(
            cve_id="CVE-2024-INT-004",
            title="Vuln 1",
            cvss_base_score=8.0
        )
        vuln2 = Vulnerability(
            cve_id="CVE-2024-INT-005",
            title="Vuln 2",
            cvss_base_score=7.5
        )
        db_session.add_all([vuln1, vuln2])
        db_session.commit()

        patch = Patch(
            patch_id="PATCH-INT-001",
            name="Integration Test Patch",
            vendor="Test Vendor",
            product="Test Product",
            vulnerabilities_fixed_count=2
        )
        patch.vulnerabilities = [vuln1, vuln2]
        db_session.add(patch)
        db_session.commit()

        # Verify relationship
        assert len(patch.vulnerabilities) == 2
        assert vuln1 in patch.vulnerabilities
        assert vuln2 in patch.vulnerabilities


@pytest.mark.integration
class TestScanResults:
    """Test scan result creation and relationships"""

    def test_create_scan_with_results(self, db_session):
        """Create scan with vulnerability results"""
        asset = Asset(
            hostname="scan-target",
            ip_address="10.0.2.10",
            asset_type=AssetType.SERVER,
            criticality=8
        )
        db_session.add(asset)
        db_session.commit()

        scan = Scan(
            scan_id="SCAN-INT-001",
            name="Integration Test Scan",
            scan_type=ScanType.FULL,
            status="COMPLETED",
            start_time=datetime.utcnow()
        )
        db_session.add(scan)
        db_session.commit()

        vuln = Vulnerability(
            cve_id="CVE-2024-INT-006",
            title="Scan Result Test",
            cvss_base_score=7.0
        )
        db_session.add(vuln)
        db_session.commit()

        result = ScanResult(
            scan_id=scan.id,
            vulnerability_id=vuln.id,
            asset_id=asset.id,
            port=443,
            protocol="TCP",
            evidence="Test evidence"
        )
        db_session.add(result)
        db_session.commit()

        # Verify relationships
        assert result.scan == scan
        assert result.vulnerability == vuln
        assert len(scan.scan_results) == 1


@pytest.mark.integration
class TestRemediationTickets:
    """Test remediation ticket creation and linking"""

    def test_create_ticket_for_vulnerability(self, db_session):
        """Create Jira ticket linked to vulnerability"""
        vuln = Vulnerability(
            cve_id="CVE-2024-INT-007",
            title="Ticket Test Vulnerability",
            cvss_base_score=9.0,
            cvss_severity=SeverityLevel.CRITICAL,
            business_risk_score=85.0,
            remediation_status=RemediationStatus.OPEN
        )
        db_session.add(vuln)
        db_session.commit()

        ticket = RemediationTicket(
            vulnerability_id=vuln.id,
            ticket_id="VULN-INT-001",
            ticket_url="https://jira.example.com/browse/VULN-INT-001",
            ticket_system="JIRA",
            priority=TicketPriority.HIGHEST,
            sla_deadline=datetime.utcnow(),
            status="OPEN"
        )
        db_session.add(ticket)
        db_session.commit()

        # Verify relationship
        assert ticket.vulnerability == vuln
        assert len(vuln.remediation_tickets) == 1
        assert vuln.remediation_tickets[0].ticket_id == "VULN-INT-001"


@pytest.mark.integration
class TestComplianceMapping:
    """Test compliance framework mapping"""

    def test_map_vulnerability_to_framework(self, db_session):
        """Map vulnerability to NIST 800-53 control"""
        vuln = Vulnerability(
            cve_id="CVE-2024-INT-008",
            title="Compliance Test",
            cvss_base_score=7.5
        )
        db_session.add(vuln)
        db_session.commit()

        mapping = ComplianceMapping(
            vulnerability_id=vuln.id,
            framework="NIST_800_53",
            control_id="SI-2",
            control_name="Flaw Remediation",
            is_compliant=True
        )
        db_session.add(mapping)
        db_session.commit()

        # Verify relationship
        assert len(vuln.compliance_mappings) == 1
        assert vuln.compliance_mappings[0].framework == "NIST_800_53"


@pytest.mark.integration
class TestRiskHistory:
    """Test risk history tracking"""

    def test_track_risk_score_changes(self, db_session):
        """Track risk score changes over time"""
        vuln = Vulnerability(
            cve_id="CVE-2024-INT-009",
            title="Risk History Test",
            business_risk_score=50.0
        )
        db_session.add(vuln)
        db_session.commit()

        # Initial risk entry
        history1 = RiskHistory(
            vulnerability_id=vuln.id,
            business_risk_score=50.0,
            cvss_score=7.0,
            epss_score=0.5,
            snapshot_reason="INITIAL_CALCULATION"
        )
        db_session.add(history1)
        db_session.commit()

        # Risk score changed
        vuln.business_risk_score = 75.0

        history2 = RiskHistory(
            vulnerability_id=vuln.id,
            business_risk_score=75.0,
            cvss_score=8.5,
            epss_score=0.8,
            snapshot_reason="SCORE_UPDATE"
        )
        db_session.add(history2)
        db_session.commit()

        # Verify history
        assert len(vuln.risk_history) == 2
        assert vuln.risk_history[0].business_risk_score == 50.0
        assert vuln.risk_history[1].business_risk_score == 75.0


@pytest.mark.integration
class TestCascadeDeletes:
    """Test cascade delete behavior"""

    def test_delete_vulnerability_cascades(self, db_session):
        """Deleting vulnerability should cascade to related records"""
        vuln = Vulnerability(
            cve_id="CVE-2024-INT-010",
            title="Cascade Test",
            business_risk_score=60.0
        )
        db_session.add(vuln)
        db_session.commit()
        vuln_id = vuln.id

        # Add related records
        history = RiskHistory(
            vulnerability_id=vuln_id,
            business_risk_score=60.0,
            snapshot_reason="TEST"
        )
        db_session.add(history)
        db_session.commit()

        # Delete vulnerability
        db_session.delete(vuln)
        db_session.commit()

        # Verify cascade
        remaining_history = db_session.query(RiskHistory).filter_by(
            vulnerability_id=vuln_id
        ).count()
        assert remaining_history == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-m", "integration"])
