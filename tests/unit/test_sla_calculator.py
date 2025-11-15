"""
Unit Tests for SLA Calculator
Tests SLA deadline calculation and compliance monitoring
"""

import pytest
from datetime import datetime, timedelta
from src.prioritisation.sla import SLACalculator, SLAPriority


class TestSLACalculator:
    """Test SLA calculator functionality"""

    def test_critical_priority_classification(self):
        """Risk score ≥80 should be CRITICAL priority"""
        calc = SLACalculator()
        priority = calc.get_priority(85.0)
        assert priority == SLAPriority.CRITICAL

    def test_high_priority_classification(self):
        """Risk score 60-79 should be HIGH priority"""
        calc = SLACalculator()
        priority = calc.get_priority(70.0)
        assert priority == SLAPriority.HIGH

    def test_medium_priority_classification(self):
        """Risk score 40-59 should be MEDIUM priority"""
        calc = SLACalculator()
        priority = calc.get_priority(50.0)
        assert priority == SLAPriority.MEDIUM

    def test_low_priority_classification(self):
        """Risk score <40 should be LOW priority"""
        calc = SLACalculator()
        priority = calc.get_priority(25.0)
        assert priority == SLAPriority.LOW

    def test_boundary_critical_high(self):
        """Risk score exactly 80 should be CRITICAL"""
        calc = SLACalculator()
        assert calc.get_priority(80.0) == SLAPriority.CRITICAL
        assert calc.get_priority(79.9) == SLAPriority.HIGH

    def test_boundary_high_medium(self):
        """Risk score exactly 60 should be HIGH"""
        calc = SLACalculator()
        assert calc.get_priority(60.0) == SLAPriority.HIGH
        assert calc.get_priority(59.9) == SLAPriority.MEDIUM

    def test_boundary_medium_low(self):
        """Risk score exactly 40 should be MEDIUM"""
        calc = SLACalculator()
        assert calc.get_priority(40.0) == SLAPriority.MEDIUM
        assert calc.get_priority(39.9) == SLAPriority.LOW

    def test_critical_deadline_7_days(self):
        """CRITICAL vulnerabilities should have 7-day deadline"""
        calc = SLACalculator()
        now = datetime.utcnow()
        deadline = calc.calculate_deadline(85.0, discovery_date=now)

        expected_deadline = now + timedelta(days=7)
        delta = abs((deadline - expected_deadline).total_seconds())

        assert delta < 1, "Deadline should be exactly 7 days from discovery"

    def test_high_deadline_30_days(self):
        """HIGH vulnerabilities should have 30-day deadline"""
        calc = SLACalculator()
        now = datetime.utcnow()
        deadline = calc.calculate_deadline(70.0, discovery_date=now)

        expected_deadline = now + timedelta(days=30)
        delta = abs((deadline - expected_deadline).total_seconds())

        assert delta < 1, "Deadline should be exactly 30 days from discovery"

    def test_medium_deadline_90_days(self):
        """MEDIUM vulnerabilities should have 90-day deadline"""
        calc = SLACalculator()
        now = datetime.utcnow()
        deadline = calc.calculate_deadline(50.0, discovery_date=now)

        expected_deadline = now + timedelta(days=90)
        delta = abs((deadline - expected_deadline).total_seconds())

        assert delta < 1, "Deadline should be exactly 90 days from discovery"

    def test_low_deadline_365_days(self):
        """LOW vulnerabilities should have 365-day deadline"""
        calc = SLACalculator()
        now = datetime.utcnow()
        deadline = calc.calculate_deadline(25.0, discovery_date=now)

        expected_deadline = now + timedelta(days=365)
        delta = abs((deadline - expected_deadline).total_seconds())

        assert delta < 1, "Deadline should be exactly 365 days from discovery"

    def test_deadline_with_info(self):
        """Detailed deadline info should include all fields"""
        calc = SLACalculator()
        result = calc.calculate_deadline_with_info(85.0)

        assert 'deadline' in result
        assert 'priority' in result
        assert 'sla_days' in result
        assert 'discovery_date' in result
        assert 'explanation' in result

        assert result['priority'] == 'CRITICAL'
        assert result['sla_days'] == 7

    def test_custom_sla_days(self):
        """Custom SLA days should override defaults"""
        custom_sla = {
            SLAPriority.CRITICAL: 3,
            SLAPriority.HIGH: 14,
            SLAPriority.MEDIUM: 60,
            SLAPriority.LOW: 180
        }
        calc = SLACalculator(custom_sla_days=custom_sla)

        result = calc.calculate_deadline_with_info(85.0)
        assert result['sla_days'] == 3

    def test_check_sla_compliance_overdue(self):
        """Overdue vulnerability should be detected"""
        calc = SLACalculator()
        past_deadline = datetime.utcnow() - timedelta(days=5)

        compliance = calc.check_sla_compliance(
            deadline=past_deadline,
            current_status="OPEN"
        )

        assert compliance['status'] == "OVERDUE"
        assert compliance['is_overdue'] is True
        assert compliance['days_remaining'] < 0

    def test_check_sla_compliance_at_risk(self):
        """Vulnerability with <7 days remaining should be at risk"""
        calc = SLACalculator()
        near_deadline = datetime.utcnow() + timedelta(days=5)

        compliance = calc.check_sla_compliance(
            deadline=near_deadline,
            current_status="OPEN"
        )

        assert compliance['status'] == "AT_RISK"
        assert compliance['is_at_risk'] is True
        assert 0 <= compliance['days_remaining'] <= 7

    def test_check_sla_compliance_on_track(self):
        """Vulnerability with >7 days remaining should be on track"""
        calc = SLACalculator()
        future_deadline = datetime.utcnow() + timedelta(days=20)

        compliance = calc.check_sla_compliance(
            deadline=future_deadline,
            current_status="OPEN"
        )

        assert compliance['status'] == "ON_TRACK"
        assert compliance['days_remaining'] > 7

    def test_check_sla_resolved_on_time(self):
        """Resolved vulnerability within SLA should show as on-time"""
        calc = SLACalculator()
        deadline = datetime.utcnow() + timedelta(days=5)
        resolved_date = datetime.utcnow()

        compliance = calc.check_sla_compliance(
            deadline=deadline,
            resolved_date=resolved_date,
            current_status="RESOLVED"
        )

        assert compliance['sla_met'] is True
        assert compliance['status'] == "RESOLVED_ON_TIME"

    def test_check_sla_resolved_late(self):
        """Resolved vulnerability after SLA should show as late"""
        calc = SLACalculator()
        deadline = datetime.utcnow() - timedelta(days=5)
        resolved_date = datetime.utcnow()

        compliance = calc.check_sla_compliance(
            deadline=deadline,
            resolved_date=resolved_date,
            current_status="RESOLVED"
        )

        assert compliance['sla_met'] is False
        assert compliance['status'] == "RESOLVED_LATE"
        assert compliance['days_variance'] > 0


class TestSLASummary:
    """Test SLA summary statistics"""

    def test_get_sla_summary_empty_list(self):
        """Empty vulnerability list should return zero stats"""
        calc = SLACalculator()
        summary = calc.get_sla_summary([])

        assert summary['total_vulnerabilities'] == 0
        assert summary['compliance_rate'] == 0

    def test_get_sla_summary_all_on_track(self):
        """All on-track vulnerabilities should show 100% compliance"""
        from unittest.mock import Mock

        calc = SLACalculator()
        future_deadline = datetime.utcnow() + timedelta(days=20)

        mock_vulns = []
        for i in range(5):
            vuln = Mock()
            vuln.remediation_deadline = future_deadline
            vuln.resolved_date = None
            vuln.remediation_status = "OPEN"
            mock_vulns.append(vuln)

        summary = calc.get_sla_summary(mock_vulns)

        assert summary['active']['on_track'] == 5
        assert summary['active']['at_risk'] == 0
        assert summary['active']['overdue'] == 0

    def test_get_sla_summary_mixed_status(self):
        """Mixed vulnerability statuses should be categorized correctly"""
        from unittest.mock import Mock

        calc = SLACalculator()

        mock_vulns = []

        # 2 on track
        for i in range(2):
            vuln = Mock()
            vuln.remediation_deadline = datetime.utcnow() + timedelta(days=20)
            vuln.resolved_date = None
            vuln.remediation_status = "OPEN"
            mock_vulns.append(vuln)

        # 1 at risk
        vuln = Mock()
        vuln.remediation_deadline = datetime.utcnow() + timedelta(days=5)
        vuln.resolved_date = None
        vuln.remediation_status = "OPEN"
        mock_vulns.append(vuln)

        # 1 overdue
        vuln = Mock()
        vuln.remediation_deadline = datetime.utcnow() - timedelta(days=5)
        vuln.resolved_date = None
        vuln.remediation_status = "OPEN"
        mock_vulns.append(vuln)

        summary = calc.get_sla_summary(mock_vulns)

        assert summary['active']['on_track'] == 2
        assert summary['active']['at_risk'] == 1
        assert summary['active']['overdue'] == 1
        assert summary['total_vulnerabilities'] == 4


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
