"""
Vulnerability Management Pipeline - SLA Calculator
Calculates remediation deadlines based on risk severity
"""

import os
from datetime import datetime, timedelta
from typing import Dict, Optional
from enum import Enum


class SLAPriority(str, Enum):
    """SLA priority levels based on risk score"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class SLACalculator:
    """
    Service Level Agreement (SLA) calculator for vulnerability remediation.

    Determines remediation deadlines based on business risk score.
    """

    # Default SLA timeframes (days) - configurable via environment
    DEFAULT_SLA_DAYS = {
        SLAPriority.CRITICAL: int(os.getenv("SLA_CRITICAL_DAYS", "7")),    # 7 days
        SLAPriority.HIGH: int(os.getenv("SLA_HIGH_DAYS", "30")),          # 30 days
        SLAPriority.MEDIUM: int(os.getenv("SLA_MEDIUM_DAYS", "90")),      # 90 days
        SLAPriority.LOW: int(os.getenv("SLA_LOW_DAYS", "365")),           # 1 year
    }

    # Risk score thresholds for SLA priority levels
    RISK_THRESHOLDS = {
        SLAPriority.CRITICAL: 80.0,  # ≥80
        SLAPriority.HIGH: 60.0,      # 60-79
        SLAPriority.MEDIUM: 40.0,    # 40-59
        SLAPriority.LOW: 0.0,        # <40
    }

    def __init__(self, custom_sla_days: Optional[Dict[SLAPriority, int]] = None):
        """
        Initialize SLA calculator with custom timeframes.

        Args:
            custom_sla_days: Custom SLA deadlines in days, or None for defaults
        """
        self.sla_days = custom_sla_days or self.DEFAULT_SLA_DAYS

    def get_priority(self, risk_score: float) -> SLAPriority:
        """
        Determine SLA priority level from business risk score.

        Args:
            risk_score: Business risk score (0-100)

        Returns:
            SLAPriority enum value

        Example:
            >>> calculator = SLACalculator()
            >>> calculator.get_priority(85.5)
            <SLAPriority.CRITICAL: 'CRITICAL'>
        """
        if risk_score >= self.RISK_THRESHOLDS[SLAPriority.CRITICAL]:
            return SLAPriority.CRITICAL
        elif risk_score >= self.RISK_THRESHOLDS[SLAPriority.HIGH]:
            return SLAPriority.HIGH
        elif risk_score >= self.RISK_THRESHOLDS[SLAPriority.MEDIUM]:
            return SLAPriority.MEDIUM
        else:
            return SLAPriority.LOW

    def calculate_deadline(
        self,
        risk_score: float,
        discovery_date: Optional[datetime] = None
    ) -> datetime:
        """
        Calculate remediation deadline based on risk score.

        Args:
            risk_score: Business risk score (0-100)
            discovery_date: When vulnerability was discovered (default: now)

        Returns:
            Datetime of remediation deadline

        Example:
            >>> calculator = SLACalculator()
            >>> deadline = calculator.calculate_deadline(85.0)
            >>> # Returns 7 days from now for CRITICAL
        """
        priority = self.get_priority(risk_score)
        days_to_remediate = self.sla_days[priority]

        start_date = discovery_date or datetime.utcnow()
        deadline = start_date + timedelta(days=days_to_remediate)

        return deadline

    def calculate_deadline_with_info(
        self,
        risk_score: float,
        discovery_date: Optional[datetime] = None
    ) -> Dict:
        """
        Calculate deadline with detailed information.

        Args:
            risk_score: Business risk score (0-100)
            discovery_date: When vulnerability was discovered (default: now)

        Returns:
            Dictionary with deadline, priority, days, and explanation
        """
        priority = self.get_priority(risk_score)
        days_to_remediate = self.sla_days[priority]
        start_date = discovery_date or datetime.utcnow()
        deadline = start_date + timedelta(days=days_to_remediate)

        return {
            "deadline": deadline,
            "priority": priority.value,
            "sla_days": days_to_remediate,
            "discovery_date": start_date,
            "explanation": (
                f"{priority.value} priority vulnerability "
                f"(risk score {risk_score}/100) must be remediated "
                f"within {days_to_remediate} days by {deadline.strftime('%Y-%m-%d')}"
            )
        }

    def check_sla_compliance(
        self,
        deadline: datetime,
        resolved_date: Optional[datetime] = None,
        current_status: str = "OPEN"
    ) -> Dict:
        """
        Check if SLA was met for a vulnerability.

        Args:
            deadline: SLA deadline
            resolved_date: When vulnerability was resolved (None if still open)
            current_status: Current remediation status

        Returns:
            Dictionary with compliance status and details
        """
        now = datetime.utcnow()

        # If resolved, check if it was within SLA
        if resolved_date:
            sla_met = resolved_date <= deadline
            days_variance = (resolved_date - deadline).days

            return {
                "sla_met": sla_met,
                "status": "RESOLVED_ON_TIME" if sla_met else "RESOLVED_LATE",
                "days_variance": days_variance,
                "explanation": (
                    f"Resolved {abs(days_variance)} days "
                    f"{'before' if days_variance < 0 else 'after'} deadline"
                    if days_variance != 0
                    else "Resolved exactly on deadline"
                )
            }

        # If not resolved, check if approaching or past deadline
        days_remaining = (deadline - now).days

        if days_remaining < 0:
            status = "OVERDUE"
            explanation = f"Overdue by {abs(days_remaining)} days"
        elif days_remaining <= 7:
            status = "AT_RISK"
            explanation = f"Due in {days_remaining} days (approaching deadline)"
        else:
            status = "ON_TRACK"
            explanation = f"Due in {days_remaining} days"

        return {
            "sla_met": None,  # Unknown until resolved
            "status": status,
            "days_remaining": days_remaining,
            "is_overdue": days_remaining < 0,
            "is_at_risk": 0 <= days_remaining <= 7,
            "explanation": explanation
        }

    def get_sla_summary(self, vulnerabilities: list) -> Dict:
        """
        Generate SLA compliance summary for a list of vulnerabilities.

        Args:
            vulnerabilities: List of vulnerability objects with 'remediation_deadline',
                           'resolved_date', and 'remediation_status' attributes

        Returns:
            Dictionary with compliance statistics
        """
        total = len(vulnerabilities)
        on_track = 0
        at_risk = 0
        overdue = 0
        resolved_on_time = 0
        resolved_late = 0

        for vuln in vulnerabilities:
            if not vuln.remediation_deadline:
                continue

            compliance = self.check_sla_compliance(
                deadline=vuln.remediation_deadline,
                resolved_date=getattr(vuln, 'resolved_date', None),
                current_status=getattr(vuln, 'remediation_status', 'OPEN')
            )

            status = compliance['status']
            if status == "ON_TRACK":
                on_track += 1
            elif status == "AT_RISK":
                at_risk += 1
            elif status == "OVERDUE":
                overdue += 1
            elif status == "RESOLVED_ON_TIME":
                resolved_on_time += 1
            elif status == "RESOLVED_LATE":
                resolved_late += 1

        active_vulns = on_track + at_risk + overdue
        compliance_rate = (
            ((on_track + resolved_on_time) / total * 100)
            if total > 0
            else 0
        )

        return {
            "total_vulnerabilities": total,
            "active": {
                "on_track": on_track,
                "at_risk": at_risk,
                "overdue": overdue,
                "total": active_vulns
            },
            "resolved": {
                "on_time": resolved_on_time,
                "late": resolved_late,
                "total": resolved_on_time + resolved_late
            },
            "compliance_rate": round(compliance_rate, 2),
            "at_risk_rate": round((at_risk / active_vulns * 100) if active_vulns > 0 else 0, 2),
            "overdue_rate": round((overdue / active_vulns * 100) if active_vulns > 0 else 0, 2)
        }


# Example usage
if __name__ == "__main__":
    calculator = SLACalculator()

    # Example 1: Calculate deadline for CRITICAL vulnerability
    print("=" * 60)
    print("Example 1: CRITICAL Vulnerability (Risk Score 85)")
    print("=" * 60)
    result = calculator.calculate_deadline_with_info(risk_score=85.0)
    print(f"Priority: {result['priority']}")
    print(f"SLA Days: {result['sla_days']}")
    print(f"Deadline: {result['deadline'].strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Explanation: {result['explanation']}")

    # Example 2: Check SLA compliance for overdue vulnerability
    print("\n" + "=" * 60)
    print("Example 2: Overdue Vulnerability Check")
    print("=" * 60)
    past_deadline = datetime.utcnow() - timedelta(days=10)
    compliance = calculator.check_sla_compliance(
        deadline=past_deadline,
        current_status="OPEN"
    )
    print(f"Status: {compliance['status']}")
    print(f"Is Overdue: {compliance['is_overdue']}")
    print(f"Days Remaining: {compliance['days_remaining']}")
    print(f"Explanation: {compliance['explanation']}")

    # Example 3: Priority classification
    print("\n" + "=" * 60)
    print("Example 3: Risk Score to Priority Mapping")
    print("=" * 60)
    test_scores = [95, 75, 55, 25]
    for score in test_scores:
        priority = calculator.get_priority(score)
        deadline_info = calculator.calculate_deadline_with_info(score)
        print(f"Risk {score}/100 → {priority.value} ({deadline_info['sla_days']} days)")

    # Example 4: Custom SLA timeframes
    print("\n" + "=" * 60)
    print("Example 4: Custom SLA Timeframes")
    print("=" * 60)
    custom_calculator = SLACalculator(custom_sla_days={
        SLAPriority.CRITICAL: 3,   # 3 days for CRITICAL
        SLAPriority.HIGH: 14,      # 2 weeks for HIGH
        SLAPriority.MEDIUM: 60,    # 2 months for MEDIUM
        SLAPriority.LOW: 180,      # 6 months for LOW
    })

    result = custom_calculator.calculate_deadline_with_info(85.0)
    print(f"CRITICAL with custom SLA: {result['sla_days']} days")
    print(f"Deadline: {result['deadline'].strftime('%Y-%m-%d')}")
