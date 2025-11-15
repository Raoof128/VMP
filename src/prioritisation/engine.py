"""
Vulnerability Management Pipeline - Prioritisation Engine
Main engine orchestrating risk scoring, prioritisation, and remediation optimization
"""

from typing import List, Dict, Optional
from datetime import datetime
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_
import logging
import numpy as np

from ..database.models import (
    Vulnerability, Asset, Patch, RemediationStatus,
    RiskHistory, asset_vulnerability
)
from .scoring import RiskScorer, RiskWeights
from .sla import SLACalculator, SLAPriority

logger = logging.getLogger(__name__)


class PrioritisationEngine:
    """
    Intelligent vulnerability prioritisation engine.

    Orchestrates:
    - Risk scoring (CVSS + EPSS + business context)
    - SLA deadline calculation
    - Risk history tracking
    - Prioritised vulnerability ranking
    """

    def __init__(
        self,
        db_session: Session,
        risk_weights: Optional[RiskWeights] = None,
        sla_calculator: Optional[SLACalculator] = None
    ):
        """
        Initialize prioritisation engine.

        Args:
            db_session: SQLAlchemy database session
            risk_weights: Custom risk scoring weights
            sla_calculator: Custom SLA calculator
        """
        self.db = db_session
        self.scorer = RiskScorer(weights=risk_weights)
        self.sla_calc = sla_calculator or SLACalculator()

    def score_vulnerability(self, vulnerability: Vulnerability) -> float:
        """
        Calculate and update business risk score for a single vulnerability.

        Args:
            vulnerability: Vulnerability ORM object

        Returns:
            Calculated business risk score (0-100)
        """
        # Get average asset criticality
        asset_criticality_avg = self._calculate_asset_criticality_avg(vulnerability)

        # Get remediation difficulty (default to 3 if not set)
        remediation_difficulty = vulnerability.remediation_difficulty or 3

        # Calculate risk score
        result = self.scorer.calculate_business_risk(
            cvss_base_score=vulnerability.cvss_base_score or 0.0,
            epss_score=vulnerability.epss_score or 0.0,
            asset_criticality=asset_criticality_avg,
            remediation_difficulty=remediation_difficulty
        )

        # Update vulnerability record
        old_score = vulnerability.business_risk_score
        new_score = result['total_score']

        vulnerability.business_risk_score = new_score
        vulnerability.risk_score_explanation = result['explanation']
        vulnerability.asset_criticality_avg = asset_criticality_avg

        # Calculate SLA deadline
        if not vulnerability.remediation_deadline:
            vulnerability.remediation_deadline = self.sla_calc.calculate_deadline(
                risk_score=new_score,
                discovery_date=vulnerability.discovered_date
            )

        # Track risk history if score changed significantly
        if old_score is None or abs(old_score - new_score) >= 5.0:
            self._record_risk_history(
                vulnerability=vulnerability,
                reason="SCORE_UPDATE" if old_score else "INITIAL_CALCULATION"
            )

        self.db.commit()
        logger.info(
            f"Scored {vulnerability.cve_id}: "
            f"{old_score or 0:.1f} → {new_score:.1f} ({result['explanation'][:50]}...)"
        )

        return new_score

    def score_all_vulnerabilities(
        self,
        status_filter: Optional[List[RemediationStatus]] = None
    ) -> Dict[str, int]:
        """
        Score all vulnerabilities in the database.

        Args:
            status_filter: Only score vulnerabilities with these statuses
                         (default: OPEN and IN_PROGRESS)

        Returns:
            Dictionary with scoring statistics
        """
        if status_filter is None:
            status_filter = [RemediationStatus.OPEN, RemediationStatus.IN_PROGRESS]

        # Query vulnerabilities
        query = self.db.query(Vulnerability).filter(
            Vulnerability.remediation_status.in_(status_filter)
        )
        vulnerabilities = query.all()

        stats = {
            'total': len(vulnerabilities),
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'errors': 0
        }

        for vuln in vulnerabilities:
            try:
                score = self.score_vulnerability(vuln)

                # Count by severity
                if score >= 80:
                    stats['critical'] += 1
                elif score >= 60:
                    stats['high'] += 1
                elif score >= 40:
                    stats['medium'] += 1
                else:
                    stats['low'] += 1

            except Exception as e:
                logger.error(f"Failed to score {vuln.cve_id}: {e}")
                stats['errors'] += 1

        logger.info(
            f"Scored {stats['total']} vulnerabilities: "
            f"{stats['critical']} CRITICAL, {stats['high']} HIGH, "
            f"{stats['medium']} MEDIUM, {stats['low']} LOW"
        )

        return stats

    def get_prioritised_vulnerabilities(
        self,
        limit: Optional[int] = None,
        min_risk_score: float = 0.0,
        status_filter: Optional[List[RemediationStatus]] = None
    ) -> List[Vulnerability]:
        """
        Get vulnerabilities ranked by business risk score.

        Args:
            limit: Maximum number of vulnerabilities to return
            min_risk_score: Minimum risk score threshold
            status_filter: Filter by remediation status

        Returns:
            List of vulnerabilities sorted by risk score (descending)
        """
        if status_filter is None:
            status_filter = [RemediationStatus.OPEN, RemediationStatus.IN_PROGRESS]

        query = self.db.query(Vulnerability).filter(
            and_(
                Vulnerability.remediation_status.in_(status_filter),
                Vulnerability.business_risk_score >= min_risk_score
            )
        ).order_by(Vulnerability.business_risk_score.desc())

        if limit:
            query = query.limit(limit)

        return query.all()

    def get_overdue_vulnerabilities(self) -> List[Vulnerability]:
        """
        Get all overdue vulnerabilities (past SLA deadline).

        Returns:
            List of overdue vulnerabilities sorted by days overdue
        """
        now = datetime.utcnow()

        vulnerabilities = self.db.query(Vulnerability).filter(
            and_(
                Vulnerability.remediation_status.in_([
                    RemediationStatus.OPEN,
                    RemediationStatus.IN_PROGRESS
                ]),
                Vulnerability.remediation_deadline < now
            )
        ).all()

        # Sort by days overdue (most overdue first)
        vulnerabilities.sort(
            key=lambda v: (now - v.remediation_deadline).days,
            reverse=True
        )

        return vulnerabilities

    def _calculate_asset_criticality_avg(self, vulnerability: Vulnerability) -> float:
        """
        Calculate average criticality of assets affected by this vulnerability.

        Args:
            vulnerability: Vulnerability object

        Returns:
            Average asset criticality (1-10 scale)
        """
        if not vulnerability.affected_assets:
            return 5.0  # Default medium criticality

        criticalities = [asset.criticality for asset in vulnerability.affected_assets]
        return float(np.mean(criticalities))

    def _record_risk_history(
        self,
        vulnerability: Vulnerability,
        reason: str = "MANUAL"
    ):
        """
        Record vulnerability risk score in history for trend analysis.

        Args:
            vulnerability: Vulnerability object
            reason: Reason for recording (e.g., "SCAN_UPDATE", "MANUAL_ADJUSTMENT")
        """
        history_entry = RiskHistory(
            vulnerability_id=vulnerability.id,
            business_risk_score=vulnerability.business_risk_score,
            cvss_score=vulnerability.cvss_base_score,
            epss_score=vulnerability.epss_score,
            asset_criticality_avg=vulnerability.asset_criticality_avg,
            remediation_status=vulnerability.remediation_status.value,
            snapshot_reason=reason,
            recorded_at=datetime.utcnow()
        )

        self.db.add(history_entry)
        self.db.commit()


class RemediationOptimiser:
    """
    Remediation optimization engine for ROI-based patch prioritization.

    Identifies high-impact patches that fix multiple critical vulnerabilities.
    """

    def __init__(self, db_session: Session):
        """
        Initialize remediation optimizer.

        Args:
            db_session: SQLAlchemy database session
        """
        self.db = db_session

    def identify_high_impact_patches(
        self,
        top_n: int = 10,
        min_risk_score: float = 60.0
    ) -> List[Dict]:
        """
        Identify patches with highest ROI (vulnerabilities fixed / effort).

        Args:
            top_n: Number of top patches to return
            min_risk_score: Only count vulnerabilities above this risk score

        Returns:
            List of dictionaries with patch impact analysis

        Example:
            >>> optimizer = RemediationOptimiser(db)
            >>> top_patches = optimizer.identify_high_impact_patches(top_n=5)
            >>> print(top_patches[0]['patch_id'])
            'KB5034441'
        """
        patches = self.db.query(Patch).all()

        impact_scores = []

        for patch in patches:
            # Count high-risk vulnerabilities this patch fixes
            high_risk_vulns = [
                v for v in patch.vulnerabilities
                if v.business_risk_score and v.business_risk_score >= min_risk_score
                and v.remediation_status in [RemediationStatus.OPEN, RemediationStatus.IN_PROGRESS]
            ]

            high_risk_count = len(high_risk_vulns)

            if high_risk_count == 0:
                continue  # Skip patches with no high-risk fixes

            # Estimate deployment effort
            effort_hours = patch.estimated_deployment_hours or self._estimate_patch_effort(patch)

            # Calculate ROI: vulnerabilities fixed per hour
            roi = high_risk_count / max(effort_hours, 1)

            # Calculate total risk reduction
            total_risk_reduction = sum(v.business_risk_score for v in high_risk_vulns)

            impact_scores.append({
                'patch_id': patch.patch_id,
                'patch_name': patch.name,
                'vendor': patch.vendor,
                'product': patch.product,
                'high_risk_vulns_fixed': high_risk_count,
                'total_vulns_fixed': len(patch.vulnerabilities),
                'effort_hours': effort_hours,
                'roi': round(roi, 2),
                'total_risk_reduction': round(total_risk_reduction, 2),
                'requires_reboot': patch.requires_reboot,
                'cve_ids': [v.cve_id for v in high_risk_vulns],
                'patch_url': patch.patch_url
            })

        # Sort by ROI (descending)
        impact_scores.sort(key=lambda x: x['roi'], reverse=True)

        return impact_scores[:top_n]

    def get_quick_wins(
        self,
        max_effort_hours: float = 4.0,
        min_vulns_fixed: int = 5
    ) -> List[Dict]:
        """
        Identify "quick win" patches: low effort, high impact.

        Args:
            max_effort_hours: Maximum acceptable deployment effort
            min_vulns_fixed: Minimum vulnerabilities that must be fixed

        Returns:
            List of quick win patches
        """
        all_patches = self.identify_high_impact_patches(top_n=100)

        quick_wins = [
            patch for patch in all_patches
            if patch['effort_hours'] <= max_effort_hours
            and patch['high_risk_vulns_fixed'] >= min_vulns_fixed
        ]

        return quick_wins

    def calculate_remediation_coverage(self, patch_ids: List[str]) -> Dict:
        """
        Calculate coverage if given patches are deployed.

        Args:
            patch_ids: List of patch IDs to simulate deployment

        Returns:
            Dictionary with coverage statistics
        """
        # Get patches
        patches = self.db.query(Patch).filter(Patch.patch_id.in_(patch_ids)).all()

        # Collect all vulnerabilities fixed
        fixed_vulns = set()
        total_effort_hours = 0

        for patch in patches:
            for vuln in patch.vulnerabilities:
                if vuln.remediation_status in [RemediationStatus.OPEN, RemediationStatus.IN_PROGRESS]:
                    fixed_vulns.add(vuln.id)
            total_effort_hours += patch.estimated_deployment_hours or self._estimate_patch_effort(patch)

        # Get all open vulnerabilities
        all_open_vulns = self.db.query(Vulnerability).filter(
            Vulnerability.remediation_status.in_([
                RemediationStatus.OPEN,
                RemediationStatus.IN_PROGRESS
            ])
        ).count()

        coverage_pct = (len(fixed_vulns) / all_open_vulns * 100) if all_open_vulns > 0 else 0

        return {
            'patches_count': len(patches),
            'vulnerabilities_fixed': len(fixed_vulns),
            'total_open_vulnerabilities': all_open_vulns,
            'coverage_percentage': round(coverage_pct, 2),
            'total_effort_hours': round(total_effort_hours, 2),
            'avg_effort_per_patch': round(total_effort_hours / len(patches), 2) if patches else 0
        }

    def _estimate_patch_effort(self, patch: Patch) -> float:
        """
        Estimate patch deployment effort based on complexity factors.

        Args:
            patch: Patch object

        Returns:
            Estimated effort in hours
        """
        # Base effort
        effort = 2.0  # 2 hours base

        # Add time for complexity
        if patch.deployment_difficulty:
            effort += patch.deployment_difficulty * 1.5

        # Add reboot time
        if patch.requires_reboot:
            effort += 1.0

        # Add testing time
        effort += 1.0

        return effort


# Example usage
if __name__ == "__main__":
    from ..database.engine import get_db_context

    with get_db_context() as db:
        # Initialize engine
        engine = PrioritisationEngine(db)

        # Score all vulnerabilities
        print("Scoring all vulnerabilities...")
        stats = engine.score_all_vulnerabilities()
        print(f"Stats: {stats}")

        # Get top 10 highest risk vulnerabilities
        print("\nTop 10 Highest Risk Vulnerabilities:")
        top_vulns = engine.get_prioritised_vulnerabilities(limit=10)
        for i, vuln in enumerate(top_vulns, 1):
            print(f"{i}. {vuln.cve_id}: {vuln.business_risk_score:.1f}/100")

        # Check for overdue vulnerabilities
        print("\nOverdue Vulnerabilities:")
        overdue = engine.get_overdue_vulnerabilities()
        print(f"Found {len(overdue)} overdue vulnerabilities")

        # Identify high-impact patches
        optimizer = RemediationOptimiser(db)
        print("\nTop 5 High-Impact Patches:")
        top_patches = optimizer.identify_high_impact_patches(top_n=5)
        for i, patch in enumerate(top_patches, 1):
            print(
                f"{i}. {patch['patch_id']}: "
                f"{patch['high_risk_vulns_fixed']} vulns, "
                f"{patch['effort_hours']}h effort, "
                f"ROI={patch['roi']}"
            )
