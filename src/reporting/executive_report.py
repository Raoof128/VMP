"""
Executive Report Generator
Generates monthly reports with business impact quantification
"""

import os
from typing import Dict, Optional
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
import numpy as np
import logging

logger = logging.getLogger(__name__)


class ExecutiveReportGenerator:
    """
    Generate executive-level vulnerability management reports.

    Features:
    - Monthly vulnerability statistics
    - Risk reduction metrics
    - Financial impact quantification (AUD)
    - Compliance status
    - Remediation recommendations
    """

    def __init__(self, db_session: Session):
        """
        Initialize report generator.

        Args:
            db_session: Database session
        """
        self.db = db_session

        # AUD cost factors
        self.breach_cost_per_record = float(os.getenv(
            "BREACH_COST_PER_RECORD_AUD",
            "6400"
        ))
        self.avg_records_per_asset = float(os.getenv(
            "AVG_RECORDS_PER_CRITICAL_ASSET",
            "50000"
        ))
        self.remediation_cost_factor = float(os.getenv(
            "REMEDIATION_COST_FACTOR_AUD",
            "50000"
        ))

    def generate_report(
        self,
        month: Optional[str] = None,
        output_format: str = "html"
    ) -> str:
        """
        Generate executive report.

        Args:
            month: Month in YYYY-MM format (default: current month)
            output_format: Output format (html or pdf)

        Returns:
            Path to generated report
        """
        from ..database.models import Vulnerability, Asset, Patch, RemediationStatus

        # Parse month
        if month:
            report_date = datetime.strptime(month, "%Y-%m")
        else:
            report_date = datetime.utcnow()

        month_start = report_date.replace(day=1, hour=0, minute=0, second=0)
        if report_date.month == 12:
            month_end = report_date.replace(year=report_date.year + 1, month=1, day=1)
        else:
            month_end = report_date.replace(month=report_date.month + 1, day=1)
        month_end = month_end - timedelta(seconds=1)

        # Collect metrics
        metrics = self._collect_metrics(month_start, month_end)

        # Generate HTML report
        html_content = self._generate_html_report(metrics, report_date)

        # Save report
        output_dir = "data/exports"
        os.makedirs(output_dir, exist_ok=True)

        filename = f"executive_report_{report_date.strftime('%Y-%m')}.html"
        output_path = os.path.join(output_dir, filename)

        with open(output_path, 'w') as f:
            f.write(html_content)

        logger.info(f"✓ Generated executive report: {output_path}")

        return output_path

    def _collect_metrics(
        self,
        month_start: datetime,
        month_end: datetime
    ) -> Dict:
        """Collect all metrics for report"""
        from ..database.models import Vulnerability, Asset, Patch, RemediationStatus, Scan

        metrics = {}

        # Current vulnerability counts
        total_vulns = self.db.query(Vulnerability).count()
        metrics['total_vulnerabilities'] = total_vulns

        critical_count = self.db.query(Vulnerability).filter(
            Vulnerability.business_risk_score >= 80
        ).count()
        metrics['critical_count'] = critical_count

        high_count = self.db.query(Vulnerability).filter(
            Vulnerability.business_risk_score >= 60,
            Vulnerability.business_risk_score < 80
        ).count()
        metrics['high_count'] = high_count

        medium_count = self.db.query(Vulnerability).filter(
            Vulnerability.business_risk_score >= 40,
            Vulnerability.business_risk_score < 60
        ).count()
        metrics['medium_count'] = medium_count

        low_count = self.db.query(Vulnerability).filter(
            Vulnerability.business_risk_score < 40
        ).count()
        metrics['low_count'] = low_count

        # Average risk score
        all_vulns = self.db.query(Vulnerability).all()
        if all_vulns:
            metrics['avg_risk_score'] = np.mean([
                v.business_risk_score for v in all_vulns
                if v.business_risk_score is not None
            ])
        else:
            metrics['avg_risk_score'] = 0.0

        # Historical comparison (previous month)
        prev_month_start = month_start - timedelta(days=30)
        prev_month_end = month_start - timedelta(seconds=1)

        prev_vulns = self.db.query(Vulnerability).filter(
            Vulnerability.discovered_date <= prev_month_end
        ).all()

        if prev_vulns:
            prev_avg_risk = np.mean([
                v.business_risk_score for v in prev_vulns
                if v.business_risk_score is not None
            ])
            metrics['prev_avg_risk'] = prev_avg_risk
            metrics['risk_reduction_pct'] = (
                (prev_avg_risk - metrics['avg_risk_score']) / prev_avg_risk * 100
                if prev_avg_risk > 0 else 0
            )
        else:
            metrics['prev_avg_risk'] = metrics['avg_risk_score']
            metrics['risk_reduction_pct'] = 0.0

        # SLA compliance
        open_vulns = self.db.query(Vulnerability).filter(
            Vulnerability.remediation_status.in_([
                RemediationStatus.OPEN,
                RemediationStatus.IN_PROGRESS
            ])
        ).all()

        on_track = sum(
            1 for v in open_vulns
            if v.remediation_deadline and v.remediation_deadline > datetime.utcnow()
        )
        metrics['sla_compliance'] = (
            on_track / len(open_vulns) * 100 if open_vulns else 100.0
        )

        # Financial impact
        metrics['potential_breach_cost'] = self._calculate_potential_breach_cost()
        metrics['risk_mitigation_value'] = self._calculate_risk_mitigation(month_start, month_end)
        metrics['patch_savings'] = self._calculate_patch_savings()

        # Top vulnerabilities
        metrics['top_vulns'] = self.db.query(Vulnerability).order_by(
            Vulnerability.business_risk_score.desc()
        ).limit(5).all()

        # Top patches
        metrics['top_patches'] = self.db.query(Patch).order_by(
            Patch.roi_score.desc()
        ).limit(5).all()

        # Asset counts
        metrics['total_assets'] = self.db.query(Asset).count()
        metrics['critical_assets'] = self.db.query(Asset).filter(
            Asset.criticality >= 9
        ).count()

        # Scan statistics
        metrics['scans_this_month'] = self.db.query(Scan).filter(
            Scan.start_time >= month_start,
            Scan.start_time <= month_end
        ).count()

        return metrics

    def _calculate_potential_breach_cost(self) -> float:
        """Calculate potential breach cost based on critical asset exposure"""
        from ..database.models import Asset

        high_risk_assets = self.db.query(Asset).filter(
            Asset.criticality >= 8
        ).all()

        total_records_at_risk = len(high_risk_assets) * self.avg_records_per_asset
        potential_cost = self.breach_cost_per_record * total_records_at_risk

        return potential_cost

    def _calculate_risk_mitigation(
        self,
        month_start: datetime,
        month_end: datetime
    ) -> float:
        """Calculate value of risk mitigated this month"""
        from ..database.models import Vulnerability, RemediationStatus

        resolved_vulns = self.db.query(Vulnerability).filter(
            Vulnerability.remediation_status == RemediationStatus.RESOLVED,
            Vulnerability.resolved_date >= month_start,
            Vulnerability.resolved_date <= month_end
        ).all()

        if not resolved_vulns:
            return 0.0

        avg_resolved_risk = np.mean([
            v.business_risk_score for v in resolved_vulns
            if v.business_risk_score is not None
        ])

        mitigation_value = (
            len(resolved_vulns) *
            (avg_resolved_risk / 100) *
            self.remediation_cost_factor
        )

        return mitigation_value

    def _calculate_patch_savings(self) -> float:
        """Calculate cost savings from patch prioritization"""
        # Simplified calculation: assume prioritization saves 30% of effort
        return self.remediation_cost_factor * 0.3

    def _generate_html_report(self, metrics: Dict, report_date: datetime) -> str:
        """Generate HTML report content"""

        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerability Management Executive Report - {report_date.strftime('%B %Y')}</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            border-radius: 10px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            margin: 0;
            font-size: 2.5em;
        }}
        .header p {{
            margin: 10px 0 0 0;
            opacity: 0.9;
        }}
        .section {{
            background: white;
            padding: 30px;
            margin-bottom: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .section h2 {{
            margin-top: 0;
            color: #667eea;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
        }}
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }}
        .metric-card {{
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #667eea;
        }}
        .metric-card.critical {{
            border-left-color: #dc3545;
        }}
        .metric-card.high {{
            border-left-color: #fd7e14;
        }}
        .metric-card.medium {{
            border-left-color: #ffc107;
        }}
        .metric-card.low {{
            border-left-color: #28a745;
        }}
        .metric-value {{
            font-size: 2.5em;
            font-weight: bold;
            margin: 10px 0;
        }}
        .metric-label {{
            font-size: 0.9em;
            color: #666;
            text-transform: uppercase;
        }}
        .metric-change {{
            font-size: 0.9em;
            font-weight: bold;
        }}
        .metric-change.positive {{
            color: #28a745;
        }}
        .metric-change.negative {{
            color: #dc3545;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background: #667eea;
            color: white;
            font-weight: 600;
        }}
        tr:hover {{
            background: #f8f9fa;
        }}
        .badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: bold;
        }}
        .badge.critical {{
            background: #dc3545;
            color: white;
        }}
        .badge.high {{
            background: #fd7e14;
            color: white;
        }}
        .badge.medium {{
            background: #ffc107;
            color: #333;
        }}
        .badge.low {{
            background: #28a745;
            color: white;
        }}
        .recommendation {{
            background: #e7f3ff;
            border-left: 4px solid #0066cc;
            padding: 15px;
            margin: 10px 0;
            border-radius: 4px;
        }}
        .footer {{
            text-align: center;
            color: #666;
            margin-top: 40px;
            padding: 20px;
            border-top: 1px solid #ddd;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Vulnerability Management Executive Report</h1>
        <p>Reporting Period: {report_date.strftime('%B %Y')}</p>
        <p>Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
    </div>

    <!-- Executive Summary -->
    <div class="section">
        <h2>Executive Summary</h2>
        <p>
            This month's vulnerability management efforts achieved a <strong>{abs(metrics['risk_reduction_pct']):.1f}%
            {'reduction' if metrics['risk_reduction_pct'] > 0 else 'increase'}</strong> in business risk,
            {'preventing' if metrics['risk_mitigation_value'] > 0 else 'managing'} an estimated
            <strong>AUD ${metrics['risk_mitigation_value']:,.0f}</strong> in potential losses.
        </p>
    </div>

    <!-- Key Metrics -->
    <div class="section">
        <h2>Key Metrics</h2>
        <div class="metrics-grid">
            <div class="metric-card">
                <div class="metric-label">Total Vulnerabilities</div>
                <div class="metric-value">{metrics['total_vulnerabilities']}</div>
            </div>
            <div class="metric-card critical">
                <div class="metric-label">Critical (≥80)</div>
                <div class="metric-value">{metrics['critical_count']}</div>
            </div>
            <div class="metric-card high">
                <div class="metric-label">High (60-79)</div>
                <div class="metric-value">{metrics['high_count']}</div>
            </div>
            <div class="metric-card medium">
                <div class="metric-label">Medium (40-59)</div>
                <div class="metric-value">{metrics['medium_count']}</div>
            </div>
            <div class="metric-card low">
                <div class="metric-label">Low (<40)</div>
                <div class="metric-value">{metrics['low_count']}</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Average Risk Score</div>
                <div class="metric-value">{metrics['avg_risk_score']:.1f}</div>
                <div class="metric-change {'positive' if metrics['risk_reduction_pct'] > 0 else 'negative'}">
                    {'+' if metrics['risk_reduction_pct'] < 0 else '-'}{abs(metrics['risk_reduction_pct']):.1f}% vs last month
                </div>
            </div>
            <div class="metric-card">
                <div class="metric-label">SLA Compliance</div>
                <div class="metric-value">{metrics['sla_compliance']:.1f}%</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Scans This Month</div>
                <div class="metric-value">{metrics['scans_this_month']}</div>
            </div>
        </div>
    </div>

    <!-- Financial Impact -->
    <div class="section">
        <h2>Financial Impact Analysis</h2>
        <table>
            <tr>
                <th>Metric</th>
                <th>Value (AUD)</th>
                <th>Description</th>
            </tr>
            <tr>
                <td>Potential Breach Cost</td>
                <td><strong>${metrics['potential_breach_cost']:,.0f}</strong></td>
                <td>Estimated cost if critical assets compromised</td>
            </tr>
            <tr>
                <td>Risk Mitigation Value</td>
                <td><strong>${metrics['risk_mitigation_value']:,.0f}</strong></td>
                <td>Value of vulnerabilities resolved this month</td>
            </tr>
            <tr>
                <td>Patch Prioritization Savings</td>
                <td><strong>${metrics['patch_savings']:,.0f}</strong></td>
                <td>Cost savings from intelligent patch prioritization</td>
            </tr>
            <tr style="background: #e7f3ff; font-weight: bold;">
                <td>Net Benefit</td>
                <td><strong>${metrics['risk_mitigation_value'] + metrics['patch_savings']:,.0f}</strong></td>
                <td>Total business value delivered</td>
            </tr>
        </table>
    </div>

    <!-- Top Vulnerabilities -->
    <div class="section">
        <h2>Top 5 Highest Risk Vulnerabilities</h2>
        <table>
            <tr>
                <th>CVE ID</th>
                <th>Title</th>
                <th>Risk Score</th>
                <th>CVSS</th>
                <th>Assets</th>
                <th>Status</th>
            </tr>
            {"".join([f'''
            <tr>
                <td>{v.cve_id}</td>
                <td>{v.title[:60]}...</td>
                <td><span class="badge {'critical' if v.business_risk_score >= 80 else 'high' if v.business_risk_score >= 60 else 'medium'}">{v.business_risk_score:.1f}</span></td>
                <td>{v.cvss_base_score:.1f}</td>
                <td>{len(v.affected_assets)}</td>
                <td>{v.remediation_status.value if v.remediation_status else 'N/A'}</td>
            </tr>
            ''' for v in metrics['top_vulns']])}
        </table>
    </div>

    <!-- Top Patches -->
    <div class="section">
        <h2>Top 5 High-Impact Patches</h2>
        <table>
            <tr>
                <th>Patch ID</th>
                <th>Name</th>
                <th>Vulns Fixed</th>
                <th>Effort (hrs)</th>
                <th>ROI</th>
            </tr>
            {"".join([f'''
            <tr>
                <td>{p.patch_id}</td>
                <td>{p.name[:50]}</td>
                <td>{p.vulnerabilities_fixed_count} ({p.high_risk_vulns_fixed} high-risk)</td>
                <td>{p.estimated_deployment_hours:.1f}</td>
                <td>{p.roi_score:.2f}</td>
            </tr>
            ''' for p in metrics['top_patches'] if metrics['top_patches']])}
        </table>
    </div>

    <!-- Recommendations -->
    <div class="section">
        <h2>Recommendations</h2>
        <div class="recommendation">
            <strong>1. Critical Vulnerability Remediation</strong>
            <p>Prioritize deployment of {metrics['critical_count']} CRITICAL vulnerabilities within 7-day SLA window.</p>
        </div>
        <div class="recommendation">
            <strong>2. High-Impact Patching</strong>
            <p>Deploy top 5 patches to address {sum(p.high_risk_vulns_fixed for p in metrics['top_patches'] if metrics['top_patches'])} high-risk vulnerabilities with minimal effort.</p>
        </div>
        <div class="recommendation">
            <strong>3. Asset Hardening</strong>
            <p>Focus remediation efforts on {metrics['critical_assets']} critical assets (criticality ≥9) to maximize risk reduction.</p>
        </div>
    </div>

    <div class="footer">
        <p>Report generated by VMP (Vulnerability Management Pipeline)</p>
        <p>For questions, contact: security@company.com</p>
    </div>
</body>
</html>
"""

        return html


# Example usage
if __name__ == "__main__":
    from ..database.engine import get_db_context

    logging.basicConfig(level=logging.INFO)

    with get_db_context() as db:
        generator = ExecutiveReportGenerator(db)
        report_path = generator.generate_report()
        print(f"✓ Report generated: {report_path}")
