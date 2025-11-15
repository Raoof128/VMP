"""
Celery Application - Background Task Scheduler
Handles automated scans, reports, and vulnerability enrichment
"""

import os
from celery import Celery
from celery.schedules import crontab
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

# Initialize Celery
celery_app = Celery(
    'vmp',
    broker=os.getenv('CELERY_BROKER_URL', 'redis://localhost:6379/0'),
    backend=os.getenv('CELERY_RESULT_BACKEND', 'redis://localhost:6379/0')
)

# Configure Celery
celery_app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
    task_track_started=True,
    task_time_limit=14400,  # 4 hours max
    worker_prefetch_multiplier=1,
    worker_max_tasks_per_child=1000
)


# =============================================================================
# Scanning Tasks
# =============================================================================

@celery_app.task(name='vmp.scan.full_network_scan')
def run_full_network_scan(target_range: str = "10.0.0.0/16"):
    """
    Run full network vulnerability scan.

    Args:
        target_range: IP range to scan
    """
    logger.info(f"Starting full network scan: {target_range}")

    from ..scanner.openvas_client import OpenVASClient
    from ..database.engine import get_db_context
    from ..database.models import Scan, ScanType

    try:
        # Create scan record
        with get_db_context() as db:
            scan = Scan(
                scan_id=f"full-scan-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}",
                name=f"Full Network Scan - {datetime.utcnow().strftime('%Y-%m-%d')}",
                scan_type=ScanType.FULL,
                target_range=target_range,
                status="RUNNING",
                scheduled_time=datetime.utcnow(),
                start_time=datetime.utcnow(),
                scanner_name="OPENVAS"
            )
            db.add(scan)
            db.commit()
            scan_id = scan.id

        # Run OpenVAS scan
        client = OpenVASClient()
        results = client.full_scan_workflow(target_hosts=target_range)

        # Update scan record
        with get_db_context() as db:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.end_time = datetime.utcnow()
                scan.status = "COMPLETED"
                scan.vulnerabilities_found = len(results)
                db.commit()

        logger.info(f"✓ Full scan completed: {len(results)} vulnerabilities found")

        # Trigger vulnerability processing
        process_scan_results.delay(scan_id, results)

        return {
            'scan_id': scan_id,
            'vulnerabilities_found': len(results),
            'status': 'completed'
        }

    except Exception as e:
        logger.error(f"Full scan failed: {e}")
        raise


@celery_app.task(name='vmp.scan.incremental_scan')
def run_incremental_scan():
    """Run incremental vulnerability scan (only changed assets)"""
    logger.info("Starting incremental scan")

    from ..database.engine import get_db_context
    from ..database.models import Asset
    from datetime import timedelta

    # Get assets not scanned in last 24 hours
    with get_db_context() as db:
        cutoff = datetime.utcnow() - timedelta(hours=24)
        assets = db.query(Asset).filter(
            (Asset.last_scan_date < cutoff) | (Asset.last_scan_date == None)
        ).limit(100).all()

        targets = [asset.ip_address for asset in assets if asset.ip_address]

    if not targets:
        logger.info("No assets need scanning")
        return {'status': 'no_targets'}

    logger.info(f"Incremental scan: {len(targets)} targets")

    # Run scan for these targets
    target_range = ','.join(targets[:50])  # Limit to 50 for quick scan
    return run_full_network_scan.delay(target_range)


# =============================================================================
# Vulnerability Processing Tasks
# =============================================================================

@celery_app.task(name='vmp.vuln.process_scan_results')
def process_scan_results(scan_id: int, results: list):
    """
    Process scan results: create/update vulnerabilities.

    Args:
        scan_id: Scan database ID
        results: List of vulnerability results
    """
    logger.info(f"Processing results from scan {scan_id}")

    from ..database.engine import get_db_context
    from ..database.models import Vulnerability, Asset, ScanResult

    with get_db_context() as db:
        for result in results:
            # Find or create vulnerability
            vuln = db.query(Vulnerability).filter(
                Vulnerability.cve_id == result.get('cve_id')
            ).first()

            if not vuln:
                vuln = Vulnerability(cve_id=result.get('cve_id'))
                db.add(vuln)

            # Update vulnerability data
            vuln.title = result.get('name')
            vuln.cvss_base_score = result.get('severity')
            vuln.last_scanned = datetime.utcnow()
            vuln.scan_count = (vuln.scan_count or 0) + 1

            # Create scan result record
            scan_result = ScanResult(
                scan_id=scan_id,
                vulnerability_id=vuln.id,
                port=result.get('port'),
                evidence=result.get('description')
            )
            db.add(scan_result)

        db.commit()

    logger.info(f"✓ Processed {len(results)} vulnerability results")

    # Trigger enrichment
    enrich_vulnerabilities.delay()


@celery_app.task(name='vmp.vuln.enrich_vulnerabilities')
def enrich_vulnerabilities():
    """Enrich vulnerabilities with threat intelligence (NVD, EPSS, CISA KEV)"""
    logger.info("Enriching vulnerabilities with threat intelligence")

    from ..scanner.threat_intel import ThreatIntelligenceEnricher
    from ..database.engine import get_db_context
    from ..database.models import Vulnerability

    enricher = ThreatIntelligenceEnricher()

    with get_db_context() as db:
        # Get vulnerabilities needing enrichment (no EPSS score)
        vulns = db.query(Vulnerability).filter(
            Vulnerability.epss_score == None
        ).limit(100).all()  # Batch of 100

        cve_ids = [v.cve_id for v in vulns]

    if not cve_ids:
        logger.info("No vulnerabilities need enrichment")
        return {'status': 'no_vulns'}

    # Batch enrich
    enriched = enricher.enrich_batch(cve_ids)

    # Update database
    with get_db_context() as db:
        for cve_id, data in enriched.items():
            vuln = db.query(Vulnerability).filter(
                Vulnerability.cve_id == cve_id
            ).first()

            if vuln:
                vuln.epss_score = data.get('epss_score')
                vuln.epss_percentile = data.get('epss_percentile')
                vuln.in_cisa_kev = data.get('in_cisa_kev', False)
                vuln.cwe_ids = data.get('cwe_ids', [])

        db.commit()

    logger.info(f"✓ Enriched {len(enriched)} vulnerabilities")

    # Trigger risk scoring
    calculate_risk_scores.delay()


@celery_app.task(name='vmp.vuln.calculate_risk_scores')
def calculate_risk_scores():
    """Calculate business risk scores for all open vulnerabilities"""
    logger.info("Calculating business risk scores")

    from ..prioritisation.engine import PrioritisationEngine
    from ..database.engine import get_db_context

    with get_db_context() as db:
        engine = PrioritisationEngine(db)
        stats = engine.score_all_vulnerabilities()

    logger.info(f"✓ Scored vulnerabilities: {stats}")

    # Trigger Jira ticket creation
    create_jira_tickets_for_critical.delay()

    return stats


# =============================================================================
# Jira Integration Tasks
# =============================================================================

@celery_app.task(name='vmp.jira.create_tickets_for_critical')
def create_jira_tickets_for_critical():
    """Create Jira tickets for CRITICAL vulnerabilities without tickets"""
    logger.info("Creating Jira tickets for CRITICAL vulnerabilities")

    from ..workflow.jira_integration import JiraWorkflowManager
    from ..database.engine import get_db_context
    from ..database.models import Vulnerability, RemediationStatus

    jira = JiraWorkflowManager()

    if not jira.enabled:
        logger.info("Jira integration disabled")
        return {'status': 'disabled'}

    with get_db_context() as db:
        # Get CRITICAL vulns without tickets
        vulns = db.query(Vulnerability).filter(
            Vulnerability.business_risk_score >= 80,
            Vulnerability.remediation_status == RemediationStatus.OPEN,
            Vulnerability.jira_ticket_id == None
        ).all()

        tickets_created = 0

        for vuln in vulns:
            ticket_id = jira.create_remediation_ticket(vuln)
            if ticket_id:
                vuln.jira_ticket_id = ticket_id
                vuln.jira_ticket_url = f"{jira.jira_url}/browse/{ticket_id}"
                tickets_created += 1

        db.commit()

    logger.info(f"✓ Created {tickets_created} Jira tickets")

    return {'tickets_created': tickets_created}


@celery_app.task(name='vmp.jira.monitor_sla_compliance')
def monitor_sla_compliance():
    """Monitor SLA compliance and escalate overdue tickets"""
    logger.info("Monitoring SLA compliance")

    from ..workflow.jira_integration import JiraWorkflowManager
    from ..database.engine import get_db_context
    from ..database.models import Vulnerability, RemediationStatus

    jira = JiraWorkflowManager()

    if not jira.enabled:
        return {'status': 'disabled'}

    with get_db_context() as db:
        vulns = db.query(Vulnerability).filter(
            Vulnerability.remediation_status.in_([
                RemediationStatus.OPEN,
                RemediationStatus.IN_PROGRESS
            ]),
            Vulnerability.jira_ticket_id != None
        ).all()

        sla_report = jira.monitor_sla_compliance(vulns)

        # Escalate overdue tickets
        escalated = jira.escalate_overdue_tickets(sla_report['overdue'])

    logger.info(
        f"SLA compliance: {len(sla_report['on_track'])} on track, "
        f"{len(sla_report['at_risk'])} at risk, "
        f"{len(sla_report['overdue'])} overdue (escalated: {escalated})"
    )

    return sla_report


# =============================================================================
# Reporting Tasks
# =============================================================================

@celery_app.task(name='vmp.report.generate_executive_report')
def generate_executive_report(month: str = None):
    """
    Generate monthly executive report.

    Args:
        month: Month in YYYY-MM format (default: current month)
    """
    logger.info(f"Generating executive report for {month or 'current month'}")

    from ..reporting.executive_report import ExecutiveReportGenerator
    from ..database.engine import get_db_context

    with get_db_context() as db:
        generator = ExecutiveReportGenerator(db)
        report_path = generator.generate_report(month=month)

    logger.info(f"✓ Generated executive report: {report_path}")

    return {'report_path': report_path}


# =============================================================================
# Maintenance Tasks
# =============================================================================

@celery_app.task(name='vmp.maintenance.cleanup_old_data')
def cleanup_old_data():
    """Clean up old scan results and resolved vulnerabilities"""
    logger.info("Cleaning up old data")

    from ..database.engine import get_db_context
    from ..database.models import Scan, Vulnerability, RemediationStatus
    from datetime import timedelta

    with get_db_context() as db:
        # Delete old scans (> 365 days)
        cutoff = datetime.utcnow() - timedelta(days=365)
        old_scans = db.query(Scan).filter(Scan.start_time < cutoff).delete()

        # Archive resolved vulnerabilities (> 730 days)
        archive_cutoff = datetime.utcnow() - timedelta(days=730)
        archived = db.query(Vulnerability).filter(
            Vulnerability.remediation_status == RemediationStatus.RESOLVED,
            Vulnerability.resolved_date < archive_cutoff
        ).count()

        db.commit()

    logger.info(f"✓ Cleanup: {old_scans} scans deleted, {archived} vulns archived")

    return {'scans_deleted': old_scans, 'vulns_archived': archived}


# =============================================================================
# Periodic Task Schedule
# =============================================================================

@celery_app.on_after_configure.connect
def setup_periodic_tasks(sender, **kwargs):
    """Configure periodic task schedule"""

    # Daily full network scan (2 AM)
    sender.add_periodic_task(
        crontab(hour=2, minute=0),
        run_full_network_scan.s(),
        name='daily-full-scan'
    )

    # Incremental scan every 4 hours
    sender.add_periodic_task(
        crontab(minute=0, hour='*/4'),
        run_incremental_scan.s(),
        name='incremental-scan-4h'
    )

    # Vulnerability enrichment (hourly)
    sender.add_periodic_task(
        crontab(minute=30),
        enrich_vulnerabilities.s(),
        name='hourly-enrichment'
    )

    # Risk score calculation (every 2 hours)
    sender.add_periodic_task(
        crontab(minute=0, hour='*/2'),
        calculate_risk_scores.s(),
        name='risk-scoring-2h'
    )

    # Jira ticket creation (every hour)
    sender.add_periodic_task(
        crontab(minute=15),
        create_jira_tickets_for_critical.s(),
        name='jira-tickets-hourly'
    )

    # SLA monitoring (daily at 9 AM)
    sender.add_periodic_task(
        crontab(hour=9, minute=0),
        monitor_sla_compliance.s(),
        name='daily-sla-monitoring'
    )

    # Executive report (monthly on 1st at 9 AM)
    sender.add_periodic_task(
        crontab(day_of_month=1, hour=9, minute=0),
        generate_executive_report.s(),
        name='monthly-executive-report'
    )

    # Weekly cleanup (Sunday at 3 AM)
    sender.add_periodic_task(
        crontab(day_of_week=0, hour=3, minute=0),
        cleanup_old_data.s(),
        name='weekly-cleanup'
    )

    logger.info("✓ Periodic tasks configured")


if __name__ == '__main__':
    # Start Celery worker
    celery_app.start()
