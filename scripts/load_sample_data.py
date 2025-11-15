"""
Load Sample Data for VMP Demo
Generates realistic vulnerabilities, assets, scans, and patches for demonstration
"""

import sys
import os
from datetime import datetime, timedelta
import random

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.database.engine import get_db_context, init_db
from src.database.models import (
    Vulnerability, Asset, Scan, RemediationTicket, Patch,
    SeverityLevel, RemediationStatus, AssetType, ScanType, TicketPriority,
    asset_vulnerability, patch_vulnerability
)
from src.prioritisation.scoring import RiskScorer
from src.prioritisation.sla import SLACalculator


# Sample CVE data (real vulnerabilities for demonstration)
SAMPLE_CVES = [
    {
        "cve_id": "CVE-2021-44228",
        "title": "Apache Log4j2 Remote Code Execution (Log4Shell)",
        "description": "Remote code execution vulnerability in Apache Log4j2 allows attackers to execute arbitrary code via specially crafted LDAP requests.",
        "cvss_base_score": 10.0,
        "cvss_version": "3.1",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "cvss_severity": SeverityLevel.CRITICAL,
        "epss_score": 0.975,
        "epss_percentile": 99.8,
        "cwe_ids": ["CWE-502", "CWE-400"],
        "exploit_available": True,
        "exploit_maturity": "FUNCTIONAL",
        "in_cisa_kev": True,
        "published_date": datetime(2021, 12, 9)
    },
    {
        "cve_id": "CVE-2023-23397",
        "title": "Microsoft Outlook Elevation of Privilege",
        "description": "Elevation of privilege vulnerability in Microsoft Outlook allows attackers to steal NTLM hashes.",
        "cvss_base_score": 9.8,
        "cvss_version": "3.1",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cvss_severity": SeverityLevel.CRITICAL,
        "epss_score": 0.892,
        "epss_percentile": 98.5,
        "cwe_ids": ["CWE-269"],
        "exploit_available": True,
        "exploit_maturity": "FUNCTIONAL",
        "in_cisa_kev": True,
        "published_date": datetime(2023, 3, 14)
    },
    {
        "cve_id": "CVE-2023-36884",
        "title": "Microsoft Office and Windows HTML Remote Code Execution",
        "description": "Remote code execution vulnerability in Microsoft Office and Windows HTML allows attackers to execute code via specially crafted documents.",
        "cvss_base_score": 8.3,
        "cvss_version": "3.1",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:L",
        "cvss_severity": SeverityLevel.HIGH,
        "epss_score": 0.756,
        "epss_percentile": 95.2,
        "cwe_ids": ["CWE-20"],
        "exploit_available": True,
        "exploit_maturity": "POC",
        "in_cisa_kev": True,
        "published_date": datetime(2023, 7, 11)
    },
    {
        "cve_id": "CVE-2024-21413",
        "title": "Microsoft Outlook Information Disclosure",
        "description": "Information disclosure vulnerability in Microsoft Outlook allows leak of NTLM hashes.",
        "cvss_base_score": 7.5,
        "cvss_version": "3.1",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cvss_severity": SeverityLevel.HIGH,
        "epss_score": 0.623,
        "epss_percentile": 92.1,
        "cwe_ids": ["CWE-200"],
        "exploit_available": False,
        "in_cisa_kev": False,
        "published_date": datetime(2024, 2, 13)
    },
    {
        "cve_id": "CVE-2024-3400",
        "title": "Palo Alto Networks PAN-OS Command Injection",
        "description": "Command injection vulnerability in GlobalProtect feature of PAN-OS allows authenticated attackers to execute arbitrary commands.",
        "cvss_base_score": 8.8,
        "cvss_version": "3.1",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "cvss_severity": SeverityLevel.HIGH,
        "epss_score": 0.834,
        "epss_percentile": 97.3,
        "cwe_ids": ["CWE-77"],
        "exploit_available": True,
        "exploit_maturity": "FUNCTIONAL",
        "in_cisa_kev": True,
        "published_date": datetime(2024, 4, 12)
    },
    {
        "cve_id": "CVE-2023-46604",
        "title": "Apache ActiveMQ Remote Code Execution",
        "description": "Remote code execution vulnerability in Apache ActiveMQ allows attackers to run arbitrary shell commands.",
        "cvss_base_score": 9.8,
        "cvss_version": "3.1",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cvss_severity": SeverityLevel.CRITICAL,
        "epss_score": 0.912,
        "epss_percentile": 98.9,
        "cwe_ids": ["CWE-502"],
        "exploit_available": True,
        "exploit_maturity": "FUNCTIONAL",
        "in_cisa_kev": True,
        "published_date": datetime(2023, 10, 27)
    },
    {
        "cve_id": "CVE-2023-34362",
        "title": "Progress MOVEit Transfer SQL Injection",
        "description": "SQL injection vulnerability in Progress MOVEit Transfer allows attackers to access sensitive data.",
        "cvss_base_score": 9.8,
        "cvss_version": "3.1",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cvss_severity": SeverityLevel.CRITICAL,
        "epss_score": 0.956,
        "epss_percentile": 99.5,
        "cwe_ids": ["CWE-89"],
        "exploit_available": True,
        "exploit_maturity": "FUNCTIONAL",
        "in_cisa_kev": True,
        "published_date": datetime(2023, 5, 31)
    },
    {
        "cve_id": "CVE-2024-4577",
        "title": "PHP CGI Argument Injection",
        "description": "Argument injection vulnerability in PHP CGI allows remote code execution on Windows systems.",
        "cvss_base_score": 9.8,
        "cvss_version": "3.1",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cvss_severity": SeverityLevel.CRITICAL,
        "epss_score": 0.887,
        "epss_percentile": 98.2,
        "cwe_ids": ["CWE-78"],
        "exploit_available": True,
        "exploit_maturity": "POC",
        "in_cisa_kev": False,
        "published_date": datetime(2024, 6, 6)
    },
    {
        "cve_id": "CVE-2023-22515",
        "title": "Atlassian Confluence Privilege Escalation",
        "description": "Privilege escalation vulnerability in Atlassian Confluence allows unauthenticated attackers to create admin accounts.",
        "cvss_base_score": 9.8,
        "cvss_version": "3.1",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cvss_severity": SeverityLevel.CRITICAL,
        "epss_score": 0.923,
        "epss_percentile": 99.1,
        "cwe_ids": ["CWE-269"],
        "exploit_available": True,
        "exploit_maturity": "FUNCTIONAL",
        "in_cisa_kev": True,
        "published_date": datetime(2023, 10, 4)
    },
    {
        "cve_id": "CVE-2023-4863",
        "title": "Chrome WebP Image Processing Heap Buffer Overflow",
        "description": "Heap buffer overflow in libwebp allows remote attackers to execute code via crafted WebP images.",
        "cvss_base_score": 8.8,
        "cvss_version": "3.1",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
        "cvss_severity": SeverityLevel.HIGH,
        "epss_score": 0.743,
        "epss_percentile": 94.8,
        "cwe_ids": ["CWE-122"],
        "exploit_available": True,
        "exploit_maturity": "FUNCTIONAL",
        "in_cisa_kev": True,
        "published_date": datetime(2023, 9, 25)
    }
]

# Additional medium/low severity CVEs
ADDITIONAL_CVES = [
    {
        "cve_id": f"CVE-2024-{1000 + i}",
        "title": f"Sample Vulnerability {i}",
        "description": f"This is a sample vulnerability for demonstration purposes.",
        "cvss_base_score": random.uniform(3.0, 7.0),
        "cvss_version": "3.1",
        "cvss_severity": SeverityLevel.MEDIUM if random.random() > 0.5 else SeverityLevel.LOW,
        "epss_score": random.uniform(0.01, 0.5),
        "epss_percentile": random.uniform(10, 70),
        "cwe_ids": [f"CWE-{random.randint(10, 999)}"],
        "exploit_available": random.random() > 0.7,
        "in_cisa_kev": False,
        "published_date": datetime(2024, random.randint(1, 11), random.randint(1, 28))
    }
    for i in range(1, 91)  # 90 additional vulnerabilities
]

# Sample assets
SAMPLE_ASSETS = [
    # Production servers (criticality 8-10)
    {"hostname": "web-prod-01", "ip_address": "10.0.1.10", "asset_type": AssetType.SERVER, "criticality": 9, "os": "Ubuntu 22.04", "owner_team": "Platform", "environment": "PRODUCTION"},
    {"hostname": "web-prod-02", "ip_address": "10.0.1.11", "asset_type": AssetType.SERVER, "criticality": 9, "os": "Ubuntu 22.04", "owner_team": "Platform", "environment": "PRODUCTION"},
    {"hostname": "db-prod-01", "ip_address": "10.0.1.20", "asset_type": AssetType.DATABASE, "criticality": 10, "os": "PostgreSQL 15", "owner_team": "Data", "environment": "PRODUCTION"},
    {"hostname": "api-prod-01", "ip_address": "10.0.1.30", "asset_type": AssetType.SERVER, "criticality": 9, "os": "Ubuntu 22.04", "owner_team": "Backend", "environment": "PRODUCTION"},
    {"hostname": "auth-prod-01", "ip_address": "10.0.1.40", "asset_type": AssetType.SERVER, "criticality": 10, "os": "RHEL 9", "owner_team": "Security", "environment": "PRODUCTION"},

    # Staging servers (criticality 6-7)
    {"hostname": "web-staging-01", "ip_address": "10.0.2.10", "asset_type": AssetType.SERVER, "criticality": 7, "os": "Ubuntu 22.04", "owner_team": "Platform", "environment": "STAGING"},
    {"hostname": "api-staging-01", "ip_address": "10.0.2.20", "asset_type": AssetType.SERVER, "criticality": 6, "os": "Ubuntu 22.04", "owner_team": "Backend", "environment": "STAGING"},

    # Development servers (criticality 3-5)
    {"hostname": "dev-vm-01", "ip_address": "10.0.3.10", "asset_type": AssetType.SERVER, "criticality": 3, "os": "Ubuntu 20.04", "owner_team": "Engineering", "environment": "DEVELOPMENT"},
    {"hostname": "dev-vm-02", "ip_address": "10.0.3.11", "asset_type": AssetType.SERVER, "criticality": 3, "os": "CentOS 7", "owner_team": "Engineering", "environment": "DEVELOPMENT"},
    {"hostname": "test-runner-01", "ip_address": "10.0.3.20", "asset_type": AssetType.SERVER, "criticality": 4, "os": "Ubuntu 22.04", "owner_team": "QA", "environment": "DEVELOPMENT"},

    # Workstations (criticality 5-8)
    {"hostname": "ceo-laptop", "ip_address": "10.0.4.10", "asset_type": AssetType.WORKSTATION, "criticality": 10, "os": "Windows 11", "owner_team": "Executive", "environment": "PRODUCTION"},
    {"hostname": "cfo-laptop", "ip_address": "10.0.4.11", "asset_type": AssetType.WORKSTATION, "criticality": 9, "os": "macOS 14", "owner_team": "Finance", "environment": "PRODUCTION"},
    {"hostname": "dev-workstation-01", "ip_address": "10.0.4.20", "asset_type": AssetType.WORKSTATION, "criticality": 5, "os": "Ubuntu 22.04", "owner_team": "Engineering", "environment": "PRODUCTION"},

    # Network devices (criticality 8-9)
    {"hostname": "firewall-01", "ip_address": "10.0.0.1", "asset_type": AssetType.NETWORK_DEVICE, "criticality": 9, "os": "Palo Alto PAN-OS", "owner_team": "Network", "environment": "PRODUCTION"},
    {"hostname": "vpn-gateway-01", "ip_address": "10.0.0.2", "asset_type": AssetType.NETWORK_DEVICE, "criticality": 8, "os": "Cisco IOS", "owner_team": "Network", "environment": "PRODUCTION"},
]

# Sample patches
SAMPLE_PATCHES = [
    {
        "patch_id": "MS-2024-001",
        "name": "Windows Security Update January 2024",
        "vendor": "Microsoft",
        "product": "Windows Server",
        "version": "2022",
        "release_date": datetime(2024, 1, 9),
        "deployment_difficulty": 2,
        "requires_reboot": True,
        "estimated_deployment_hours": 4.0,
        "patch_url": "https://msrc.microsoft.com/update-guide/",
        "cve_fixes": ["CVE-2023-23397", "CVE-2024-21413"]
    },
    {
        "patch_id": "APACHE-LOG4J-2.17.1",
        "name": "Apache Log4j 2.17.1",
        "vendor": "Apache",
        "product": "Log4j",
        "version": "2.17.1",
        "release_date": datetime(2021, 12, 27),
        "deployment_difficulty": 3,
        "requires_reboot": False,
        "estimated_deployment_hours": 8.0,
        "patch_url": "https://logging.apache.org/log4j/2.x/security.html",
        "cve_fixes": ["CVE-2021-44228"]
    },
    {
        "patch_id": "CHROME-125.0.6422.60",
        "name": "Google Chrome 125.0.6422.60",
        "vendor": "Google",
        "product": "Chrome",
        "version": "125.0.6422.60",
        "release_date": datetime(2023, 9, 26),
        "deployment_difficulty": 1,
        "requires_reboot": False,
        "estimated_deployment_hours": 1.0,
        "patch_url": "https://chromereleases.googleblog.com/",
        "cve_fixes": ["CVE-2023-4863"]
    },
    {
        "patch_id": "CONFLUENCE-8.5.4",
        "name": "Atlassian Confluence 8.5.4",
        "vendor": "Atlassian",
        "product": "Confluence",
        "version": "8.5.4",
        "release_date": datetime(2023, 10, 4),
        "deployment_difficulty": 4,
        "requires_reboot": True,
        "estimated_deployment_hours": 12.0,
        "patch_url": "https://confluence.atlassian.com/security/",
        "cve_fixes": ["CVE-2023-22515"]
    },
    {
        "patch_id": "PHP-8.3.8",
        "name": "PHP 8.3.8",
        "vendor": "PHP Group",
        "product": "PHP",
        "version": "8.3.8",
        "release_date": datetime(2024, 6, 6),
        "deployment_difficulty": 3,
        "requires_reboot": False,
        "estimated_deployment_hours": 6.0,
        "patch_url": "https://www.php.net/ChangeLog-8.php",
        "cve_fixes": ["CVE-2024-4577"]
    }
]


def create_sample_assets(db):
    """Create sample assets"""
    print("\n" + "=" * 60)
    print("Creating Sample Assets")
    print("=" * 60)

    assets = []
    for asset_data in SAMPLE_ASSETS:
        asset = Asset(
            hostname=asset_data["hostname"],
            ip_address=asset_data["ip_address"],
            asset_type=asset_data["asset_type"],
            criticality=asset_data["criticality"],
            operating_system=asset_data["os"],
            owner_team=asset_data["owner_team"],
            environment=asset_data["environment"],
            is_active=True,
            last_scan_date=datetime.utcnow() - timedelta(days=random.randint(0, 7))
        )
        db.add(asset)
        assets.append(asset)

    db.commit()
    print(f"✓ Created {len(assets)} assets")
    return assets


def create_sample_vulnerabilities(db, assets):
    """Create sample vulnerabilities and link to assets"""
    print("\n" + "=" * 60)
    print("Creating Sample Vulnerabilities")
    print("=" * 60)

    scorer = RiskScorer()
    sla_calc = SLACalculator()

    all_cves = SAMPLE_CVES + ADDITIONAL_CVES
    vulnerabilities = []

    for cve_data in all_cves:
        # Randomly assign to 1-5 assets
        affected_assets = random.sample(assets, k=random.randint(1, min(5, len(assets))))

        # Calculate average asset criticality
        asset_criticality_avg = sum(a.criticality for a in affected_assets) / len(affected_assets)

        # Random remediation difficulty
        remediation_difficulty = random.randint(1, 5)

        # Calculate business risk score
        risk_result = scorer.calculate_business_risk(
            cvss_base_score=cve_data["cvss_base_score"],
            epss_score=cve_data["epss_score"],
            asset_criticality=asset_criticality_avg,
            remediation_difficulty=remediation_difficulty
        )

        # Determine remediation status (80% open, 15% in_progress, 5% resolved)
        status_roll = random.random()
        if status_roll < 0.80:
            status = RemediationStatus.OPEN
            resolved_date = None
        elif status_roll < 0.95:
            status = RemediationStatus.IN_PROGRESS
            resolved_date = None
        else:
            status = RemediationStatus.RESOLVED
            resolved_date = datetime.utcnow() - timedelta(days=random.randint(1, 30))

        # Calculate SLA deadline
        sla_info = sla_calc.calculate_deadline_with_info(
            risk_score=risk_result['total_score'],
            discovery_date=datetime.utcnow() - timedelta(days=random.randint(1, 60))
        )

        # Create vulnerability
        vuln = Vulnerability(
            cve_id=cve_data["cve_id"],
            title=cve_data["title"],
            description=cve_data.get("description", ""),
            cvss_base_score=cve_data["cvss_base_score"],
            cvss_version=cve_data.get("cvss_version"),
            cvss_vector=cve_data.get("cvss_vector"),
            cvss_severity=cve_data["cvss_severity"],
            epss_score=cve_data["epss_score"],
            epss_percentile=cve_data.get("epss_percentile"),
            epss_last_updated=datetime.utcnow(),
            cwe_ids=cve_data.get("cwe_ids", []),
            business_risk_score=risk_result['total_score'],
            risk_score_explanation=risk_result['explanation'],
            asset_criticality_avg=asset_criticality_avg,
            remediation_difficulty=remediation_difficulty,
            exploit_available=cve_data.get("exploit_available", False),
            exploit_maturity=cve_data.get("exploit_maturity"),
            in_cisa_kev=cve_data.get("in_cisa_kev", False),
            remediation_status=status,
            remediation_deadline=sla_info['deadline'],
            discovered_date=sla_info['discovery_date'],
            first_seen=sla_info['discovery_date'],
            last_scanned=datetime.utcnow() - timedelta(days=random.randint(0, 7)),
            resolved_date=resolved_date,
            scan_count=random.randint(1, 10),
            published_date=cve_data.get("published_date"),
            data_source="OPENVAS"
        )

        # Link to affected assets
        vuln.affected_assets = affected_assets

        db.add(vuln)
        vulnerabilities.append(vuln)

    db.commit()
    print(f"✓ Created {len(vulnerabilities)} vulnerabilities")

    # Print statistics
    critical = sum(1 for v in vulnerabilities if v.business_risk_score >= 80)
    high = sum(1 for v in vulnerabilities if 60 <= v.business_risk_score < 80)
    medium = sum(1 for v in vulnerabilities if 40 <= v.business_risk_score < 60)
    low = sum(1 for v in vulnerabilities if v.business_risk_score < 40)

    print(f"  - CRITICAL (≥80): {critical}")
    print(f"  - HIGH (60-79): {high}")
    print(f"  - MEDIUM (40-59): {medium}")
    print(f"  - LOW (<40): {low}")

    return vulnerabilities


def create_sample_patches(db, vulnerabilities):
    """Create sample patches and link to vulnerabilities"""
    print("\n" + "=" * 60)
    print("Creating Sample Patches")
    print("=" * 60)

    patches = []
    for patch_data in SAMPLE_PATCHES:
        # Find vulnerabilities this patch fixes
        fixed_vulns = [
            v for v in vulnerabilities
            if v.cve_id in patch_data.get("cve_fixes", [])
        ]

        patch = Patch(
            patch_id=patch_data["patch_id"],
            name=patch_data["name"],
            vendor=patch_data["vendor"],
            product=patch_data["product"],
            version=patch_data.get("version"),
            release_date=patch_data.get("release_date"),
            deployment_difficulty=patch_data.get("deployment_difficulty", 3),
            requires_reboot=patch_data.get("requires_reboot", False),
            estimated_deployment_hours=patch_data.get("estimated_deployment_hours", 4.0),
            patch_url=patch_data.get("patch_url"),
            vulnerabilities_fixed_count=len(fixed_vulns),
            high_risk_vulns_fixed=sum(1 for v in fixed_vulns if v.business_risk_score >= 60)
        )

        # Link to vulnerabilities
        patch.vulnerabilities = fixed_vulns

        # Calculate ROI
        if patch.estimated_deployment_hours > 0:
            patch.roi_score = len(fixed_vulns) / patch.estimated_deployment_hours

        db.add(patch)
        patches.append(patch)

    db.commit()
    print(f"✓ Created {len(patches)} patches")

    for patch in patches:
        print(f"  - {patch.patch_id}: fixes {patch.vulnerabilities_fixed_count} vulns "
              f"({patch.high_risk_vulns_fixed} high-risk), ROI={patch.roi_score:.2f}")

    return patches


def create_sample_scans(db, assets, vulnerabilities):
    """Create sample scan records"""
    print("\n" + "=" * 60)
    print("Creating Sample Scans")
    print("=" * 60)

    scans = []

    # Create 5 historical scans
    for i in range(5):
        scan_date = datetime.utcnow() - timedelta(days=(5 - i) * 7)  # Weekly scans

        scan = Scan(
            scan_id=f"scan-{scan_date.strftime('%Y%m%d')}-{i:03d}",
            name=f"Weekly Full Scan - {scan_date.strftime('%Y-%m-%d')}",
            scan_type=ScanType.FULL,
            target_asset_id=random.choice(assets).id if assets else None,
            target_range="10.0.0.0/16",
            scheduled_time=scan_date - timedelta(hours=1),
            start_time=scan_date,
            end_time=scan_date + timedelta(hours=4),
            duration_seconds=14400,
            status="COMPLETED",
            progress_percentage=100,
            total_hosts_scanned=len(assets),
            vulnerabilities_found=len(vulnerabilities),
            critical_count=sum(1 for v in vulnerabilities if v.business_risk_score >= 80),
            high_count=sum(1 for v in vulnerabilities if 60 <= v.business_risk_score < 80),
            medium_count=sum(1 for v in vulnerabilities if 40 <= v.business_risk_score < 60),
            low_count=sum(1 for v in vulnerabilities if v.business_risk_score < 40),
            scanner_name="OPENVAS",
            scanner_version="22.4"
        )

        db.add(scan)
        scans.append(scan)

    db.commit()
    print(f"✓ Created {len(scans)} scan records")

    return scans


def print_summary(db):
    """Print summary statistics"""
    print("\n" + "=" * 60)
    print("SAMPLE DATA SUMMARY")
    print("=" * 60)

    total_assets = db.query(Asset).count()
    total_vulns = db.query(Vulnerability).count()
    total_patches = db.query(Patch).count()
    total_scans = db.query(Scan).count()

    critical_vulns = db.query(Vulnerability).filter(
        Vulnerability.business_risk_score >= 80
    ).count()

    open_vulns = db.query(Vulnerability).filter(
        Vulnerability.remediation_status == RemediationStatus.OPEN
    ).count()

    print(f"\n📊 Database Contents:")
    print(f"  - Assets: {total_assets}")
    print(f"  - Vulnerabilities: {total_vulns}")
    print(f"  - Patches: {total_patches}")
    print(f"  - Scans: {total_scans}")

    print(f"\n🚨 Risk Summary:")
    print(f"  - CRITICAL vulnerabilities: {critical_vulns}")
    print(f"  - OPEN vulnerabilities: {open_vulns}")

    # Top 5 riskiest vulnerabilities
    top_vulns = db.query(Vulnerability).order_by(
        Vulnerability.business_risk_score.desc()
    ).limit(5).all()

    print(f"\n🔥 Top 5 Highest Risk Vulnerabilities:")
    for i, vuln in enumerate(top_vulns, 1):
        print(f"  {i}. {vuln.cve_id}: {vuln.business_risk_score:.1f}/100 "
              f"({vuln.cvss_severity.value if vuln.cvss_severity else 'N/A'})")

    # Most critical assets
    critical_assets = db.query(Asset).filter(
        Asset.criticality >= 9
    ).all()

    print(f"\n💎 Critical Assets (criticality ≥9):")
    for asset in critical_assets:
        vuln_count = len(asset.vulnerabilities)
        print(f"  - {asset.hostname}: criticality={asset.criticality}, "
              f"vulnerabilities={vuln_count}")

    print("\n" + "=" * 60)
    print("✓ Sample data loaded successfully!")
    print("=" * 60)
    print(f"\nYou can now:")
    print(f"  1. Start API: docker-compose up -d")
    print(f"  2. View API docs: http://localhost:8000/docs")
    print(f"  3. View Grafana: http://localhost:3000")
    print(f"  4. Query database: docker-compose exec api python")
    print("=" * 60 + "\n")


def main():
    """Main function to load sample data"""
    print("\n" + "=" * 60)
    print("VMP SAMPLE DATA LOADER")
    print("=" * 60)
    print("This script will populate the database with realistic sample data")
    print("for demonstration and testing purposes.")
    print("=" * 60)

    # Initialize database
    print("\nInitializing database...")
    init_db()
    print("✓ Database initialized")

    # Create sample data
    with get_db_context() as db:
        assets = create_sample_assets(db)
        vulnerabilities = create_sample_vulnerabilities(db, assets)
        patches = create_sample_patches(db, vulnerabilities)
        scans = create_sample_scans(db, assets, vulnerabilities)

        print_summary(db)


if __name__ == "__main__":
    main()
