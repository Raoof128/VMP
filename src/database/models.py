"""
Vulnerability Management Pipeline - Database Models
SQLAlchemy ORM models for vulnerability management
"""

from datetime import datetime
from typing import Optional, List
from sqlalchemy import (
    Column, Integer, String, Float, DateTime, Text, Boolean,
    ForeignKey, JSON, Table, Enum as SQLEnum, UniqueConstraint, Index
)
from sqlalchemy.orm import declarative_base, relationship
from sqlalchemy.sql import func
import enum

Base = declarative_base()


# =============================================================================
# Enums
# =============================================================================

class SeverityLevel(str, enum.Enum):
    """CVSS Severity Levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE = "NONE"


class RemediationStatus(str, enum.Enum):
    """Vulnerability remediation tracking status"""
    OPEN = "OPEN"
    IN_PROGRESS = "IN_PROGRESS"
    RESOLVED = "RESOLVED"
    WAIVED = "WAIVED"
    RISK_ACCEPTED = "RISK_ACCEPTED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class AssetType(str, enum.Enum):
    """Asset classification"""
    SERVER = "SERVER"
    WORKSTATION = "WORKSTATION"
    NETWORK_DEVICE = "NETWORK_DEVICE"
    WEB_APPLICATION = "WEB_APPLICATION"
    DATABASE = "DATABASE"
    CONTAINER = "CONTAINER"
    CLOUD_RESOURCE = "CLOUD_RESOURCE"
    IOT_DEVICE = "IOT_DEVICE"


class ScanType(str, enum.Enum):
    """Vulnerability scan types"""
    FULL = "FULL"
    INCREMENTAL = "INCREMENTAL"
    WEB_ONLY = "WEB_ONLY"
    AUTHENTICATED = "AUTHENTICATED"
    UNAUTHENTICATED = "UNAUTHENTICATED"


class TicketPriority(str, enum.Enum):
    """Jira ticket priority levels"""
    HIGHEST = "HIGHEST"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    LOWEST = "LOWEST"


# =============================================================================
# Association Tables (Many-to-Many relationships)
# =============================================================================

asset_vulnerability = Table(
    'asset_vulnerability',
    Base.metadata,
    Column('asset_id', Integer, ForeignKey('assets.id', ondelete='CASCADE'), primary_key=True),
    Column('vulnerability_id', Integer, ForeignKey('vulnerabilities.id', ondelete='CASCADE'), primary_key=True),
    Column('discovered_date', DateTime, default=datetime.utcnow),
    Column('last_seen', DateTime, default=datetime.utcnow, onupdate=datetime.utcnow),
)

patch_vulnerability = Table(
    'patch_vulnerability',
    Base.metadata,
    Column('patch_id', Integer, ForeignKey('patches.id', ondelete='CASCADE'), primary_key=True),
    Column('vulnerability_id', Integer, ForeignKey('vulnerabilities.id', ondelete='CASCADE'), primary_key=True),
)


# =============================================================================
# Core Models
# =============================================================================

class Vulnerability(Base):
    """
    Core vulnerability model combining CVE data with business risk scoring.

    This model represents a unique vulnerability (CVE) and tracks:
    - Technical severity (CVSS)
    - Exploit probability (EPSS)
    - Business risk score (custom calculation)
    - Remediation tracking
    """
    __tablename__ = 'vulnerabilities'

    # Primary Key
    id = Column(Integer, primary_key=True, autoincrement=True)

    # CVE Identification
    cve_id = Column(String(20), unique=True, nullable=False, index=True)
    title = Column(String(500), nullable=False)
    description = Column(Text)

    # CVSS Scoring (Technical Severity)
    cvss_base_score = Column(Float)  # 0.0 - 10.0
    cvss_version = Column(String(10))  # 3.1, 3.0, 2.0
    cvss_vector = Column(String(100))  # AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    cvss_severity = Column(SQLEnum(SeverityLevel), index=True)

    # EPSS (Exploit Prediction Scoring System)
    epss_score = Column(Float)  # 0.0 - 1.0 (probability of exploitation)
    epss_percentile = Column(Float)  # Percentile ranking
    epss_last_updated = Column(DateTime)

    # CWE (Common Weakness Enumeration)
    cwe_ids = Column(JSON)  # List of CWE IDs: ["CWE-79", "CWE-89"]

    # Business Risk Scoring (Custom)
    business_risk_score = Column(Float, index=True)  # 0.0 - 100.0
    risk_score_explanation = Column(Text)  # Human-readable explanation
    asset_criticality_avg = Column(Float)  # Average criticality of affected assets
    remediation_difficulty = Column(Integer)  # 1-5 scale

    # Exploit Intelligence
    exploit_available = Column(Boolean, default=False)
    exploit_maturity = Column(String(50))  # FUNCTIONAL, POC, HIGH, UNPROVEN
    in_cisa_kev = Column(Boolean, default=False)  # CISA Known Exploited Vulnerabilities

    # Remediation Tracking
    remediation_status = Column(SQLEnum(RemediationStatus), default=RemediationStatus.OPEN, index=True)
    remediation_deadline = Column(DateTime, index=True)  # SLA-based deadline
    remediation_notes = Column(Text)
    waiver_reason = Column(Text)
    waiver_approved_by = Column(String(100))
    waiver_expiry_date = Column(DateTime)

    # Jira Integration
    jira_ticket_id = Column(String(20), index=True)
    jira_ticket_url = Column(String(500))

    # Timestamps
    discovered_date = Column(DateTime, default=datetime.utcnow, nullable=False)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_scanned = Column(DateTime, onupdate=datetime.utcnow)
    resolved_date = Column(DateTime)
    scan_count = Column(Integer, default=1)

    # Metadata
    published_date = Column(DateTime)  # CVE publication date
    last_modified_date = Column(DateTime)  # CVE last modified
    data_source = Column(String(50))  # OPENVAS, NESSUS, NVD

    # Audit
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    affected_assets = relationship("Asset", secondary=asset_vulnerability, back_populates="vulnerabilities")
    patches = relationship("Patch", secondary=patch_vulnerability, back_populates="vulnerabilities")
    scan_results = relationship("ScanResult", back_populates="vulnerability", cascade="all, delete-orphan")
    remediation_tickets = relationship("RemediationTicket", back_populates="vulnerability", cascade="all, delete-orphan")
    compliance_mappings = relationship("ComplianceMapping", back_populates="vulnerability", cascade="all, delete-orphan")
    risk_history = relationship("RiskHistory", back_populates="vulnerability", cascade="all, delete-orphan")

    # Indexes
    __table_args__ = (
        Index('idx_vuln_severity_status', 'cvss_severity', 'remediation_status'),
        Index('idx_vuln_risk_score', 'business_risk_score'),
        Index('idx_vuln_deadline', 'remediation_deadline'),
    )

    def __repr__(self):
        return f"<Vulnerability(cve_id='{self.cve_id}', risk={self.business_risk_score}, status='{self.remediation_status}')>"

    @property
    def is_critical(self) -> bool:
        """Check if vulnerability is CRITICAL severity"""
        return self.business_risk_score >= 80 if self.business_risk_score else False

    @property
    def is_overdue(self) -> bool:
        """Check if remediation is overdue"""
        if self.remediation_deadline and self.remediation_status in [RemediationStatus.OPEN, RemediationStatus.IN_PROGRESS]:
            return datetime.utcnow() > self.remediation_deadline
        return False

    @property
    def days_until_deadline(self) -> Optional[int]:
        """Calculate days until remediation deadline"""
        if self.remediation_deadline:
            delta = self.remediation_deadline - datetime.utcnow()
            return delta.days
        return None


class Asset(Base):
    """
    IT asset model representing systems, applications, and infrastructure.

    Assets are tagged with criticality scores (1-10) to influence
    business risk calculations for vulnerabilities.
    """
    __tablename__ = 'assets'

    # Primary Key
    id = Column(Integer, primary_key=True, autoincrement=True)

    # Identification
    hostname = Column(String(255), unique=True, nullable=False, index=True)
    ip_address = Column(String(45), index=True)  # IPv4 or IPv6
    mac_address = Column(String(17))
    fqdn = Column(String(255))

    # Classification
    asset_type = Column(SQLEnum(AssetType), nullable=False, index=True)
    criticality = Column(Integer, nullable=False, default=5)  # 1-10 scale (10 = most critical)

    # Metadata
    operating_system = Column(String(100))
    os_version = Column(String(50))
    manufacturer = Column(String(100))
    model = Column(String(100))

    # Business Context
    owner_team = Column(String(100))
    owner_email = Column(String(255))
    department = Column(String(100))
    location = Column(String(200))  # Physical or cloud region
    environment = Column(String(50))  # PRODUCTION, STAGING, DEVELOPMENT

    # Tags & Labels
    tags = Column(JSON)  # Flexible tagging: {"compliance": ["PCI-DSS"], "project": "web-portal"}

    # Status
    is_active = Column(Boolean, default=True)
    last_scan_date = Column(DateTime)

    # Audit
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    vulnerabilities = relationship("Vulnerability", secondary=asset_vulnerability, back_populates="affected_assets")
    scans = relationship("Scan", back_populates="target_asset", cascade="all, delete-orphan")

    # Indexes
    __table_args__ = (
        Index('idx_asset_criticality', 'criticality'),
        Index('idx_asset_type_active', 'asset_type', 'is_active'),
    )

    def __repr__(self):
        return f"<Asset(hostname='{self.hostname}', type='{self.asset_type}', criticality={self.criticality})>"

    @property
    def vulnerability_count(self) -> int:
        """Count of vulnerabilities affecting this asset"""
        return len(self.vulnerabilities)

    @property
    def critical_vulnerability_count(self) -> int:
        """Count of CRITICAL vulnerabilities on this asset"""
        return sum(1 for v in self.vulnerabilities if v.is_critical)


class Scan(Base):
    """
    Vulnerability scan execution tracking.

    Records metadata about each scan: targets, timing, results count.
    """
    __tablename__ = 'scans'

    # Primary Key
    id = Column(Integer, primary_key=True, autoincrement=True)

    # Scan Identification
    scan_id = Column(String(100), unique=True, nullable=False, index=True)  # External scanner ID
    name = Column(String(255), nullable=False)
    scan_type = Column(SQLEnum(ScanType), nullable=False)

    # Target
    target_asset_id = Column(Integer, ForeignKey('assets.id', ondelete='SET NULL'))
    target_range = Column(String(100))  # IP range or hostname pattern

    # Timing
    scheduled_time = Column(DateTime)
    start_time = Column(DateTime)
    end_time = Column(DateTime)
    duration_seconds = Column(Integer)

    # Status
    status = Column(String(50))  # SCHEDULED, RUNNING, COMPLETED, FAILED, CANCELLED
    progress_percentage = Column(Integer, default=0)

    # Results Summary
    total_hosts_scanned = Column(Integer, default=0)
    vulnerabilities_found = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)

    # Scanner Details
    scanner_name = Column(String(50))  # OPENVAS, NESSUS
    scanner_version = Column(String(50))
    scan_config = Column(JSON)  # Scanner-specific configuration

    # Error Handling
    error_message = Column(Text)
    retry_count = Column(Integer, default=0)

    # Audit
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    target_asset = relationship("Asset", back_populates="scans")
    scan_results = relationship("ScanResult", back_populates="scan", cascade="all, delete-orphan")

    # Indexes
    __table_args__ = (
        Index('idx_scan_status_time', 'status', 'start_time'),
    )

    def __repr__(self):
        return f"<Scan(scan_id='{self.scan_id}', type='{self.scan_type}', status='{self.status}')>"


class ScanResult(Base):
    """
    Individual vulnerability finding from a scan.

    Links a specific vulnerability to a specific scan and asset.
    """
    __tablename__ = 'scan_results'

    # Primary Key
    id = Column(Integer, primary_key=True, autoincrement=True)

    # Foreign Keys
    scan_id = Column(Integer, ForeignKey('scans.id', ondelete='CASCADE'), nullable=False)
    vulnerability_id = Column(Integer, ForeignKey('vulnerabilities.id', ondelete='CASCADE'), nullable=False)
    asset_id = Column(Integer, ForeignKey('assets.id', ondelete='CASCADE'), nullable=False)

    # Finding Details
    port = Column(Integer)
    protocol = Column(String(10))  # TCP, UDP
    service = Column(String(100))
    evidence = Column(Text)  # Scanner output/proof

    # Status
    is_false_positive = Column(Boolean, default=False)
    verified = Column(Boolean, default=False)

    # Audit
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    scan = relationship("Scan", back_populates="scan_results")
    vulnerability = relationship("Vulnerability", back_populates="scan_results")

    # Indexes
    __table_args__ = (
        Index('idx_scan_result_scan', 'scan_id'),
        Index('idx_scan_result_vuln', 'vulnerability_id'),
        UniqueConstraint('scan_id', 'vulnerability_id', 'asset_id', name='uq_scan_vuln_asset'),
    )

    def __repr__(self):
        return f"<ScanResult(scan_id={self.scan_id}, cve='{self.vulnerability.cve_id if self.vulnerability else 'N/A'}')>"


class RemediationTicket(Base):
    """
    Remediation tracking via external ticketing systems (Jira, ServiceNow).

    Links vulnerabilities to tickets and tracks SLA compliance.
    """
    __tablename__ = 'remediation_tickets'

    # Primary Key
    id = Column(Integer, primary_key=True, autoincrement=True)

    # Foreign Key
    vulnerability_id = Column(Integer, ForeignKey('vulnerabilities.id', ondelete='CASCADE'), nullable=False)

    # Ticket Details
    ticket_id = Column(String(50), unique=True, nullable=False, index=True)  # VULN-1234
    ticket_url = Column(String(500))
    ticket_system = Column(String(50))  # JIRA, SERVICENOW

    # Assignment
    assignee = Column(String(100))
    assignee_email = Column(String(255))
    team = Column(String(100))

    # Priority & SLA
    priority = Column(SQLEnum(TicketPriority), nullable=False)
    sla_deadline = Column(DateTime, nullable=False, index=True)
    sla_met = Column(Boolean)

    # Status Tracking
    status = Column(String(50))  # OPEN, IN_PROGRESS, RESOLVED, CLOSED
    resolution = Column(String(100))  # FIXED, WAIVED, RISK_ACCEPTED, FALSE_POSITIVE
    resolution_notes = Column(Text)

    # Timing
    created_date = Column(DateTime, default=datetime.utcnow, nullable=False)
    resolved_date = Column(DateTime)
    closed_date = Column(DateTime)

    # Effort Tracking
    estimated_hours = Column(Float)
    actual_hours = Column(Float)

    # Audit
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    vulnerability = relationship("Vulnerability", back_populates="remediation_tickets")

    # Indexes
    __table_args__ = (
        Index('idx_ticket_status_sla', 'status', 'sla_deadline'),
    )

    def __repr__(self):
        return f"<RemediationTicket(ticket_id='{self.ticket_id}', status='{self.status}')>"

    @property
    def is_overdue(self) -> bool:
        """Check if ticket is overdue"""
        if self.sla_deadline and self.status not in ['RESOLVED', 'CLOSED']:
            return datetime.utcnow() > self.sla_deadline
        return False


class Patch(Base):
    """
    Software patches and updates that remediate vulnerabilities.

    Tracks which patches fix which vulnerabilities for ROI analysis.
    """
    __tablename__ = 'patches'

    # Primary Key
    id = Column(Integer, primary_key=True, autoincrement=True)

    # Patch Identification
    patch_id = Column(String(100), unique=True, nullable=False, index=True)  # KB5034, OpenSSL-3.1.2
    name = Column(String(255), nullable=False)
    description = Column(Text)

    # Vendor Information
    vendor = Column(String(100))  # Microsoft, Oracle, Apache
    product = Column(String(100))  # Windows, Java, httpd
    version = Column(String(50))

    # Release Information
    release_date = Column(DateTime)
    superseded_by = Column(String(100))  # Newer patch ID

    # Deployment Tracking
    deployment_difficulty = Column(Integer)  # 1-5 scale
    requires_reboot = Column(Boolean, default=False)
    estimated_deployment_hours = Column(Float)

    # Impact Analysis
    vulnerabilities_fixed_count = Column(Integer, default=0)
    high_risk_vulns_fixed = Column(Integer, default=0)
    roi_score = Column(Float)  # Vulnerabilities fixed / effort hours

    # URLs
    patch_url = Column(String(500))
    advisory_url = Column(String(500))

    # Audit
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    vulnerabilities = relationship("Vulnerability", secondary=patch_vulnerability, back_populates="patches")

    def __repr__(self):
        return f"<Patch(patch_id='{self.patch_id}', fixes={self.vulnerabilities_fixed_count} vulns)>"


class ComplianceMapping(Base):
    """
    Maps vulnerabilities to compliance frameworks (NIST, ISO, CIS, PCI-DSS).

    Enables compliance reporting and framework coverage analysis.
    """
    __tablename__ = 'compliance_mappings'

    # Primary Key
    id = Column(Integer, primary_key=True, autoincrement=True)

    # Foreign Key
    vulnerability_id = Column(Integer, ForeignKey('vulnerabilities.id', ondelete='CASCADE'), nullable=False)

    # Framework Details
    framework = Column(String(50), nullable=False, index=True)  # NIST_800_53, ISO_27001, CIS, PCI_DSS
    control_id = Column(String(50), nullable=False)  # SI-2, A.12.6.1, 7.1
    control_name = Column(String(255))

    # Compliance Status
    is_compliant = Column(Boolean, default=False)
    compliance_notes = Column(Text)

    # Audit
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    vulnerability = relationship("Vulnerability", back_populates="compliance_mappings")

    # Indexes
    __table_args__ = (
        Index('idx_compliance_framework', 'framework', 'control_id'),
        UniqueConstraint('vulnerability_id', 'framework', 'control_id', name='uq_vuln_framework_control'),
    )

    def __repr__(self):
        return f"<ComplianceMapping(framework='{self.framework}', control='{self.control_id}')>"


class RiskHistory(Base):
    """
    Historical tracking of vulnerability risk scores over time.

    Enables trend analysis and risk reduction metrics.
    """
    __tablename__ = 'risk_history'

    # Primary Key
    id = Column(Integer, primary_key=True, autoincrement=True)

    # Foreign Key
    vulnerability_id = Column(Integer, ForeignKey('vulnerabilities.id', ondelete='CASCADE'), nullable=False)

    # Risk Snapshot
    business_risk_score = Column(Float, nullable=False)
    cvss_score = Column(Float)
    epss_score = Column(Float)
    asset_criticality_avg = Column(Float)
    remediation_status = Column(String(50))

    # Metadata
    snapshot_reason = Column(String(100))  # SCAN_UPDATE, MANUAL_ADJUSTMENT, STATUS_CHANGE

    # Audit
    recorded_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    # Relationships
    vulnerability = relationship("Vulnerability", back_populates="risk_history")

    # Indexes
    __table_args__ = (
        Index('idx_risk_history_vuln_date', 'vulnerability_id', 'recorded_at'),
    )

    def __repr__(self):
        return f"<RiskHistory(vuln_id={self.vulnerability_id}, risk={self.business_risk_score}, date={self.recorded_at})>"
