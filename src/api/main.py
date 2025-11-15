"""
Vulnerability Management Pipeline - FastAPI Application
Main API entry point
"""

from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
import os
from datetime import datetime

from ..database.engine import get_db, DatabaseManager
from ..database.models import Vulnerability, Asset

# Initialize FastAPI app
app = FastAPI(
    title="Vulnerability Management Pipeline API",
    description="Enterprise vulnerability management with intelligent risk prioritization",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS Configuration
origins = os.getenv("CORS_ORIGINS", "http://localhost:3000,http://localhost:8000").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =============================================================================
# Health Check Endpoints
# =============================================================================

@app.get("/")
async def root():
    """Root endpoint - API information"""
    return {
        "name": "Vulnerability Management Pipeline API",
        "version": "1.0.0",
        "status": "operational",
        "documentation": "/docs",
        "endpoints": {
            "health": "/health",
            "vulnerabilities": "/api/vulnerabilities",
            "assets": "/api/assets",
            "scans": "/api/scans"
        }
    }


@app.get("/health")
async def health_check():
    """Health check endpoint for monitoring"""
    # Check database connectivity
    db_healthy = DatabaseManager.check_connection()

    return {
        "status": "healthy" if db_healthy else "unhealthy",
        "version": "1.0.0",
        "timestamp": datetime.utcnow().isoformat(),
        "services": {
            "database": "up" if db_healthy else "down",
            "api": "up"
        }
    }


# =============================================================================
# Vulnerability Endpoints
# =============================================================================

@app.get("/api/vulnerabilities")
async def get_vulnerabilities(
    skip: int = 0,
    limit: int = 100,
    min_risk: float = 0.0,
    sort: str = "risk_score",
    db: Session = Depends(get_db)
):
    """
    Get list of vulnerabilities with filtering and sorting.

    Query Parameters:
    - skip: Number of records to skip (pagination)
    - limit: Maximum number of records to return
    - min_risk: Minimum business risk score (0-100)
    - sort: Sort field (risk_score, discovered_date, cve_id)
    """
    query = db.query(Vulnerability).filter(
        Vulnerability.business_risk_score >= min_risk
    )

    # Apply sorting
    if sort == "risk_score":
        query = query.order_by(Vulnerability.business_risk_score.desc())
    elif sort == "discovered_date":
        query = query.order_by(Vulnerability.discovered_date.desc())
    elif sort == "cve_id":
        query = query.order_by(Vulnerability.cve_id)

    total = query.count()
    vulnerabilities = query.offset(skip).limit(limit).all()

    return {
        "total": total,
        "skip": skip,
        "limit": limit,
        "data": [
            {
                "id": v.id,
                "cve_id": v.cve_id,
                "title": v.title,
                "cvss_base_score": v.cvss_base_score,
                "cvss_severity": v.cvss_severity.value if v.cvss_severity else None,
                "epss_score": v.epss_score,
                "business_risk_score": v.business_risk_score,
                "remediation_status": v.remediation_status.value if v.remediation_status else None,
                "remediation_deadline": v.remediation_deadline.isoformat() if v.remediation_deadline else None,
                "affected_assets_count": len(v.affected_assets),
                "jira_ticket_id": v.jira_ticket_id,
                "discovered_date": v.discovered_date.isoformat() if v.discovered_date else None
            }
            for v in vulnerabilities
        ]
    }


@app.get("/api/vulnerabilities/{cve_id}")
async def get_vulnerability(cve_id: str, db: Session = Depends(get_db)):
    """
    Get detailed information about a specific vulnerability.

    Path Parameters:
    - cve_id: CVE identifier (e.g., CVE-2024-1234)
    """
    vulnerability = db.query(Vulnerability).filter(
        Vulnerability.cve_id == cve_id
    ).first()

    if not vulnerability:
        return {"error": "Vulnerability not found"}, 404

    return {
        "id": vulnerability.id,
        "cve_id": vulnerability.cve_id,
        "title": vulnerability.title,
        "description": vulnerability.description,
        "cvss_base_score": vulnerability.cvss_base_score,
        "cvss_version": vulnerability.cvss_version,
        "cvss_vector": vulnerability.cvss_vector,
        "cvss_severity": vulnerability.cvss_severity.value if vulnerability.cvss_severity else None,
        "epss_score": vulnerability.epss_score,
        "epss_percentile": vulnerability.epss_percentile,
        "business_risk_score": vulnerability.business_risk_score,
        "risk_score_explanation": vulnerability.risk_score_explanation,
        "cwe_ids": vulnerability.cwe_ids,
        "exploit_available": vulnerability.exploit_available,
        "in_cisa_kev": vulnerability.in_cisa_kev,
        "remediation_status": vulnerability.remediation_status.value if vulnerability.remediation_status else None,
        "remediation_deadline": vulnerability.remediation_deadline.isoformat() if vulnerability.remediation_deadline else None,
        "remediation_notes": vulnerability.remediation_notes,
        "jira_ticket_id": vulnerability.jira_ticket_id,
        "jira_ticket_url": vulnerability.jira_ticket_url,
        "affected_assets": [
            {
                "id": asset.id,
                "hostname": asset.hostname,
                "ip_address": asset.ip_address,
                "asset_type": asset.asset_type.value if asset.asset_type else None,
                "criticality": asset.criticality
            }
            for asset in vulnerability.affected_assets
        ],
        "discovered_date": vulnerability.discovered_date.isoformat() if vulnerability.discovered_date else None,
        "last_scanned": vulnerability.last_scanned.isoformat() if vulnerability.last_scanned else None,
        "scan_count": vulnerability.scan_count
    }


# =============================================================================
# Asset Endpoints
# =============================================================================

@app.get("/api/assets")
async def get_assets(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    """Get list of assets"""
    query = db.query(Asset)
    total = query.count()
    assets = query.offset(skip).limit(limit).all()

    return {
        "total": total,
        "skip": skip,
        "limit": limit,
        "data": [
            {
                "id": a.id,
                "hostname": a.hostname,
                "ip_address": a.ip_address,
                "asset_type": a.asset_type.value if a.asset_type else None,
                "criticality": a.criticality,
                "owner_team": a.owner_team,
                "environment": a.environment,
                "vulnerability_count": len(a.vulnerabilities)
            }
            for a in assets
        ]
    }


# =============================================================================
# Statistics Endpoints
# =============================================================================

@app.get("/api/metrics/summary")
async def get_metrics_summary(db: Session = Depends(get_db)):
    """Get high-level vulnerability metrics"""
    from ..database.models import RemediationStatus

    total_vulns = db.query(Vulnerability).count()

    critical_count = db.query(Vulnerability).filter(
        Vulnerability.business_risk_score >= 80
    ).count()

    high_count = db.query(Vulnerability).filter(
        Vulnerability.business_risk_score >= 60,
        Vulnerability.business_risk_score < 80
    ).count()

    medium_count = db.query(Vulnerability).filter(
        Vulnerability.business_risk_score >= 40,
        Vulnerability.business_risk_score < 60
    ).count()

    low_count = db.query(Vulnerability).filter(
        Vulnerability.business_risk_score < 40
    ).count()

    open_count = db.query(Vulnerability).filter(
        Vulnerability.remediation_status == RemediationStatus.OPEN
    ).count()

    return {
        "total_vulnerabilities": total_vulns,
        "by_priority": {
            "critical": critical_count,
            "high": high_count,
            "medium": medium_count,
            "low": low_count
        },
        "by_status": {
            "open": open_count
        },
        "timestamp": datetime.utcnow().isoformat()
    }


# =============================================================================
# Startup Event
# =============================================================================

@app.on_event("startup")
async def startup_event():
    """Initialize on startup"""
    print("=" * 60)
    print("Vulnerability Management Pipeline API")
    print("=" * 60)
    print(f"Version: 1.0.0")
    print(f"Environment: {os.getenv('ENVIRONMENT', 'development')}")
    print(f"Database: {DatabaseManager.check_connection()}")
    print("=" * 60)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
