# VMP Architecture Documentation

## System Overview

The Vulnerability Management Pipeline (VMP) is designed as a **microservices architecture** with clear separation of concerns:

1. **Scanner Orchestrator**: Manages vulnerability scanning workflows
2. **Prioritisation Engine**: Calculates business risk scores
3. **Database Layer**: Normalizes and stores vulnerability data
4. **API Gateway**: Exposes REST endpoints for external integrations
5. **Workflow Engine**: Automates remediation tracking via Jira
6. **Reporting Engine**: Generates executive reports and dashboards

---

## Component Architecture

### 1. Scanner Orchestrator

**Responsibilities:**
- Schedule vulnerability scans (full, incremental, web-only)
- Manage OpenVAS/Nessus API connections
- Parse and normalize scan results
- Enrich findings with threat intelligence (CVSS, EPSS, CWE)

**Data Flow:**
```
OpenVAS/Nessus → Scan Results (XML/JSON) → Parser → Database
                                                ↓
                                        NVD API (CVSS)
                                        EPSS API (Exploit Probability)
                                        CISA KEV (Known Exploits)
```

**Key Design Decisions:**
- **Staggered Scanning**: Delays between targets to prevent network saturation
- **Retry Logic**: Exponential backoff for failed scans
- **Incremental Updates**: Only rescan changed assets to reduce overhead

---

### 2. Prioritisation Engine

**Responsibilities:**
- Calculate business risk scores (0-100 scale)
- Assign SLA deadlines based on severity
- Track risk score history for trend analysis
- Identify high-ROI remediation opportunities

**Risk Calculation Formula:**
```python
Business Risk Score = (
    (CVSS_Base_Score * 0.4) +
    (EPSS_Score * 0.3) +
    (Asset_Criticality * 0.2) +
    (Remediation_Difficulty * 0.1)
) * 10  # Normalize to 0-100
```

**Weighting Rationale:**
- **CVSS (40%)**: Technical severity is most important
- **EPSS (30%)**: Exploit probability determines real-world risk
- **Asset Criticality (20%)**: Business impact varies by asset
- **Remediation Difficulty (10%)**: Operational burden affects prioritization

**SLA Tiers:**
| Risk Score | Priority | Deadline |
|------------|----------|----------|
| ≥80 | CRITICAL | 7 days |
| 60-79 | HIGH | 30 days |
| 40-59 | MEDIUM | 90 days |
| <40 | LOW | 365 days |

---

### 3. Database Schema

**Core Tables:**

```sql
-- Vulnerabilities (1:N with Assets)
vulnerabilities
├── id (PK)
├── cve_id (UNIQUE)
├── cvss_base_score
├── epss_score
├── business_risk_score
├── remediation_status
├── remediation_deadline
└── jira_ticket_id

-- Assets (1:N with Vulnerabilities)
assets
├── id (PK)
├── hostname (UNIQUE)
├── ip_address
├── asset_type
├── criticality (1-10)
└── owner_team

-- Association Table
asset_vulnerability
├── asset_id (FK)
├── vulnerability_id (FK)
└── discovered_date

-- Scans (Execution Tracking)
scans
├── id (PK)
├── scan_id (UNIQUE)
├── scan_type
├── start_time
├── vulnerabilities_found
└── status

-- Remediation Tickets (Jira Sync)
remediation_tickets
├── id (PK)
├── vulnerability_id (FK)
├── ticket_id (UNIQUE)
├── sla_deadline
├── status
└── sla_met

-- Patches (ROI Analysis)
patches
├── id (PK)
├── patch_id (UNIQUE)
├── vendor
├── estimated_deployment_hours
└── roi_score

-- Risk History (Trend Analysis)
risk_history
├── id (PK)
├── vulnerability_id (FK)
├── business_risk_score
├── snapshot_reason
└── recorded_at
```

**Indexing Strategy:**
- `vulnerabilities.cve_id` (UNIQUE)
- `vulnerabilities.business_risk_score` (DESC) - for prioritization queries
- `vulnerabilities.remediation_deadline` (ASC) - for SLA monitoring
- `assets.hostname` (UNIQUE)
- `asset_vulnerability (asset_id, vulnerability_id)` - for lookups

---

### 4. API Gateway (FastAPI)

**Endpoints:**

```
GET    /api/vulnerabilities
       Query params: ?sort=risk_score&limit=10&min_risk=60

GET    /api/vulnerabilities/{cve_id}
       Returns: Full vulnerability details with affected assets

POST   /api/scans
       Body: {"target": "192.168.1.0/24", "scan_type": "FULL"}

GET    /api/scans/{scan_id}
       Returns: Scan status and results

GET    /api/patches/high-impact
       Query params: ?top=5
       Returns: Top N patches by ROI

GET    /api/metrics/sla-compliance
       Returns: SLA compliance statistics

POST   /api/vulnerabilities/{id}/update-status
       Body: {"status": "RESOLVED"}

GET    /health
       Returns: Service health check
```

**Authentication:**
- API Key authentication (X-API-Key header)
- JWT tokens for user sessions
- Role-based access control (RBAC) for multi-tenant scenarios

---

### 5. Workflow Engine (Celery + Redis)

**Background Tasks:**

```python
# Scheduled Tasks (Celery Beat)
@celery.task(name="daily_vulnerability_scan")
def daily_scan():
    """Run daily incremental scans"""

@celery.task(name="weekly_full_scan")
def weekly_full_scan():
    """Run comprehensive weekly scan"""

@celery.task(name="nightly_risk_scoring")
def nightly_risk_scoring():
    """Recalculate risk scores for all open vulnerabilities"""

@celery.task(name="monthly_executive_report")
def generate_executive_report():
    """Generate and email monthly report"""

# Event-Driven Tasks
@celery.task(name="create_jira_ticket")
def create_jira_ticket(vulnerability_id):
    """Create Jira ticket for high-risk vulnerability"""

@celery.task(name="enrich_vulnerability")
def enrich_vulnerability(cve_id):
    """Fetch CVSS, EPSS, CWE data from external APIs"""
```

**Queue Configuration:**
- **Priority Queue**: High-risk vulnerability processing
- **Default Queue**: Standard tasks
- **Low-Priority Queue**: Report generation, cleanup

---

### 6. Reporting Engine

**Report Types:**

1. **Executive Summary (Monthly)**
   - Total vulnerabilities by severity
   - Risk reduction metrics (vs. last month)
   - Financial impact (AUD breach cost estimation)
   - Compliance status (NIST, ISO, CIS)

2. **Technical Report (Weekly)**
   - New vulnerabilities discovered
   - Remediation progress by team
   - Overdue tickets
   - Patch deployment recommendations

3. **Compliance Report (Quarterly)**
   - Framework mapping (NIST 800-53, ISO 27001)
   - Coverage percentages
   - Evidence of remediation activities

**Export Formats:**
- PDF (for executives)
- HTML (for email distribution)
- JSON (for API consumers)
- CSV (for data analysis)

---

## Data Flow Diagrams

### Scan → Score → Remediate Flow

```
┌──────────────┐
│   Scanner    │ (1) Initiate Scan
│ Orchestrator │──────────────┐
└──────────────┘              │
                              ▼
                    ┌────────────────┐
                    │  OpenVAS/Nessus│
                    └────────┬───────┘
                             │ (2) Return Results
                             ▼
                    ┌────────────────┐
                    │  Result Parser │
                    └────────┬───────┘
                             │ (3) Normalize Data
                             ▼
                    ┌────────────────┐
                    │   PostgreSQL   │◄────┐
                    └────────┬───────┘     │
                             │             │ (5) Store Enriched Data
                             ▼             │
                    ┌────────────────┐     │
                    │  Enrichment    │     │
                    │  (NVD/EPSS)    │─────┘
                    └────────┬───────┘
                             │ (6) Trigger Scoring
                             ▼
                    ┌────────────────┐
                    │ Prioritisation │
                    │     Engine     │
                    └────────┬───────┘
                             │ (7) Calculate Risk Score
                             ▼
                    ┌────────────────┐
                    │  SLA Calculator│
                    └────────┬───────┘
                             │ (8) Set Deadline
                             ▼
                    ┌────────────────┐
                    │ Jira Workflow  │
                    │  (if risk ≥60) │
                    └────────────────┘
```

### Risk Scoring Detail

```
Vulnerability
    ├─ CVSS Base Score (from NVD)
    ├─ EPSS Score (from FIRST.org)
    ├─ Asset Criticality (from Asset DB)
    │   └─ Calculate Average across affected assets
    ├─ Remediation Difficulty (manual input or ML model)
    │
    └─► Business Risk Score = Weighted Sum
        └─► SLA Deadline = f(Risk Score)
```

---

## Scalability Considerations

### Horizontal Scaling

**Stateless Services:**
- API Gateway (FastAPI): Can run multiple instances behind load balancer
- Celery Workers: Add workers to process more background tasks

**Stateful Services:**
- PostgreSQL: Master-slave replication for read scaling
- Redis: Cluster mode for task queue scaling

### Performance Optimizations

1. **Database Query Optimization**
   - Composite indexes on frequently queried columns
   - Materialized views for dashboard metrics
   - Connection pooling (20 connections, 10 overflow)

2. **Caching Strategy**
   - Redis cache for EPSS scores (24h TTL)
   - In-memory cache for CVSS lookups
   - Dashboard metric caching (5min TTL)

3. **Batch Processing**
   - Bulk insert scan results (1000 per batch)
   - Batch EPSS API calls (100 CVEs per request)
   - Parallel vulnerability scoring (multiprocessing)

---

## Security Architecture

### Authentication & Authorization

```
User → API Key → FastAPI Middleware → RBAC Check → Route Handler
                                    ↓
                            JWT Token Validation
```

**Roles:**
- **Admin**: Full access to all endpoints
- **Analyst**: Read vulnerabilities, update status, create tickets
- **Viewer**: Read-only access to dashboards and reports

### Data Protection

- **Encryption at Rest**: PostgreSQL TDE (Transparent Data Encryption)
- **Encryption in Transit**: TLS 1.3 for all API communications
- **Secrets Management**: Environment variables, AWS Secrets Manager (production)
- **API Rate Limiting**: 100 requests/minute per API key

### Vulnerability Data Handling

- **No PII Storage**: Only technical vulnerability data
- **Audit Logging**: All status changes tracked with user, timestamp
- **Access Controls**: Row-level security for multi-tenant deployments

---

## Deployment Architecture

### Development (Docker Compose)

```
localhost:8000  → API (FastAPI)
localhost:3000  → Grafana
localhost:5432  → PostgreSQL
localhost:6379  → Redis
localhost:9390  → OpenVAS
```

### Production (Kubernetes - Future)

```
Ingress Controller (NGINX)
    ├─► api-deployment (3 replicas)
    ├─► celery-worker-deployment (5 replicas)
    ├─► celery-beat-deployment (1 replica)
    ├─► grafana-deployment (2 replicas)
    │
    └─► PostgreSQL (StatefulSet)
        Redis (StatefulSet)
```

---

## Monitoring & Observability

### Metrics (Prometheus)

- **API Metrics**: Request rate, latency (p50, p95, p99), error rate
- **Database Metrics**: Connection pool usage, query duration
- **Scan Metrics**: Scans completed, vulnerabilities discovered, scan duration
- **Business Metrics**: Open vulnerabilities, SLA compliance rate, risk score distribution

### Logging (Structured JSON)

```json
{
  "timestamp": "2024-11-15T10:30:00Z",
  "level": "INFO",
  "service": "prioritisation_engine",
  "message": "Scored CVE-2024-1234",
  "cve_id": "CVE-2024-1234",
  "risk_score": 56.25,
  "priority": "HIGH",
  "trace_id": "abc123"
}
```

### Alerting (Future)

- **Critical**: SLA compliance <90%, API error rate >5%
- **Warning**: Risk score calculation failures >1%
- **Info**: Monthly report generation completed

---

## Technology Justification

| Technology | Alternatives Considered | Why Chosen |
|------------|------------------------|------------|
| **FastAPI** | Flask, Django REST | Async support, auto OpenAPI docs, type hints |
| **PostgreSQL** | MySQL, MongoDB | JSONB support, strong consistency, mature |
| **Celery** | RQ, Dramatiq | Wide adoption, feature-rich, battle-tested |
| **Docker** | Vagrant, bare metal | Reproducibility, easy deployment, isolation |
| **SQLAlchemy** | Raw SQL, Django ORM | Flexibility, database-agnostic, migrations |
| **Grafana** | Kibana, Tableau | Open-source, time-series focus, customizable |

---

## Future Architecture Enhancements

1. **Machine Learning Integration**
   - Predict patch deployment success rate
   - Anomaly detection for unusual vulnerability patterns
   - Auto-classification of vulnerability types

2. **Event-Driven Architecture**
   - Kafka/RabbitMQ for event streaming
   - Real-time vulnerability notifications
   - Webhook support for external integrations

3. **Multi-Tenancy**
   - Schema-per-tenant isolation
   - Tenant-specific risk scoring weights
   - Cross-tenant analytics for MSSPs

4. **Cloud-Native Features**
   - AWS Lambda for serverless scanning
   - S3 for scan result archival
   - CloudWatch for centralized logging

---

## API Performance Benchmarks

| Endpoint | Avg Latency | Throughput | Database Queries |
|----------|-------------|------------|------------------|
| `GET /vulnerabilities` | 45ms | 200 req/s | 1 (with pagination) |
| `GET /vulnerabilities/{id}` | 12ms | 500 req/s | 2 (vuln + assets) |
| `POST /scans` | 80ms | 50 req/s | 3 (insert + update) |
| `GET /patches/high-impact` | 120ms | 30 req/s | 5 (complex joins) |

**Tested with:**
- Dataset: 10,000 vulnerabilities, 1,000 assets
- Tool: Apache Bench (ab)
- Concurrency: 50 concurrent users

---

## Conclusion

VMP's architecture prioritizes:
- **Modularity**: Each component can be developed/deployed independently
- **Scalability**: Stateless services allow horizontal scaling
- **Maintainability**: Clear separation of concerns, comprehensive logging
- **Extensibility**: Plugin architecture for new scanners/integrations

See [SETUP.md](SETUP.md) for deployment instructions.
