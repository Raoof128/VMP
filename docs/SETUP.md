# VMP Installation & Setup Guide

This guide walks you through setting up the Vulnerability Management Pipeline in development and production environments.

---

## Prerequisites

### Required Software

| Software | Minimum Version | Purpose |
|----------|----------------|---------|
| **Docker** | 20.10+ | Container runtime |
| **Docker Compose** | 2.0+ | Multi-container orchestration |
| **Python** | 3.11+ | For local development |
| **PostgreSQL** | 15+ | Database (if running outside Docker) |
| **Git** | 2.30+ | Version control |

### Optional Tools

- **Make** (for convenience commands)
- **Postman** or **curl** (for API testing)
- **pgAdmin** (PostgreSQL GUI)

### System Requirements

**Development Environment:**
- **CPU**: 4 cores minimum
- **RAM**: 8 GB minimum (16 GB recommended)
- **Disk**: 20 GB free space
- **OS**: macOS, Linux (Ubuntu 20.04+, Fedora 35+), Windows 10+ with WSL2

**Production Environment:**
- **CPU**: 8 cores minimum
- **RAM**: 16 GB minimum (32 GB recommended for 10K+ vulns)
- **Disk**: 100 GB SSD
- **OS**: Linux (Ubuntu 22.04 LTS recommended)

---

## Installation Methods

### Option 1: Docker Compose (Recommended)

This is the **fastest and easiest** method for development.

#### Step 1: Clone Repository

```bash
git clone https://github.com/Raoof128/VMP.git
cd VMP
```

#### Step 2: Configure Environment

```bash
# Copy environment template
cp .env.example .env

# Edit with your settings
nano .env  # or vim, code, etc.
```

**Required Configuration:**

```bash
# Database
DB_PASSWORD=your_secure_password_here

# OpenVAS (if using)
OPENVAS_PASSWORD=openvas_secure_password

# Jira Integration (optional for Phase 1)
JIRA_URL=https://your-company.atlassian.net
JIRA_API_TOKEN=your_jira_token_here

# NVD API Key (recommended for CVSS enrichment)
NVD_API_KEY=your_nvd_api_key_here  # Get from https://nvd.nist.gov/developers/request-an-api-key

# Grafana
GRAFANA_ADMIN_PASSWORD=grafana_secure_password
```

#### Step 3: Start Services

```bash
# Start all containers in background
docker-compose up -d

# Check status
docker-compose ps

# Expected output:
# NAME                 STATUS              PORTS
# vmp-postgres         Up (healthy)        5432
# vmp-redis            Up (healthy)        6379
# vmp-api              Up                  8000
# vmp-celery-worker    Up
# vmp-celery-beat      Up
# vmp-grafana          Up                  3000
# vmp-prometheus       Up                  9090
# vmp-openvas          Up                  9390, 9392
```

#### Step 4: Initialize Database

```bash
# Run database migrations
docker-compose exec api python -m src.database.engine

# Expected output:
# ✓ Database connection successful
# ✓ Database tables created successfully
```

#### Step 5: Verify Installation

```bash
# Test API health
curl http://localhost:8000/health

# Expected response:
# {"status": "healthy", "version": "1.0.0"}

# Access Grafana dashboard
open http://localhost:3000  # macOS
xdg-open http://localhost:3000  # Linux
```

**Default Credentials:**
- **Grafana**: admin / changeme_grafana_password (from .env)
- **OpenVAS**: admin / changeme_openvas_password (from .env)

#### Step 6: Load Sample Data (Optional)

```bash
# Load test vulnerabilities
docker-compose exec api python scripts/load_sample_data.py

# Expected output:
# ✓ Created 10 assets
# ✓ Loaded 100 vulnerabilities
# ✓ Calculated risk scores
```

**Total Installation Time: ~5 minutes**

---

### Option 2: Local Development (Python virtualenv)

For developers who want to run the API locally without Docker.

#### Step 1: Clone & Setup

```bash
git clone https://github.com/Raoof128/VMP.git
cd VMP

# Create virtual environment
python3.11 -m venv venv
source venv/bin/activate  # Linux/macOS
# OR
.\venv\Scripts\activate  # Windows

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt
```

#### Step 2: Setup PostgreSQL

**Option A: Use Docker for Database Only**
```bash
docker run -d \
  --name vmp-postgres \
  -e POSTGRES_DB=vuln_management \
  -e POSTGRES_USER=vmp_admin \
  -e POSTGRES_PASSWORD=changeme \
  -p 5432:5432 \
  postgres:15-alpine
```

**Option B: Install PostgreSQL Locally**
```bash
# macOS
brew install postgresql@15
brew services start postgresql@15

# Ubuntu/Debian
sudo apt-get install postgresql-15
sudo systemctl start postgresql

# Create database
createdb vuln_management
```

#### Step 3: Configure Environment

```bash
cp .env.example .env

# Update DATABASE_URL for local PostgreSQL
# DATABASE_URL=postgresql://vmp_admin:changeme@localhost:5432/vuln_management
```

#### Step 4: Initialize Database

```bash
python -m src.database.engine
```

#### Step 5: Run API Server

```bash
# Development mode (auto-reload)
uvicorn src.api.main:app --reload --host 0.0.0.0 --port 8000

# Production mode
uvicorn src.api.main:app --workers 4 --host 0.0.0.0 --port 8000
```

#### Step 6: Run Celery Workers (Separate Terminal)

```bash
# Terminal 2: Celery worker
celery -A src.workflow.celery_app worker --loglevel=info

# Terminal 3: Celery beat (scheduler)
celery -A src.workflow.celery_app beat --loglevel=info
```

---

## Post-Installation Configuration

### 1. Configure Jira Integration

```bash
# Test Jira connection
docker-compose exec api python -c "
from src.workflow.jira_integration import JiraWorkflowManager
jira = JiraWorkflowManager()
print('✓ Jira connection successful' if jira.test_connection() else '✗ Jira connection failed')
"
```

### 2. Setup Scheduled Scans

Edit `src/workflow/celery_app.py` to configure scan schedules:

```python
# Example: Daily incremental scan at 2 AM
@celery_app.on_after_configure.connect
def setup_periodic_tasks(sender, **kwargs):
    sender.add_periodic_task(
        crontab(hour=2, minute=0),  # 2:00 AM daily
        run_incremental_scan.s(),
        name='daily-incremental-scan'
    )
```

### 3. Configure Asset Inventory

```bash
# Import assets from CSV
docker-compose exec api python scripts/import_assets.py --file assets.csv

# CSV format:
# hostname,ip_address,asset_type,criticality,owner_team
# web-prod-01,192.168.1.10,SERVER,9,Platform Team
# db-prod-01,192.168.1.11,DATABASE,10,Data Team
```

### 4. Setup Grafana Dashboards

1. Login to Grafana: http://localhost:3000
2. Navigate to **Dashboards → Import**
3. Upload dashboards from `src/dashboard/grafana/dashboards/`
4. Select PostgreSQL datasource

**Pre-built Dashboards:**
- **Vulnerability Overview**: Risk distribution, SLA compliance
- **Executive Summary**: Financial impact, remediation trends
- **Compliance Dashboard**: NIST/ISO/CIS alignment

---

## OpenVAS Configuration

### Initial Setup (First Time Only)

OpenVAS requires initial setup after first start:

```bash
# Wait for OpenVAS to initialize (takes 5-10 minutes)
docker-compose logs -f openvas

# When you see "greenbone-security-assistant started successfully":
# Access OpenVAS web UI
open http://localhost:9392

# Login: admin / changeme_openvas_password
```

### Configure Scan Targets

1. Navigate to **Configuration → Targets**
2. Click **New Target**
3. Enter:
   - **Name**: Production Network
   - **Hosts**: 192.168.1.0/24 (or your IP range)
   - **Port List**: All TCP and UDP
4. Save

### Create Scan Task

1. Navigate to **Scans → Tasks**
2. Click **New Task**
3. Configure:
   - **Name**: Weekly Full Scan
   - **Scan Targets**: Production Network
   - **Scanner**: OpenVAS Default
   - **Schedule**: Create schedule (e.g., Weekly on Sundays at 2 AM)
4. Save

### Integrate with VMP

VMP will automatically fetch scan results via OpenVAS API. Verify:

```bash
# Test OpenVAS connection
docker-compose exec api python -c "
from src.scanner.openvas_client import OpenVASClient
client = OpenVASClient()
print('✓ OpenVAS connection successful' if client.test_connection() else '✗ Failed')
"
```

---

## Troubleshooting

### Issue: "Database connection failed"

**Solution 1: Check PostgreSQL is running**
```bash
docker-compose ps postgres

# If not running:
docker-compose up -d postgres
```

**Solution 2: Verify credentials**
```bash
# Check .env file
cat .env | grep DB_

# Test connection manually
docker-compose exec postgres psql -U vmp_admin -d vuln_management -c "SELECT 1;"
```

---

### Issue: "OpenVAS not accessible"

**Solution: Wait for initialization**
```bash
# OpenVAS takes 5-10 minutes to initialize on first start
docker-compose logs -f openvas

# Look for: "greenbone-security-assistant started successfully"
```

---

### Issue: "Grafana dashboard shows no data"

**Solution 1: Check PostgreSQL datasource**
1. Grafana → Configuration → Data Sources
2. Select PostgreSQL
3. Click "Test" → Should show "Database connection OK"

**Solution 2: Verify vulnerabilities exist**
```bash
docker-compose exec api python -c "
from src.database.engine import get_db_context
from src.database.models import Vulnerability
with get_db_context() as db:
    count = db.query(Vulnerability).count()
    print(f'Vulnerabilities in database: {count}')
"
```

---

### Issue: "Celery tasks not running"

**Solution: Check Redis connection**
```bash
# Test Redis
docker-compose exec redis redis-cli ping

# Expected: PONG

# Check Celery worker logs
docker-compose logs celery-worker
```

---

### Issue: "Out of memory"

**Solution: Increase Docker resource limits**

**macOS/Windows Docker Desktop:**
1. Docker Desktop → Settings → Resources
2. Increase Memory to 8GB+ (16GB recommended)
3. Apply & Restart

**Linux:**
```bash
# Check available memory
free -h

# OpenVAS requires 2GB minimum
# PostgreSQL requires 2GB for 10K+ vulnerabilities
# Total recommended: 8GB system RAM
```

---

## Performance Tuning

### Database Optimization

```sql
-- Create indexes for common queries
CREATE INDEX idx_vuln_risk_score ON vulnerabilities(business_risk_score DESC);
CREATE INDEX idx_vuln_status ON vulnerabilities(remediation_status);
CREATE INDEX idx_vuln_deadline ON vulnerabilities(remediation_deadline);

-- Analyze tables
ANALYZE vulnerabilities;
ANALYZE assets;
```

### API Scaling

```yaml
# docker-compose.yml
api:
  deploy:
    replicas: 3  # Run 3 API instances
    resources:
      limits:
        cpus: '2'
        memory: 4G
```

### Celery Worker Scaling

```bash
# Scale workers horizontally
docker-compose up -d --scale celery-worker=5

# 5 workers for parallel scan processing
```

---

## Backup & Recovery

### Database Backup

```bash
# Backup database
docker-compose exec postgres pg_dump -U vmp_admin vuln_management > backup.sql

# Restore
docker-compose exec -T postgres psql -U vmp_admin vuln_management < backup.sql
```

### Configuration Backup

```bash
# Backup environment and configs
tar -czf vmp-config-backup.tar.gz .env config/ src/dashboard/grafana/
```

---

## Upgrading VMP

```bash
# Pull latest changes
git pull origin main

# Rebuild containers
docker-compose down
docker-compose build --no-cache
docker-compose up -d

# Run database migrations
docker-compose exec api alembic upgrade head
```

---

## Uninstallation

### Remove All Containers & Data

```bash
# Stop and remove containers
docker-compose down

# Remove volumes (WARNING: deletes all data)
docker-compose down -v

# Remove images
docker rmi $(docker images -q 'vmp-*')
```

### Remove Python Environment

```bash
# Deactivate virtualenv
deactivate

# Remove directory
rm -rf venv/
```

---

## Production Deployment Checklist

- [ ] Change all default passwords in `.env`
- [ ] Generate secure `SECRET_KEY` for JWT
- [ ] Enable TLS/SSL for API (use nginx reverse proxy)
- [ ] Configure firewall rules (allow only necessary ports)
- [ ] Setup automated backups (daily database dumps)
- [ ] Configure email alerts (SMTP settings)
- [ ] Enable audit logging (all API requests)
- [ ] Setup monitoring alerts (Prometheus → Alertmanager)
- [ ] Document disaster recovery procedures
- [ ] Implement rate limiting (API throttling)
- [ ] Enable container security scanning (Trivy, Clair)

---

## Getting Help

- **Documentation**: See [docs/](../docs/)
- **GitHub Issues**: https://github.com/Raoof128/VMP/issues
- **Email**: your.email@example.com

---

## Next Steps

After installation:

1. **Load Sample Data**: `python scripts/load_sample_data.py`
2. **Run First Scan**: See [Scanner Documentation](SCANNER.md)
3. **Configure Dashboards**: Import Grafana templates
4. **Setup Jira Integration**: Test ticket creation
5. **Generate First Report**: `python src/reporting/executive_report.py`

See [README.md](../README.md) for usage examples.
