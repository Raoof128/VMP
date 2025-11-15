# VMP Quick Start Guide

Get your Vulnerability Management Pipeline up and running in under 10 minutes!

## Prerequisites

- Docker Desktop installed and running
- Git installed
- 4GB+ RAM available
- 10GB+ free disk space

## Quick Install (Docker - Recommended)

### 1. Clone the Repository

```bash
git clone https://github.com/Raoof128/VMP.git
cd VMP
```

### 2. Configure Environment

```bash
# Copy example environment file
cp .env.example .env

# Edit .env if needed (optional for demo)
# Default values work out of the box
```

### 3. Start All Services

```bash
# One command to rule them all!
make quickstart
```

This will:
- Start PostgreSQL, Redis, OpenVAS, and other services
- Initialize the database schema
- Load 100 sample vulnerabilities
- Start the API server
- Start Celery workers

**Total time: ~3-5 minutes** (depending on your internet speed for Docker images)

### 4. Access the Services

Open your browser and visit:

- **API Documentation**: http://localhost:8000/docs
- **Grafana Dashboard**: http://localhost:3000 (admin/changeme_grafana_password)
- **API Health Check**: http://localhost:8000/health

---

## Explore the Demo

### View Vulnerabilities

```bash
# Get top 10 critical vulnerabilities
curl "http://localhost:8000/api/vulnerabilities?min_risk=80&limit=10" | jq
```

### Run Interactive Demo

```bash
make demo
```

This interactive demo will walk you through:
- Risk scoring examples
- SLA deadline calculation
- Vulnerability prioritization
- Patch ROI analysis
- Business impact quantification

### Generate Executive Report

```bash
make report
```

View the generated report at: `reports/executive_report_YYYY-MM.html`

---

## Manual Setup (For Development)

### 1. Create Virtual Environment

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 2. Install Dependencies

```bash
# Production dependencies
pip install -r requirements.txt

# Development dependencies (optional)
pip install -r requirements-dev.txt
```

### 3. Start Supporting Services

```bash
# Start PostgreSQL and Redis
docker-compose up -d postgres redis
```

### 4. Initialize Database

```bash
# Create database tables
python -c "from src.database.engine import init_db; init_db()"

# Load sample data
python scripts/load_sample_data.py
```

### 5. Start API Server

```bash
# Development mode with auto-reload
uvicorn src.api.main:app --reload --host 0.0.0.0 --port 8000
```

### 6. Start Celery Workers (Optional)

```bash
# In another terminal
celery -A src.workflow.celery_app worker --loglevel=info

# In another terminal (for scheduled tasks)
celery -A src.workflow.celery_app beat --loglevel=info
```

---

## Common Commands

```bash
# Start all services
make docker-up

# Stop all services
make docker-down

# View logs
make logs

# Run tests
make test

# View API logs
docker-compose logs -f api

# Access database
make db-shell

# Restart API service
docker-compose restart api

# View Celery worker logs
docker-compose logs -f celery-worker
```

---

## First Steps After Installation

### 1. Explore the API

Visit http://localhost:8000/docs to see:
- All available endpoints
- Request/response schemas
- Try out API calls directly in the browser

### 2. Check Metrics

```bash
curl http://localhost:8000/api/metrics/summary | jq
```

Expected output:
```json
{
  "total_vulnerabilities": 100,
  "by_priority": {
    "critical": 10,
    "high": 25,
    "medium": 35,
    "low": 30
  },
  "by_status": {
    "open": 80
  },
  "timestamp": "2024-11-15T10:30:00Z"
}
```

### 3. View Top Vulnerabilities

```bash
curl "http://localhost:8000/api/vulnerabilities?sort=risk_score&limit=5" | jq '.data[] | {cve_id, risk: .business_risk_score, title}'
```

### 4. Configure Grafana Dashboard

1. Navigate to http://localhost:3000
2. Login: `admin` / `changeme_grafana_password`
3. Go to **Dashboards** → **Import**
4. Select `src/dashboard/grafana/dashboards/vmp-vulnerability-overview.json`
5. Choose **VMP PostgreSQL** as the data source
6. Click **Import**

---

## Configuration Tips

### Customize Risk Weights

Edit `.env`:

```bash
# Default: CVSS=40%, EPSS=30%, Asset=20%, Remediation=10%
RISK_WEIGHT_CVSS=0.4
RISK_WEIGHT_EPSS=0.3
RISK_WEIGHT_ASSET_CRITICALITY=0.2
RISK_WEIGHT_REMEDIATION_DIFFICULTY=0.1
```

### Adjust SLA Deadlines

```bash
# Default values
SLA_CRITICAL_DAYS=7
SLA_HIGH_DAYS=30
SLA_MEDIUM_DAYS=90
SLA_LOW_DAYS=365
```

### Configure Scanner

```bash
OPENVAS_HOST=openvas
OPENVAS_PORT=9390
OPENVAS_USERNAME=admin
OPENVAS_PASSWORD=changeme_openvas_password
```

### Enable Jira Integration

```bash
JIRA_ENABLED=True
JIRA_URL=https://your-company.atlassian.net
JIRA_USERNAME=your.email@company.com
JIRA_API_TOKEN=your_jira_api_token
JIRA_PROJECT_KEY=VULN
```

---

## Troubleshooting

### Port Already in Use

If port 8000, 5432, or 3000 is already in use:

```bash
# Change ports in docker-compose.yml
ports:
  - "8001:8000"  # Change 8000 to 8001
```

### Database Connection Error

```bash
# Check if PostgreSQL is running
docker-compose ps postgres

# View PostgreSQL logs
docker-compose logs postgres

# Restart PostgreSQL
docker-compose restart postgres
```

### OpenVAS Not Starting

OpenVAS requires significant resources:

```bash
# Check Docker resource allocation
docker stats

# Increase Docker memory to 4GB+ in Docker Desktop settings
```

### API Returns 500 Error

```bash
# Check API logs
docker-compose logs api

# Check database connection
docker-compose exec api python -c "from src.database.engine import DatabaseManager; print(DatabaseManager.check_connection())"
```

---

## Sample Queries

### Get All CRITICAL Vulnerabilities

```bash
curl "http://localhost:8000/api/vulnerabilities?min_risk=80" | jq
```

### Get Specific Vulnerability Details

```bash
curl "http://localhost:8000/api/vulnerabilities/CVE-2021-44228" | jq
```

### Get Assets

```bash
curl "http://localhost:8000/api/assets" | jq
```

### Check API Health

```bash
curl "http://localhost:8000/health" | jq
```

---

## Next Steps

1. **Customize Configuration**: Edit `.env` for your environment
2. **Add Real Scanners**: Configure OpenVAS or Nessus credentials
3. **Enable Jira**: Set up Jira integration for ticket management
4. **Configure Scanning**: Schedule automated scans
5. **Set Up Monitoring**: Configure Grafana alerts
6. **Review Documentation**: Read full docs in `docs/` directory

---

## Production Deployment Checklist

Before deploying to production:

- [ ] Change all default passwords in `.env`
- [ ] Enable TLS/SSL certificates
- [ ] Configure firewall rules
- [ ] Set up database backups
- [ ] Enable API authentication
- [ ] Configure log aggregation
- [ ] Set up monitoring and alerts
- [ ] Review security settings
- [ ] Configure rate limiting
- [ ] Set up CI/CD pipeline

See [docs/SETUP.md](docs/SETUP.md) for detailed production deployment guide.

---

## Learning Resources

- **Architecture Overview**: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- **Risk Scoring Model**: [docs/RISK_MODEL.md](docs/RISK_MODEL.md)
- **API Reference**: [docs/API.md](docs/API.md)
- **Contributing Guide**: [CONTRIBUTING.md](CONTRIBUTING.md)
- **Security Policy**: [SECURITY.md](SECURITY.md)

---

## Getting Help

- **GitHub Issues**: https://github.com/Raoof128/VMP/issues
- **Documentation**: https://github.com/Raoof128/VMP/tree/main/docs
- **Examples**: Check `scripts/demo.py`

---

**Quick Start Complete!** 🎉

You now have a fully functional Vulnerability Management Pipeline running locally. Explore the API, customize the configuration, and integrate with your existing security tools!
