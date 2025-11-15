# VMP API Documentation

## Base URL

```
http://localhost:8000
```

## Authentication

API authentication is configurable via environment variables. By default, the API is accessible without authentication in development mode.

For production deployments:

```bash
# Set API key in .env
API_KEY_HEADER=X-API-Key
API_KEY=your-secret-api-key-here
```

Include the API key in request headers:

```bash
curl -H "X-API-Key: your-secret-api-key-here" http://localhost:8000/api/vulnerabilities
```

---

## Interactive Documentation

FastAPI provides auto-generated interactive API documentation:

- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc
- **OpenAPI JSON**: http://localhost:8000/openapi.json

---

## API Endpoints

### Health & Status

#### GET `/`

Root endpoint providing API information.

**Response:**

```json
{
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
```

#### GET `/health`

Health check endpoint for monitoring and load balancers.

**Response:**

```json
{
  "status": "healthy",
  "version": "1.0.0",
  "timestamp": "2024-11-15T10:30:00Z",
  "services": {
    "database": "up",
    "api": "up"
  }
}
```

---

### Vulnerabilities

#### GET `/api/vulnerabilities`

List vulnerabilities with filtering, sorting, and pagination.

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `skip` | integer | 0 | Number of records to skip (pagination) |
| `limit` | integer | 100 | Maximum records to return (max: 1000) |
| `min_risk` | float | 0.0 | Minimum business risk score (0-100) |
| `sort` | string | "risk_score" | Sort field: `risk_score`, `discovered_date`, `cve_id` |

**Example Request:**

```bash
curl "http://localhost:8000/api/vulnerabilities?min_risk=80&limit=10&sort=risk_score"
```

**Example Response:**

```json
{
  "total": 156,
  "skip": 0,
  "limit": 10,
  "data": [
    {
      "id": 1,
      "cve_id": "CVE-2021-44228",
      "title": "Apache Log4j2 Remote Code Execution (Log4Shell)",
      "cvss_base_score": 10.0,
      "cvss_severity": "CRITICAL",
      "epss_score": 0.975,
      "business_risk_score": 95.2,
      "remediation_status": "OPEN",
      "remediation_deadline": "2024-11-22T00:00:00Z",
      "affected_assets_count": 12,
      "jira_ticket_id": "VULN-123",
      "discovered_date": "2024-11-15T08:00:00Z"
    }
  ]
}
```

#### GET `/api/vulnerabilities/{cve_id}`

Get detailed information about a specific vulnerability.

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `cve_id` | string | CVE identifier (e.g., CVE-2024-1234) |

**Example Request:**

```bash
curl "http://localhost:8000/api/vulnerabilities/CVE-2021-44228"
```

**Example Response:**

```json
{
  "id": 1,
  "cve_id": "CVE-2021-44228",
  "title": "Apache Log4j2 Remote Code Execution (Log4Shell)",
  "description": "Remote code execution vulnerability in Apache Log4j2...",
  "cvss_base_score": 10.0,
  "cvss_version": "3.1",
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
  "cvss_severity": "CRITICAL",
  "epss_score": 0.975,
  "epss_percentile": 99.8,
  "business_risk_score": 95.2,
  "risk_score_explanation": "Business Risk Score: 95.2/100 (CRITICAL)...",
  "cwe_ids": ["CWE-502", "CWE-400"],
  "exploit_available": true,
  "in_cisa_kev": true,
  "remediation_status": "OPEN",
  "remediation_deadline": "2024-11-22T00:00:00Z",
  "remediation_notes": null,
  "jira_ticket_id": "VULN-123",
  "jira_ticket_url": "https://company.atlassian.net/browse/VULN-123",
  "affected_assets": [
    {
      "id": 5,
      "hostname": "web-prod-01",
      "ip_address": "10.0.1.10",
      "asset_type": "SERVER",
      "criticality": 9
    }
  ],
  "discovered_date": "2024-11-15T08:00:00Z",
  "last_scanned": "2024-11-15T10:00:00Z",
  "scan_count": 3
}
```

**Error Response (404):**

```json
{
  "detail": "Vulnerability CVE-9999-99999 not found"
}
```

---

### Assets

#### GET `/api/assets`

List all assets with pagination.

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `skip` | integer | 0 | Number of records to skip |
| `limit` | integer | 100 | Maximum records to return |

**Example Request:**

```bash
curl "http://localhost:8000/api/assets?limit=20"
```

**Example Response:**

```json
{
  "total": 45,
  "skip": 0,
  "limit": 20,
  "data": [
    {
      "id": 1,
      "hostname": "web-prod-01",
      "ip_address": "10.0.1.10",
      "asset_type": "SERVER",
      "criticality": 9,
      "owner_team": "Platform",
      "environment": "PRODUCTION",
      "vulnerability_count": 8
    }
  ]
}
```

---

### Metrics & Statistics

#### GET `/api/metrics/summary`

Get high-level vulnerability metrics and statistics.

**Example Request:**

```bash
curl "http://localhost:8000/api/metrics/summary"
```

**Example Response:**

```json
{
  "total_vulnerabilities": 156,
  "by_priority": {
    "critical": 12,
    "high": 34,
    "medium": 68,
    "low": 42
  },
  "by_status": {
    "open": 98
  },
  "timestamp": "2024-11-15T10:30:00Z"
}
```

---

## Risk Scoring

### Business Risk Score Formula

```python
Business Risk Score = (
    (CVSS × 0.4) +
    (EPSS × 0.3) +
    (Asset_Criticality × 0.2) +
    (Remediation_Difficulty × 0.1)
) × 10
```

**Components:**

- **CVSS** (0-10): Technical severity from CVSS v3.1
- **EPSS** (0-1): Exploit prediction score (probability of exploitation within 30 days)
- **Asset Criticality** (1-10): Business importance of affected asset
- **Remediation Difficulty** (1-5): Complexity of fixing the vulnerability

**Risk Levels:**

| Score Range | Priority | SLA Deadline |
|-------------|----------|--------------|
| 80-100 | CRITICAL | 7 days |
| 60-79 | HIGH | 30 days |
| 40-59 | MEDIUM | 90 days |
| 0-39 | LOW | 365 days |

---

## Filtering Examples

### Get only CRITICAL vulnerabilities

```bash
curl "http://localhost:8000/api/vulnerabilities?min_risk=80"
```

### Get HIGH and CRITICAL vulnerabilities

```bash
curl "http://localhost:8000/api/vulnerabilities?min_risk=60"
```

### Get recently discovered vulnerabilities

```bash
curl "http://localhost:8000/api/vulnerabilities?sort=discovered_date&limit=50"
```

### Get vulnerabilities with pagination

```bash
# Page 1 (1-100)
curl "http://localhost:8000/api/vulnerabilities?skip=0&limit=100"

# Page 2 (101-200)
curl "http://localhost:8000/api/vulnerabilities?skip=100&limit=100"
```

---

## Rate Limiting

Default rate limits (configurable):

- **100 requests per minute** per IP address
- **1000 requests per hour** per API key

**Rate Limit Headers:**

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1637075400
```

**Rate Limit Exceeded Response (429):**

```json
{
  "detail": "Rate limit exceeded. Please try again in 45 seconds."
}
```

---

## Error Responses

### Standard Error Format

```json
{
  "detail": "Error message describing what went wrong"
}
```

### HTTP Status Codes

| Code | Meaning | Description |
|------|---------|-------------|
| 200 | OK | Request successful |
| 400 | Bad Request | Invalid request parameters |
| 401 | Unauthorized | Missing or invalid API key |
| 403 | Forbidden | Insufficient permissions |
| 404 | Not Found | Resource not found |
| 422 | Unprocessable Entity | Validation error |
| 429 | Too Many Requests | Rate limit exceeded |
| 500 | Internal Server Error | Server error |
| 503 | Service Unavailable | Service temporarily unavailable |

---

## CORS Configuration

Cross-Origin Resource Sharing (CORS) is enabled for:

```
http://localhost:3000  # Grafana
http://localhost:8000  # API itself
```

Configure additional origins in `.env`:

```bash
CORS_ORIGINS=http://localhost:3000,https://dashboard.company.com
```

---

## Webhooks

### Jira Webhook Integration

VMP can receive webhook notifications from Jira for status updates.

**Endpoint:** `POST /api/webhooks/jira`

**Payload Example:**

```json
{
  "webhookEvent": "jira:issue_updated",
  "issue": {
    "key": "VULN-123",
    "fields": {
      "status": {
        "name": "Done"
      }
    }
  }
}
```

---

## Code Examples

### Python (requests)

```python
import requests

# Get vulnerabilities
response = requests.get(
    'http://localhost:8000/api/vulnerabilities',
    params={'min_risk': 80, 'limit': 10},
    headers={'X-API-Key': 'your-api-key'}
)

vulnerabilities = response.json()['data']

for vuln in vulnerabilities:
    print(f"{vuln['cve_id']}: {vuln['business_risk_score']}")
```

### Python (httpx - async)

```python
import httpx
import asyncio

async def get_vulnerabilities():
    async with httpx.AsyncClient() as client:
        response = await client.get(
            'http://localhost:8000/api/vulnerabilities',
            params={'min_risk': 60}
        )
        return response.json()

vulnerabilities = asyncio.run(get_vulnerabilities())
```

### JavaScript (fetch)

```javascript
fetch('http://localhost:8000/api/vulnerabilities?min_risk=80')
  .then(response => response.json())
  .then(data => {
    console.log(`Total: ${data.total}`);
    data.data.forEach(vuln => {
      console.log(`${vuln.cve_id}: ${vuln.business_risk_score}`);
    });
  });
```

### cURL with jq

```bash
# Get top 5 critical vulnerabilities
curl -s "http://localhost:8000/api/vulnerabilities?min_risk=80&limit=5" | \
  jq '.data[] | {cve_id, risk: .business_risk_score, status: .remediation_status}'
```

---

## Monitoring & Metrics

### Prometheus Metrics

Metrics endpoint: `http://localhost:8000/metrics`

**Available Metrics:**

- `vmp_vulnerabilities_total` - Total number of vulnerabilities
- `vmp_vulnerabilities_by_priority` - Vulnerabilities grouped by priority
- `vmp_api_requests_total` - Total API requests
- `vmp_api_request_duration_seconds` - Request duration histogram
- `vmp_scan_duration_seconds` - Scan duration histogram
- `vmp_sla_compliance_ratio` - SLA compliance percentage

---

## Best Practices

1. **Use pagination** for large result sets
2. **Filter by risk score** to focus on high-priority vulnerabilities
3. **Cache responses** when appropriate (consider using ETags)
4. **Handle rate limits** with exponential backoff
5. **Monitor health endpoint** for service availability
6. **Use API keys** in production
7. **Enable HTTPS** for production deployments
8. **Validate input** on client side before sending requests

---

## Changelog

### v1.0.0 (2024-11-15)

- Initial API release
- Vulnerability management endpoints
- Asset management endpoints
- Metrics and statistics
- Health checks
- OpenAPI documentation

---

## Support

- **Documentation**: https://github.com/Raoof128/VMP/tree/main/docs
- **Issues**: https://github.com/Raoof128/VMP/issues
- **API Bugs**: Report via GitHub Issues with `api` label

---

**Last Updated**: 2024-11-15
