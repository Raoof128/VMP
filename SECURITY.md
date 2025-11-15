# Security Policy

## Supported Versions

We actively support the following versions of VMP with security updates:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

---

## Reporting a Vulnerability

**Please do NOT report security vulnerabilities through public GitHub issues.**

We take security seriously. If you discover a security vulnerability in VMP, please report it privately to allow us to address it before public disclosure.

### How to Report

1. **Email**: Send details to **security@your-organization.com** (replace with actual email)
2. **Subject Line**: Use "VMP Security Vulnerability Report"
3. **Include**:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if available)
   - Your contact information

### What to Expect

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 5 business days
- **Progress Updates**: Every 7 days
- **Resolution Timeline**: Varies by severity (see below)

### Severity Levels

| Severity | Response Time | Fix Timeline |
|----------|--------------|--------------|
| **Critical** | 24 hours | 7 days |
| **High** | 48 hours | 30 days |
| **Medium** | 5 days | 90 days |
| **Low** | 7 days | Next release |

---

## Security Measures

### Application Security

VMP implements multiple security layers:

#### 1. Authentication & Authorization
- **API Keys**: Required for all API endpoints (configurable)
- **JWT Tokens**: For session management (optional)
- **Role-Based Access Control** (RBAC): Planned for v1.1

#### 2. Data Protection
- **Encryption at Rest**: Database encryption recommended
- **Encryption in Transit**: TLS 1.3 for all network communication
- **Secrets Management**: Environment variables, never in code
- **Credential Scanning**: Automated via Bandit and pre-commit hooks

#### 3. Input Validation
- **SQL Injection Prevention**: SQLAlchemy ORM with parameterized queries
- **XSS Protection**: FastAPI automatic HTML escaping
- **CSRF Protection**: Implemented for state-changing operations
- **Request Size Limits**: Configured in API gateway

#### 4. Dependency Management
- **Automated Scanning**: Dependabot enabled
- **Safety Checks**: Vulnerability scanning in CI/CD
- **Regular Updates**: Monthly dependency review

#### 5. Docker Security
- **Non-Root User**: Application runs as `vmpuser` (UID 1000)
- **Minimal Base Image**: Python 3.11-slim
- **Read-Only Filesystem**: Where possible
- **Resource Limits**: Configured in docker-compose.yml

#### 6. Network Security
- **Firewall Rules**: Recommended in production
- **Network Isolation**: Docker bridge network
- **Rate Limiting**: Configured for API endpoints
- **DDoS Protection**: CloudFlare or equivalent recommended

---

## Security Best Practices

### For Developers

#### Code Security
```python
# ❌ BAD - Vulnerable to SQL injection
query = f"SELECT * FROM vulnerabilities WHERE cve_id = '{user_input}'"

# ✅ GOOD - Parameterized query
query = db.query(Vulnerability).filter(Vulnerability.cve_id == user_input)
```

#### Secrets Management
```python
# ❌ BAD - Hardcoded credentials
JIRA_API_TOKEN = "abc123xyz"

# ✅ GOOD - Environment variables
JIRA_API_TOKEN = os.getenv("JIRA_API_TOKEN")
```

#### Error Handling
```python
# ❌ BAD - Exposes internal details
except Exception as e:
    return {"error": str(e), "traceback": traceback.format_exc()}

# ✅ GOOD - Generic error message
except Exception as e:
    logger.error(f"Internal error: {e}")
    return {"error": "Internal server error"}
```

### For Deployment

#### Environment Variables
```bash
# Never commit these files
.env
.env.production
credentials.json
*.pem
*.key
```

#### Docker Security
```yaml
# docker-compose.yml
services:
  api:
    # Use specific version tags, not 'latest'
    image: vmp:1.0.0

    # Run as non-root user
    user: "1000:1000"

    # Read-only root filesystem
    read_only: true

    # Drop all capabilities
    cap_drop:
      - ALL

    # Resource limits
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 2G
```

#### Network Configuration
```yaml
# Isolate services
networks:
  frontend:
    driver: bridge
  backend:
    driver: bridge
    internal: true  # No external access
```

---

## Known Security Considerations

### OpenVAS Scanner Integration
- **Network Access**: OpenVAS requires network access to scan targets
- **Credential Storage**: Scanner credentials stored in environment variables
- **Scan Results**: May contain sensitive information; restrict access

### Database
- **Connection String**: Contains credentials; never log or expose
- **Data Sensitivity**: Vulnerability data may reveal internal infrastructure
- **Backups**: Encrypt backups and restrict access

### Jira Integration
- **API Tokens**: Use tokens, not passwords
- **Webhook Security**: Validate webhook signatures
- **Data Exposure**: Vulnerability details in Jira tickets; review permissions

### Third-Party APIs
- **NVD API**: Public data, but rate limits apply
- **EPSS API**: Public data, no authentication required
- **CISA KEV**: Public data, cached locally

---

## Security Checklist for Production

Before deploying to production, ensure:

### Infrastructure
- [ ] TLS/SSL certificates configured
- [ ] Firewall rules implemented
- [ ] VPN or bastion host for admin access
- [ ] Database backups encrypted
- [ ] Secrets management solution (Vault, AWS Secrets Manager)
- [ ] Logging and monitoring enabled
- [ ] Intrusion detection system (IDS) configured

### Application
- [ ] Environment variables set correctly
- [ ] Debug mode disabled
- [ ] API rate limiting enabled
- [ ] CORS configured restrictively
- [ ] Default credentials changed
- [ ] Unnecessary services disabled
- [ ] File upload restrictions enforced

### Database
- [ ] Strong passwords used
- [ ] Network access restricted
- [ ] Encryption at rest enabled
- [ ] Audit logging enabled
- [ ] Regular backups scheduled
- [ ] Backup restoration tested

### Docker
- [ ] Images scanned for vulnerabilities
- [ ] Running as non-root user
- [ ] Resource limits configured
- [ ] Unnecessary capabilities dropped
- [ ] Health checks configured
- [ ] Logs centralized

### Monitoring
- [ ] Security event logging
- [ ] Failed login attempt tracking
- [ ] Anomaly detection configured
- [ ] Alert notifications set up
- [ ] Log retention policy defined
- [ ] Incident response plan documented

---

## Vulnerability Disclosure Policy

### Public Disclosure Timeline

1. **Day 0**: Vulnerability reported privately
2. **Day 1-7**: Initial triage and confirmation
3. **Day 7-30**: Fix developed and tested
4. **Day 30**: Security patch released
5. **Day 37**: Public disclosure (7 days after patch)

### Coordinated Disclosure

We follow responsible disclosure principles:

- **90-Day Deadline**: Maximum time before public disclosure
- **Extension Available**: If actively working on complex fix
- **CVE Assignment**: For critical vulnerabilities
- **Credit Given**: To reporter (if desired)
- **Security Advisory**: Published on GitHub

### Bug Bounty Program

Status: **Not currently active**

We are considering a bug bounty program for v1.1. Stay tuned!

---

## Security Tools

### Automated Scanning

```bash
# Dependency vulnerability scan
safety check --json

# Security issue detection
bandit -r src/ -f json

# Docker image scanning
docker scan vmp:latest

# SAST (Static Application Security Testing)
semgrep --config=auto src/
```

### Manual Review

```bash
# Check for hardcoded secrets
git secrets --scan

# Review dependencies
pip-audit

# Check for exposed secrets in git history
trufflehog git file://. --only-verified
```

---

## Security Contacts

- **Security Team**: security@your-organization.com
- **Project Lead**: Your Name <your.email@example.com>
- **GPG Key**: Available at keybase.io/yourname

---

## Security Updates

Subscribe to security advisories:

- **GitHub Watch**: Enable "Security alerts" on the repository
- **RSS Feed**: https://github.com/Raoof128/VMP/security/advisories.atom
- **Mailing List**: security-announce@your-organization.com

---

## References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [Docker Security Best Practices](https://docs.docker.com/engine/security/)
- [FastAPI Security](https://fastapi.tiangolo.com/tutorial/security/)

---

## Acknowledgments

We thank the following security researchers for responsible disclosure:

- *No vulnerabilities reported yet*

---

**Last Updated**: 2024-11-15
**Version**: 1.0
