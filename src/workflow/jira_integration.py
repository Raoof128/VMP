"""
Jira Integration - Remediation Ticket Management
Automates creation and tracking of remediation tickets in Jira
"""

import os
from typing import Dict, Optional, List
from datetime import datetime
import logging

try:
    from jira import JIRA, JIRAError
    JIRA_AVAILABLE = True
except ImportError:
    JIRA_AVAILABLE = False
    logging.warning("jira library not installed. Jira integration disabled.")

from ..database.models import Vulnerability, RemediationTicket, TicketPriority

logger = logging.getLogger(__name__)


class JiraWorkflowManager:
    """
    Jira workflow automation for vulnerability remediation.

    Handles:
    - Automatic ticket creation for high-risk vulnerabilities
    - SLA deadline tracking
    - Status synchronization
    - Escalation management
    """

    def __init__(
        self,
        jira_url: Optional[str] = None,
        username: Optional[str] = None,
        api_token: Optional[str] = None,
        project_key: Optional[str] = None
    ):
        """
        Initialize Jira client.

        Args:
            jira_url: Jira instance URL (e.g., https://company.atlassian.net)
            username: Jira username/email
            api_token: Jira API token
            project_key: Jira project key (e.g., VULN)
        """
        if not JIRA_AVAILABLE:
            raise ImportError(
                "jira library not installed. "
                "Install with: pip install jira"
            )

        self.jira_url = jira_url or os.getenv("JIRA_URL")
        self.username = username or os.getenv("JIRA_USERNAME")
        self.api_token = api_token or os.getenv("JIRA_API_TOKEN")
        self.project_key = project_key or os.getenv("JIRA_PROJECT_KEY", "VULN")

        self.jira = None
        self.enabled = os.getenv("JIRA_ENABLED", "False").lower() == "true"

    def connect(self) -> bool:
        """Connect to Jira"""
        if not self.enabled:
            logger.warning("Jira integration is disabled in configuration")
            return False

        try:
            self.jira = JIRA(
                server=self.jira_url,
                basic_auth=(self.username, self.api_token)
            )

            # Test connection
            self.jira.myself()
            logger.info("✓ Connected to Jira")
            return True

        except JIRAError as e:
            logger.error(f"Failed to connect to Jira: {e}")
            return False
        except Exception as e:
            logger.error(f"Jira connection error: {e}")
            return False

    def test_connection(self) -> bool:
        """Test Jira connection"""
        if not self.enabled:
            logger.info("Jira integration disabled - skipping connection test")
            return True  # Return True to not block workflows

        return self.connect()

    def get_priority(self, risk_score: float) -> TicketPriority:
        """
        Determine Jira ticket priority from business risk score.

        Args:
            risk_score: Business risk score (0-100)

        Returns:
            TicketPriority enum value
        """
        if risk_score >= 80:
            return TicketPriority.HIGHEST
        elif risk_score >= 60:
            return TicketPriority.HIGH
        elif risk_score >= 40:
            return TicketPriority.MEDIUM
        else:
            return TicketPriority.LOW

    def create_remediation_ticket(
        self,
        vulnerability: Vulnerability,
        assignee: Optional[str] = None
    ) -> Optional[str]:
        """
        Create Jira ticket for vulnerability remediation.

        Args:
            vulnerability: Vulnerability object
            assignee: Jira username to assign (optional)

        Returns:
            Jira ticket ID (e.g., VULN-123) or None
        """
        if not self.enabled:
            logger.info("Jira integration disabled - skipping ticket creation")
            return None

        if not self.jira:
            if not self.connect():
                return None

        try:
            # Determine priority
            priority = self.get_priority(vulnerability.business_risk_score or 0)

            # Build description
            description = self._build_ticket_description(vulnerability)

            # Prepare issue fields
            issue_dict = {
                'project': {'key': self.project_key},
                'summary': f"Remediate {vulnerability.cve_id}: {vulnerability.title[:100]}",
                'description': description,
                'issuetype': {'name': 'Task'},
                'priority': {'name': priority.value},
                'labels': [
                    'vulnerability',
                    vulnerability.cvss_severity.value.lower() if vulnerability.cvss_severity else 'unknown',
                    'automated'
                ]
            }

            # Add due date if SLA deadline is set
            if vulnerability.remediation_deadline:
                issue_dict['duedate'] = vulnerability.remediation_deadline.strftime('%Y-%m-%d')

            # Add assignee if specified
            if assignee:
                issue_dict['assignee'] = {'name': assignee}

            # Create issue
            issue = self.jira.create_issue(fields=issue_dict)
            ticket_id = issue.key

            logger.info(f"✓ Created Jira ticket {ticket_id} for {vulnerability.cve_id}")

            return ticket_id

        except JIRAError as e:
            logger.error(f"Failed to create Jira ticket: {e}")
            return None
        except Exception as e:
            logger.error(f"Jira ticket creation error: {e}")
            return None

    def _build_ticket_description(self, vulnerability: Vulnerability) -> str:
        """Build Jira ticket description"""
        affected_assets_list = '\n'.join([
            f"- {asset.hostname} ({asset.ip_address}) - Criticality: {asset.criticality}/10"
            for asset in vulnerability.affected_assets[:10]  # Limit to 10
        ])

        if len(vulnerability.affected_assets) > 10:
            affected_assets_list += f"\n- ... and {len(vulnerability.affected_assets) - 10} more"

        description = f"""
h2. Vulnerability Details

*CVE ID:* {vulnerability.cve_id}
*Title:* {vulnerability.title}

h3. Risk Assessment

*CVSS Score:* {vulnerability.cvss_base_score}/10.0 ({vulnerability.cvss_severity.value if vulnerability.cvss_severity else 'N/A'})
*EPSS Score:* {vulnerability.epss_score:.1%} (Exploit Probability)
*Business Risk Score:* {vulnerability.business_risk_score:.1f}/100

*Risk Explanation:*
{vulnerability.risk_score_explanation or 'No explanation available'}

h3. Affected Assets ({len(vulnerability.affected_assets)})

{affected_assets_list}

h3. Vulnerability Description

{vulnerability.description or 'No description available'}

h3. CWE Categories

{', '.join(vulnerability.cwe_ids) if vulnerability.cwe_ids else 'N/A'}

h3. Exploit Information

*Exploit Available:* {'Yes ⚠️' if vulnerability.exploit_available else 'No'}
*CISA Known Exploited:* {'Yes ⚠️⚠️' if vulnerability.in_cisa_kev else 'No'}
{f'*Exploit Maturity:* {vulnerability.exploit_maturity}' if vulnerability.exploit_maturity else ''}

h3. Remediation Requirements

*SLA Deadline:* {vulnerability.remediation_deadline.strftime('%Y-%m-%d') if vulnerability.remediation_deadline else 'Not set'}
*Remediation Difficulty:* {vulnerability.remediation_difficulty}/5

h3. Remediation Steps

# Review vulnerability details in NVD: https://nvd.nist.gov/vuln/detail/{vulnerability.cve_id}
# Assess patch availability
# Test patch in staging environment
# Schedule deployment to production
# Verify fix with follow-up vulnerability scan
# Update ticket status to "Resolved"

h3. Tracking

*Discovered:* {vulnerability.discovered_date.strftime('%Y-%m-%d') if vulnerability.discovered_date else 'Unknown'}
*Last Scanned:* {vulnerability.last_scanned.strftime('%Y-%m-%d') if vulnerability.last_scanned else 'Unknown'}
*Scan Count:* {vulnerability.scan_count}

---
_This ticket was automatically created by VMP (Vulnerability Management Pipeline)_
"""

        return description

    def update_ticket_status(
        self,
        ticket_id: str,
        status: str,
        comment: Optional[str] = None
    ) -> bool:
        """
        Update Jira ticket status.

        Args:
            ticket_id: Jira ticket ID
            status: New status
            comment: Optional comment to add

        Returns:
            True if successful
        """
        if not self.enabled:
            return True

        if not self.jira:
            if not self.connect():
                return False

        try:
            issue = self.jira.issue(ticket_id)

            # Transition to new status
            transitions = self.jira.transitions(issue)
            for transition in transitions:
                if transition['name'].lower() == status.lower():
                    self.jira.transition_issue(issue, transition['id'])
                    logger.info(f"✓ Updated {ticket_id} status to {status}")

                    if comment:
                        self.jira.add_comment(issue, comment)

                    return True

            logger.warning(f"Status '{status}' not available for {ticket_id}")
            return False

        except JIRAError as e:
            logger.error(f"Failed to update ticket status: {e}")
            return False

    def add_comment(self, ticket_id: str, comment: str) -> bool:
        """Add comment to Jira ticket"""
        if not self.enabled:
            return True

        if not self.jira:
            if not self.connect():
                return False

        try:
            issue = self.jira.issue(ticket_id)
            self.jira.add_comment(issue, comment)
            logger.info(f"✓ Added comment to {ticket_id}")
            return True

        except JIRAError as e:
            logger.error(f"Failed to add comment: {e}")
            return False

    def get_ticket_status(self, ticket_id: str) -> Optional[str]:
        """Get current ticket status"""
        if not self.enabled:
            return None

        if not self.jira:
            if not self.connect():
                return None

        try:
            issue = self.jira.issue(ticket_id)
            return issue.fields.status.name

        except JIRAError as e:
            logger.error(f"Failed to get ticket status: {e}")
            return None

    def monitor_sla_compliance(
        self,
        vulnerabilities: List[Vulnerability]
    ) -> Dict[str, List[Dict]]:
        """
        Monitor SLA compliance for vulnerabilities with Jira tickets.

        Args:
            vulnerabilities: List of vulnerabilities

        Returns:
            Dictionary with compliance categories
        """
        now = datetime.utcnow()

        sla_report = {
            'on_track': [],
            'at_risk': [],
            'overdue': []
        }

        for vuln in vulnerabilities:
            if not vuln.jira_ticket_id or not vuln.remediation_deadline:
                continue

            days_until_deadline = (vuln.remediation_deadline - now).days

            ticket_info = {
                'cve': vuln.cve_id,
                'ticket_id': vuln.jira_ticket_id,
                'risk_score': vuln.business_risk_score,
                'deadline': vuln.remediation_deadline.strftime('%Y-%m-%d')
            }

            if days_until_deadline < 0:
                ticket_info['days_overdue'] = abs(days_until_deadline)
                sla_report['overdue'].append(ticket_info)
            elif days_until_deadline <= 7:
                ticket_info['days_remaining'] = days_until_deadline
                sla_report['at_risk'].append(ticket_info)
            else:
                ticket_info['days_remaining'] = days_until_deadline
                sla_report['on_track'].append(ticket_info)

        logger.info(
            f"SLA Report: {len(sla_report['on_track'])} on track, "
            f"{len(sla_report['at_risk'])} at risk, "
            f"{len(sla_report['overdue'])} overdue"
        )

        return sla_report

    def escalate_overdue_tickets(
        self,
        overdue_tickets: List[Dict],
        escalation_comment: str = "This ticket is overdue. Please prioritize remediation."
    ) -> int:
        """
        Escalate overdue tickets with comments.

        Args:
            overdue_tickets: List of overdue ticket info dicts
            escalation_comment: Comment to add

        Returns:
            Number of tickets escalated
        """
        if not self.enabled:
            return 0

        escalated = 0

        for ticket_info in overdue_tickets:
            ticket_id = ticket_info['ticket_id']
            days_overdue = ticket_info['days_overdue']

            comment = f"{escalation_comment}\n\nThis ticket is {days_overdue} days overdue."

            if self.add_comment(ticket_id, comment):
                escalated += 1

        logger.info(f"✓ Escalated {escalated} overdue tickets")

        return escalated


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    # Test connection
    jira_manager = JiraWorkflowManager()

    if jira_manager.test_connection():
        print("✓ Jira connection test successful")
    else:
        print("✗ Jira connection test failed")
        print("\nMake sure:")
        print("  1. JIRA_ENABLED=True in .env file")
        print("  2. JIRA_URL is set (e.g., https://company.atlassian.net)")
        print("  3. JIRA_API_TOKEN is valid")
        print("  4. JIRA_PROJECT_KEY exists (e.g., VULN)")
