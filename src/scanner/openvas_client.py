"""
OpenVAS Scanner Client
Integrates with OpenVAS/GVM (Greenbone Vulnerability Management) API
"""

import os
import time
from typing import List, Dict, Optional
from datetime import datetime
import xml.etree.ElementTree as ET
from dataclasses import dataclass
import logging

try:
    from gvm.connections import UnixSocketConnection
    from gvm.protocols.gmp import Gmp
    from gvm.transforms import EtreeTransform
    GVM_AVAILABLE = True
except ImportError:
    GVM_AVAILABLE = False
    logging.warning("python-gvm not installed. OpenVAS integration disabled.")

logger = logging.getLogger(__name__)


@dataclass
class ScanTarget:
    """Scan target configuration"""
    name: str
    hosts: str  # IP range or hostname
    port_list_id: Optional[str] = None
    credentials_id: Optional[str] = None


@dataclass
class ScanTask:
    """Scan task information"""
    task_id: str
    name: str
    target_id: str
    status: str
    progress: int
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None


@dataclass
class VulnerabilityResult:
    """Individual vulnerability result from scan"""
    nvt_oid: str
    name: str
    severity: float
    qod: int  # Quality of Detection
    host: str
    port: str
    description: str
    solution: str
    cve_refs: List[str]
    threat: str  # High, Medium, Low, Log


class OpenVASClient:
    """
    OpenVAS/GVM API client for vulnerability scanning.

    Requires: python-gvm library
    Install: pip install python-gvm
    """

    def __init__(
        self,
        socket_path: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None
    ):
        """
        Initialize OpenVAS client.

        Args:
            socket_path: Path to GVM Unix socket (default: /run/gvmd/gvmd.sock)
            username: GVM username (default: from env OPENVAS_USERNAME)
            password: GVM password (default: from env OPENVAS_PASSWORD)
        """
        if not GVM_AVAILABLE:
            raise ImportError(
                "python-gvm library not installed. "
                "Install with: pip install python-gvm"
            )

        self.socket_path = socket_path or os.getenv(
            "OPENVAS_SOCKET",
            "/run/gvmd/gvmd.sock"
        )
        self.username = username or os.getenv("OPENVAS_USERNAME", "admin")
        self.password = password or os.getenv("OPENVAS_PASSWORD", "admin")

        self.connection = None
        self.gmp = None

    def connect(self):
        """Establish connection to GVM"""
        try:
            self.connection = UnixSocketConnection(path=self.socket_path)
            self.gmp = Gmp(connection=self.connection, transform=EtreeTransform())

            # Authenticate
            self.gmp.authenticate(self.username, self.password)
            logger.info("✓ Connected to OpenVAS/GVM")
            return True

        except Exception as e:
            logger.error(f"Failed to connect to OpenVAS: {e}")
            return False

    def disconnect(self):
        """Close connection"""
        if self.connection:
            self.connection.disconnect()
            logger.info("✓ Disconnected from OpenVAS")

    def test_connection(self) -> bool:
        """Test connection to OpenVAS"""
        try:
            if self.connect():
                version = self.get_version()
                logger.info(f"OpenVAS version: {version}")
                self.disconnect()
                return True
        except Exception as e:
            logger.error(f"Connection test failed: {e}")
        return False

    def get_version(self) -> str:
        """Get GVM version"""
        try:
            response = self.gmp.get_version()
            return response.find('version').text
        except Exception as e:
            logger.error(f"Failed to get version: {e}")
            return "Unknown"

    def create_target(self, target: ScanTarget) -> Optional[str]:
        """
        Create a scan target.

        Args:
            target: ScanTarget configuration

        Returns:
            Target ID if successful, None otherwise
        """
        try:
            # Get default port list if not specified
            if not target.port_list_id:
                port_lists = self.gmp.get_port_lists()
                default_port_list = port_lists.find('.//port_list')
                if default_port_list is not None:
                    target.port_list_id = default_port_list.get('id')

            # Create target
            response = self.gmp.create_target(
                name=target.name,
                hosts=[target.hosts],
                port_list_id=target.port_list_id
            )

            target_id = response.get('id')
            logger.info(f"✓ Created target '{target.name}': {target_id}")
            return target_id

        except Exception as e:
            logger.error(f"Failed to create target: {e}")
            return None

    def create_task(
        self,
        name: str,
        target_id: str,
        scanner_id: Optional[str] = None,
        config_id: Optional[str] = None
    ) -> Optional[str]:
        """
        Create a scan task.

        Args:
            name: Task name
            target_id: Target ID
            scanner_id: Scanner ID (default: OpenVAS Default)
            config_id: Scan config ID (default: Full and fast)

        Returns:
            Task ID if successful, None otherwise
        """
        try:
            # Get default scanner if not specified
            if not scanner_id:
                scanners = self.gmp.get_scanners()
                default_scanner = scanners.find('.//scanner[name="OpenVAS Default"]')
                if default_scanner is not None:
                    scanner_id = default_scanner.get('id')

            # Get default config if not specified
            if not config_id:
                configs = self.gmp.get_scan_configs()
                default_config = configs.find('.//config[name="Full and fast"]')
                if default_config is not None:
                    config_id = default_config.get('id')

            # Create task
            response = self.gmp.create_task(
                name=name,
                config_id=config_id,
                target_id=target_id,
                scanner_id=scanner_id
            )

            task_id = response.get('id')
            logger.info(f"✓ Created task '{name}': {task_id}")
            return task_id

        except Exception as e:
            logger.error(f"Failed to create task: {e}")
            return None

    def start_task(self, task_id: str) -> bool:
        """
        Start a scan task.

        Args:
            task_id: Task ID

        Returns:
            True if started successfully
        """
        try:
            self.gmp.start_task(task_id)
            logger.info(f"✓ Started task {task_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to start task: {e}")
            return False

    def get_task_status(self, task_id: str) -> Optional[ScanTask]:
        """
        Get task status.

        Args:
            task_id: Task ID

        Returns:
            ScanTask with status information
        """
        try:
            response = self.gmp.get_task(task_id)
            task_elem = response.find('task')

            if task_elem is None:
                return None

            status = task_elem.find('status').text
            progress = int(task_elem.find('progress').text)
            name = task_elem.find('name').text

            # Parse timestamps if available
            start_time = None
            end_time = None

            report = task_elem.find('.//report')
            if report is not None:
                timestamp_elem = report.find('timestamp')
                if timestamp_elem is not None:
                    start_time = datetime.fromisoformat(timestamp_elem.text)

            return ScanTask(
                task_id=task_id,
                name=name,
                target_id=task_elem.find('target').get('id'),
                status=status,
                progress=progress,
                start_time=start_time,
                end_time=end_time
            )

        except Exception as e:
            logger.error(f"Failed to get task status: {e}")
            return None

    def wait_for_task(
        self,
        task_id: str,
        poll_interval: int = 30,
        timeout: int = 14400  # 4 hours
    ) -> bool:
        """
        Wait for task to complete.

        Args:
            task_id: Task ID
            poll_interval: Seconds between status checks
            timeout: Maximum wait time in seconds

        Returns:
            True if completed successfully
        """
        start = time.time()

        while time.time() - start < timeout:
            task = self.get_task_status(task_id)

            if not task:
                logger.error("Failed to get task status")
                return False

            logger.info(f"Task {task_id}: {task.status} ({task.progress}%)")

            if task.status == "Done":
                logger.info(f"✓ Task {task_id} completed")
                return True
            elif task.status in ["Stopped", "Interrupted"]:
                logger.error(f"Task {task_id} stopped unexpectedly")
                return False

            time.sleep(poll_interval)

        logger.error(f"Task {task_id} timed out after {timeout}s")
        return False

    def get_results(self, task_id: str) -> List[VulnerabilityResult]:
        """
        Get vulnerability results from completed task.

        Args:
            task_id: Task ID

        Returns:
            List of VulnerabilityResult objects
        """
        try:
            # Get task report
            task = self.gmp.get_task(task_id)
            report_id = task.find('.//report[@id]').get('id')

            # Get full report with results
            report = self.gmp.get_report(
                report_id=report_id,
                details=True
            )

            # Parse results
            results = []
            for result_elem in report.findall('.//result'):
                # Extract CVE references
                cve_refs = [
                    ref.get('id')
                    for ref in result_elem.findall('.//ref[@type="cve"]')
                ]

                # Create result object
                result = VulnerabilityResult(
                    nvt_oid=result_elem.find('nvt').get('oid'),
                    name=result_elem.find('name').text,
                    severity=float(result_elem.find('severity').text or 0.0),
                    qod=int(result_elem.find('.//qod/value').text or 0),
                    host=result_elem.find('host').text,
                    port=result_elem.find('port').text,
                    description=result_elem.find('description').text or "",
                    solution=result_elem.find('.//solution').text or "",
                    cve_refs=cve_refs,
                    threat=result_elem.find('threat').text or "Log"
                )

                results.append(result)

            logger.info(f"✓ Retrieved {len(results)} vulnerability results")
            return results

        except Exception as e:
            logger.error(f"Failed to get results: {e}")
            return []

    def full_scan_workflow(
        self,
        target_hosts: str,
        scan_name: Optional[str] = None
    ) -> List[VulnerabilityResult]:
        """
        Complete workflow: create target, create task, run scan, get results.

        Args:
            target_hosts: IP range or hostname(s)
            scan_name: Custom scan name

        Returns:
            List of vulnerability results
        """
        scan_name = scan_name or f"VMP Scan {datetime.now().strftime('%Y-%m-%d %H:%M')}"

        try:
            # Connect
            if not self.connect():
                raise Exception("Failed to connect to OpenVAS")

            # Create target
            target = ScanTarget(
                name=f"{scan_name} - Target",
                hosts=target_hosts
            )
            target_id = self.create_target(target)
            if not target_id:
                raise Exception("Failed to create target")

            # Create task
            task_id = self.create_task(
                name=scan_name,
                target_id=target_id
            )
            if not task_id:
                raise Exception("Failed to create task")

            # Start task
            if not self.start_task(task_id):
                raise Exception("Failed to start task")

            # Wait for completion
            if not self.wait_for_task(task_id):
                raise Exception("Task did not complete successfully")

            # Get results
            results = self.get_results(task_id)

            return results

        except Exception as e:
            logger.error(f"Scan workflow failed: {e}")
            return []

        finally:
            self.disconnect()


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    # Test connection
    client = OpenVASClient()

    if client.test_connection():
        print("✓ OpenVAS connection test successful")
    else:
        print("✗ OpenVAS connection test failed")
        print("\nMake sure:")
        print("  1. OpenVAS is running: docker-compose up -d openvas")
        print("  2. GVM socket is accessible: /run/gvmd/gvmd.sock")
        print("  3. Credentials are correct in .env file")
