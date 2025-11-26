"""
BurpSuite Integration for SecPluger
Provides Python interface to BurpSuite Professional via REST API
Supports automated scanning, passive scanning, sitemap analysis, and reporting
"""

import logging
import requests
import time
import json
import subprocess
import shutil
from pathlib import Path
from typing import Optional, Dict, List, Any
from dataclasses import dataclass
from enum import Enum

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ScanType(Enum):
    """Burp Suite scan types"""
    CRAWL_AND_AUDIT = "CrawlAndAudit"
    CRAWL_ONLY = "Crawl"
    AUDIT_ONLY = "Audit"


class ScanStatus(Enum):
    """Scan status values"""
    PAUSED = "paused"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


@dataclass
class BurpConfig:
    """BurpSuite configuration"""
    api_url: str = "http://127.0.0.1:1337"  # burp-rest-api default
    api_key: Optional[str] = None
    burp_jar: Optional[Path] = None
    headless: bool = True
    proxy_port: int = 8080
    rest_api_port: int = 1337


class BurpSuiteIntegration:
    """
    BurpSuite Professional integration via REST API

    Supports:
    - Automated active scanning
    - Passive scanning
    - Sitemap/spider crawling
    - Issue reporting
    - Proxy history analysis

    Requirements:
    - BurpSuite Professional
    - burp-rest-api (https://github.com/vmware/burp-rest-api)
    """

    def __init__(self, config: Optional[BurpConfig] = None, evidence_dir: Optional[Path] = None):
        """
        Initialize BurpSuite integration

        Args:
            config: BurpSuite configuration
            evidence_dir: Directory to save scan results
        """
        self.config = config or BurpConfig()
        self.evidence_dir = Path(evidence_dir) if evidence_dir else Path("evidence/burp")
        self.evidence_dir.mkdir(parents=True, exist_ok=True)

        self.burp_process = None
        self.session = requests.Session()

        if self.config.api_key:
            self.session.headers.update({"X-API-Key": self.config.api_key})

        logger.info(f"BurpSuite integration initialized (API: {self.config.api_url})")

    def check_burp_available(self) -> bool:
        """Check if BurpSuite and burp-rest-api are available"""
        try:
            response = self.session.get(f"{self.config.api_url}/burp/versions")
            if response.status_code == 200:
                versions = response.json()
                logger.info(f"✅ BurpSuite connected: {versions}")
                return True
        except Exception as e:
            logger.error(f"❌ BurpSuite not available: {e}")
            return False
        return False

    def start_burp_headless(self) -> bool:
        """
        Start BurpSuite in headless mode with REST API

        Note: Requires burp-rest-api.jar
        """
        if not self.config.burp_jar:
            logger.error("❌ burp_jar path not configured")
            return False

        if not self.config.burp_jar.exists():
            logger.error(f"❌ BurpSuite JAR not found: {self.config.burp_jar}")
            return False

        try:
            cmd = [
                "java",
                "-jar", str(self.config.burp_jar),
                f"--headless.mode={str(self.config.headless).lower()}",
                f"--proxy.port={self.config.proxy_port}",
                f"--rest.port={self.config.rest_api_port}"
            ]

            logger.info(f"🚀 Starting BurpSuite: {' '.join(cmd)}")

            self.burp_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )

            # Wait for Burp to start
            time.sleep(10)

            if self.check_burp_available():
                logger.info("✅ BurpSuite started successfully")
                return True
            else:
                logger.error("❌ BurpSuite failed to start")
                return False

        except Exception as e:
            logger.error(f"❌ Failed to start BurpSuite: {e}")
            return False

    def stop_burp(self):
        """Stop BurpSuite process"""
        if self.burp_process:
            self.burp_process.terminate()
            self.burp_process.wait(timeout=10)
            logger.info("✅ BurpSuite stopped")

    def scan_url(self, base_url: str, scan_type: ScanType = ScanType.CRAWL_AND_AUDIT) -> Optional[str]:
        """
        Start automated scan of URL

        Args:
            base_url: Target URL to scan
            scan_type: Type of scan (CRAWL_AND_AUDIT, CRAWL_ONLY, AUDIT_ONLY)

        Returns:
            Scan task ID or None if failed
        """
        try:
            payload = {
                "baseUrl": base_url,
                "scanType": scan_type.value
            }

            logger.info(f"🔍 Starting {scan_type.value} scan: {base_url}")

            response = self.session.post(
                f"{self.config.api_url}/burp/scanner/scans/active",
                json=payload
            )

            if response.status_code in [200, 201]:
                scan_id = response.json().get("taskId")
                logger.info(f"✅ Scan started: Task ID {scan_id}")
                return scan_id
            else:
                logger.error(f"❌ Scan failed: {response.status_code} - {response.text}")
                return None

        except Exception as e:
            logger.error(f"❌ Scan error: {e}")
            return None

    def get_scan_status(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """
        Get status of active scan

        Args:
            scan_id: Scan task ID

        Returns:
            Scan status information
        """
        try:
            response = self.session.get(
                f"{self.config.api_url}/burp/scanner/scans/{scan_id}"
            )

            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"❌ Failed to get scan status: {response.status_code}")
                return None

        except Exception as e:
            logger.error(f"❌ Status check error: {e}")
            return None

    def wait_for_scan(self, scan_id: str, timeout: int = 3600, check_interval: int = 10) -> bool:
        """
        Wait for scan to complete

        Args:
            scan_id: Scan task ID
            timeout: Maximum wait time in seconds
            check_interval: Status check interval in seconds

        Returns:
            True if scan succeeded, False otherwise
        """
        start_time = time.time()

        while (time.time() - start_time) < timeout:
            status = self.get_scan_status(scan_id)

            if not status:
                return False

            scan_status = status.get("scanStatus")
            scan_metrics = status.get("scanMetrics", {})

            logger.info(f"📊 Scan progress: {scan_status} - "
                       f"Requests: {scan_metrics.get('requestsMade', 0)}, "
                       f"Issues: {scan_metrics.get('issuesFound', 0)}")

            if scan_status == ScanStatus.SUCCEEDED.value:
                logger.info("✅ Scan completed successfully")
                return True
            elif scan_status == ScanStatus.FAILED.value:
                logger.error("❌ Scan failed")
                return False

            time.sleep(check_interval)

        logger.error(f"❌ Scan timeout after {timeout} seconds")
        return False

    def get_issues(self, url_prefix: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get all scanner issues

        Args:
            url_prefix: Filter issues by URL prefix

        Returns:
            List of scanner issues
        """
        try:
            params = {}
            if url_prefix:
                params["urlPrefix"] = url_prefix

            response = self.session.get(
                f"{self.config.api_url}/burp/scanner/issues",
                params=params
            )

            if response.status_code == 200:
                issues = response.json()
                logger.info(f"✅ Found {len(issues)} issues")
                return issues
            else:
                logger.error(f"❌ Failed to get issues: {response.status_code}")
                return []

        except Exception as e:
            logger.error(f"❌ Error getting issues: {e}")
            return []

    def generate_report(self, report_type: str = "HTML", url_prefix: Optional[str] = None) -> Optional[str]:
        """
        Generate scan report

        Args:
            report_type: Report format (HTML, XML)
            url_prefix: Filter report by URL prefix

        Returns:
            Report content or None if failed
        """
        try:
            params = {"reportType": report_type}
            if url_prefix:
                params["urlPrefix"] = url_prefix

            logger.info(f"📄 Generating {report_type} report...")

            response = self.session.get(
                f"{self.config.api_url}/burp/report",
                params=params
            )

            if response.status_code == 200:
                logger.info(f"✅ Report generated ({len(response.content)} bytes)")
                return response.text if report_type == "HTML" else response.content
            else:
                logger.error(f"❌ Report generation failed: {response.status_code}")
                return None

        except Exception as e:
            logger.error(f"❌ Report error: {e}")
            return None

    def save_report(self, report_content: str, filename: str):
        """
        Save report to evidence directory

        Args:
            report_content: Report content
            filename: Output filename
        """
        report_path = self.evidence_dir / filename

        with open(report_path, 'w') as f:
            f.write(report_content)

        logger.info(f"✅ Report saved: {report_path}")
        return report_path

    def get_sitemap(self, url_prefix: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get sitemap (discovered URLs)

        Args:
            url_prefix: Filter sitemap by URL prefix

        Returns:
            List of sitemap entries
        """
        try:
            params = {}
            if url_prefix:
                params["urlPrefix"] = url_prefix

            response = self.session.get(
                f"{self.config.api_url}/burp/target/sitemap",
                params=params
            )

            if response.status_code == 200:
                sitemap = response.json()
                logger.info(f"✅ Sitemap: {len(sitemap)} URLs")
                return sitemap
            else:
                logger.error(f"❌ Failed to get sitemap: {response.status_code}")
                return []

        except Exception as e:
            logger.error(f"❌ Sitemap error: {e}")
            return []

    def add_to_scope(self, url: str):
        """
        Add URL to Burp scope

        Args:
            url: URL to add to scope
        """
        try:
            payload = {"url": url}

            response = self.session.put(
                f"{self.config.api_url}/burp/target/scope",
                json=payload
            )

            if response.status_code in [200, 204]:
                logger.info(f"✅ Added to scope: {url}")
                return True
            else:
                logger.error(f"❌ Failed to add to scope: {response.status_code}")
                return False

        except Exception as e:
            logger.error(f"❌ Scope error: {e}")
            return False

    def send_to_repeater(self, request: str, host: str, port: int, https: bool = True):
        """
        Send request to Burp Repeater

        Args:
            request: HTTP request
            host: Target host
            port: Target port
            https: Use HTTPS
        """
        try:
            payload = {
                "request": request,
                "host": host,
                "port": port,
                "protocol": "https" if https else "http"
            }

            response = self.session.post(
                f"{self.config.api_url}/burp/repeater",
                json=payload
            )

            if response.status_code in [200, 201]:
                logger.info(f"✅ Sent to Repeater: {host}")
                return True
            else:
                logger.error(f"❌ Failed to send to Repeater: {response.status_code}")
                return False

        except Exception as e:
            logger.error(f"❌ Repeater error: {e}")
            return False

    def export_state(self, filename: str):
        """
        Export Burp state/project file

        Args:
            filename: Output filename
        """
        try:
            response = self.session.get(
                f"{self.config.api_url}/burp/stop"
            )

            if response.status_code == 200:
                state_path = self.evidence_dir / filename
                with open(state_path, 'wb') as f:
                    f.write(response.content)

                logger.info(f"✅ State exported: {state_path}")
                return state_path
            else:
                logger.error(f"❌ Export failed: {response.status_code}")
                return None

        except Exception as e:
            logger.error(f"❌ Export error: {e}")
            return None


# Standalone usage example
if __name__ == "__main__":
    import sys

    # Check if burp-rest-api is available
    if not shutil.which("java"):
        print("❌ Java not installed. Required for BurpSuite.")
        sys.exit(1)

    # Initialize
    evidence_dir = Path("evidence/burp_test")
    evidence_dir.mkdir(parents=True, exist_ok=True)

    config = BurpConfig(
        api_url="http://127.0.0.1:1337",
        proxy_port=8080,
        headless=True
    )

    burp = BurpSuiteIntegration(config=config, evidence_dir=evidence_dir)

    # Check if Burp is running
    if not burp.check_burp_available():
        print("\n⚠️ BurpSuite REST API not available")
        print("\nTo use this integration:")
        print("1. Download burp-rest-api from https://github.com/vmware/burp-rest-api")
        print("2. Start it: java -jar burp-rest-api.jar")
        print("3. Or set burp_jar in config and use start_burp_headless()")
        sys.exit(1)

    # Example scan
    if len(sys.argv) > 1:
        target_url = sys.argv[1]

        print(f"\n🎯 Scanning: {target_url}\n")

        # Add to scope
        burp.add_to_scope(target_url)

        # Start scan
        scan_id = burp.scan_url(target_url, ScanType.CRAWL_AND_AUDIT)

        if scan_id:
            # Wait for completion
            success = burp.wait_for_scan(scan_id, timeout=600)

            if success:
                # Get results
                issues = burp.get_issues(url_prefix=target_url)
                print(f"\n✅ Found {len(issues)} issues\n")

                # Generate report
                report_html = burp.generate_report(report_type="HTML", url_prefix=target_url)
                if report_html:
                    report_path = burp.save_report(report_html, "burp_scan_report.html")
                    print(f"✅ Report: {report_path}")

                # Get sitemap
                sitemap = burp.get_sitemap(url_prefix=target_url)
                print(f"✅ Sitemap: {len(sitemap)} URLs discovered")

    else:
        print("Usage: python burpsuite.py <target_url>")
        print("Example: python burpsuite.py http://testphp.vulnweb.com")
