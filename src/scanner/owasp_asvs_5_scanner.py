#!/usr/bin/env python3
"""
OWASP ASVS 5.0 Security Scanner
Comprehensive security testing based on OWASP ASVS 5.0.0 (345 requirements)

Features:
- Level filtering (L1, L2, L3) - User can select appropriate level
- Screenshot evidence capture with Playwright
- Affected URL tracking for each finding
- 17 ASVS categories with 345 requirements
- Automated compliance reporting

Levels:
- L1 (70 requirements): Basic security - OWASP Top 10, essential controls
- L2 (183 requirements): Standard security - Most web applications
- L3 (92 requirements): Advanced security - High-value applications, critical data

Note: There is NO Level 4. ASVS 5.0 only defines L1, L2, and L3.
      Even military/government applications use L3 (Advanced).
"""

import requests
import json
import csv
import re
import sys
from typing import Dict, List, Optional, Set
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse, urljoin
import logging

# Optional Playwright for screenshots
try:
    from playwright.async_api import async_playwright, Browser, Page
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    print("[!] Playwright not available. Install with: pip install playwright && playwright install chromium")

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class OWASPASVS5Scanner:
    """
    OWASP ASVS 5.0.0 Security Scanner

    Performs comprehensive security testing based on OWASP Application Security
    Verification Standard version 5.0.0 with 345 security requirements.
    """

    def __init__(self, target_url: str, evidence_dir: Optional[str] = None,
                 level: int = 2, enable_screenshots: bool = True):
        """
        Initialize ASVS 5.0 Scanner

        Args:
            target_url: Target application URL
            evidence_dir: Directory to store evidence
            level: ASVS level (1=L1/Basic, 2=L2/Standard, 3=L3/Advanced)
            enable_screenshots: Enable screenshot capture (requires Playwright)
        """
        self.target_url = target_url.rstrip('/')
        self.evidence_dir = Path(evidence_dir or "evidence")
        self.evidence_dir.mkdir(parents=True, exist_ok=True)

        # Level validation
        if level not in [1, 2, 3]:
            raise ValueError("ASVS level must be 1, 2, or 3. There is no Level 4.")
        self.level = level

        self.enable_screenshots = enable_screenshots and PLAYWRIGHT_AVAILABLE
        if enable_screenshots and not PLAYWRIGHT_AVAILABLE:
            logger.warning("Screenshots requested but Playwright not available")

        # Screenshot directory
        self.screenshot_dir = self.evidence_dir / "screenshots"
        self.screenshot_dir.mkdir(parents=True, exist_ok=True)

        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'OWASP-ASVS-Scanner/5.0'
        })

        # Load ASVS 5.0 requirements from CSV
        self.requirements = self._load_asvs_requirements()
        self.findings = []

        # Playwright browser (initialized on demand)
        self.browser = None
        self.playwright = None

    def _load_asvs_requirements(self) -> List[Dict]:
        """Load ASVS 5.0 requirements from CSV file"""
        asvs_csv_path = Path(__file__).parent / "data" / "asvs_5.0.0.csv"

        if not asvs_csv_path.exists():
            raise FileNotFoundError(
                f"ASVS 5.0 CSV not found at {asvs_csv_path}. "
                "Download from: https://github.com/OWASP/ASVS/tree/v5.0.0/5.0/docs_en/"
            )

        requirements = []
        with open(asvs_csv_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Filter by selected level (cumulative - L3 includes L2 and L1)
                try:
                    req_level = int(row['L'].strip())
                    if req_level <= self.level:
                        requirements.append({
                            'chapter_id': row['chapter_id'],
                            'chapter_name': row['chapter_name'],
                            'section_id': row['section_id'],
                            'section_name': row['section_name'],
                            'req_id': row['req_id'],
                            'req_description': row['req_description'],
                            'level': req_level
                        })
                except (ValueError, KeyError) as e:
                    # Skip malformed rows
                    continue

        logger.info(f"Loaded {len(requirements)} ASVS 5.0 requirements for Level {self.level}")
        return requirements

    async def _init_browser(self):
        """Initialize Playwright browser for screenshots"""
        if not self.enable_screenshots or self.browser:
            return

        self.playwright = await async_playwright().start()
        self.browser = await self.playwright.chromium.launch(headless=True)
        logger.info("Playwright browser initialized for screenshot capture")

    async def _close_browser(self):
        """Close Playwright browser"""
        if self.browser:
            await self.browser.close()
        if self.playwright:
            await self.playwright.stop()

    async def _capture_screenshot(self, url: str, check_id: str, description: str) -> Optional[str]:
        """
        Capture screenshot for evidence

        Returns: Screenshot filename or None
        """
        if not self.enable_screenshots:
            return None

        try:
            if not self.browser:
                await self._init_browser()

            context = await self.browser.new_context(
                viewport={'width': 1920, 'height': 1080},
                ignore_https_errors=True
            )
            page = await context.new_page()

            # Navigate to URL
            await page.goto(url, wait_until='networkidle', timeout=15000)

            # Generate screenshot filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_check_id = check_id.replace('.', '_')
            screenshot_filename = f"{safe_check_id}_{timestamp}.png"
            screenshot_path = self.screenshot_dir / screenshot_filename

            # Capture full page screenshot
            await page.screenshot(path=str(screenshot_path), full_page=True)

            await context.close()

            logger.info(f"Screenshot captured: {screenshot_filename}")
            return screenshot_filename

        except Exception as e:
            logger.warning(f"Screenshot capture failed for {check_id}: {e}")
            return None

    def _make_request(self, url: str, method: str = 'GET', **kwargs) -> Optional[requests.Response]:
        """Make HTTP request with error handling"""
        try:
            response = self.session.request(method, url, timeout=10, **kwargs)
            return response
        except Exception as e:
            logger.debug(f"Request failed: {e}")
            return None

    def _add_finding(self, req_id: str, req_description: str,
                    status: str, details: str, affected_urls: List[str],
                    severity: str = "MEDIUM", screenshot: Optional[str] = None,
                    chapter_name: str = "", section_name: str = "", level: int = 2):
        """
        Add security finding

        Args:
            req_id: ASVS requirement ID (e.g., V1.1.1)
            req_description: Requirement description
            status: PASS, FAIL, WARN, INFO, ERROR
            details: Test result details
            affected_urls: List of URLs where issue was found
            severity: CRITICAL, HIGH, MEDIUM, LOW, INFO
            screenshot: Screenshot filename if captured
            chapter_name: ASVS chapter name
            section_name: ASVS section name
            level: ASVS level (1, 2, or 3)
        """
        finding = {
            'req_id': req_id,
            'req_description': req_description,
            'chapter_name': chapter_name,
            'section_name': section_name,
            'level': level,
            'status': status,
            'severity': severity,
            'details': details,
            'affected_urls': affected_urls,
            'screenshot': screenshot,
            'tested_at': datetime.now().isoformat()
        }
        self.findings.append(finding)

    async def scan(self) -> Dict:
        """
        Perform comprehensive OWASP ASVS 5.0 scan

        Returns:
            Dict containing scan results
        """
        print("="*80)
        print("OWASP ASVS 5.0 SECURITY SCANNER")
        print("="*80)
        print(f"Target:           {self.target_url}")
        print(f"ASVS Level:       L{self.level} ({self._get_level_description()})")
        print(f"Requirements:     {len(self.requirements)}")
        print(f"Screenshots:      {'Enabled' if self.enable_screenshots else 'Disabled'}")
        print(f"Evidence Dir:     {self.evidence_dir}")
        print("="*80)
        print()

        # Group requirements by chapter
        chapters = {}
        for req in self.requirements:
            chapter_id = req['chapter_id']
            if chapter_id not in chapters:
                chapters[chapter_id] = {
                    'name': req['chapter_name'],
                    'requirements': []
                }
            chapters[chapter_id]['requirements'].append(req)

        # Test each chapter
        results = {
            'target': self.target_url,
            'timestamp': datetime.now().isoformat(),
            'asvs_version': '5.0.0',
            'asvs_level': self.level,
            'level_description': self._get_level_description(),
            'total_requirements': len(self.requirements),
            'chapters': {}
        }

        for chapter_id in sorted(chapters.keys()):
            chapter = chapters[chapter_id]
            print(f"[*] Testing {chapter_id}: {chapter['name']}")

            chapter_results = await self._test_chapter(
                chapter_id,
                chapter['name'],
                chapter['requirements']
            )

            results['chapters'][chapter_id] = chapter_results

            passed = chapter_results['stats']['passed']
            total = chapter_results['stats']['total']
            print(f"    [{passed}/{total}] checks passed\n")

        # Calculate overall statistics
        results['summary'] = self._calculate_summary(results)

        # Close browser if opened
        await self._close_browser()

        # Save results
        self._save_results(results)

        return results

    async def _test_chapter(self, chapter_id: str, chapter_name: str,
                          requirements: List[Dict]) -> Dict:
        """
        Test all requirements in a chapter

        For automated testing, we perform generic checks.
        Manual testing would be needed for complete coverage.
        """
        chapter_results = {
            'name': chapter_name,
            'requirements': [],
            'stats': {
                'total': len(requirements),
                'passed': 0,
                'failed': 0,
                'warnings': 0,
                'info': 0,
                'error': 0  # Fixed: was 'errors' but code uses 'error'
            }
        }

        for req in requirements:
            # Perform automated test based on requirement
            result = await self._test_requirement(req)

            chapter_results['requirements'].append(result)
            chapter_results['stats'][result['status'].lower()] += 1

        return chapter_results

    async def _test_requirement(self, req: Dict) -> Dict:
        """
        Test individual ASVS requirement

        This performs automated checks where possible.
        Many ASVS requirements require manual code review.
        """
        req_id = req['req_id']
        req_description = req['req_description']
        chapter_name = req['chapter_name']
        section_name = req['section_name']
        level = req['level']

        # Map requirements to automated tests
        # V9: Communication chapter - Can test HTTPS
        if req_id.startswith('V9.'):
            return await self._test_communication_req(req)

        # V3: Web Frontend Security - Can test headers
        elif req_id.startswith('V3.'):
            return await self._test_frontend_req(req)

        # V16: Error Handling - Can test error messages
        elif req_id.startswith('V16.'):
            return await self._test_error_handling_req(req)

        # Most other requirements need manual testing
        else:
            return await self._test_generic_req(req)

    async def _test_communication_req(self, req: Dict) -> Dict:
        """Test communication security requirements (V9)"""
        req_id = req['req_id']

        # V9.1.x: HTTPS/TLS requirements
        if 'V9.1.' in req_id or 'TLS' in req['req_description'] or 'HTTPS' in req['req_description']:
            parsed = urlparse(self.target_url)
            is_https = parsed.scheme == 'https'

            screenshot = None
            if not is_https and self.enable_screenshots:
                screenshot = await self._capture_screenshot(
                    self.target_url, req_id, "HTTP instead of HTTPS"
                )

            if is_https:
                self._add_finding(
                    req_id=req_id,
                    req_description=req['req_description'],
                    status='PASS',
                    details='Application uses HTTPS/TLS encryption',
                    affected_urls=[self.target_url],
                    severity='INFO',
                    screenshot=screenshot,
                    chapter_name=req['chapter_name'],
                    section_name=req['section_name'],
                    level=req['level']
                )
                return {'req_id': req_id, 'status': 'passed'}
            else:
                self._add_finding(
                    req_id=req_id,
                    req_description=req['req_description'],
                    status='FAIL',
                    details='Application does not enforce HTTPS/TLS - uses HTTP',
                    affected_urls=[self.target_url],
                    severity='CRITICAL',
                    screenshot=screenshot,
                    chapter_name=req['chapter_name'],
                    section_name=req['section_name'],
                    level=req['level']
                )
                return {'req_id': req_id, 'status': 'failed'}

        # Other V9 requirements - manual test needed
        return await self._test_generic_req(req)

    async def _test_frontend_req(self, req: Dict) -> Dict:
        """Test web frontend security requirements (V3)"""
        req_id = req['req_id']

        # V3.4.x: Security headers
        if 'V3.4.' in req_id or 'header' in req['req_description'].lower():
            response = self._make_request(self.target_url)

            if not response:
                return {'req_id': req_id, 'status': 'error'}

            # Check for security headers
            headers_to_check = {
                'X-Frame-Options': 'Clickjacking protection',
                'X-Content-Type-Options': 'MIME sniffing protection',
                'Content-Security-Policy': 'CSP protection',
                'Strict-Transport-Security': 'HSTS enabled',
                'X-XSS-Protection': 'XSS filter'
            }

            missing_headers = []
            for header, description in headers_to_check.items():
                if header not in response.headers:
                    missing_headers.append(f"{header} ({description})")

            if missing_headers:
                screenshot = None
                if self.enable_screenshots:
                    screenshot = await self._capture_screenshot(
                        self.target_url, req_id, "Missing security headers"
                    )

                self._add_finding(
                    req_id=req_id,
                    req_description=req['req_description'],
                    status='WARN',
                    details=f"Missing security headers: {', '.join(missing_headers)}",
                    affected_urls=[self.target_url],
                    severity='MEDIUM',
                    screenshot=screenshot,
                    chapter_name=req['chapter_name'],
                    section_name=req['section_name'],
                    level=req['level']
                )
                return {'req_id': req_id, 'status': 'warnings'}
            else:
                self._add_finding(
                    req_id=req_id,
                    req_description=req['req_description'],
                    status='PASS',
                    details='All recommended security headers present',
                    affected_urls=[self.target_url],
                    severity='INFO',
                    chapter_name=req['chapter_name'],
                    section_name=req['section_name'],
                    level=req['level']
                )
                return {'req_id': req_id, 'status': 'passed'}

        return await self._test_generic_req(req)

    async def _test_error_handling_req(self, req: Dict) -> Dict:
        """Test error handling requirements (V16)"""
        req_id = req['req_id']

        # V16.5.x: Error messages
        if 'V16.5.' in req_id or 'error' in req['req_description'].lower():
            # Test error page
            error_url = urljoin(self.target_url, '/nonexistent-page-12345')
            response = self._make_request(error_url)

            if response and response.status_code == 404:
                error_text = response.text.lower()

                # Check for sensitive information disclosure
                sensitive_patterns = [
                    'stack trace', 'traceback', 'exception',
                    'sql', 'database', 'connection string',
                    'password', 'secret', 'token'
                ]

                found_sensitive = []
                for pattern in sensitive_patterns:
                    if pattern in error_text:
                        found_sensitive.append(pattern)

                if found_sensitive:
                    screenshot = None
                    if self.enable_screenshots:
                        screenshot = await self._capture_screenshot(
                            error_url, req_id, "Error page leaking information"
                        )

                    self._add_finding(
                        req_id=req_id,
                        req_description=req['req_description'],
                        status='FAIL',
                        details=f"Error page may leak sensitive information: {', '.join(found_sensitive)}",
                        affected_urls=[error_url],
                        severity='MEDIUM',
                        screenshot=screenshot,
                        chapter_name=req['chapter_name'],
                        section_name=req['section_name'],
                        level=req['level']
                    )
                    return {'req_id': req_id, 'status': 'failed'}
                else:
                    self._add_finding(
                        req_id=req_id,
                        req_description=req['req_description'],
                        status='PASS',
                        details='Error page does not leak sensitive information',
                        affected_urls=[error_url],
                        severity='INFO',
                        chapter_name=req['chapter_name'],
                        section_name=req['section_name'],
                        level=req['level']
                    )
                    return {'req_id': req_id, 'status': 'passed'}

        return await self._test_generic_req(req)

    async def _test_generic_req(self, req: Dict) -> Dict:
        """
        Generic test for requirements that need manual verification

        Marks as INFO status - requires manual code review
        """
        self._add_finding(
            req_id=req['req_id'],
            req_description=req['req_description'],
            status='INFO',
            details='Manual verification required - automated test not available',
            affected_urls=[self.target_url],
            severity='INFO',
            chapter_name=req['chapter_name'],
            section_name=req['section_name'],
            level=req['level']
        )
        return {'req_id': req['req_id'], 'status': 'info'}

    def _get_level_description(self) -> str:
        """Get ASVS level description"""
        descriptions = {
            1: "L1 (Basic) - Essential security controls, OWASP Top 10",
            2: "L2 (Standard) - Standard security for most web applications",
            3: "L3 (Advanced) - High-value applications, critical data, military/government"
        }
        return descriptions.get(self.level, "Unknown")

    def _calculate_summary(self, results: Dict) -> Dict:
        """Calculate overall scan summary"""
        total_checks = 0
        passed = 0
        failed = 0
        warnings = 0
        info_count = 0
        errors = 0

        severity_counts = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0,
            'INFO': 0
        }

        for chapter_id, chapter in results['chapters'].items():
            stats = chapter['stats']
            total_checks += stats['total']
            passed += stats['passed']
            failed += stats['failed']
            warnings += stats['warnings']
            info_count += stats['info']
            errors += stats['error']  # Fixed: was 'errors' but dict uses 'error'

        # Count by severity
        for finding in self.findings:
            severity = finding.get('severity', 'INFO')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        # Calculate score (100 - deductions for failures)
        if total_checks > 0:
            # CRITICAL = -20 points, HIGH = -10, MEDIUM = -5, LOW = -2
            deductions = (
                severity_counts['CRITICAL'] * 20 +
                severity_counts['HIGH'] * 10 +
                severity_counts['MEDIUM'] * 5 +
                severity_counts['LOW'] * 2
            )
            score = max(0, 100 - deductions)
        else:
            score = 0

        # Calculate grade
        if score >= 90:
            grade = 'A'
        elif score >= 80:
            grade = 'B'
        elif score >= 70:
            grade = 'C'
        elif score >= 60:
            grade = 'D'
        else:
            grade = 'F'

        # Compliance status
        if failed == 0 and severity_counts['CRITICAL'] == 0 and severity_counts['HIGH'] == 0:
            compliance = 'COMPLIANT'
        elif severity_counts['CRITICAL'] > 0:
            compliance = 'NON-COMPLIANT'
        else:
            compliance = 'PARTIAL'

        return {
            'total_checks': total_checks,
            'passed': passed,
            'failed': failed,
            'warnings': warnings,
            'info': info_count,
            'errors': errors,
            'critical_issues': severity_counts['CRITICAL'],
            'high_issues': severity_counts['HIGH'],
            'medium_issues': severity_counts['MEDIUM'],
            'low_issues': severity_counts['LOW'],
            'info_issues': severity_counts['INFO'],
            'overall_score': score,
            'overall_grade': grade,
            'compliance_status': compliance
        }

    def _save_results(self, results: Dict):
        """Save scan results to JSON file"""
        output_file = self.evidence_dir / "owasp_asvs_5.0_results.json"

        # Add findings to results
        results['findings'] = self.findings

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)

        print(f"\n[+] Results saved to: {output_file}")
        print(f"[+] Screenshots saved to: {self.screenshot_dir}")

        # Print summary
        summary = results['summary']
        print("\n" + "="*80)
        print("SCAN SUMMARY")
        print("="*80)
        print(f"Total Checks:      {summary['total_checks']}")
        print(f"Passed:            {summary['passed']}")
        print(f"Failed:            {summary['failed']}")
        print(f"Warnings:          {summary['warnings']}")
        print(f"Info:              {summary['info']}")
        print(f"\nIssues by Severity:")
        print(f"  CRITICAL:        {summary['critical_issues']}")
        print(f"  HIGH:            {summary['high_issues']}")
        print(f"  MEDIUM:          {summary['medium_issues']}")
        print(f"  LOW:             {summary['low_issues']}")
        print(f"  INFO:            {summary['info_issues']}")
        print(f"\nOverall Score:     {summary['overall_score']}/100")
        print(f"Grade:             {summary['overall_grade']}")
        print(f"Compliance:        {summary['compliance_status']}")
        print("="*80)


async def main():
    """Main entry point for CLI usage"""
    import argparse

    parser = argparse.ArgumentParser(
        description='OWASP ASVS 5.0 Security Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
ASVS Levels:
  L1: Basic security (70 requirements) - Essential controls, OWASP Top 10
  L2: Standard security (183 requirements) - Most web applications [DEFAULT]
  L3: Advanced security (92 requirements) - High-value/critical applications

Note: There is NO Level 4. Even military/government apps use L3.

Examples:
  # Scan with default L2 (Standard)
  python3 owasp_asvs_5_scanner.py http://target.com ./evidence

  # Scan with L1 (Basic - fewer checks)
  python3 owasp_asvs_5_scanner.py http://target.com ./evidence --level 1

  # Scan with L3 (Advanced - all checks)
  python3 owasp_asvs_5_scanner.py http://target.com ./evidence --level 3

  # Disable screenshots
  python3 owasp_asvs_5_scanner.py http://target.com ./evidence --no-screenshots
        """
    )

    parser.add_argument('target_url', help='Target application URL')
    parser.add_argument('evidence_dir', help='Evidence directory path')
    parser.add_argument('--level', type=int, choices=[1, 2, 3], default=2,
                       help='ASVS level (1=L1/Basic, 2=L2/Standard, 3=L3/Advanced) [default: 2]')
    parser.add_argument('--no-screenshots', action='store_true',
                       help='Disable screenshot capture')

    args = parser.parse_args()

    try:
        scanner = OWASPASVS5Scanner(
            target_url=args.target_url,
            evidence_dir=args.evidence_dir,
            level=args.level,
            enable_screenshots=not args.no_screenshots
        )

        results = await scanner.scan()

        sys.exit(0 if results['summary']['compliance_status'] == 'COMPLIANT' else 1)

    except Exception as e:
        logger.error(f"Scanner error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
