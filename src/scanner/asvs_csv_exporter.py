#!/usr/bin/env python3
"""
Enhanced ASVS CSV Exporter
Exports ASVS scan results to CSV format with enhanced fields for client/developer usability

Enhanced Fields:
- Valid: Validation status (Pass/Fail/Manual/N/A)
- Source Code Reference: File:line location of vulnerability
- Comment: Auditor notes and additional context
- Tool Used: Security tool that detected the issue
"""

import csv
import json
from pathlib import Path
from typing import Dict, List, Optional


class ASVSCSVExporter:
    """Export ASVS results to enhanced CSV format"""

    # CSV Headers (14 columns total: 7 original + 7 new)
    CSV_HEADERS = [
        'Category',
        'Check ID',
        'Title',
        'Severity',
        'Status',
        'Details',
        'Recommendation',
        'Valid',  # NEW
        'Source Code Reference',  # NEW
        'Comment',  # NEW
        'Tool Used',  # NEW
        'CWE',  # NEW - Common Weakness Enumeration
        'NIST',  # NEW - NIST SP 800-53 Controls
        'Affected Endpoints'  # NEW - URLs/endpoints affected by this issue
    ]

    # Status to Valid mapping
    STATUS_TO_VALID_MAP = {
        'PASS': 'Pass',
        'FAIL': 'Fail',
        'WARN': 'Fail',
        'INFO': 'Manual',
        'SKIP': 'N/A'
    }

    # ASVS Check ID to CWE mapping (Common Weakness Enumeration)
    ASVS_TO_CWE_MAP = {
        # V1: Architecture
        'V1.14.1': 'CWE-200',  # Exposure of Sensitive Information
        'V1.14.2': 'CWE-538',  # Insertion of Sensitive Information into Externally-Accessible File

        # V2: Authentication
        'V2.1.1': 'CWE-521',  # Weak Password Requirements
        'V2.2.1': 'CWE-307',  # Improper Restriction of Excessive Authentication Attempts
        'V2.3.1': 'CWE-798',  # Use of Hard-coded Credentials
        'V2.10.1': 'CWE-306',  # Missing Authentication for Critical Function

        # V3: Session Management
        'V3.2.1': 'CWE-330',  # Use of Insufficiently Random Values
        'V3.4.1': 'CWE-614',  # Sensitive Cookie Without 'HttpOnly' Flag

        # V4: Access Control
        'V4.1.1': 'CWE-284',  # Improper Access Control
        'V4.3.1': 'CWE-425',  # Direct Request ('Forced Browsing')

        # V5: Validation, Sanitization and Encoding
        'V5.2.1': 'CWE-79',   # Cross-site Scripting (XSS)
        'V5.2.8': 'CWE-89',   # SQL Injection
        'V5.3.3': 'CWE-1336', # Server-Side Template Injection (SSTI)
        'V5.3.10': 'CWE-78',  # OS Command Injection

        # V7: Error Handling and Logging
        'V7.4.1': 'CWE-209',  # Generation of Error Message Containing Sensitive Information

        # V9: Communication
        'V9.1.1': 'CWE-319',  # Cleartext Transmission of Sensitive Information

        # V11: Business Logic
        'V11.1.4': 'CWE-770', # Allocation of Resources Without Limits or Throttling

        # V12: Files and Resources
        'V12.1.1': 'CWE-434', # Unrestricted Upload of File with Dangerous Type
        'V12.3.1': 'CWE-22',  # Path Traversal

        # V13: API and Web Service
        'V13.2.3': 'CWE-770', # Allocation of Resources Without Limits or Throttling
        'V13.4.1': 'CWE-400', # Uncontrolled Resource Consumption

        # V14: Configuration
        'V14.4.1': 'CWE-1021', # Content Security Policy Missing
        'V14.4.2': 'CWE-1021', # X-Content-Type-Options Missing
        'V14.4.3': 'CWE-1021', # Strict-Transport-Security Missing
        'V14.4.4': 'CWE-1021', # X-Frame-Options Missing
        'V14.4.5': 'CWE-1021', # Referrer-Policy Missing
    }

    # ASVS Check ID to NIST SP 800-53 Control mapping
    ASVS_TO_NIST_MAP = {
        # V1: Architecture
        'V1.14.1': 'CM-7, SC-2',  # Configuration Management, Separation of System and User Functionality
        'V1.14.2': 'AC-3, AC-6',  # Access Enforcement, Least Privilege

        # V2: Authentication
        'V2.1.1': 'IA-5',         # Authenticator Management
        'V2.2.1': 'AC-7',         # Unsuccessful Logon Attempts
        'V2.3.1': 'IA-5(1)',      # Password-based Authentication
        'V2.10.1': 'AC-3, IA-2',  # Access Enforcement, Identification and Authentication

        # V3: Session Management
        'V3.2.1': 'SC-13',        # Cryptographic Protection
        'V3.4.1': 'SC-23',        # Session Authenticity

        # V4: Access Control
        'V4.1.1': 'AC-3',         # Access Enforcement
        'V4.3.1': 'AC-3, AC-6',   # Access Enforcement, Least Privilege

        # V5: Validation, Sanitization and Encoding
        'V5.2.1': 'SI-10',        # Information Input Validation
        'V5.2.8': 'SI-10',        # Information Input Validation
        'V5.3.3': 'SI-10',        # Information Input Validation
        'V5.3.10': 'SI-10',       # Information Input Validation

        # V7: Error Handling and Logging
        'V7.4.1': 'SI-11',        # Error Handling

        # V9: Communication
        'V9.1.1': 'SC-8',         # Transmission Confidentiality and Integrity

        # V11: Business Logic
        'V11.1.4': 'SC-5',        # Denial of Service Protection

        # V12: Files and Resources
        'V12.1.1': 'SI-10',       # Information Input Validation
        'V12.3.1': 'SI-10',       # Information Input Validation

        # V13: API and Web Service
        'V13.2.3': 'SC-5',        # Denial of Service Protection
        'V13.4.1': 'SC-5',        # Denial of Service Protection

        # V14: Configuration
        'V14.4.1': 'SC-3, SC-31', # Security Function Isolation, Covert Channel Analysis
        'V14.4.2': 'SC-3',        # Security Function Isolation
        'V14.4.3': 'SC-8, SC-20', # Transmission Confidentiality and Integrity
        'V14.4.4': 'SC-3',        # Security Function Isolation
        'V14.4.5': 'SC-8',        # Transmission Confidentiality and Integrity
    }

    def __init__(self):
        """Initialize CSV exporter"""
        pass

    def export_to_csv(self, json_results: Dict, csv_path: str) -> None:
        """
        Export ASVS JSON results to enhanced CSV format

        Args:
            json_results: ASVS scan results dictionary
            csv_path: Output CSV file path
        """
        csv_path = Path(csv_path)
        csv_path.parent.mkdir(parents=True, exist_ok=True)

        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(self.CSV_HEADERS)

            # Process each category
            categories = json_results.get('categories', {})
            for category_key, category_data in categories.items():
                category_name = category_data.get('category', category_key)
                findings = category_data.get('findings', [])

                for finding in findings:
                    row = self._finding_to_csv_row(finding, category_name)
                    writer.writerow(row)

        print(f"[+] Enhanced CSV exported: {csv_path}")
        print(f"    Format: 14 columns (7 original + 7 enhanced)")
        print(f"    Total rows: {sum(len(cat.get('findings', [])) for cat in categories.values()) + 1}")  # +1 for header

    def _finding_to_csv_row(self, finding: Dict, category_name: str) -> List[str]:
        """
        Convert a single finding to CSV row with 14 columns

        Args:
            finding: Finding dictionary
            category_name: ASVS category name

        Returns:
            List of 14 column values
        """
        result = finding.get('result', {})
        status = result.get('status', 'INFO')
        details = result.get('details', '')
        recommendation = result.get('recommendation', '')

        # Original 7 columns
        check_id = finding.get('id', '')
        title = finding.get('title', '')
        severity = finding.get('severity', 'INFO')

        # Truncate details if too long (keep first 500 chars)
        if len(details) > 500:
            details = details[:497] + '...'

        # NEW FIELDS (columns 8-14)

        # 8. Valid - Convert status to validation format
        valid = self.STATUS_TO_VALID_MAP.get(status, 'Manual')

        # 9. Source Code Reference - Extract from details if available
        source_code_ref = self._extract_source_reference(finding, details)

        # 10. Comment - Initialize empty for auditor to fill
        comment = self._generate_comment(finding, status)

        # 11. Tool Used - Identify which tool detected this
        tool_used = self._identify_tool_used(finding, check_id)

        # 12. CWE - Map ASVS check to Common Weakness Enumeration
        cwe = self._map_to_cwe(check_id)

        # 13. NIST - Map ASVS check to NIST SP 800-53 Controls
        nist = self._map_to_nist(check_id)

        # 14. Affected Endpoints - Extract URLs/endpoints from details
        affected_endpoints = self._extract_affected_endpoints(finding, details)

        return [
            category_name,
            check_id,
            title,
            severity,
            status,
            details,
            recommendation,
            valid,
            source_code_ref,
            comment,
            tool_used,
            cwe,
            nist,
            affected_endpoints
        ]

    def _extract_source_reference(self, finding: Dict, details: str) -> str:
        """
        Extract source code reference from finding details

        Looks for patterns like:
        - /path/to/file.py:123
        - file.js line 42
        - app/controllers/user.rb:56

        Args:
            finding: Finding dictionary
            details: Details text

        Returns:
            Source code reference string or empty string
        """
        import re

        # Check if result has source_ref field (for future enhancement)
        result = finding.get('result', {})
        if 'source_ref' in result:
            return result['source_ref']

        # Pattern 1: /path/file.ext:line
        pattern1 = r'([/\w\-\.]+\.\w+):(\d+)'
        match = re.search(pattern1, details)
        if match:
            return f"{match.group(1)}:{match.group(2)}"

        # Pattern 2: file.ext line N
        pattern2 = r'(\w+\.\w+)\s+line\s+(\d+)'
        match = re.search(pattern2, details, re.IGNORECASE)
        if match:
            return f"{match.group(1)}:{match.group(2)}"

        # Pattern 3: Look for URL paths that might indicate code location
        pattern3 = r'(/[\w/\-\.]+\.(?:php|py|js|rb|java|go|ts))'
        match = re.search(pattern3, details)
        if match:
            return match.group(1)

        return ''

    def _generate_comment(self, finding: Dict, status: str) -> str:
        """
        Generate initial comment based on finding status

        Args:
            finding: Finding dictionary
            status: Current status

        Returns:
            Initial comment for auditor
        """
        if status == 'FAIL' or status == 'WARN':
            return 'Requires remediation'
        elif status == 'INFO':
            return 'Manual verification required'
        elif status == 'PASS':
            return 'Verified secure'
        elif status == 'SKIP':
            return 'Not applicable'
        else:
            return ''

    def _identify_tool_used(self, finding: Dict, check_id: str) -> str:
        """
        Identify which security tool was used for this check

        Args:
            finding: Finding dictionary
            check_id: ASVS check ID

        Returns:
            Tool name or 'owasp_asvs_scanner'
        """
        # Check if result has tool_used field (for future enhancement)
        result = finding.get('result', {})
        if 'tool_used' in result:
            return result['tool_used']

        # Map ASVS categories to common tools
        tool_map = {
            'V1': 'owasp_asvs_scanner',
            'V2': 'owasp_asvs_scanner',
            'V3': 'owasp_asvs_scanner',
            'V4': 'owasp_asvs_scanner',
            'V5.2': 'xss_scanner',  # XSS checks
            'V5.2.8': 'sqlmap',  # SQL injection
            'V5.3.3': 'template_scanner',  # Template injection
            'V5.3.10': 'command_injection_scanner',  # Command injection
            'V9': 'ssl_scanner',  # SSL/TLS checks
            'V12': 'file_upload_scanner',  # File handling
            'V13': 'api_scanner',  # API security
            'V14.4': 'header_scanner'  # HTTP headers
        }

        # Try to match specific check IDs
        for prefix, tool in tool_map.items():
            if check_id.startswith(prefix):
                return tool

        # Default to ASVS scanner
        return 'owasp_asvs_scanner'

    def _map_to_cwe(self, check_id: str) -> str:
        """
        Map ASVS check ID to CWE (Common Weakness Enumeration)

        Args:
            check_id: ASVS check identifier (e.g., V5.2.8)

        Returns:
            CWE identifier (e.g., CWE-89) or empty string
        """
        # Direct lookup
        if check_id in self.ASVS_TO_CWE_MAP:
            return self.ASVS_TO_CWE_MAP[check_id]

        # Try category-level match (e.g., V5.2.8 -> V5.2)
        parts = check_id.split('.')
        if len(parts) >= 2:
            category_prefix = f"{parts[0]}.{parts[1]}"
            if category_prefix in self.ASVS_TO_CWE_MAP:
                return self.ASVS_TO_CWE_MAP[category_prefix]

        # Try top-level category (e.g., V5.2.8 -> V5)
        if len(parts) >= 1:
            top_level = parts[0]
            if top_level in self.ASVS_TO_CWE_MAP:
                return self.ASVS_TO_CWE_MAP[top_level]

        return ''

    def _map_to_nist(self, check_id: str) -> str:
        """
        Map ASVS check ID to NIST SP 800-53 Controls

        Args:
            check_id: ASVS check identifier (e.g., V5.2.8)

        Returns:
            NIST control(s) (e.g., SI-10) or empty string
        """
        # Direct lookup
        if check_id in self.ASVS_TO_NIST_MAP:
            return self.ASVS_TO_NIST_MAP[check_id]

        # Try category-level match (e.g., V5.2.8 -> V5.2)
        parts = check_id.split('.')
        if len(parts) >= 2:
            category_prefix = f"{parts[0]}.{parts[1]}"
            if category_prefix in self.ASVS_TO_NIST_MAP:
                return self.ASVS_TO_NIST_MAP[category_prefix]

        # Try top-level category (e.g., V5.2.8 -> V5)
        if len(parts) >= 1:
            top_level = parts[0]
            if top_level in self.ASVS_TO_NIST_MAP:
                return self.ASVS_TO_NIST_MAP[top_level]

        return ''

    def _extract_affected_endpoints(self, finding: Dict, details: str) -> str:
        """
        Extract affected endpoints/URLs from finding details

        Looks for patterns like:
        - http://localhost:3000/api/users
        - /rest/products/search
        - GET /api/v1/data
        - POST /auth/login

        Args:
            finding: Finding dictionary
            details: Details text

        Returns:
            Comma-separated list of affected endpoints or empty string
        """
        import re

        endpoints = []

        # Check if result has endpoints field (for future enhancement)
        result = finding.get('result', {})
        if 'endpoints' in result:
            # Handle both list of strings and list of dicts
            eps = result['endpoints']
            if isinstance(eps, list) and eps:
                if isinstance(eps[0], dict):
                    # Extract URL from dict if present
                    return ', '.join([ep.get('url', ep.get('path', str(ep))) for ep in eps[:5]])
                else:
                    return ', '.join([str(ep) for ep in eps[:5]])

        # Pattern 1: Full URLs (http://domain/path)
        url_pattern = r'https?://[^\s]+?(/[\w\-/\?=&%\.]+)'
        urls = re.findall(url_pattern, details)
        for url in urls:
            if url not in endpoints:
                endpoints.append(url)

        # Pattern 2: URL paths (/path/to/endpoint)
        path_pattern = r'(?:^|\s)(/[\w\-/]+(?:\?[\w=&%]+)?)'
        paths = re.findall(path_pattern, details)
        for path in paths:
            if path not in endpoints and len(path) > 1:  # Skip single '/'
                endpoints.append(path)

        # Pattern 3: HTTP methods with paths (GET /api/users)
        method_pattern = r'(?:GET|POST|PUT|DELETE|PATCH)\s+(/[\w\-/\?=&%]+)'
        methods = re.findall(method_pattern, details, re.IGNORECASE)
        for method in methods:
            if method not in endpoints:
                endpoints.append(method)

        # Pattern 4: Admin interfaces mentioned in details
        admin_patterns = [
            r'/admin', r'/administrator', r'/manage', r'/dashboard',
            r'/console', r'/panel', r'/api', r'/rest', r'/graphql'
        ]
        for pattern in admin_patterns:
            if re.search(pattern, details, re.IGNORECASE):
                path = pattern.replace('\\', '')
                if path not in endpoints:
                    endpoints.append(path)

        # Pattern 5: Exposed files
        file_pattern = r"'(/[\w/\-\.]+\.(?:php|jsp|asp|config|env|git|json|xml))'"
        files = re.findall(file_pattern, details)
        for file in files:
            if file not in endpoints:
                endpoints.append(file)

        # Limit to first 5 endpoints to avoid overwhelming the column
        if len(endpoints) > 5:
            endpoints = endpoints[:5] + ['...']

        return ', '.join(endpoints) if endpoints else ''

    def export_json_file_to_csv(self, json_file_path: str, csv_file_path: Optional[str] = None) -> None:
        """
        Export JSON file to CSV (convenience method)

        Args:
            json_file_path: Path to ASVS JSON results file
            csv_file_path: Output CSV path (auto-generated if None)
        """
        # Load JSON
        with open(json_file_path, 'r') as f:
            json_results = json.load(f)

        # Auto-generate CSV path if not provided
        if csv_file_path is None:
            json_path = Path(json_file_path)
            csv_file_path = json_path.parent / 'owasp_asvs_detailed_results_enhanced.csv'

        # Export
        self.export_to_csv(json_results, csv_file_path)

    def generate_summary_stats(self, json_results: Dict) -> Dict:
        """
        Generate summary statistics for CSV export

        Args:
            json_results: ASVS scan results

        Returns:
            Dictionary with statistics
        """
        categories = json_results.get('categories', {})

        total_checks = 0
        status_counts = {'Pass': 0, 'Fail': 0, 'Manual': 0, 'N/A': 0}
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}

        for category_data in categories.values():
            findings = category_data.get('findings', [])
            total_checks += len(findings)

            for finding in findings:
                result = finding.get('result', {})
                status = result.get('status', 'INFO')
                severity = finding.get('severity', 'INFO')

                # Count valid status
                valid = self.STATUS_TO_VALID_MAP.get(status, 'Manual')
                status_counts[valid] = status_counts.get(valid, 0) + 1

                # Count severity
                severity_counts[severity] = severity_counts.get(severity, 0) + 1

        return {
            'total_checks': total_checks,
            'validation_status': status_counts,
            'severity_distribution': severity_counts
        }


# Singleton instance
_csv_exporter = None

def get_csv_exporter() -> ASVSCSVExporter:
    """Get singleton CSV exporter instance"""
    global _csv_exporter
    if _csv_exporter is None:
        _csv_exporter = ASVSCSVExporter()
    return _csv_exporter


# CLI interface for standalone usage
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python3 asvs_csv_exporter.py <json_file> [csv_file]")
        print("\nEnhanced ASVS CSV Exporter")
        print("Exports ASVS JSON results to 11-column CSV format")
        print("\nNew Columns:")
        print("  - Valid: Pass/Fail/Manual/N/A validation status")
        print("  - Source Code Reference: File:line location")
        print("  - Comment: Auditor notes field")
        print("  - Tool Used: Detection tool attribution")
        sys.exit(1)

    json_file = sys.argv[1]
    csv_file = sys.argv[2] if len(sys.argv) > 2 else None

    exporter = get_csv_exporter()
    exporter.export_json_file_to_csv(json_file, csv_file)

    # Load and show stats
    with open(json_file, 'r') as f:
        results = json.load(f)

    stats = exporter.generate_summary_stats(results)
    print("\nCSV Export Summary:")
    print(f"  Total Checks: {stats['total_checks']}")
    print(f"  Validation Status:")
    for status, count in stats['validation_status'].items():
        print(f"    - {status}: {count}")
    print(f"  Severity Distribution:")
    for severity, count in stats['severity_distribution'].items():
        if count > 0:
            print(f"    - {severity}: {count}")
