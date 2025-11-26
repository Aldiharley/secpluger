#!/usr/bin/env python3
"""
OWASP ASVS CSV Exporter with Evidence Tracking

This module exports OWASP ASVS scan results to CSV format compatible with
standard compliance tracking tools. Includes:
- All 14 ASVS categories
- Per-check status (PASS/FAIL/WARN/INFO)
- Evidence file links
- Screenshot references
- Compliance status
- Remediation recommendations

Based on industry best practices from:
- OWASP ASVS 4.0.3 official checklist
- ReqView ASVS template format
- PivotPoint Security ASVS spreadsheet
"""

import csv
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any


class ASVSCSVExporter:
    """
    Export OWASP ASVS results to CSV checklist format with evidence tracking
    """

    def __init__(self, evidence_dir: str = "evidence"):
        self.evidence_dir = Path(evidence_dir)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)

    def export_to_csv(self, asvs_results: Dict,
                     output_filename: Optional[str] = None,
                     include_passed: bool = True) -> str:
        """
        Export ASVS results to CSV checklist format

        Args:
            asvs_results: OWASP ASVS scan results (from owasp_asvs_scanner.py)
            output_filename: Optional custom filename
            include_passed: Include passed checks (default: True)

        Returns:
            Path to generated CSV file
        """

        if output_filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            target = asvs_results.get('target', 'unknown').replace('http://', '').replace('https://', '').replace('/', '_')
            output_filename = f"OWASP_ASVS_Checklist_{target}_{timestamp}.csv"

        csv_path = self.evidence_dir / output_filename

        # CSV Headers (compatible with standard compliance tracking tools)
        headers = [
            'Requirement ID',
            'Category',
            'ASVS Level',
            'Requirement Title',
            'Test Description',
            'Severity',
            'Status',
            'Test Result',
            'Details',
            'Evidence Files',
            'Screenshot',
            'Compliance',
            'Recommendation',
            'Tested Date',
            'Tester Notes'
        ]

        rows = []

        # Extract data from ASVS results
        target = asvs_results.get('target', 'Unknown')
        timestamp_tested = asvs_results.get('timestamp', datetime.now().isoformat())
        asvs_level = asvs_results.get('asvs_level', 2)

        # Process each category
        for category_key in sorted(asvs_results.get('categories', {}).keys()):
            category_data = asvs_results['categories'][category_key]
            category_name = category_data.get('category', category_key)

            # Process each finding/check in the category
            for finding in category_data.get('findings', []):
                test_result = finding.get('result', {})
                status = test_result.get('status', 'UNKNOWN')

                # Skip passed checks if requested
                if not include_passed and status == 'PASS':
                    continue

                # Build row data
                row = {
                    'Requirement ID': finding.get('id', 'N/A'),
                    'Category': category_name,
                    'ASVS Level': str(asvs_level),
                    'Requirement Title': finding.get('title', 'N/A'),
                    'Test Description': finding.get('test', 'N/A'),
                    'Severity': finding.get('severity', 'INFO'),
                    'Status': status,
                    'Test Result': self._get_status_label(status),
                    'Details': test_result.get('details', 'N/A'),
                    'Evidence Files': self._get_evidence_files(finding, category_key),
                    'Screenshot': self._get_screenshot_path(finding, category_key),
                    'Compliance': self._get_compliance_status(status),
                    'Recommendation': test_result.get('recommendation', 'N/A') if status in ['FAIL', 'WARN'] else 'N/A',
                    'Tested Date': timestamp_tested,
                    'Tester Notes': ''  # Blank for manual notes
                }

                rows.append(row)

        # Write CSV file
        with open(csv_path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=headers)
            writer.writeheader()
            writer.writerows(rows)

        return str(csv_path)

    def export_summary_csv(self, asvs_results: Dict,
                          output_filename: Optional[str] = None) -> str:
        """
        Export category-level summary CSV

        Args:
            asvs_results: OWASP ASVS scan results
            output_filename: Optional custom filename

        Returns:
            Path to generated summary CSV file
        """

        if output_filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            target = asvs_results.get('target', 'unknown').replace('http://', '').replace('https://', '').replace('/', '_')
            output_filename = f"OWASP_ASVS_Summary_{target}_{timestamp}.csv"

        csv_path = self.evidence_dir / output_filename

        headers = [
            'Category',
            'Total Checks',
            'Passed',
            'Failed',
            'Warnings',
            'Score',
            'Grade',
            'CRITICAL Issues',
            'HIGH Issues',
            'MEDIUM Issues',
            'LOW Issues',
            'INFO Issues',
            'Compliance Status'
        ]

        rows = []

        # Process each category
        for category_key in sorted(asvs_results.get('categories', {}).keys()):
            category_data = asvs_results['categories'][category_key]
            score_info = category_data.get('score', {})
            findings = category_data.get('findings', [])

            # Count by status
            passed = sum(1 for f in findings if f['result'].get('status') == 'PASS')
            failed = sum(1 for f in findings if f['result'].get('status') == 'FAIL')
            warnings = sum(1 for f in findings if f['result'].get('status') == 'WARN')

            # Count by severity (only failed/warn)
            critical = sum(1 for f in findings if f.get('severity') == 'CRITICAL' and f['result'].get('status') in ['FAIL', 'WARN'])
            high = sum(1 for f in findings if f.get('severity') == 'HIGH' and f['result'].get('status') in ['FAIL', 'WARN'])
            medium = sum(1 for f in findings if f.get('severity') == 'MEDIUM' and f['result'].get('status') in ['FAIL', 'WARN'])
            low = sum(1 for f in findings if f.get('severity') == 'LOW' and f['result'].get('status') in ['FAIL', 'WARN'])
            info = sum(1 for f in findings if f.get('severity') == 'INFO' and f['result'].get('status') in ['FAIL', 'WARN'])

            # Compliance status based on grade
            grade = score_info.get('grade', 'F')
            compliance = 'COMPLIANT' if grade in ['A', 'B'] else 'NON-COMPLIANT' if grade == 'F' else 'PARTIAL'

            row = {
                'Category': category_data.get('category', category_key),
                'Total Checks': str(score_info.get('total_findings', 0)),
                'Passed': str(passed),
                'Failed': str(failed),
                'Warnings': str(warnings),
                'Score': f"{score_info.get('score', 0)}/100",
                'Grade': grade,
                'CRITICAL Issues': str(critical),
                'HIGH Issues': str(high),
                'MEDIUM Issues': str(medium),
                'LOW Issues': str(low),
                'INFO Issues': str(info),
                'Compliance Status': compliance
            }

            rows.append(row)

        # Add overall summary row
        summary = asvs_results.get('summary', {})
        overall_row = {
            'Category': 'OVERALL ASSESSMENT',
            'Total Checks': str(summary.get('total_checks', 0)),
            'Passed': str(summary.get('total_checks', 0) - sum([
                summary.get('critical_issues', 0),
                summary.get('high_issues', 0),
                summary.get('medium_issues', 0),
                summary.get('low_issues', 0),
                summary.get('info_issues', 0)
            ])),
            'Failed': str(sum([
                summary.get('critical_issues', 0),
                summary.get('high_issues', 0),
                summary.get('medium_issues', 0),
                summary.get('low_issues', 0),
                summary.get('info_issues', 0)
            ])),
            'Warnings': '0',
            'Score': f"{summary.get('overall_score', 0):.1f}/100",
            'Grade': summary.get('overall_grade', 'F'),
            'CRITICAL Issues': str(summary.get('critical_issues', 0)),
            'HIGH Issues': str(summary.get('high_issues', 0)),
            'MEDIUM Issues': str(summary.get('medium_issues', 0)),
            'LOW Issues': str(summary.get('low_issues', 0)),
            'INFO Issues': str(summary.get('info_issues', 0)),
            'Compliance Status': 'COMPLIANT' if summary.get('overall_grade', 'F') in ['A', 'B'] else 'NON-COMPLIANT'
        }

        rows.append(overall_row)

        # Write CSV file
        with open(csv_path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=headers)
            writer.writeheader()
            writer.writerows(rows)

        return str(csv_path)

    def _get_status_label(self, status: str) -> str:
        """Convert status to human-readable label"""
        labels = {
            'PASS': 'Passed',
            'FAIL': 'Failed',
            'WARN': 'Warning',
            'ERROR': 'Test Error',
            'SKIP': 'Skipped',
            'INFO': 'Informational'
        }
        return labels.get(status, status)

    def _get_compliance_status(self, status: str) -> str:
        """Get compliance status based on test result"""
        if status == 'PASS':
            return 'COMPLIANT'
        elif status in ['FAIL', 'ERROR']:
            return 'NON-COMPLIANT'
        elif status == 'WARN':
            return 'PARTIAL COMPLIANCE'
        else:
            return 'NOT TESTED'

    def _get_evidence_files(self, finding: Dict, category_key: str) -> str:
        """Get comma-separated list of evidence files for this finding"""
        # Check for evidence files in the evidence directory
        finding_id = finding.get('id', '').replace('.', '_')
        category_prefix = category_key.split('_')[0]  # e.g., V1, V2

        evidence_files = []

        # Look for common evidence file patterns
        patterns = [
            f"{category_prefix}_{finding_id}_*.txt",
            f"{category_prefix}_{finding_id}_*.json",
            f"{category_prefix}_{finding_id}_*.html",
            f"{finding_id}_*.txt"
        ]

        for pattern in patterns:
            matches = list(self.evidence_dir.glob(pattern))
            evidence_files.extend([f.name for f in matches])

        return ', '.join(evidence_files) if evidence_files else 'N/A'

    def _get_screenshot_path(self, finding: Dict, category_key: str) -> str:
        """Get screenshot filename for this finding"""
        finding_id = finding.get('id', '').replace('.', '_')
        category_prefix = category_key.split('_')[0]

        # Look for screenshot files
        screenshot_patterns = [
            f"{category_prefix}_{finding_id}_*.png",
            f"{category_prefix}_{finding_id}_*.jpg",
            f"screenshot_{finding_id}_*.png"
        ]

        for pattern in screenshot_patterns:
            matches = list(self.evidence_dir.glob(pattern))
            if matches:
                return matches[0].name

        return 'N/A'


def main():
    """Test the CSV exporter"""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python3 asvs_csv_exporter.py <asvs_results.json> [evidence_dir]")
        print("\nExamples:")
        print("  python3 asvs_csv_exporter.py evidence/owasp_asvs_results.json")
        print("  python3 asvs_csv_exporter.py evidence/owasp_asvs_results.json ./evidence")
        sys.exit(1)

    results_file = sys.argv[1]
    evidence_dir = sys.argv[2] if len(sys.argv) > 2 else os.path.dirname(results_file)

    # Load ASVS results
    if not os.path.exists(results_file):
        print(f"Error: Results file not found: {results_file}")
        sys.exit(1)

    with open(results_file, 'r') as f:
        asvs_results = json.load(f)

    # Create exporter
    exporter = ASVSCSVExporter(evidence_dir=evidence_dir)

    # Export detailed checklist
    print(f"[*] Exporting detailed OWASP ASVS checklist...")
    detailed_csv = exporter.export_to_csv(asvs_results, include_passed=True)
    print(f"[+] Detailed checklist: {detailed_csv}")

    # Export summary
    print(f"[*] Exporting category summary...")
    summary_csv = exporter.export_summary_csv(asvs_results)
    print(f"[+] Summary: {summary_csv}")

    # Show statistics
    total_rows = 0
    with open(detailed_csv, 'r') as f:
        total_rows = sum(1 for _ in f) - 1  # Subtract header row

    print(f"\n[+] Export complete!")
    print(f"    Total checks exported: {total_rows}")
    print(f"    Evidence directory: {evidence_dir}")
    print(f"\nFiles created:")
    print(f"  1. {detailed_csv} - Complete ASVS checklist")
    print(f"  2. {summary_csv} - Category-level summary")


if __name__ == "__main__":
    main()
