#!/usr/bin/env python3
"""
OWASP ASVS 5.0 CSV Exporter with Evidence Tracking

Exports OWASP ASVS 5.0 scan results to CSV format compatible with:
- Excel/Google Sheets
- Compliance tracking tools (ReqView, JIRA, etc.)
- Internal audit systems

NEW FEATURES for ASVS 5.0:
- Screenshot evidence tracking with filenames
- Affected URL columns showing WHERE vulnerabilities were found
- ASVS Level support (L1/L2/L3)
- Enhanced compliance mapping
"""

import csv
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any


class ASVS5CSVExporter:
    """
    Export OWASP ASVS 5.0 results to CSV checklist format
    with screenshot and affected URL tracking
    """

    def __init__(self, evidence_dir: str = "evidence"):
        self.evidence_dir = Path(evidence_dir)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)

    def export_to_csv(self, asvs_results: Dict,
                     output_filename: Optional[str] = None,
                     include_passed: bool = True) -> str:
        """
        Export ASVS 5.0 results to detailed CSV checklist

        Args:
            asvs_results: ASVS 5.0 scan results from owasp_asvs_5_scanner.py
            output_filename: Optional custom filename
            include_passed: Include passed checks (default: True)

        Returns:
            Path to generated CSV file
        """
        if not output_filename:
            target = asvs_results.get('target', 'unknown').replace('http://', '').replace('https://', '').replace('/', '_')
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_filename = f"OWASP_ASVS_5.0_Checklist_{target}_{timestamp}.csv"

        output_path = self.evidence_dir / output_filename

        # Enhanced CSV headers for ASVS 5.0
        headers = [
            'Requirement ID',         # ASVS ID (e.g., V1.1.1)
            'Chapter',                # ASVS Chapter (e.g., V1: Encoding and Sanitization)
            'Section',                # ASVS Section (e.g., V1.1: Encoding Architecture)
            'ASVS Level',            # L1, L2, or L3
            'Requirement Description', # Full requirement text
            'Status',                 # PASS/FAIL/WARN/INFO/ERROR
            'Severity',               # CRITICAL/HIGH/MEDIUM/LOW/INFO
            'Test Result',            # Human-readable result
            'Details',                # Technical details
            'Affected URLs',          # URLs where issue found (NEW!)
            'Screenshot',             # Screenshot filename (NEW!)
            'Evidence Files',         # Other evidence files
            'Compliance',             # COMPLIANT/NON-COMPLIANT/PARTIAL
            'Recommendation',         # How to fix
            'Tested Date',            # ISO timestamp
            'Tester Notes'            # Blank for manual annotations
        ]

        rows = []

        # Process findings from scanner
        findings = asvs_results.get('findings', [])

        for finding in findings:
            # Skip passed checks if requested
            if not include_passed and finding.get('status') == 'PASS':
                continue

            # Format affected URLs
            affected_urls = finding.get('affected_urls', [])
            affected_urls_str = '\n'.join(affected_urls) if affected_urls else ''

            # Screenshot filename
            screenshot = finding.get('screenshot', '')

            # Status mapping
            status_map = {
                'PASS': 'Passed',
                'FAIL': 'Failed',
                'WARN': 'Warning',
                'INFO': 'Information',
                'ERROR': 'Error'
            }
            status_text = status_map.get(finding.get('status', 'INFO'), finding.get('status', 'INFO'))

            # Compliance status
            compliance_map = {
                'PASS': 'COMPLIANT',
                'FAIL': 'NON-COMPLIANT',
                'WARN': 'PARTIAL',
                'INFO': 'COMPLIANT',
                'ERROR': 'UNKNOWN'
            }
            compliance = compliance_map.get(finding.get('status', 'INFO'), 'UNKNOWN')

            # Generate recommendation based on severity
            recommendation = self._generate_recommendation(
                finding.get('status'),
                finding.get('severity'),
                finding.get('details', '')
            )

            row = [
                finding.get('req_id', ''),
                finding.get('chapter_name', ''),
                finding.get('section_name', ''),
                f"L{finding.get('level', 2)}",
                finding.get('req_description', ''),
                status_text,
                finding.get('severity', 'INFO'),
                finding.get('details', ''),
                finding.get('details', ''),  # Details (duplicate for compatibility)
                affected_urls_str,            # NEW: Affected URLs
                screenshot,                   # NEW: Screenshot
                '',                           # Evidence files (placeholder)
                compliance,
                recommendation,
                finding.get('tested_at', datetime.now().isoformat()),
                ''                            # Blank for tester notes
            ]
            rows.append(row)

        # Write CSV
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            writer.writerows(rows)

        print(f"[+] Detailed CSV checklist exported: {output_path}")
        print(f"    Total checks: {len(rows)}")
        print(f"    Columns: {len(headers)} (including Affected URLs and Screenshots)")
        return str(output_path)

    def export_summary_csv(self, asvs_results: Dict,
                          output_filename: Optional[str] = None) -> str:
        """
        Export category-level summary CSV

        Args:
            asvs_results: ASVS 5.0 scan results
            output_filename: Optional custom filename

        Returns:
            Path to generated CSV file
        """
        if not output_filename:
            target = asvs_results.get('target', 'unknown').replace('http://', '').replace('https://', '').replace('/', '_')
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_filename = f"OWASP_ASVS_5.0_Summary_{target}_{timestamp}.csv"

        output_path = self.evidence_dir / output_filename

        headers = [
            'Chapter ID',
            'Chapter Name',
            'Total Checks',
            'Passed',
            'Failed',
            'Warnings',
            'Info',
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

        # Process each chapter
        chapters = asvs_results.get('chapters', {})

        for chapter_id in sorted(chapters.keys()):
            chapter = chapters[chapter_id]
            stats = chapter.get('stats', {})

            # Count by severity
            severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}

            for req in chapter.get('requirements', []):
                # Find corresponding finding
                findings = [f for f in asvs_results.get('findings', [])
                           if f.get('req_id') == req.get('req_id')]

                if findings:
                    severity = findings[0].get('severity', 'INFO')
                    severity_counts[severity] = severity_counts.get(severity, 0) + 1

            # Calculate score
            total = stats.get('total', 0)
            failed = stats.get('failed', 0)
            if total > 0:
                score = int(((total - failed) / total) * 100)
            else:
                score = 100

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
            if failed == 0 and severity_counts['CRITICAL'] == 0:
                compliance = 'COMPLIANT'
            elif severity_counts['CRITICAL'] > 0:
                compliance = 'NON-COMPLIANT'
            else:
                compliance = 'PARTIAL'

            row = [
                chapter_id,
                chapter.get('name', ''),
                total,
                stats.get('passed', 0),
                failed,
                stats.get('warnings', 0),
                stats.get('info', 0),
                f"{score}/100",
                grade,
                severity_counts['CRITICAL'],
                severity_counts['HIGH'],
                severity_counts['MEDIUM'],
                severity_counts['LOW'],
                severity_counts['INFO'],
                compliance
            ]
            rows.append(row)

        # Overall summary
        summary = asvs_results.get('summary', {})
        overall_row = [
            'OVERALL',
            'ASSESSMENT',
            summary.get('total_checks', 0),
            summary.get('passed', 0),
            summary.get('failed', 0),
            summary.get('warnings', 0),
            summary.get('info', 0),
            f"{summary.get('overall_score', 0)}/100",
            summary.get('overall_grade', 'F'),
            summary.get('critical_issues', 0),
            summary.get('high_issues', 0),
            summary.get('medium_issues', 0),
            summary.get('low_issues', 0),
            summary.get('info_issues', 0),
            summary.get('compliance_status', 'UNKNOWN')
        ]
        rows.append(overall_row)

        # Write CSV
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            writer.writerows(rows)

        print(f"[+] Summary CSV exported: {output_path}")
        print(f"    Categories: {len(rows) - 1}")
        return str(output_path)

    def _generate_recommendation(self, status: str, severity: str, details: str) -> str:
        """Generate remediation recommendation based on finding"""

        if status == 'PASS':
            return 'No action required - check passed'

        if status == 'INFO':
            return 'Manual verification recommended'

        if status == 'ERROR':
            return 'Technical error - review test configuration'

        # Generate recommendations based on severity
        recommendations = {
            'CRITICAL': 'IMMEDIATE ACTION REQUIRED: Address this critical vulnerability within 24-48 hours',
            'HIGH': 'HIGH PRIORITY: Remediate within 1 week',
            'MEDIUM': 'MEDIUM PRIORITY: Address within 30 days',
            'LOW': 'LOW PRIORITY: Address in next development cycle',
        }

        base_rec = recommendations.get(severity, 'Review and address as appropriate')

        # Add specific guidance based on details
        if 'HTTPS' in details or 'TLS' in details:
            base_rec += '. Implement HTTPS/TLS encryption immediately'
        elif 'header' in details.lower():
            base_rec += '. Configure security headers on web server'
        elif 'error' in details.lower() and 'sensitive' in details.lower():
            base_rec += '. Implement generic error pages, disable stack traces in production'

        return base_rec


def main():
    """CLI interface for CSV export"""
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description='Export OWASP ASVS 5.0 results to CSV format',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Export from JSON results
  python3 asvs_5_csv_exporter.py results.json ./evidence

  # Export detailed checklist only
  python3 asvs_5_csv_exporter.py results.json ./evidence --checklist-only

  # Export summary only
  python3 asvs_5_csv_exporter.py results.json ./evidence --summary-only

  # Include only failed checks
  python3 asvs_5_csv_exporter.py results.json ./evidence --failed-only
        """
    )

    parser.add_argument('results_file', help='ASVS 5.0 results JSON file')
    parser.add_argument('evidence_dir', help='Evidence directory for CSV output')
    parser.add_argument('--checklist-only', action='store_true',
                       help='Export detailed checklist only')
    parser.add_argument('--summary-only', action='store_true',
                       help='Export summary only')
    parser.add_argument('--failed-only', action='store_true',
                       help='Include only failed checks in detailed checklist')

    args = parser.parse_args()

    # Load results
    try:
        with open(args.results_file, 'r') as f:
            results = json.load(f)
    except Exception as e:
        print(f"[!] Error loading results: {e}")
        sys.exit(1)

    # Export
    exporter = ASVS5CSVExporter(evidence_dir=args.evidence_dir)

    try:
        if not args.summary_only:
            checklist_path = exporter.export_to_csv(
                results,
                include_passed=not args.failed_only
            )
            print(f"\n[+] Detailed checklist: {checklist_path}")

        if not args.checklist_only:
            summary_path = exporter.export_summary_csv(results)
            print(f"[+] Summary: {summary_path}")

        print("\n[+] CSV export complete!")

    except Exception as e:
        print(f"[!] Export error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
