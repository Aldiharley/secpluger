#!/usr/bin/env python3
"""
Professional PDF Report Generator for SecPluger v2
Generates production-quality penetration test reports using ReportLab
"""

from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, PageBreak,
    Table, TableStyle, Image, KeepTogether
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional
import json


class ProfessionalReportGenerator:
    """
    Generates professional PDF penetration test reports

    Features:
    - Cover page with branding
    - Executive summary
    - Detailed findings with severity classification
    - Evidence sections
    - Recommendations
    - Professional styling
    """

    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Setup styles
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()

        # Color scheme
        self.colors = {
            'critical': colors.Color(0.8, 0, 0),      # Dark Red
            'high': colors.Color(1, 0.4, 0),          # Orange
            'medium': colors.Color(1, 0.8, 0),        # Yellow
            'low': colors.Color(0.2, 0.6, 1),         # Blue
            'info': colors.Color(0.5, 0.5, 0.5),      # Gray
            'primary': colors.Color(0.2, 0.4, 0.6),   # Dark Blue
        }

    def _setup_custom_styles(self):
        """Setup custom paragraph styles"""

        # Title style
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#2C3E50'),
            spaceAfter=30,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        ))

        # Heading styles
        self.styles.add(ParagraphStyle(
            name='CustomHeading1',
            parent=self.styles['Heading1'],
            fontSize=18,
            textColor=colors.HexColor('#34495E'),
            spaceAfter=12,
            spaceBefore=12,
            fontName='Helvetica-Bold'
        ))

        self.styles.add(ParagraphStyle(
            name='CustomHeading2',
            parent=self.styles['Heading2'],
            fontSize=14,
            textColor=colors.HexColor('#34495E'),
            spaceAfter=10,
            spaceBefore=10,
            fontName='Helvetica-Bold'
        ))

        # Body text
        self.styles.add(ParagraphStyle(
            name='CustomBody',
            parent=self.styles['BodyText'],
            fontSize=11,
            leading=14,
            alignment=TA_JUSTIFY,
            spaceAfter=10
        ))

        # Code block
        self.styles.add(ParagraphStyle(
            name='CodeBlock',
            parent=self.styles['Code'],
            fontSize=9,
            fontName='Courier',
            textColor=colors.HexColor('#2C3E50'),
            backColor=colors.HexColor('#ECF0F1'),
            leftIndent=20,
            rightIndent=20,
            spaceAfter=10
        ))

    def generate_pentest_report(self,
                                target: str,
                                findings: List[Dict],
                                evidence_dir: str,
                                output_filename: Optional[str] = None) -> str:
        """
        Generate complete penetration test report

        Args:
            target: Target IP/domain
            findings: List of vulnerability findings
            evidence_dir: Path to evidence directory
            output_filename: Custom output filename (optional)

        Returns:
            str: Path to generated PDF report
        """
        if output_filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_filename = f"pentest_report_{target}_{timestamp}.pdf"

        output_path = self.output_dir / output_filename

        # Create PDF document
        doc = SimpleDocTemplate(
            str(output_path),
            pagesize=letter,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=18,
        )

        # Build report content
        story = []

        # Cover page
        story.extend(self._build_cover_page(target))
        story.append(PageBreak())

        # Executive summary
        story.extend(self._build_executive_summary(target, findings))
        story.append(PageBreak())

        # Findings
        story.extend(self._build_findings_section(findings))
        story.append(PageBreak())

        # Evidence
        story.extend(self._build_evidence_section(evidence_dir))
        story.append(PageBreak())

        # Recommendations
        story.extend(self._build_recommendations(findings))

        # Build PDF
        doc.build(story)

        return str(output_path)

    def _build_cover_page(self, target: str) -> List:
        """Build cover page"""
        elements = []

        # Spacer to center content
        elements.append(Spacer(1, 2*inch))

        # Title
        title = Paragraph(
            "PENETRATION TEST REPORT",
            self.styles['CustomTitle']
        )
        elements.append(title)
        elements.append(Spacer(1, 0.5*inch))

        # Target
        target_text = Paragraph(
            f"<b>Target:</b> {target}",
            self.styles['CustomHeading2']
        )
        elements.append(target_text)
        elements.append(Spacer(1, 0.3*inch))

        # Date
        date_text = Paragraph(
            f"<b>Date:</b> {datetime.now().strftime('%B %d, %Y')}",
            self.styles['CustomBody']
        )
        elements.append(date_text)
        elements.append(Spacer(1, 0.3*inch))

        # Generated by
        footer_text = Paragraph(
            "<i>Generated with SecPluger v2 Auto-Orchestration</i>",
            self.styles['CustomBody']
        )
        elements.append(footer_text)

        return elements

    def _build_executive_summary(self, target: str, findings: List[Dict]) -> List:
        """Build executive summary"""
        elements = []

        elements.append(Paragraph("EXECUTIVE SUMMARY", self.styles['CustomHeading1']))
        elements.append(Spacer(1, 0.2*inch))

        # Summary text
        summary_text = f"""
        SecPluger v2 conducted a comprehensive penetration test of {target} on
        {datetime.now().strftime('%B %d, %Y')}. The assessment identified
        {len(findings)} security findings across multiple severity levels.
        """
        elements.append(Paragraph(summary_text, self.styles['CustomBody']))
        elements.append(Spacer(1, 0.2*inch))

        # Findings summary table
        severity_counts = self._count_by_severity(findings)

        table_data = [
            ['Severity', 'Count', 'Risk Level'],
            ['Critical', str(severity_counts.get('critical', 0)), 'CRITICAL'],
            ['High', str(severity_counts.get('high', 0)), 'HIGH'],
            ['Medium', str(severity_counts.get('medium', 0)), 'MEDIUM'],
            ['Low', str(severity_counts.get('low', 0)), 'LOW'],
            ['Info', str(severity_counts.get('info', 0)), 'INFORMATIONAL'],
        ]

        table = Table(table_data, colWidths=[2*inch, 1.5*inch, 2*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), self.colors['primary']),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))

        elements.append(table)

        return elements

    def _build_findings_section(self, findings: List[Dict]) -> List:
        """Build detailed findings section"""
        elements = []

        elements.append(Paragraph("DETAILED FINDINGS", self.styles['CustomHeading1']))
        elements.append(Spacer(1, 0.2*inch))

        # Group findings by severity
        grouped = self._group_by_severity(findings)

        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            if severity in grouped and grouped[severity]:
                severity_color = self.colors[severity]

                severity_header = Paragraph(
                    f"<font color='{severity_color.hexval()}'><b>{severity.upper()} SEVERITY FINDINGS</b></font>",
                    self.styles['CustomHeading2']
                )
                elements.append(severity_header)
                elements.append(Spacer(1, 0.1*inch))

                for idx, finding in enumerate(grouped[severity], 1):
                    finding_elements = self._format_finding(finding, idx)
                    elements.append(KeepTogether(finding_elements))

                elements.append(Spacer(1, 0.3*inch))

        return elements

    def _format_finding(self, finding: Dict, index: int) -> List:
        """Format a single finding"""
        elements = []

        # Finding title
        title = Paragraph(
            f"<b>{index}. {finding.get('title', 'Untitled Finding')}</b>",
            self.styles['CustomHeading2']
        )
        elements.append(title)

        # Description
        desc = Paragraph(
            f"<b>Description:</b> {finding.get('description', 'No description')}",
            self.styles['CustomBody']
        )
        elements.append(desc)

        # Impact
        if 'impact' in finding:
            impact = Paragraph(
                f"<b>Impact:</b> {finding['impact']}",
                self.styles['CustomBody']
            )
            elements.append(impact)

        # Remediation
        if 'remediation' in finding:
            remediation = Paragraph(
                f"<b>Remediation:</b> {finding['remediation']}",
                self.styles['CustomBody']
            )
            elements.append(remediation)

        elements.append(Spacer(1, 0.2*inch))

        return elements

    def _build_evidence_section(self, evidence_dir: str) -> List:
        """Build evidence section"""
        elements = []

        elements.append(Paragraph("EVIDENCE", self.styles['CustomHeading1']))
        elements.append(Spacer(1, 0.2*inch))

        evidence_path = Path(evidence_dir)

        if evidence_path.exists():
            evidence_files = sorted(evidence_path.glob("*"))

            if evidence_files:
                files_text = "<br/>".join([f"• {f.name}" for f in evidence_files[:20]])
                elements.append(Paragraph(
                    f"<b>Evidence Files ({len(evidence_files)} total):</b><br/>{files_text}",
                    self.styles['CustomBody']
                ))
            else:
                elements.append(Paragraph(
                    "No evidence files found.",
                    self.styles['CustomBody']
                ))
        else:
            elements.append(Paragraph(
                f"Evidence directory not found: {evidence_dir}",
                self.styles['CustomBody']
            ))

        return elements

    def _build_recommendations(self, findings: List[Dict]) -> List:
        """Build recommendations section"""
        elements = []

        elements.append(Paragraph("RECOMMENDATIONS", self.styles['CustomHeading1']))
        elements.append(Spacer(1, 0.2*inch))

        recommendations = [
            "Immediately address all CRITICAL and HIGH severity findings",
            "Implement a vulnerability management program",
            "Conduct regular security assessments",
            "Apply security patches promptly",
            "Implement defense-in-depth security controls",
            "Provide security awareness training to staff"
        ]

        for rec in recommendations:
            elements.append(Paragraph(f"• {rec}", self.styles['CustomBody']))

        return elements

    def _count_by_severity(self, findings: List[Dict]) -> Dict[str, int]:
        """Count findings by severity"""
        counts = {}
        for finding in findings:
            severity = finding.get('severity', 'info').lower()
            counts[severity] = counts.get(severity, 0) + 1
        return counts

    def _group_by_severity(self, findings: List[Dict]) -> Dict[str, List[Dict]]:
        """Group findings by severity"""
        grouped = {}
        for finding in findings:
            severity = finding.get('severity', 'info').lower()
            if severity not in grouped:
                grouped[severity] = []
            grouped[severity].append(finding)
        return grouped


# ============================================================================
# SINGLETON PATTERN FOR AUTO-INIT
# ============================================================================

_report_generator_instance = None

def get_report_generator(output_dir: str = "reports"):
    """
    Factory function for singleton report generator

    Args:
        output_dir: Directory for generated reports

    Returns:
        ProfessionalReportGenerator: Singleton instance
    """
    global _report_generator_instance

    if _report_generator_instance is None:
        _report_generator_instance = ProfessionalReportGenerator(output_dir)

    return _report_generator_instance


# CLI interface
if __name__ == "__main__":
    import sys

    print("=" * 70)
    print("PROFESSIONAL PDF REPORT GENERATOR - TEST MODE")
    print("=" * 70)
    print()

    # Test with sample data
    test_findings = [
        {
            'title': 'SQL Injection in Login Form',
            'severity': 'critical',
            'description': 'The login form is vulnerable to SQL injection attacks',
            'impact': 'Attacker can bypass authentication and access sensitive data',
            'remediation': 'Use parameterized queries and input validation'
        },
        {
            'title': 'Cross-Site Scripting (XSS)',
            'severity': 'high',
            'description': 'User input is not properly sanitized',
            'impact': 'Attacker can execute arbitrary JavaScript',
            'remediation': 'Implement output encoding and Content Security Policy'
        },
        {
            'title': 'Weak Password Policy',
            'severity': 'medium',
            'description': 'Password policy allows weak passwords',
            'impact': 'Accounts vulnerable to brute force attacks',
            'remediation': 'Enforce strong password requirements'
        },
        {
            'title': 'Information Disclosure',
            'severity': 'low',
            'description': 'Server headers reveal version information',
            'impact': 'Aids in reconnaissance for targeted attacks',
            'remediation': 'Remove or obfuscate server version headers'
        },
        {
            'title': 'Missing Security Headers',
            'severity': 'info',
            'description': 'Security headers like X-Frame-Options are missing',
            'impact': 'Reduced defense-in-depth',
            'remediation': 'Implement recommended security headers'
        }
    ]

    generator = get_report_generator()

    try:
        pdf_path = generator.generate_pentest_report(
            target="test.example.com",
            findings=test_findings,
            evidence_dir="evidence/test",
            output_filename="test_report.pdf"
        )

        print(f"✅ Test report generated successfully!")
        print(f"📄 Report saved to: {pdf_path}")
        print()
        print(f"Findings Summary:")
        counts = generator._count_by_severity(test_findings)
        for severity, count in sorted(counts.items()):
            print(f"   - {severity.upper()}: {count}")

    except Exception as e:
        print(f"❌ Error generating report: {e}")
        import traceback
        traceback.print_exc()
