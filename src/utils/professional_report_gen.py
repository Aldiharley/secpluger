"""
SecPluger Professional Report Generator
Production-level penetration testing reports following PTES, OWASP, and SANS standards
"""

from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
import json
from dataclasses import dataclass, asdict
from enum import Enum


class Severity(Enum):
    """CVSS-based severity levels"""
    CRITICAL = "Critical"  # 9.0-10.0
    HIGH = "High"          # 7.0-8.9
    MEDIUM = "Medium"      # 4.0-6.9
    LOW = "Low"            # 0.1-3.9
    INFO = "Informational" # 0.0


class RiskLevel(Enum):
    """Business risk levels"""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Informational"


@dataclass
class CVSSScore:
    """CVSS v3.1 scoring components"""
    base_score: float
    attack_vector: str  # Network, Adjacent, Local, Physical
    attack_complexity: str  # Low, High
    privileges_required: str  # None, Low, High
    user_interaction: str  # None, Required
    scope: str  # Unchanged, Changed
    confidentiality_impact: str  # None, Low, High
    integrity_impact: str  # None, Low, High
    availability_impact: str  # None, Low, High

    def get_severity(self) -> Severity:
        """Convert CVSS score to severity level"""
        if self.base_score >= 9.0:
            return Severity.CRITICAL
        elif self.base_score >= 7.0:
            return Severity.HIGH
        elif self.base_score >= 4.0:
            return Severity.MEDIUM
        elif self.base_score > 0.0:
            return Severity.LOW
        else:
            return Severity.INFO

    def to_vector_string(self) -> str:
        """Generate CVSS vector string"""
        av_map = {"Network": "N", "Adjacent": "A", "Local": "L", "Physical": "P"}
        ac_map = {"Low": "L", "High": "H"}
        pr_map = {"None": "N", "Low": "L", "High": "H"}
        ui_map = {"None": "N", "Required": "R"}
        s_map = {"Unchanged": "U", "Changed": "C"}
        c_map = {"None": "N", "Low": "L", "High": "H"}

        return (f"CVSS:3.1/AV:{av_map[self.attack_vector]}/"
                f"AC:{ac_map[self.attack_complexity]}/"
                f"PR:{pr_map[self.privileges_required]}/"
                f"UI:{ui_map[self.user_interaction]}/"
                f"S:{s_map[self.scope]}/"
                f"C:{c_map[self.confidentiality_impact]}/"
                f"I:{c_map[self.integrity_impact]}/"
                f"A:{c_map[self.availability_impact]}")


@dataclass
class Finding:
    """Individual security finding"""
    id: str
    title: str
    description: str
    severity: Severity
    cvss: Optional[CVSSScore]
    affected_systems: List[str]
    exploitation_steps: List[str]
    evidence: List[str]  # File paths (logs, pcaps, etc.)
    screenshots: List[str] = None  # Screenshot file paths
    remediation: str = ""
    references: List[str] = None  # CVE, CWE, OWASP references
    business_impact: str = ""
    technical_impact: str = ""
    likelihood: str = "Possible"  # Unlikely, Possible, Likely, Certain

    def __post_init__(self):
        """Initialize default values for optional fields"""
        if self.screenshots is None:
            self.screenshots = []
        if self.references is None:
            self.references = []

    def get_risk_level(self) -> RiskLevel:
        """Calculate risk level from severity and likelihood"""
        risk_matrix = {
            ("Critical", "Certain"): RiskLevel.CRITICAL,
            ("Critical", "Likely"): RiskLevel.CRITICAL,
            ("High", "Certain"): RiskLevel.CRITICAL,
            ("High", "Likely"): RiskLevel.HIGH,
            ("Medium", "Certain"): RiskLevel.HIGH,
            ("Medium", "Likely"): RiskLevel.MEDIUM,
        }
        return risk_matrix.get((self.severity.value, self.likelihood), RiskLevel.MEDIUM)


@dataclass
class ComplianceMapping:
    """Map findings to compliance frameworks"""
    pci_dss: List[str]  # e.g., ["6.5.1", "6.5.7"]
    owasp_top10: List[str]  # e.g., ["A03:2021-Injection"]
    cwe: List[str]  # e.g., ["CWE-89"]
    nist: List[str]  # e.g., ["SC-7", "SI-10"]
    iso27001: List[str]  # e.g., ["A.12.6.1"]


class ProfessionalReportGenerator:
    """
    Production-level penetration testing report generator
    Follows PTES, OWASP OPTRS, and SANS standards
    """

    def __init__(self, evidence_path: Path, execution_id: str, metadata: Dict[str, Any] = None):
        self.evidence_path = Path(evidence_path)
        self.execution_id = execution_id
        self.metadata = metadata or {}
        self.findings: List[Finding] = []

    def add_finding(self, finding: Finding):
        """Add a security finding to the report"""
        self.findings.append(finding)

    def generate_executive_summary(self) -> str:
        """Generate executive summary following SANS guidelines"""
        total_findings = len(self.findings)
        critical = sum(1 for f in self.findings if f.severity == Severity.CRITICAL)
        high = sum(1 for f in self.findings if f.severity == Severity.HIGH)
        medium = sum(1 for f in self.findings if f.severity == Severity.MEDIUM)
        low = sum(1 for f in self.findings if f.severity == Severity.LOW)

        target = self.metadata.get('target', 'N/A')
        test_type = self.metadata.get('test_type', 'Black-box Penetration Test')
        duration = self.metadata.get('duration', 'N/A')

        summary = f"""# Executive Summary

## Engagement Overview

**Target**: {target}
**Test Type**: {test_type}
**Duration**: {duration}
**Date**: {datetime.now().strftime('%Y-%m-%d')}
**Tester**: {self.metadata.get('tester', 'SecPluger v2')}

## Key Findings

This penetration test identified **{total_findings} security findings** across the target environment:

- 🔴 **Critical**: {critical} findings
- 🟠 **High**: {high} findings
- 🟡 **Medium**: {medium} findings
- 🔵 **Low**: {low} findings

## Risk Assessment

"""
        if critical > 0 or high > 0:
            summary += """**Overall Risk**: 🔴 **CRITICAL**

The target environment contains critical security vulnerabilities that pose immediate risk to confidentiality, integrity, and availability of systems and data. Immediate remediation is strongly recommended.

"""
        elif medium > 0:
            summary += """**Overall Risk**: 🟠 **HIGH**

The target environment contains significant security weaknesses that should be addressed in the near term to prevent potential compromise.

"""
        else:
            summary += """**Overall Risk**: 🟡 **MEDIUM**

The target environment has a generally acceptable security posture with minor weaknesses that should be addressed as part of regular security maintenance.

"""

        summary += """## Recommendations Priority

1. **Immediate Action Required**: Address all Critical and High severity findings within 7-14 days
2. **Short-term**: Remediate Medium severity findings within 30-60 days
3. **Long-term**: Address Low severity and informational findings within 90 days
4. **Continuous**: Implement security monitoring and regular penetration testing

## Business Impact

"""

        # Add business impact of most critical findings
        critical_findings = [f for f in self.findings if f.severity == Severity.CRITICAL]
        if critical_findings:
            summary += "The most critical findings pose the following business risks:\n\n"
            for finding in critical_findings[:3]:  # Top 3
                summary += f"- **{finding.title}**: {finding.business_impact}\n"

        return summary

    def generate_methodology_section(self) -> str:
        """Document testing methodology (PTES standard)"""
        return """# Testing Methodology

This penetration test followed the **Penetration Testing Execution Standard (PTES)** methodology:

## 1. Pre-Engagement Interactions
- Scope definition and rules of engagement
- Objectives and goals alignment
- Authorization and legal documentation

## 2. Intelligence Gathering
- Passive reconnaissance
- Active reconnaissance
- OSINT collection

## 3. Threat Modeling
- Business asset analysis
- Attack surface mapping
- Threat actor profiling

## 4. Vulnerability Analysis
- Network service enumeration
- Web application scanning
- Vulnerability identification and validation

## 5. Exploitation
- Proof-of-concept exploitation
- Privilege escalation
- Lateral movement testing

## 6. Post-Exploitation
- Persistence mechanisms
- Data exfiltration simulation
- Impact assessment

## 7. Reporting
- Finding documentation
- Risk assessment
- Remediation guidance

## Tools Used

The following industry-standard tools were employed:

**Network Scanning**: nmap, masscan
**Web Scanning**: nuclei, wapiti, nikto
**Enumeration**: gobuster, ffuf, dirb
**Exploitation**: Metasploit Framework, custom exploits
**Traffic Analysis**: mitmproxy, Wireshark
**Automated Testing**: SecPluger v2 workflow engine

## Testing Constraints

- Testing conducted during: {testing_window}
- No social engineering performed
- No physical security testing
- No denial-of-service attacks
- Production systems handled with care
"""

    def generate_findings_section(self) -> str:
        """Generate detailed findings section"""
        if not self.findings:
            return "# Detailed Findings\n\nNo security findings were identified during this assessment.\n"

        # Sort by severity
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4
        }
        sorted_findings = sorted(self.findings, key=lambda f: severity_order[f.severity])

        section = "# Detailed Findings\n\n"

        for idx, finding in enumerate(sorted_findings, 1):
            severity_emoji = {
                Severity.CRITICAL: "🔴",
                Severity.HIGH: "🟠",
                Severity.MEDIUM: "🟡",
                Severity.LOW: "🔵",
                Severity.INFO: "⚪"
            }

            section += f"## Finding {idx}: {finding.title}\n\n"
            section += f"**Severity**: {severity_emoji[finding.severity]} {finding.severity.value}\n"

            if finding.cvss:
                section += f"**CVSS Score**: {finding.cvss.base_score} ({finding.cvss.get_severity().value})\n"
                section += f"**CVSS Vector**: `{finding.cvss.to_vector_string()}`\n"

            section += f"**Risk Level**: {finding.get_risk_level().value}\n"
            section += f"**Likelihood**: {finding.likelihood}\n\n"

            section += f"### Description\n\n{finding.description}\n\n"

            section += f"### Affected Systems\n\n"
            for system in finding.affected_systems:
                section += f"- {system}\n"
            section += "\n"

            section += f"### Technical Impact\n\n{finding.technical_impact}\n\n"
            section += f"### Business Impact\n\n{finding.business_impact}\n\n"

            if finding.exploitation_steps:
                section += f"### Proof of Concept\n\n"
                for step_idx, step in enumerate(finding.exploitation_steps, 1):
                    section += f"{step_idx}. {step}\n"
                section += "\n"

            if finding.evidence:
                section += f"### Evidence\n\n"
                for evidence in finding.evidence:
                    section += f"- `{evidence}`\n"
                section += "\n"

            if finding.screenshots:
                section += f"### Screenshots\n\n"
                for screenshot in finding.screenshots:
                    section += f"![Screenshot]({screenshot})\n\n"
                    section += f"*{Path(screenshot).name}*\n\n"
                section += "\n"

            section += f"### Remediation\n\n{finding.remediation}\n\n"

            if finding.references:
                section += f"### References\n\n"
                for ref in finding.references:
                    section += f"- {ref}\n"
                section += "\n"

            section += "---\n\n"

        return section

    def generate_risk_matrix(self) -> str:
        """Generate visual risk matrix"""
        return """# Risk Assessment Matrix

## Risk Calculation

Risk is calculated using the formula: **Risk = Severity × Likelihood**

| Severity | Likelihood | Risk Level |
|----------|------------|------------|
| Critical | Certain    | CRITICAL   |
| Critical | Likely     | CRITICAL   |
| High     | Certain    | CRITICAL   |
| High     | Likely     | HIGH       |
| Medium   | Certain    | HIGH       |
| Medium   | Likely     | MEDIUM     |
| Low      | Certain    | MEDIUM     |
| Low      | Likely     | LOW        |

## Finding Distribution

```
Severity Distribution:
Critical: █████ {critical_count}
High:     ████  {high_count}
Medium:   ███   {medium_count}
Low:      ██    {low_count}
Info:     █     {info_count}
```

## Remediation Timeline

| Priority | Timeframe | Action |
|----------|-----------|--------|
| 🔴 Critical | 0-7 days | Immediate remediation required |
| 🟠 High | 7-30 days | Urgent remediation needed |
| 🟡 Medium | 30-90 days | Scheduled remediation |
| 🔵 Low | 90+ days | Maintenance window |
"""

    def generate_compliance_section(self, mapping: ComplianceMapping) -> str:
        """Generate compliance mapping section"""
        section = "# Compliance and Standards\n\n"

        if mapping.owasp_top10:
            section += "## OWASP Top 10 2021\n\n"
            section += "This assessment identified vulnerabilities related to:\n\n"
            for item in mapping.owasp_top10:
                section += f"- {item}\n"
            section += "\n"

        if mapping.cwe:
            section += "## Common Weakness Enumeration (CWE)\n\n"
            for cwe in mapping.cwe:
                section += f"- {cwe}\n"
            section += "\n"

        if mapping.pci_dss:
            section += "## PCI DSS Requirements\n\n"
            section += "Findings impact the following PCI DSS requirements:\n\n"
            for req in mapping.pci_dss:
                section += f"- Requirement {req}\n"
            section += "\n"

        if mapping.nist:
            section += "## NIST SP 800-53 Controls\n\n"
            for control in mapping.nist:
                section += f"- {control}\n"
            section += "\n"

        return section

    def generate_full_markdown_report(self, compliance: Optional[ComplianceMapping] = None) -> str:
        """Generate complete professional markdown report"""
        report = f"""# Penetration Testing Report

**Report ID**: {self.execution_id}
**Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Classification**: CONFIDENTIAL
**Distribution**: Authorized Personnel Only

---

"""
        report += self.generate_executive_summary()
        report += "\n\n---\n\n"
        report += self.generate_methodology_section()
        report += "\n\n---\n\n"
        report += self.generate_findings_section()
        report += "\n\n---\n\n"
        report += self.generate_risk_matrix()

        if compliance:
            report += "\n\n---\n\n"
            report += self.generate_compliance_section(compliance)

        report += f"""

---

# Conclusion

This penetration test successfully identified {len(self.findings)} security findings that require attention. The findings have been prioritized based on CVSS scoring, business impact, and likelihood of exploitation.

## Next Steps

1. Review all findings with technical and business stakeholders
2. Develop remediation plan with timelines
3. Begin addressing Critical and High severity findings immediately
4. Schedule re-test after remediation
5. Implement continuous security monitoring

## Contact Information

For questions about this report or remediation guidance, please contact:

**SecPluger Team**
Email: security@secpluger.local
Generated by: SecPluger v2 - AI-Powered Pentesting Automation

---

**End of Report**

*This document contains confidential information and is intended solely for authorized personnel. Unauthorized distribution is prohibited.*
"""

        return report

    def save_report(self, output_path: Optional[Path] = None, generate_pdf: bool = True) -> Path:
        """Save the report to file"""
        if not output_path:
            output_path = self.evidence_path / "PROFESSIONAL_REPORT.md"

        report_content = self.generate_full_markdown_report()

        with open(output_path, 'w') as f:
            f.write(report_content)

        # Also save as JSON for machine parsing (OWASP OPTRS format)
        json_path = output_path.with_suffix('.json')
        self._save_json_report(json_path)

        # Generate PDF if requested
        if generate_pdf:
            try:
                pdf_path = self.generate_pdf(output_path)
                print(f"✅ PDF report generated: {pdf_path}")
            except Exception as e:
                print(f"⚠️ PDF generation failed: {e}")
                print("   Install pandoc or wkhtmltopdf for PDF generation")

        return output_path

    def _save_json_report(self, json_path: Path):
        """Save report in OWASP OPTRS JSON format"""
        report_data = {
            "report_id": self.execution_id,
            "generated": datetime.now().isoformat(),
            "metadata": self.metadata,
            "findings": [
                {
                    "id": f.id,
                    "title": f.title,
                    "description": f.description,
                    "severity": f.severity.value,
                    "cvss": asdict(f.cvss) if f.cvss else None,
                    "affected_systems": f.affected_systems,
                    "exploitation_steps": f.exploitation_steps,
                    "evidence": f.evidence,
                    "screenshots": f.screenshots,
                    "remediation": f.remediation,
                    "references": f.references,
                    "business_impact": f.business_impact,
                    "technical_impact": f.technical_impact,
                    "likelihood": f.likelihood
                }
                for f in self.findings
            ],
            "statistics": {
                "total_findings": len(self.findings),
                "critical": sum(1 for f in self.findings if f.severity == Severity.CRITICAL),
                "high": sum(1 for f in self.findings if f.severity == Severity.HIGH),
                "medium": sum(1 for f in self.findings if f.severity == Severity.MEDIUM),
                "low": sum(1 for f in self.findings if f.severity == Severity.LOW),
                "info": sum(1 for f in self.findings if f.severity == Severity.INFO)
            }
        }

        with open(json_path, 'w') as f:
            json.dump(report_data, f, indent=2)

    def generate_pdf(self, markdown_path: Path) -> Path:
        """
        Generate PDF from markdown report
        Supports multiple backends: pandoc, wkhtmltopdf, weasyprint
        """
        import subprocess
        import shutil

        pdf_path = markdown_path.with_suffix('.pdf')

        # Try pandoc first (best quality)
        if shutil.which('pandoc'):
            try:
                cmd = [
                    'pandoc',
                    str(markdown_path),
                    '-o', str(pdf_path),
                    '--pdf-engine=pdflatex',
                    '-V', 'geometry:margin=1in',
                    '-V', 'fontsize=11pt',
                    '--toc',
                    '--toc-depth=2'
                ]
                subprocess.run(cmd, check=True, capture_output=True)
                return pdf_path
            except subprocess.CalledProcessError:
                # Try without LaTeX
                try:
                    cmd = ['pandoc', str(markdown_path), '-o', str(pdf_path)]
                    subprocess.run(cmd, check=True, capture_output=True)
                    return pdf_path
                except:
                    pass

        # Try wkhtmltopdf
        if shutil.which('wkhtmltopdf'):
            # First convert markdown to HTML
            html_path = markdown_path.with_suffix('.html')
            self._markdown_to_html_for_pdf(markdown_path, html_path)

            cmd = [
                'wkhtmltopdf',
                '--enable-local-file-access',
                '--print-media-type',
                '--page-size', 'Letter',
                '--margin-top', '0.75in',
                '--margin-right', '0.75in',
                '--margin-bottom', '0.75in',
                '--margin-left', '0.75in',
                str(html_path),
                str(pdf_path)
            ]
            try:
                subprocess.run(cmd, check=True, capture_output=True)
                html_path.unlink()  # Clean up temp HTML
                return pdf_path
            except subprocess.CalledProcessError:
                pass

        # Try weasyprint (Python-based, should always work if installed)
        try:
            from weasyprint import HTML

            # Convert markdown to styled HTML (CSS embedded in HTML)
            html_path = markdown_path.with_suffix('.html')
            self._markdown_to_html_for_pdf(markdown_path, html_path)

            # WeasyPrint 60.x+ API - simpler approach
            HTML(filename=str(html_path)).write_pdf(str(pdf_path))

            html_path.unlink()  # Clean up temp HTML
            return pdf_path

        except (ImportError, Exception) as e:
            if isinstance(e, ImportError):
                raise Exception("No PDF generation backend available. Install: pip install weasyprint")
            raise

    def _markdown_to_html_for_pdf(self, md_path: Path, html_path: Path):
        """Convert markdown to HTML for PDF generation"""
        try:
            import markdown
        except ImportError:
            # Fallback: simple conversion
            with open(md_path, 'r') as f:
                content = f.read()
            html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Penetration Test Report</title></head>
<body><pre>{content}</pre></body></html>"""
            with open(html_path, 'w') as f:
                f.write(html)
            return

        # Use markdown library if available
        with open(md_path, 'r') as f:
            md_content = f.read()

        html_content = markdown.markdown(
            md_content,
            extensions=['tables', 'fenced_code', 'codehilite', 'toc']
        )

        full_html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Penetration Test Report - {self.execution_id}</title>
    <style>{self._get_pdf_css()}</style>
</head>
<body>
    {html_content}
</body>
</html>"""

        with open(html_path, 'w') as f:
            f.write(full_html)

    def _get_pdf_css(self) -> str:
        """Professional CSS styling for PDF reports"""
        return """
@page {
    size: Letter;
    margin: 0.75in;
    @top-right {
        content: "Page " counter(page) " of " counter(pages);
        font-size: 9pt;
        color: #666;
    }
}

body {
    font-family: 'Helvetica Neue', Arial, sans-serif;
    font-size: 11pt;
    line-height: 1.6;
    color: #333;
    max-width: 100%;
}

h1 {
    color: #2c3e50;
    font-size: 24pt;
    margin-top: 0;
    padding-bottom: 10pt;
    border-bottom: 3pt solid #3498db;
    page-break-after: avoid;
}

h2 {
    color: #34495e;
    font-size: 18pt;
    margin-top: 20pt;
    margin-bottom: 10pt;
    page-break-after: avoid;
}

h3 {
    color: #555;
    font-size: 14pt;
    margin-top: 15pt;
    page-break-after: avoid;
}

table {
    width: 100%;
    border-collapse: collapse;
    margin: 10pt 0;
    page-break-inside: avoid;
}

th {
    background-color: #3498db;
    color: white;
    padding: 8pt;
    text-align: left;
    font-weight: bold;
}

td {
    padding: 8pt;
    border: 1pt solid #ddd;
}

tr:nth-child(even) {
    background-color: #f8f9fa;
}

code {
    background-color: #f5f5f5;
    padding: 2pt 4pt;
    border-radius: 3pt;
    font-family: 'Courier New', monospace;
    font-size: 10pt;
}

pre {
    background-color: #f5f5f5;
    padding: 10pt;
    border-left: 3pt solid #3498db;
    overflow-x: auto;
    page-break-inside: avoid;
}

ul, ol {
    margin-left: 20pt;
}

li {
    margin-bottom: 5pt;
}

.page-break {
    page-break-before: always;
}

strong {
    font-weight: 600;
    color: #2c3e50;
}

em {
    font-style: italic;
    color: #555;
}

hr {
    border: none;
    border-top: 1pt solid #ddd;
    margin: 20pt 0;
}

blockquote {
    border-left: 3pt solid #3498db;
    padding-left: 15pt;
    margin-left: 0;
    color: #555;
    font-style: italic;
}
"""


# Example usage
if __name__ == "__main__":
    # Example: Generate report for HTB Cap machine
    evidence_path = Path("evidence/20251024_220446_10.10.10.245")

    metadata = {
        "target": "10.10.10.245 (HTB Cap)",
        "test_type": "Black-box Penetration Test",
        "duration": "2 hours",
        "tester": "SecPluger v2 + Claude Code",
        "testing_window": "2025-10-24 22:04-00:04"
    }

    gen = ProfessionalReportGenerator(evidence_path, "20251024_220446_10.10.10.245", metadata)

    # Add IDOR finding
    idor_cvss = CVSSScore(
        base_score=8.2,
        attack_vector="Network",
        attack_complexity="Low",
        privileges_required="None",
        user_interaction="None",
        scope="Unchanged",
        confidentiality_impact="High",
        integrity_impact="Low",
        availability_impact="None"
    )

    idor_finding = Finding(
        id="CAP-001",
        title="Insecure Direct Object Reference (IDOR) in PCAP Download",
        description="The web application allows unauthenticated access to packet capture files by manipulating the file ID parameter. This exposes sensitive network traffic including cleartext credentials.",
        severity=Severity.HIGH,
        cvss=idor_cvss,
        affected_systems=["10.10.10.245:80 (Web Application)"],
        exploitation_steps=[
            "Access http://10.10.10.245/data/0",
            "Download PCAP via http://10.10.10.245/download/0",
            "Analyze with tcpdump -r capture_0.pcap -A | grep -i 'USER\\|PASS'",
            "Extract credentials: nathan:Buck3tH4TF0RM3!"
        ],
        evidence=["evidence/20251024_220446_10.10.10.245/capture_0.pcap"],
        remediation="Implement authentication for PCAP downloads, validate user authorization, use UUIDs instead of sequential IDs",
        references=[
            "OWASP A01:2021 - Broken Access Control",
            "CWE-639: Authorization Bypass Through User-Controlled Key",
            "https://owasp.org/www-community/attacks/Insecure_Direct_Object_Reference_(IDOR)"
        ],
        business_impact="Exposure of network traffic containing credentials enables complete system compromise",
        technical_impact="Unauthorized access to packet captures, credential theft, complete account takeover",
        likelihood="Certain"
    )

    gen.add_finding(idor_finding)

    # Add capability finding
    cap_cvss = CVSSScore(
        base_score=7.8,
        attack_vector="Local",
        attack_complexity="Low",
        privileges_required="Low",
        user_interaction="None",
        scope="Unchanged",
        confidentiality_impact="High",
        integrity_impact="High",
        availability_impact="High"
    )

    cap_finding = Finding(
        id="CAP-002",
        title="Linux Capabilities Misconfiguration (cap_setuid)",
        description="Python3.8 binary has cap_setuid capability enabled, allowing privilege escalation from standard user to root.",
        severity=Severity.CRITICAL,
        cvss=cap_cvss,
        affected_systems=["10.10.10.245 - /usr/bin/python3.8"],
        exploitation_steps=[
            "SSH login as nathan",
            "Check capabilities: getcap -r / 2>/dev/null | grep python",
            "Found: /usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip",
            "Exploit: python3 -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'"
        ],
        evidence=["evidence/20251024_220446_10.10.10.245/root.txt"],
        remediation="Remove cap_setuid from python3.8: sudo setcap -r /usr/bin/python3.8. Only grant capabilities when absolutely necessary.",
        references=[
            "https://gtfobins.github.io/gtfobins/python/#capabilities",
            "CWE-250: Execution with Unnecessary Privileges",
            "Linux capabilities(7) man page"
        ],
        business_impact="Complete system compromise, data breach, service disruption, regulatory violations",
        technical_impact="Privilege escalation from user to root, full system control",
        likelihood="Certain"
    )

    gen.add_finding(cap_finding)

    # Generate report
    report_path = gen.save_report()
    print(f"✅ Professional report generated: {report_path}")
    print(f"✅ JSON report (OWASP OPTRS): {report_path.with_suffix('.json')}")
