# Professional Penetration Testing Reports - SecPluger v2

## Overview

SecPluger v2 now includes a production-level penetration testing report generator that follows industry standards including **PTES** (Penetration Testing Execution Standard), **OWASP OPTRS** (OWASP Penetration Test Reporting Standard), and **SANS** reporting guidelines.

## Key Features

### 1. Industry Standard Compliance

- **PTES Methodology**: 7-phase testing methodology documentation
- **OWASP Top 10 2021**: Compliance mapping for web vulnerabilities
- **CVSS v3.1 Scoring**: Precise vulnerability scoring with vector strings
- **CWE/CVE References**: Industry-standard vulnerability classification
- **Risk Matrix**: Business impact and likelihood assessment

### 2. Multiple Output Formats

| Format | Purpose | Status |
|--------|---------|--------|
| **Markdown** | Human-readable documentation | ✅ Fully functional |
| **JSON** | Machine-readable (OWASP OPTRS format) | ✅ Fully functional |
| **PDF** | Professional reports for delivery | ⚠️ Requires pandoc/wkhtmltopdf |

### 3. Professional Report Structure

```
📄 Penetration Test Report
├── Executive Summary
│   ├── Engagement overview
│   ├── Key findings summary
│   ├── Risk assessment
│   ├── Recommendations priority
│   └── Business impact analysis
├── Testing Methodology
│   ├── PTES 7-phase approach
│   ├── Tools used
│   └── Testing constraints
├── Detailed Findings
│   ├── Finding #1 (sorted by severity)
│   │   ├── CVSS score with vector string
│   │   ├── Risk level calculation
│   │   ├── Affected systems
│   │   ├── Technical impact
│   │   ├── Business impact
│   │   ├── Proof of concept steps
│   │   ├── Evidence references
│   │   ├── Remediation guidance
│   │   └── CWE/CVE/OWASP references
│   └── ...
├── Risk Assessment Matrix
│   ├── Risk calculation methodology
│   ├── Finding distribution chart
│   └── Remediation timeline
├── Compliance Mapping (Optional)
│   ├── OWASP Top 10 2021
│   ├── CWE (Common Weakness Enumeration)
│   ├── PCI DSS requirements
│   ├── NIST SP 800-53 controls
│   └── ISO 27001 controls
└── Conclusion & Next Steps
```

## Usage

### Basic Usage

```python
from pathlib import Path
from src.utils.professional_report_gen import (
    ProfessionalReportGenerator,
    Finding,
    CVSSScore,
    Severity
)

# Initialize report generator
evidence_path = Path("evidence/20251024_220446_10.10.10.245")
metadata = {
    "target": "10.10.10.245",
    "test_type": "Black-box Penetration Test",
    "duration": "2 hours",
    "tester": "SecPluger v2",
    "testing_window": "2025-10-24 22:04-00:04"
}

gen = ProfessionalReportGenerator(evidence_path, "session_id", metadata)

# Add findings
finding = Finding(
    id="VULN-001",
    title="SQL Injection in Login Form",
    description="The application is vulnerable to SQL injection...",
    severity=Severity.CRITICAL,
    cvss=CVSSScore(...),
    affected_systems=["10.10.10.245:80"],
    exploitation_steps=["Step 1...", "Step 2..."],
    evidence=["screenshot_01.png", "sqlmap_output.txt"],
    remediation="Use prepared statements and parameterized queries",
    references=["OWASP A03:2021", "CWE-89"],
    business_impact="Complete database compromise",
    technical_impact="Data exfiltration, authentication bypass",
    likelihood="Certain"
)

gen.add_finding(finding)

# Generate reports
report_path = gen.save_report()
# Generates:
# - PROFESSIONAL_REPORT.md (Markdown)
# - PROFESSIONAL_REPORT.json (OWASP OPTRS format)
# - PROFESSIONAL_REPORT.pdf (if pandoc installed)
```

### CVSS v3.1 Scoring

```python
from src.utils.professional_report_gen import CVSSScore

cvss = CVSSScore(
    base_score=8.2,                    # 0.0-10.0
    attack_vector="Network",            # Network, Adjacent, Local, Physical
    attack_complexity="Low",            # Low, High
    privileges_required="None",         # None, Low, High
    user_interaction="None",            # None, Required
    scope="Unchanged",                  # Unchanged, Changed
    confidentiality_impact="High",      # None, Low, High
    integrity_impact="Low",             # None, Low, High
    availability_impact="None"          # None, Low, High
)

# Auto-converts score to severity
severity = cvss.get_severity()  # Returns Severity.HIGH

# Generates CVSS vector string
vector = cvss.to_vector_string()
# Returns: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"
```

### Severity Levels

```python
from src.utils.professional_report_gen import Severity

Severity.CRITICAL  # 9.0-10.0 CVSS
Severity.HIGH      # 7.0-8.9 CVSS
Severity.MEDIUM    # 4.0-6.9 CVSS
Severity.LOW       # 0.1-3.9 CVSS
Severity.INFO      # 0.0 CVSS
```

### Risk Calculation

Risk = Severity × Likelihood

| Severity | Likelihood | Resulting Risk |
|----------|------------|----------------|
| Critical | Certain | CRITICAL |
| Critical | Likely | CRITICAL |
| High | Certain | CRITICAL |
| High | Likely | HIGH |
| Medium | Certain | HIGH |
| Medium | Likely | MEDIUM |

Likelihood values: **Unlikely**, **Possible**, **Likely**, **Certain**

### Compliance Mapping

```python
from src.utils.professional_report_gen import ComplianceMapping

compliance = ComplianceMapping(
    pci_dss=["6.5.1", "6.5.7"],                    # PCI DSS requirements
    owasp_top10=["A03:2021-Injection"],            # OWASP Top 10 2021
    cwe=["CWE-89"],                                # Common Weakness Enumeration
    nist=["SC-7", "SI-10"],                        # NIST SP 800-53 controls
    iso27001=["A.12.6.1", "A.14.2.5"]             # ISO 27001 controls
)

# Include in report generation
report = gen.generate_full_markdown_report()
```

## Report Sections Explained

### Executive Summary

**Purpose**: Non-technical overview for management and stakeholders

**Includes**:
- Engagement scope and timeline
- Total findings by severity (Critical/High/Medium/Low/Info)
- Overall risk assessment (Critical/High/Medium/Low)
- Priority recommendations with timelines
- Top 3 critical business impacts

**Audience**: C-level executives, business owners, compliance officers

### Testing Methodology

**Purpose**: Document systematic approach following PTES

**7 Phases**:
1. Pre-Engagement Interactions
2. Intelligence Gathering
3. Threat Modeling
4. Vulnerability Analysis
5. Exploitation
6. Post-Exploitation
7. Reporting

**Includes**:
- Tools used (nmap, nuclei, wapiti, etc.)
- Testing constraints (no DoS, production hours, etc.)
- Methodology standards (PTES, OWASP, NIST)

### Detailed Findings

**Each finding includes**:

```
## Finding N: [Title]

Severity: 🔴 Critical
CVSS Score: 9.8 (Critical)
CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
Risk Level: CRITICAL
Likelihood: Certain

### Description
[Detailed technical description]

### Affected Systems
- 10.10.10.245:80 (Web Application)
- 10.10.10.245:3306 (MySQL Database)

### Technical Impact
[What an attacker can achieve]

### Business Impact
[How this affects the organization]

### Proof of Concept
1. Navigate to http://target/login
2. Enter payload: ' OR '1'='1
3. Observe authentication bypass

### Evidence
- evidence/screenshot_login_bypass.png
- evidence/sqlmap_output.txt

### Remediation
[Step-by-step fix instructions]

### References
- OWASP A03:2021 - Injection
- CWE-89: SQL Injection
- https://owasp.org/www-community/attacks/SQL_Injection
```

### Risk Assessment Matrix

**Visual representation** of findings by severity and likelihood

**Remediation Timeline**:
- 🔴 **Critical**: 0-7 days (immediate action)
- 🟠 **High**: 7-30 days (urgent)
- 🟡 **Medium**: 30-90 days (scheduled)
- 🔵 **Low**: 90+ days (maintenance window)

## JSON Report Format (OWASP OPTRS)

The JSON output follows the OWASP Penetration Test Reporting Standard for machine parsing:

```json
{
  "report_id": "20251024_220446_10.10.10.245",
  "generated": "2025-10-25T19:24:56.866858",
  "metadata": {
    "target": "10.10.10.245",
    "test_type": "Black-box Penetration Test",
    "duration": "2 hours",
    "tester": "SecPluger v2"
  },
  "findings": [
    {
      "id": "VULN-001",
      "title": "SQL Injection",
      "severity": "Critical",
      "cvss": {
        "base_score": 9.8,
        "attack_vector": "Network",
        ...
      },
      "affected_systems": ["10.10.10.245:80"],
      "exploitation_steps": [...],
      "remediation": "..."
    }
  ],
  "statistics": {
    "total_findings": 5,
    "critical": 2,
    "high": 2,
    "medium": 1,
    "low": 0
  }
}
```

**Use cases**:
- Automated vulnerability tracking systems
- Integration with ticketing systems (Jira, ServiceNow)
- Metrics and reporting dashboards
- Compliance validation tools

## PDF Generation

### Method 1: Pandoc (Best Quality)

```bash
# Install pandoc
sudo apt install pandoc texlive-latex-base texlive-latex-extra

# Automatic PDF generation
gen.save_report(generate_pdf=True)
```

### Method 2: wkhtmltopdf

```bash
# Install wkhtmltopdf
sudo apt install wkhtmltopdf

# Automatic PDF generation
gen.save_report(generate_pdf=True)
```

### Method 3: Manual Conversion

```bash
# Markdown to PDF via pandoc
pandoc PROFESSIONAL_REPORT.md -o report.pdf \
  --pdf-engine=pdflatex \
  -V geometry:margin=1in \
  -V fontsize=11pt \
  --toc \
  --toc-depth=2

# Or use online converters
# https://www.markdowntopdf.com/
```

## Integration with SecPluger Workflow

### Automated Report Generation After Pentest

```python
from src.utils.professional_report_gen import *
from src.database.models import Database

# After pentest completion
evidence_dir = Path(f"evidence/{session_id}")

# Extract findings from database
db = Database()
findings_data = db.get_findings()

# Create professional report
gen = ProfessionalReportGenerator(evidence_dir, session_id, metadata)

# Convert database findings to Finding objects
for finding_data in findings_data:
    finding = Finding(
        id=f"FINDING-{finding_data['id']}",
        title=finding_data['title'],
        description=finding_data['description'],
        severity=Severity[finding_data['severity'].upper()],
        cvss=calculate_cvss_from_finding(finding_data),
        affected_systems=[finding_data['target']],
        exploitation_steps=extract_steps_from_evidence(finding_data),
        evidence=list_evidence_files(evidence_dir),
        remediation=finding_data.get('remediation', 'TBD'),
        references=extract_references(finding_data),
        business_impact=calculate_business_impact(finding_data),
        technical_impact=finding_data['description'],
        likelihood="Certain"  # Can be auto-calculated
    )
    gen.add_finding(finding)

# Generate all formats
report_path = gen.save_report(generate_pdf=True)
print(f"✅ Professional report: {report_path}")
print(f"✅ JSON report: {report_path.with_suffix('.json')}")
print(f"✅ PDF report: {report_path.with_suffix('.pdf')}")
```

## Customization

### Custom Risk Matrix

```python
class CustomRiskLevel(Enum):
    CATASTROPHIC = "Catastrophic"
    SEVERE = "Severe"
    MAJOR = "Major"
    MODERATE = "Moderate"
    MINOR = "Minor"

# Implement custom get_risk_level() in Finding class
```

### Custom Compliance Frameworks

```python
compliance = ComplianceMapping(
    pci_dss=["6.5.1"],
    owasp_top10=["A03:2021"],
    cwe=["CWE-89"],
    nist=["SC-7"],
    iso27001=["A.12.6.1"],
    # Add custom frameworks
    hipaa=["164.308(a)(1)(ii)(D)"],
    sox=["Section 404"],
    gdpr=["Article 32"]
)
```

### Custom Report Branding

Modify `_get_pdf_css()` to customize:
- Colors and fonts
- Company logo
- Page headers/footers
- Report styling

## Best Practices

### 1. Finding Quality

✅ **Good Finding**:
- Clear, descriptive title
- Detailed technical description
- Accurate CVSS scoring
- Step-by-step exploitation
- Specific remediation steps
- Multiple evidence files
- Industry-standard references

❌ **Poor Finding**:
- Vague title ("Security Issue")
- Minimal description
- No CVSS score
- Missing exploitation steps
- Generic remediation
- No evidence
- No references

### 2. CVSS Scoring

- Use [CVSS v3.1 Calculator](https://www.first.org/cvss/calculator/3.1)
- Base scores only (no temporal/environmental)
- Be conservative (don't overstate severity)
- Document scoring rationale

### 3. Evidence Collection

- Screenshots with timestamps
- Tool output (nmap, sqlmap, etc.)
- PCAP files for network attacks
- Proof flags (for CTF/practice)
- Video demonstrations for complex attacks

### 4. Remediation Guidance

- Specific, actionable steps
- Code examples where applicable
- Reference official documentation
- Include verification steps
- Prioritize by risk level

### 5. Professional Language

- Avoid jargon in Executive Summary
- Technical details in Findings section
- Clear, concise writing
- Proofread for errors
- Consistent formatting

## Example Reports

### HTB "Cap" Machine

See `evidence/20251024_220446_10.10.10.245/PROFESSIONAL_REPORT.md` for a complete example including:
- 2 findings (1 Critical, 1 High)
- CVSS v3.1 scoring
- Full exploitation chains
- Evidence references
- Remediation steps

## Comparison with Original Report Generator

| Feature | Original (`report_gen.py`) | Professional (`professional_report_gen.py`) |
|---------|----------------------------|---------------------------------------------|
| Executive Summary | Basic stats only | SANS-compliant with business impact |
| Finding Details | Command output only | CVSSv3.1, risk levels, POC, remediation |
| Methodology | Not documented | Full PTES 7-phase methodology |
| Compliance | None | OWASP, CWE, PCI-DSS, NIST, ISO 27001 |
| Risk Assessment | None | Risk matrix with likelihood calculation |
| Output Formats | HTML only | Markdown, JSON (OWASP OPTRS), PDF |
| Industry Standards | None | PTES, OWASP, SANS guidelines |
| Audience | Technical only | Executive + Technical |

**Recommendation**: Use `ProfessionalReportGenerator` for client deliverables and compliance requirements. Use original `ReportGenerator` for quick internal workflow summaries.

## References

- [PTES - Penetration Testing Execution Standard](http://www.pentest-standard.org/)
- [OWASP OPTRS - Penetration Test Reporting Standard](https://owasp.org/www-project-penetration-test-reporting-standard/)
- [SANS Penetration Testing Report Guide](https://www.sans.org/white-papers/33343/)
- [CVSS v3.1 Specification](https://www.first.org/cvss/v3.1/specification-document)
- [OWASP Top 10 2021](https://owasp.org/Top10/)
- [CWE - Common Weakness Enumeration](https://cwe.mitre.org/)

## Troubleshooting

### PDF Generation Issues

**Problem**: `PDF generation failed: PDF.__init__() takes 1 positional argument`

**Solution**: Install pandoc or wkhtmltopdf:
```bash
sudo apt install pandoc
# OR
sudo apt install wkhtmltopdf
```

**Alternative**: Convert markdown manually or use online tools

### Missing CVSS Scores

**Problem**: Findings don't show CVSS scores

**Solution**: Always provide CVSSScore object:
```python
finding.cvss = CVSSScore(base_score=7.5, ...)
```

### Compliance Mapping Not Showing

**Problem**: Compliance section missing from report

**Solution**: Pass ComplianceMapping to report generator:
```python
compliance = ComplianceMapping(...)
report = gen.generate_full_markdown_report()  # Compliance auto-included if findings have references
```

## Future Enhancements

- [ ] Automated CVSS calculation from vulnerability type
- [ ] Integration with NVD/CVE databases
- [ ] Attack chain visualization (graph diagrams)
- [ ] Automated executive summary generation (AI)
- [ ] Multi-language report support
- [ ] Custom report templates
- [ ] Interactive HTML reports with charts
- [ ] Automated finding deduplication
- [ ] Integration with vulnerability management platforms

---

**Version**: 1.0.0
**Last Updated**: 2025-10-25
**Author**: SecPluger Team
**License**: For authorized security testing only
