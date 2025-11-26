# OWASP ASVS Resources for Security Testing

## Overview

This directory contains OWASP Application Security Verification Standard (ASVS) resources for conducting comprehensive security assessments. These templates are designed for use with SecPluger v2's built-in ASVS 5.0 scanner and can be used for pentesting practice against vulnerable applications like OWASP Juice Shop.

## Available Resources

### 1. ASVS 4.0.2 Checklist (Excel)
- **File**: `ASVS-checklist-en.xlsx` (71 KB)
- **Source**: https://github.com/shenril/owasp-asvs-checklist
- **Version**: ASVS 4.0.2 compatible
- **Format**: Microsoft Excel 2007+
- **Purpose**: Manual checklist for compliance audits (legacy version)
- **Use Case**: Manual testing, audit documentation, compliance tracking

### 2. ASVS 5.0.0 Database (CSV)
- **File**: `OWASP_Application_Security_Verification_Standard_5.0.0_en.csv`
- **Source**: https://github.com/OWASP/ASVS (Official OWASP repository)
- **Version**: ASVS 5.0.0 (Latest - Released October 2024)
- **Format**: CSV with 345 security requirements
- **Purpose**: Programmatic import for SecPluger's automated scanner
- **Use Case**: Automated scanning, CI/CD integration, compliance automation

### 3. Full ASVS Repository (Multi-format)
- **Directory**: `ASVS/` (git submodule - removed from repo)
- **Note**: The full ASVS repository is excluded from git to prevent embedded repository issues
- **Access**: Clone separately from https://github.com/OWASP/ASVS
- **Available Formats**: CSV, JSON, PDF, DOCX
- **Languages**: English, Russian, Turkish, French, and more

## ASVS Versions: 4.0.2 vs 5.0.0

| Feature | ASVS 4.0.2 | ASVS 5.0.0 |
|---------|-----------|-----------|
| **Requirements** | ~286 requirements | **345 requirements** |
| **Categories** | 14 chapters | **17 chapters** |
| **Format** | Excel checklist | CSV/JSON database |
| **Release Date** | March 2019 | October 2024 |
| **SecPluger Support** | Manual only | **Fully automated** |
| **Screenshot Evidence** | No | **Yes (Playwright)** |
| **Affected URLs** | No | **Yes (tracked per finding)** |
| **CSV Export** | No | **Yes (16-column format)** |

**Recommendation**: Use ASVS 5.0.0 for automated testing with SecPluger v2.

## Using with SecPluger v2

SecPluger v2 includes a fully automated OWASP ASVS 5.0 scanner with advanced features:

### Scanner Location
```
src/scanner/owasp_asvs_5_scanner.py
```

### Key Features
- ✅ **345 ASVS 5.0 requirements** across 17 categories
- ✅ **Level filtering**: L1 (70 reqs), L2 (183 reqs), L3 (92 reqs)
- ✅ **Screenshot evidence**: Automatic capture with Playwright
- ✅ **Affected URL tracking**: Each finding shows which URLs are vulnerable
- ✅ **CSV export**: 16-column Excel-compatible checklist
- ✅ **Summary reports**: Compliance overview with pass/fail statistics
- ✅ **Async architecture**: Fast parallel testing

### Quick Start Commands

#### Option 1: Complete Workflow (Recommended)
```bash
# Run complete ASVS 5.0 assessment with CSV export
python3 complete_asvs_5_workflow.py http://target.com target_name --level 2

# With screenshots enabled (default)
python3 complete_asvs_5_workflow.py http://target.com target_name --level 2

# Without screenshots (faster)
python3 complete_asvs_5_workflow.py http://target.com target_name --level 2 --no-screenshots

# Test against Juice Shop (L2 standard)
python3 complete_asvs_5_workflow.py http://localhost:3000 juice_shop --level 2
```

#### Option 2: Scanner Only
```bash
# Run ASVS 5.0 scanner directly
python3 src/scanner/owasp_asvs_5_scanner.py http://target.com ./evidence --level 2

# L1 (Basic) - 70 requirements, fastest
python3 src/scanner/owasp_asvs_5_scanner.py http://target.com ./evidence --level 1 --no-screenshots

# L2 (Standard) - 183 requirements, recommended for most apps
python3 src/scanner/owasp_asvs_5_scanner.py http://target.com ./evidence --level 2

# L3 (Advanced) - 92 requirements, high-security apps
python3 src/scanner/owasp_asvs_5_scanner.py http://target.com ./evidence --level 3
```

#### Option 3: Export CSV from Existing Results
```bash
# If you already have scan results JSON
python3 src/reporting/asvs_5_csv_exporter.py evidence/20241029_120000_target/owasp_asvs_5.0_results.json ./evidence

# Open in LibreOffice Calc
libreoffice evidence/20241029_120000_target/OWASP_ASVS_5.0_Checklist_*.csv
```

### Output Files

After running the complete workflow, you'll find:

```
evidence/YYYYMMDD_HHMMSS_target/
├── owasp_asvs_5.0_results.json              # Detailed scan results
├── OWASP_ASVS_5.0_Checklist_YYYYMMDD.csv   # 16-column compliance checklist
├── OWASP_ASVS_5.0_Summary_YYYYMMDD.csv     # Summary by category
├── screenshots/                              # Evidence screenshots
│   ├── V1_1_1_20241029_120530.png
│   ├── V2_3_1_20241029_120545.png
│   └── ... (one per finding with affected URLs)
└── asvs_5_scan.log                          # Scan execution log
```

### CSV Checklist Format

The exported CSV includes 16 columns:

| Column | Description |
|--------|-------------|
| **ASVS ID** | Requirement ID (e.g., V1.1.1) |
| **Category** | ASVS chapter name |
| **Requirement** | Security requirement description |
| **ASVS Level** | L1, L2, or L3 |
| **Status** | PASS / FAIL / NOT_TESTED |
| **Finding Title** | Vulnerability title (if failed) |
| **Severity** | CRITICAL / HIGH / MEDIUM / LOW / INFO |
| **Affected URLs** | List of vulnerable URLs |
| **CVSS Score** | Common Vulnerability Scoring System score |
| **CWE** | Common Weakness Enumeration ID |
| **Description** | Detailed vulnerability description |
| **Remediation** | Fix recommendations |
| **Evidence** | Technical evidence (requests, responses) |
| **Screenshot** | Path to screenshot file |
| **Test Date** | ISO 8601 timestamp |
| **Notes** | Additional observations |

Perfect for:
- ✅ Compliance audits and reporting
- ✅ Security assessments documentation
- ✅ Tracking remediation progress
- ✅ Executive summaries with filtering

## ASVS Security Levels

OWASP ASVS 5.0 defines **three security levels** (NO Level 4):

### Level 1 (L1) - Basic Security
- **Requirements**: 70 requirements
- **Target**: All applications
- **Focus**: OWASP Top 10 coverage, essential security controls
- **Use Cases**: Public websites, low-risk applications
- **Scan Time**: ~1-2 minutes
- **Command**: `--level 1`

### Level 2 (L2) - Standard Security ⭐ **RECOMMENDED**
- **Requirements**: 183 requirements (includes all L1)
- **Target**: Most web applications
- **Focus**: Defense-in-depth, secure development practices
- **Use Cases**: Business applications, e-commerce, SaaS platforms
- **Scan Time**: ~3-5 minutes
- **Command**: `--level 2`

### Level 3 (L3) - Advanced Security
- **Requirements**: 92 requirements (includes all L1 + L2)
- **Target**: High-security applications
- **Focus**: Advanced security controls, defense against APTs
- **Use Cases**: Banking, healthcare, government, critical infrastructure
- **Scan Time**: ~5-10 minutes
- **Command**: `--level 3`

**Total**: 345 unique requirements across all levels (70 L1-only + 183 L2-only + 92 L3-only)

**Note**: Even military/government applications use L3. There is NO Level 4 in ASVS 5.0.

## ASVS 5.0 Categories (17 Chapters)

SecPluger v2 tests all 17 ASVS 5.0 categories:

| Category | Chapter | Description |
|----------|---------|-------------|
| **V1** | Architecture | Design, threat modeling, secure architecture |
| **V2** | Authentication | Password security, MFA, session binding |
| **V3** | Session Management | Session lifecycle, tokens, cookies |
| **V4** | Access Control | Authorization, RBAC, privilege escalation |
| **V5** | Validation | Input validation, output encoding, sanitization |
| **V6** | Cryptography | Encryption, hashing, key management |
| **V7** | Error Handling | Logging, error messages, stack traces |
| **V8** | Data Protection | PII handling, data classification, retention |
| **V9** | Communication | TLS, certificate validation, secure channels |
| **V10** | Malicious Code | Code integrity, supply chain security |
| **V11** | Business Logic | Workflow security, rate limiting, anti-automation |
| **V12** | Files & Resources | File upload, path traversal, resource limits |
| **V13** | API Security | REST/GraphQL security, authentication, rate limiting |
| **V14** | Configuration | Security headers, hardening, dependency management |
| **V15** | Compliance | GDPR, privacy, regulatory requirements (NEW in 5.0) |
| **V16** | Container Security | Docker/K8s security, orchestration (NEW in 5.0) |
| **V17** | Supply Chain | Third-party dependencies, SBOM (NEW in 5.0) |

**New in ASVS 5.0**: V15 (Compliance), V16 (Containers), V17 (Supply Chain)

## Testing OWASP Juice Shop with ASVS

OWASP Juice Shop is an intentionally vulnerable web application that maps vulnerabilities to ASVS requirements, making it perfect for practicing ASVS-based assessments.

### Common Juice Shop Vulnerabilities → ASVS Mapping

| Vulnerability | ASVS Category | Level | Example Test |
|--------------|---------------|-------|--------------|
| **SQL Injection** | V5 (Validation) | L1, L2, L3 | Login bypass: `' OR 1=1--` |
| **XSS (Reflected)** | V5 (Validation) | L1, L2, L3 | Search: `<script>alert(1)</script>` |
| **XSS (Stored)** | V5 (Validation) | L1, L2, L3 | Review field XSS |
| **Broken Authentication** | V2 (Authentication) | L1, L2, L3 | Weak passwords, password reset flaws |
| **Session Fixation** | V3 (Session Mgmt) | L2, L3 | Session token prediction |
| **Sensitive Data Exposure** | V8 (Data Protection) | L2, L3 | Exposed confidential documents |
| **Broken Access Control** | V4 (Access Control) | L1, L2, L3 | IDOR, privilege escalation |
| **Security Misconfiguration** | V14 (Configuration) | L1, L2, L3 | Error stack traces, debug mode |
| **API Security Issues** | V13 (API Security) | L2, L3 | Mass assignment, parameter pollution |
| **Insecure Deserialization** | V5 (Validation) | L3 | Unsafe object deserialization |

### Running ASVS Assessment on Juice Shop

```bash
# Step 1: Start Juice Shop
docker run -d -p 3000:3000 bkimminich/juice-shop

# Step 2: Run complete ASVS L2 assessment (recommended)
python3 complete_asvs_5_workflow.py http://localhost:3000 juice_shop --level 2

# Step 3: Review results
cd evidence/*/
ls -la                                              # View all files
cat owasp_asvs_5.0_results.json | jq '.summary'   # JSON summary
libreoffice OWASP_ASVS_5.0_Checklist_*.csv        # Open checklist

# Step 4: View screenshots of findings
eog screenshots/                                    # Linux image viewer
```

### Expected Results from Juice Shop

When scanning Juice Shop with ASVS 5.0 L2, you should discover:
- **40-60 vulnerabilities** across multiple categories
- **V2 (Authentication)**: Multiple findings (weak passwords, broken auth)
- **V4 (Access Control)**: IDOR vulnerabilities, privilege escalation
- **V5 (Validation)**: SQLi, XSS, command injection
- **V8 (Data Protection)**: Exposed sensitive files
- **V13 (API)**: API security misconfigurations
- **V14 (Configuration)**: Security headers missing

## Installation Requirements

### Prerequisites
```bash
# Python 3.10+
python3 --version

# Install SecPluger dependencies
pip3 install -r requirements.txt
```

### Optional: Screenshot Support
```bash
# Install Playwright for screenshot evidence
pip install playwright
playwright install chromium

# Test Playwright installation
python3 -c "from playwright.sync_api import sync_playwright; print('Playwright OK')"
```

### Optional: Juice Shop Target
```bash
# Option 1: Docker (recommended)
docker run -d -p 3000:3000 bkimminich/juice-shop

# Option 2: Node.js
git clone https://github.com/juice-shop/juice-shop.git
cd juice-shop
npm install
npm start
```

## Using ASVS Resources Manually

If you prefer manual assessment:

### Excel Checklist (ASVS 4.0.2)
```bash
# Open Excel checklist
libreoffice resources/asvs_templates/ASVS-checklist-en.xlsx

# Use for:
# - Manual pentesting documentation
# - Audit trail for compliance
# - Client deliverables
```

### CSV Database (ASVS 5.0.0)
```bash
# View requirements in terminal
cat resources/asvs_templates/OWASP_Application_Security_Verification_Standard_5.0.0_en.csv | column -t -s,

# Filter by level
grep ",L2," OWASP_Application_Security_Verification_Standard_5.0.0_en.csv

# Filter by category
grep "V2\." OWASP_Application_Security_Verification_Standard_5.0.0_en.csv
```

## Integration with Claude Code (MCP)

SecPluger v2 exposes ASVS scanning via Model Context Protocol (MCP):

```python
# In Claude Code conversation:
# "Can you run an ASVS L2 scan on http://localhost:3000?"

# Claude Code will call:
asvs_scan(
    url="http://localhost:3000",
    level=2,
    enable_screenshots=True
)

# Then export CSV:
# "Can you export the results to CSV?"
```

See `docs/MCP_SETUP.md` for Claude Desktop integration.

## Resources & References

### Official OWASP Resources
- **ASVS Official Site**: https://owasp.org/www-project-application-security-verification-standard/
- **ASVS GitHub**: https://github.com/OWASP/ASVS
- **ASVS 5.0.0 Release**: https://github.com/OWASP/ASVS/releases/tag/v5.0.0
- **Juice Shop**: https://owasp.org/www-project-juice-shop/
- **OWASP Top 10**: https://owasp.org/www-project-top-ten/

### Third-Party Tools
- **ASVS Checklist Generator**: https://github.com/shenril/owasp-asvs-checklist
- **ASVS Excel Templates**: https://github.com/OWASP/ASVS/tree/master/5.0/en

### SecPluger Documentation
- **ASVS Scanner Guide**: `docs/SCANNER_GUIDE.md`
- **ASVS 5.0 Upgrade Summary**: `ASVS_5_UPGRADE_SUMMARY.md`
- **Complete Documentation**: `CLAUDE.md`
- **Quick Start**: `QUICKSTART.md`

## License & Attribution

### OWASP ASVS
- **License**: Creative Commons Attribution-ShareAlike 4.0 International
- **Copyright**: OWASP Foundation
- **Source**: https://github.com/OWASP/ASVS

### ASVS Excel Checklist
- **License**: MIT License
- **Author**: shenril
- **Source**: https://github.com/shenril/owasp-asvs-checklist

### SecPluger v2
- **License**: PolyForm Noncommercial License 1.0.0
- **Copyright**: (c) 2024 SecPluger Contributors
- **Repository**: https://github.com/Aldiharley/secpluger

## Troubleshooting

### Scanner Not Finding ASVS CSV
```bash
# Verify CSV file exists
ls -la resources/asvs_templates/OWASP_Application_Security_Verification_Standard_5.0.0_en.csv

# If missing, download from OWASP
wget https://raw.githubusercontent.com/OWASP/ASVS/v5.0.0/5.0/en/OWASP_Application_Security_Verification_Standard-5.0.0-en.csv \
  -O resources/asvs_templates/OWASP_Application_Security_Verification_Standard_5.0.0_en.csv
```

### Playwright Screenshot Errors
```bash
# Reinstall Playwright browsers
playwright install --force chromium

# Run without screenshots
python3 complete_asvs_5_workflow.py http://target.com target_name --no-screenshots
```

### Permission Denied on Evidence Directory
```bash
# Create evidence directory with proper permissions
mkdir -p evidence
chmod 755 evidence
```

---

**Last Updated**: November 26, 2024
**SecPluger v2**: AI-Powered Pentesting Workflow Automation
**ASVS Version**: 5.0.0 (October 2024 - Latest)
