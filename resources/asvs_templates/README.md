# OWASP ASVS Templates for Juice Shop Pentesting

## Downloaded Resources

### 1. ASVS Checklist (Excel)
- **File**: `ASVS-checklist-en.xlsx` (71 KB)
- **Source**: https://github.com/shenril/owasp-asvs-checklist
- **Version**: ASVS 4.0.2 compatible
- **Format**: Microsoft Excel 2007+
- **Usage**: Manual checklist for ASVS compliance audits

### 2. OWASP ASVS 5.0.0 (CSV)
- **File**: `OWASP_Application_Security_Verification_Standard_5.0.0_en.csv`
- **Source**: https://github.com/OWASP/ASVS
- **Version**: ASVS 5.0.0 (Latest - May 2025)
- **Format**: CSV
- **Usage**: Programmatic import for automated assessment tools

### 3. ASVS Repository (Full)
- **Directory**: `ASVS/`
- **Formats Available**: CSV, JSON, PDF, DOCX
- **Languages**: English, Russian, Turkish, French

## Using with OWASP Juice Shop

OWASP Juice Shop (the famous vulnerable web application) has vulnerabilities explicitly mapped to:
- OWASP Top 10
- **OWASP ASVS** categories
- OWASP API Security Top 10
- MITRE CWE

This makes it perfect for ASVS-based pentesting practice.

## Using with SecPluger v2

SecPluger v2 has a built-in OWASP ASVS scanner at:
- `src/scanner/owasp_asvs_scanner.py`

### Example Usage:

```bash
# Run ASVS scan on Juice Shop
python3 src/scanner/owasp_asvs_scanner.py http://localhost:3000 evidence/juice_shop/

# Comprehensive pentest with ASVS
python3 pentest_juice_shop.py
```

### Output Formats:
- CSV: `asvs_scan_results.csv`
- JSON: `vulnerability_scan_results.json`
- TXT: `vulnerability_summary.txt`

## ASVS Security Levels

- **Level 1**: Opportunistic - Basic security requirements
- **Level 2**: Standard - Most applications (recommended)
- **Level 3**: Advanced - High-security applications

## Quick Reference

### ASVS Categories (v5.0):
1. Architecture, Design and Threat Modeling
2. Authentication
3. Session Management
4. Access Control
5. Validation, Sanitization and Encoding
6. Stored Cryptography
7. Error Handling and Logging
8. Data Protection
9. Communication
10. Malicious Code
11. Business Logic
12. Files and Resources
13. API and Web Service
14. Configuration

## Testing Juice Shop Against ASVS

Common vulnerabilities in Juice Shop mapped to ASVS:

| Vulnerability | ASVS Category | Level |
|--------------|---------------|-------|
| SQL Injection | V5 (Validation) | 1, 2, 3 |
| XSS | V5 (Validation) | 1, 2, 3 |
| Broken Authentication | V2 (Authentication) | 1, 2, 3 |
| Sensitive Data Exposure | V8 (Data Protection) | 2, 3 |
| Broken Access Control | V4 (Access Control) | 1, 2, 3 |
| Security Misconfiguration | V14 (Configuration) | 1, 2, 3 |

## Resources

- **Official ASVS**: https://owasp.org/www-project-application-security-verification-standard/
- **Juice Shop**: https://owasp.org/www-project-juice-shop/
- **ASVS GitHub**: https://github.com/OWASP/ASVS
- **Checklist GitHub**: https://github.com/shenril/owasp-asvs-checklist

## License

- ASVS: Creative Commons Attribution-ShareAlike 4.0
- This README: Part of SecPluger v2 project

---

**Last Updated**: October 29, 2025
**SecPluger v2**: AI-Powered Pentesting Workflow Automation
