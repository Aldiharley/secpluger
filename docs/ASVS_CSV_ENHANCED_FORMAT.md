# OWASP ASVS Enhanced CSV Export Format

## Overview

The SecPluger v2 ASVS Scanner now exports results to an **enhanced 11-column CSV format** designed to improve usability for both security auditors and developers.

This enhanced format adds 4 new columns to the standard ASVS export, making it easier for clients and developers to:
- **Understand validation status** at a glance
- **Locate vulnerable code** precisely
- **Add contextual notes** during remediation
- **Track which tools** detected each issue

## CSV Column Structure

### Original Columns (1-7)

| Column # | Header | Description | Example |
|----------|--------|-------------|---------|
| 1 | Category | OWASP ASVS category name | "Authentication" |
| 2 | Check ID | ASVS requirement ID | "V2.3.1" |
| 3 | Title | Security check description | "Default Credentials Check" |
| 4 | Severity | Risk level | CRITICAL, HIGH, MEDIUM, LOW, INFO |
| 5 | Status | Scanner result | PASS, FAIL, WARN, INFO, SKIP |
| 6 | Details | Finding details (max 500 chars) | "Exposed files: [...]" |
| 7 | Recommendation | Remediation guidance | "Use environment variables for secrets" |

### Enhanced Columns (8-11) - NEW

| Column # | Header | Description | Values | Purpose |
|----------|--------|-------------|--------|---------|
| 8 | **Valid** | Validation status | Pass / Fail / Manual / N/A | Quick compliance check |
| 9 | **Source Code Reference** | Code location | file.py:123 | Developer fix location |
| 10 | **Comment** | Auditor notes | "Requires remediation" | Context and tracking |
| 11 | **Tool Used** | Detection tool | owasp_asvs_scanner, sqlmap, xss_scanner | Reproducibility |

## Field Descriptions

### Valid (Column 8)

**Purpose**: Simplified validation status for compliance reporting

**Possible Values**:
- **Pass** - Security requirement met
- **Fail** - Security requirement not met (requires fixing)
- **Manual** - Requires manual verification by auditor
- **N/A** - Not applicable to this application

**Mapping from Status**:
```
PASS   → Pass
FAIL   → Fail
WARN   → Fail
INFO   → Manual
SKIP   → N/A
```

**Usage**: Filter spreadsheet to show only "Fail" items for prioritized remediation

### Source Code Reference (Column 9)

**Purpose**: Pinpoint exact code location for developers

**Format**: `file_path:line_number` or `file_path`

**Examples**:
- `/app/controllers/auth.py:42`
- `config.php:18`
- `/static/js/login.js`

**Auto-Detection**: The CSV exporter automatically extracts source references from:
- File paths in details (`/path/to/file.ext:line`)
- Error messages containing file locations
- Exposed configuration files

**Manual Entry**: Auditors can add references during code review

**Usage**: Developers can use this to quickly navigate to vulnerable code using IDE "Go to File:Line" features

### Comment (Column 10)

**Purpose**: Auditor notes and remediation tracking

**Auto-Populated Values**:
- "Requires remediation" (for FAIL/WARN)
- "Manual verification required" (for INFO)
- "Verified secure" (for PASS)
- "Not applicable" (for SKIP)

**Manual Usage**:
- Track remediation progress: "Fixed in PR #123"
- Add context: "Only applies to admin panel"
- Note false positives: "False positive - using prepared statements"
- Add deadline: "Must fix before v2.0 release"

**Workflow**:
1. Initial scan populates default comments
2. Auditor reviews and adds detailed notes
3. Developer adds fix references
4. Re-test and update comments

### Tool Used (Column 11)

**Purpose**: Track which security tool detected each issue

**Common Values**:
- `owasp_asvs_scanner` - Built-in ASVS scanner (most checks)
- `sqlmap` - SQL injection detection (V5.2.8)
- `xss_scanner` - XSS detection (V5.2.1)
- `template_scanner` - SSTI detection (V5.3.3)
- `command_injection_scanner` - Command injection (V5.3.10)
- `ssl_scanner` - SSL/TLS checks (V9.*)
- `header_scanner` - HTTP security headers (V14.4.*)
- `api_scanner` - API security (V13.*)

**Benefits**:
- **Reproducibility**: Developers can re-run the same tool to verify fixes
- **Tool Validation**: Understand scanner capabilities and limitations
- **Automation**: Integrate specific tools into CI/CD for regression testing

## Usage Examples

### For Security Auditors

**1. Generate Enhanced CSV from Existing Scan**:
```bash
cd /home/aldi/project/secpluger-v2

# Export existing JSON to enhanced CSV
python3 src/scanner/asvs_csv_exporter.py \
    evidence/pentest_session/owasp_asvs_results.json \
    evidence/pentest_session/asvs_enhanced.csv
```

**2. Filter Critical Failures**:
Open CSV in Excel/LibreOffice and:
- Filter Column 8 (Valid) = "Fail"
- Filter Column 4 (Severity) = "CRITICAL" or "HIGH"
- Sort by Category for organized remediation

**3. Track Remediation**:
```csv
# Before fix
V5.3.10,Command Injection,CRITICAL,FAIL,...,Fail,app.py:127,Requires remediation,command_injection_scanner

# After fix (update Comment column)
V5.3.10,Command Injection,CRITICAL,FAIL,...,Fail,app.py:127,Fixed in commit abc123 - using subprocess.run with shell=False,command_injection_scanner
```

### For Developers

**1. Get List of Code Locations to Fix**:
```bash
# Extract all failed checks with source references
cat asvs_enhanced.csv | grep ",Fail," | cut -d',' -f9 | sort -u

# Output:
# /app/models/user.py:42
# /config.php:18
# /static/js/auth.js:156
```

**2. Fix Code and Document**:
```python
# Before (vulnerable code at /app/models/user.py:42)
query = f"SELECT * FROM users WHERE id = {user_id}"

# After (fixed)
query = "SELECT * FROM users WHERE id = %s"
cursor.execute(query, (user_id,))

# Update CSV Comment: "Fixed - using parameterized queries"
```

**3. Re-run Specific Tool**:
```bash
# If "Tool Used" = "sqlmap"
sqlmap -u "http://target/api/users?id=1" --batch --level=2
```

### For Compliance Officers

**1. Generate Compliance Report**:
```python
import pandas as pd

df = pd.read_csv('asvs_enhanced.csv')

# Count by validation status
print(df['Valid'].value_counts())

# Output:
# Pass     24
# Manual   48
# Fail     21
# N/A       4

# Compliance rate
total = len(df[df['Valid'] != 'Manual'])
passed = len(df[df['Valid'] == 'Pass'])
compliance = (passed / total) * 100
print(f"Compliance: {compliance:.1f}%")
```

**2. Filter Manual Review Items**:
```bash
# Get all items requiring manual verification
cat asvs_enhanced.csv | grep ",Manual," > manual_review_needed.csv
```

## File Locations

- **CSV Exporter**: `src/scanner/asvs_csv_exporter.py`
- **ASVS Scanner**: `src/scanner/owasp_asvs_scanner.py`
- **Output Location**: `evidence/<session>/owasp_asvs_detailed_results_enhanced.csv`

## Automatic Export

The enhanced CSV is **automatically generated** when running ASVS scans:

```bash
# Run ASVS scan
python3 src/scanner/owasp_asvs_scanner.py http://target.com evidence/scan_123

# Output files created:
# evidence/scan_123/owasp_asvs_results.json (JSON format)
# evidence/scan_123/owasp_asvs_detailed_results_enhanced.csv (11-column CSV)
```

## Benefits Summary

| Benefit | Old CSV (7 columns) | Enhanced CSV (11 columns) |
|---------|---------------------|---------------------------|
| Compliance tracking | Manual analysis needed | **Quick filter by "Valid" column** |
| Developer workflow | Search details text | **Direct file:line references** |
| Remediation notes | External tracking | **Built-in Comment field** |
| Reproducibility | Unknown detection method | **Tool Used attribution** |
| Client reporting | Technical jargon | **Clear Pass/Fail/Manual status** |

## Statistics

Based on Juice Shop pentest (October 29, 2025):

```
Total Checks: 97
Format: 11 columns (7 original + 4 enhanced)
File Size: 17 KB (vs 12 KB for old format)

Validation Status Distribution:
- Pass: 24 (24.7%)
- Fail: 21 (21.6%)
- Manual: 48 (49.5%)
- N/A: 4 (4.1%)

Severity Distribution:
- CRITICAL: 11
- HIGH: 32
- MEDIUM: 25
- LOW: 20
- INFO: 9
```

## Future Enhancements

Planned improvements for future versions:

1. **Auto-populate source references** from:
   - Static analysis tool integration
   - Git blame information
   - Stack trace parsing

2. **Integration with issue trackers**:
   - Export to Jira/GitHub Issues
   - Track remediation progress
   - Link to commits/PRs

3. **Diff reports**:
   - Compare scans before/after fixes
   - Show remediation progress over time
   - Generate fix verification reports

## Support

For questions or issues:
- **GitHub Issues**: https://github.com/anthropics/secpluger-v2/issues
- **Documentation**: `docs/SCANNER_GUIDE.md`
- **Code**: `src/scanner/asvs_csv_exporter.py`

---

**Last Updated**: October 31, 2025
**Version**: SecPluger v2.0
**ASVS Version**: 4.0.3
