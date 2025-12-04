# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

SecPluger v2 is an AI-powered pentesting workflow automation tool for Kali Linux that extends Claude Code with:
- **Parallel pentesting methodology** (2-5x faster than linear scanning via tool clustering)
- **OWASP ASVS 5.0 compliance testing** (345 requirements, L1/L2/L3 support, CSV export with affected URLs)
- Workflow recording and replay (save Claude's pentest actions for reuse)
- Built-in scanner suite (web crawler, fuzzer, vulnerability scanner)
- HTTP/HTTPS proxy integration (mitmproxy)
- Evidence collection and professional reporting
- MCP server for Claude Code integration
- Dynamic tool management (36+ Kali tools auto-detection)

**Key Innovations**:
1. First pentest with Claude = recorded workflow. Subsequent pentests = replay workflow with ZERO tokens
2. Parallel tool clustering (rustscan + naabu + masscan concurrent) = 2-5x faster than linear scanning
3. OWASP ASVS 5.0 scanner with level filtering, screenshot evidence, and affected URL tracking in CSV

## Development Commands

### Setup
```bash
# Install dependencies
pip3 install -r requirements.txt

# Install Playwright for screenshots (optional)
pip install playwright && playwright install chromium

# Install optional scanning tools
# nuclei, wapiti, nikto, sqlmap (for scanner modules)
# rustscan, naabu, masscan, ffuf, gobuster, feroxbuster (for parallel scanning)
```

### Running
```bash
# Run MCP server (for Claude Code integration)
python3 src/mcp/secpluger_mcp_server.py

# Run GUI application (standalone mode)
python3 src/main.py

# Run parallel pentest on target
python3 parallel_pentest_10.10.11.88.py

# Run OWASP ASVS 5.0 scan
python3 src/scanner/owasp_asvs_5_scanner.py http://target.com ./evidence --level 2

# Run ASVS 5.0 complete workflow (scan + CSV export)
python3 complete_asvs_5_workflow.py http://target.com target_name --level 2 --no-screenshots

# Test Phase 5 automatic exploitation
python3 test_phase5_complete.py
```

### Testing Scanner Modules
```bash
# Test individual scanners
cd src/scanner
python3 web_crawler.py          # Interactive crawler test
python3 fuzzer.py               # Interactive fuzzer test
python3 vulnerability_scanner.py  # Check available tools
python3 parallel_scanner.py 10.10.11.88  # Test parallel scanning

# Test OWASP ASVS 5.0 scanner
python3 owasp_asvs_5_scanner.py http://10.10.11.92 ./evidence --level 2 --no-screenshots

# Test complete workflow
python3 tests/test_scanner_workflow.py

# Check tool availability (36+ security tools)
python3 src/utils/tool_manager.py

# Generate tool availability report
python3 -c "from src.utils.tool_manager import ToolManager; ToolManager().save_report()"
cat tool_report.txt
```

### OWASP ASVS 5.0 Testing
```bash
# Run L2 (Standard) scan - most web applications
python3 complete_asvs_5_workflow.py http://target.com target_name --level 2

# Run L1 (Basic) scan - faster, fewer checks
python3 complete_asvs_5_workflow.py http://target.com target_name --level 1

# Run L3 (Advanced) scan - high-security applications
python3 complete_asvs_5_workflow.py http://target.com target_name --level 3

# Without screenshots (faster)
python3 complete_asvs_5_workflow.py http://target.com target_name --no-screenshots

# Export CSV from existing results
python3 src/reporting/asvs_5_csv_exporter.py evidence/YYYYMMDD_HHMMSS_target/owasp_asvs_5.0_results.json ./evidence

# Open CSV in LibreOffice
libreoffice evidence/*/OWASP_ASVS_5.0_Checklist_*.csv
```

## Architecture Overview

### Core Data Flow

```
Claude Code (via MCP)
    ↓
MCP Server (secpluger_mcp_server.py) - 29 tools
    ↓
┌──────────────┬─────────────┬─────────────┬─────────────┬──────────────┐
│  Workflow    │   Scanner   │    Proxy    │   Parallel  │   OWASP      │
│  Recorder    │   Modules   │ Controller  │   Scanner   │   ASVS 5.0   │
│(mcp_monitor) │             │(mitmproxy)  │             │              │
└──────────────┴─────────────┴─────────────┴─────────────┴──────────────┘
    ↓              ↓             ↓              ↓              ↓
Evidence Collection → Database → Professional Report Generation
                                       ↓
                        Screenshots, PCAP, CSV Checklists, JSON Results
```

### Three Operational Modes

1. **Recording Mode** (First Pentest)
   - `WorkflowRecorder` monitors Claude's commands
   - Each command → recorded node with evidence
   - Auto-detects vulnerabilities from tool output
   - Saves reusable workflow JSON

2. **Replay Mode** (Subsequent Pentests)
   - `WorkflowEngine` loads saved workflow JSON
   - Executes nodes sequentially with new target
   - No AI/Claude needed = zero token cost
   - Evidence collected automatically

3. **Parallel Scan Mode** (NEW - Fast Reconnaissance)
   - Tool clustering: multiple tools run concurrently
   - Port scan cluster: rustscan + naabu + masscan
   - Web fuzz cluster: ffuf + gobuster + feroxbuster
   - Result aggregation and deduplication
   - 2-5x faster than linear scanning

## Key Components

### Exploit Manager (`src/exploits/exploit_manager.py`) - PHASE 5 NEW

**Purpose**: Automatic exploit matching and execution with human-in-the-loop approval

**Key Features**:
- Automatic exploit matching using service fingerprints
- Confidence scoring (0-100%)
- Risk classification (low, medium, high, critical)
- Human approval gates before execution
- Extensible JSON exploit database (10+ exploits)
- Built-in and external exploit support
- Automatic flag detection
- Evidence collection per exploit attempt
- Comprehensive reporting

**Tool Workflow**:
```
1. match_exploits → Find exploits for target services
2. User reviews matches with confidence/risk scores
3. approve_exploit → Manually approve specific exploits
4. execute_exploits → Run approved exploits with safety checks
5. get_exploit_report → Generate professional report
```

**Exploit Database** (`data/exploit_database.json`):
- JSON-based exploit definitions
- Easy to add new exploits without coding
- Pattern-based version matching with regex
- CVE tracking and references
- 10 pre-configured exploits: XWiki RCE, Apache Path Traversal, SSH enum, etc.

**Usage**:
```python
from src.exploits.exploit_manager import ExploitManager

em = ExploitManager()

# Step 1: Match exploits
scan_results = {
    'target': '10.10.11.80',
    'services': [
        {'port': 8080, 'product': 'XWiki', 'version': '15.10'}
    ]
}
matches = em.match_exploits(scan_results)

# Step 2: Approve exploits (automatically done in interactive mode)
for match in matches:
    match.approved = True  # or use interactive approval

# Step 3: Execute
summary = em.execute_approved_exploits(interactive=True)

# Step 4: Report
print(em.get_exploit_report())
```

**Safety Features**:
- Human approval required by default
- Detailed exploit information display
- Risk visibility with color coding
- Execution logging and evidence collection
- Graceful failure handling

See `PHASE5_AUTOMATIC_EXPLOITATION.md` and `PHASE5_TEST_RESULTS.md` for complete documentation.

## Key Components

### Parallel Scanner (`src/scanner/parallel_scanner.py`) - NEW

**Purpose**: Concurrent pentesting with tool clustering for maximum speed

**Key Features**:
- Async/await architecture using Python asyncio
- Tool clustering (multiple tools same task)
- Result aggregation and deduplication
- Evidence collection per tool
- Performance metrics tracking

**Tool Clusters**:

Port Scanning Cluster:
- rustscan: Ultra-fast discovery (27s for full scan)
- naabu: Reliable Go-based scanner (270s for 65k ports)
- masscan: Fastest but less accurate (requires sudo)
- nmap: Accurate service detection (only on discovered ports)

Web Fuzzing Cluster:
- ffuf: Fastest and most flexible
- gobuster: Reliable directory fuzzing
- feroxbuster: Rust-based with auto-recursion

**Usage**:
```python
from src.scanner.parallel_scanner import ParallelScanner
import asyncio

async def pentest():
    scanner = ParallelScanner("10.10.11.88")
    results = await scanner.full_scan(include_web=True)
    # Results contain aggregated findings from all tools
    return results

asyncio.run(pentest())
```

**Performance**:
- Linear scanning: ~795s (13.2 minutes)
- Parallel scanning: ~290s (4.8 minutes)
- Improvement: 2.7x faster

See `PARALLEL_PENTESTING_GUIDE.md` for complete documentation.

### OWASP ASVS 5.0 Scanner (`src/scanner/owasp_asvs_5_scanner.py`) - NEW

**Purpose**: Application Security Verification Standard compliance testing

**Key Features**:
- 345 requirements from official OWASP ASVS 5.0.0
- Level filtering: L1 (70 reqs), L2 (183 reqs), L3 (92 reqs)
- Affected URL tracking per finding
- Screenshot evidence with Playwright
- 17 ASVS chapters (V1-V17)
- Async architecture

**Usage**:
```python
from src.scanner.owasp_asvs_5_scanner import OWASPASVS5Scanner
import asyncio

async def asvs_scan():
    scanner = OWASPASVS5Scanner(
        "http://target.com",
        "./evidence",
        level=2,  # L1=Basic, L2=Standard, L3=Advanced
        enable_screenshots=True
    )
    results = await scanner.scan()
    return results

asyncio.run(asvs_scan())
```

**CSV Export** (`src/reporting/asvs_5_csv_exporter.py`):
- 16-column checklist format
- NEW columns: ASVS Level, Affected URLs, Screenshot
- Excel/Google Sheets compatible
- Compliance tracking ready

See `ASVS_5_UPGRADE_SUMMARY.md` for complete documentation.

### MCP Server (`src/mcp/secpluger_mcp_server.py`)

Exposes 31 tools to Claude Code:

**Workflow Tools**:
- `start_recording(target)` - Begin recording session
- `record_command(command, output)` - Record single command
- `save_workflow(name)` - Save as reusable template
- `replay_workflow(workflow_path, target)` - Re-run on new target
- `create_branch(from_node_id, new_commands)` - Branch workflow

**Scanner Tools**:
- `crawl_website(url, max_depth, max_pages)` - Discover pages/forms
- `fuzz_parameter(url, parameter, attack_type)` - Test for SQLi/XSS
- `scan_vulnerabilities(target, scan_type)` - Run nuclei/wapiti/nikto
- `full_security_test(target)` - Complete automated assessment
- `parallel_scan(target, include_web, web_url)` - Parallel port/web scanning (2-5x faster)
- `asvs_scan(url, level, enable_screenshots)` - OWASP ASVS 5.0 compliance scan

**Exploitation Tools** (Phase 2, 3 & 5):
- `auto_exploit(findings, lhost, lport)` - Automatic web vulnerability exploitation (SQLi, RCE, LFI, XSS)
- `service_exploit(services, username, password_list, lhost, lport)` - Network service exploitation (SSH, FTP, SMB, databases)
- `match_exploits(target, scan_results)` - **PHASE 5** Automatic exploit matching with confidence scoring
- `approve_exploit(exploit_id, approved)` - **PHASE 5** Human approval for exploit execution
- `execute_exploits(interactive)` - **PHASE 5** Execute approved exploits with safety gates
- `get_exploit_report()` - **PHASE 5** Generate comprehensive exploitation report

**Proxy Tools**:
- `start_proxy(port, mode, target)` - Start mitmproxy
- `stop_proxy()` - Stop and save traffic
- `proxy_status()` - Check status

**Tool Management Tools**:
- `check_tools(category, priority)` - Check which security tools are installed (36+ tools)
- `get_tool_info(tool_name)` - Get detailed information about a specific tool
- `install_tool(tool_name)` - Get installation command for a security tool
- `install_missing_tools(category, priority)` - Get install commands for all missing tools

**Integration Tools** (BurpSuite, Wireshark):
- `burp_scan(url)` - Scan with BurpSuite
- `burp_spider(url)` - Spider with BurpSuite
- `burp_get_findings()` - Get BurpSuite scan results
- `wireshark_capture(interface, duration, filter)` - Capture traffic
- `wireshark_analyze(pcap_file)` - Analyze PCAP file
- `wireshark_get_status()` - Check capture status

### Workflow Recorder (`src/mcp/mcp_monitor.py`)

**Purpose**: Records Claude's pentest actions into reusable workflows

**Key Methods**:
- `start_session(target)` - Initialize recording session
- `record_command(command, output)` - Record each command as node
- `save_workflow(name)` - Export to JSON template
- `create_branch(from_node_id, commands)` - Create workflow branch

**Auto-Detection**: Parses tool output to detect:
- Open ports (nmap, rustscan, naabu)
- Discovered directories (gobuster, dirb, ffuf, feroxbuster)
- SQLi vulnerabilities (sqlmap)
- XSS findings (nuclei, wapiti)
- Command injection (various)

**Screenshot Support**: Optional screenshot capture per command (requires `mss` package)

### Workflow Engine (`src/engine/workflow_engine.py`)

**Purpose**: Executes saved workflows without AI assistance

**Key Methods**:
- `load_workflow(workflow_path)` - Load JSON workflow
- `execute(**kwargs)` - Run workflow with variables
- `_get_execution_order()` - Topological sort of nodes
- `_execute_node(node)` - Execute single workflow node

**Variable Substitution**: Replace `{{TARGET}}`, `{{PORT}}` etc. in workflow

**Conditional Logic**: Supports if/else branching based on previous output

### Scanner Suite (`src/scanner/`)

**Web Crawler** (`web_crawler.py`):
- Discovers pages, forms, GET parameters
- Recursive crawling with depth limits
- Same-origin policy enforcement
- JSON output format

**Fuzzer** (`fuzzer.py`):
- Multi-threaded parameter testing
- Built-in payload generators (SQLi, XSS, Command Injection, Path Traversal, LDAP)
- Automatic vulnerability detection
- Integration with py3webfuzz

**Vulnerability Scanner** (`vulnerability_scanner.py`):
- Integrates: nuclei, wapiti, nikto, sqlmap
- Multiple scan types: quick, full, sqli, xss
- Unified vulnerability format
- Session-based evidence collection

**Parallel Scanner** (`parallel_scanner.py`):
- Concurrent tool execution with asyncio
- Port scan cluster: rustscan + naabu + masscan
- Web fuzz cluster: ffuf + gobuster + feroxbuster
- Result aggregation and deduplication
- 2-5x speed improvement

### Proxy Controller (`src/proxy/mitmproxy_controller.py`)

**Purpose**: Manages mitmproxy instances for traffic interception

**Key Methods**:
- `start_proxy(port, mode, target)` - Launch mitmproxy
- `stop_proxy()` - Stop and save flows
- `get_status()` - Check if running
- `get_flow_summary()` - Traffic statistics

**Modes**: regular, reverse, transparent, socks5

**Evidence**: Saves all HTTP/HTTPS traffic to `.mitm` flow files

### Tool Manager (`src/utils/tool_manager.py`)

**Purpose**: Dynamically detects and manages 36+ Kali Linux security tools

**Key Features**:
- Automatic tool detection via PATH scanning
- 12 tool categories with priority levels (high/medium/low)
- Installation command generation
- Tool version detection
- Comprehensive availability reporting

**Supported Tools** (36+ tools across 12 categories):
- **Network Scanners**: nmap, masscan, zmap, rustscan, naabu
- **Web Scanners**: nuclei, wapiti, nikto, whatweb, wafw00f
- **Enumeration**: gobuster, dirb, ffuf, feroxbuster, dirbuster
- **SQL Injection**: sqlmap
- **XSS Testing**: xsser
- **Exploitation**: metasploit-framework, searchsploit
- **Proxy/MITM**: mitmproxy, burpsuite
- **Recon**: sublist3r, amass, dnsenum, dnsrecon
- **SSL/TLS**: sslscan, sslyze, testssl
- **Password Attacks**: hydra, john, hashcat, medusa
- **Wireless**: aircrack-ng, reaver
- **CMS Testing**: wpscan, joomscan
- **Network Analysis**: wireshark, tcpdump

**Usage**:
```python
from src.utils.tool_manager import get_tool_manager

tm = get_tool_manager()

# Check all tools
available = tm.get_available_tools()

# Check specific category
web_scanners = tm.get_available_tools("web_scanner")

# Get missing tools
missing = tm.get_missing_tools(priority="high")

# Get install command
install_cmd = tm.get_install_command("rustscan")
```

## Workflow JSON Format

```json
{
  "name": "workflow_name",
  "description": "What this workflow does",
  "nodes": [
    {
      "id": "1",
      "type": "nmap|gobuster|sqlmap|nuclei|...",
      "data": {
        "target": "{{TARGET}}",
        "...": "node-specific parameters"
      }
    }
  ],
  "edges": [
    {"from": "1", "to": "2"}
  ]
}
```

**Variables**: Use `{{VARIABLE}}` for substitution during execution

**Node Types**: Detected from command in recording mode, or specified explicitly

## Evidence Organization

```
evidence/
└── YYYYMMDD_HHMMSS_target/
    ├── 01_nmap.txt                    # Node 1 output
    ├── 01_rustscan_ports.txt          # Parallel scan outputs
    ├── 02_naabu_ports.json
    ├── 03_masscan_ports.txt
    ├── 04_nmap_services.txt
    ├── 05_ffuf_dirs.json
    ├── 06_gobuster_dirs.txt
    ├── 07_feroxbuster_dirs.txt
    ├── owasp_asvs_5.0_results.json    # ASVS scan results
    ├── OWASP_ASVS_5.0_Checklist_*.csv # ASVS CSV checklist
    ├── OWASP_ASVS_5.0_Summary_*.csv   # ASVS summary
    ├── screenshots/                    # ASVS screenshots
    │   ├── V3_4_1_20251027_120559.png
    │   └── V9_1_1_20251027_120630.png
    ├── parallel_scan_summary.json      # Parallel scan summary
    ├── crawler_results.json            # Crawler data
    ├── fuzz_id_*.json                  # Fuzzing results
    ├── proxy_traffic.mitm              # Proxy flows
    ├── execution_summary.json          # Workflow metadata
    └── workflow.json                   # Workflow that was executed
```

All evidence is isolated per session with unique timestamp-based directory names.

## Database Schema (`src/database/models.py`)

**Findings Table**:
- Stores detected vulnerabilities
- Fields: severity, title, description, target, port, cvss_score, status
- Status: NEW, CONFIRMED, FALSE_POSITIVE, REMEDIATED

**Key Methods**:
- `add_finding(data)` - Insert new vulnerability
- `get_findings(severity, status)` - Query findings
- `update_finding_status(id, status)` - Update vulnerability status

## Important Implementation Details

### Logger Initialization Order
Always initialize logging BEFORE importing modules that use logger:
```python
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
# Now safe to use logger in try/except blocks
```

### Path Handling
Use `sys.path.append()` for cross-module imports:
```python
sys.path.append(str(Path(__file__).parent.parent / "scanner"))
from web_crawler import WebCrawler
```

### MCP Server Communication
- Uses stdin/stdout for MCP protocol
- Returns `List[TextContent]` from tool handlers
- Async/await pattern with `mcp.server.stdio`

### Subprocess Execution
- All external tools run via `subprocess.run()`
- Set timeouts to prevent hanging (default: 120-300s depending on tool)
- Capture both stdout and stderr
- Save raw output to evidence files

### Async Parallel Execution
- Use `asyncio.gather()` for parallel tool execution
- Use `asyncio.create_subprocess_exec()` for async subprocess calls
- Set timeouts with `asyncio.wait_for()`
- Handle errors gracefully (one tool failure doesn't stop others)

### Workflow Node Execution Order
Nodes execute in topological order based on edges. Parallel scanner uses asyncio for concurrent execution of independent tools.

## Security Considerations

**Authorization Required**: This tool is for authorized penetration testing only:
- Your own systems
- Systems with written permission
- CTF/lab environments (DVWA, WebGoat, etc.)

**Dangerous Operations**:
- The workflow engine executes arbitrary commands from workflow JSON
- The fuzzer sends attack payloads to targets
- The proxy intercepts all HTTPS traffic
- Parallel scanner runs multiple aggressive tools concurrently

**Rate Limiting**: Scanner modules include delays to avoid overwhelming targets:
- Crawler: 0.5s between requests
- Fuzzer: Configurable thread count (default: 5)
- Parallel scanner: Configurable rates per tool (rustscan: 1000, naabu: 1000, ffuf: 50 threads)

**Credential Handling**: Never store credentials in workflow JSON. Use variables or environment variables.

## Common Patterns

### Running Parallel Pentest

```python
from src.scanner.parallel_scanner import ParallelScanner
import asyncio

async def main():
    scanner = ParallelScanner("10.10.11.88")

    # Phase 1: Port scanning cluster
    port_results = await scanner.port_scan_cluster()
    discovered_ports = scanner._parse_port_results(port_results)

    # Phase 2: Service detection
    if discovered_ports:
        service_result = await scanner.service_detection(list(discovered_ports))

    # Phase 3: Web fuzzing cluster (if web service found)
    if 80 in discovered_ports or 443 in discovered_ports:
        web_results = await scanner.web_fuzzing_cluster("http://10.10.11.88")
        discovered_dirs = scanner._parse_directory_results(web_results)

    # Or just run everything
    results = await scanner.full_scan(include_web=True)
    return results

asyncio.run(main())
```

### Running OWASP ASVS 5.0 Scan

```python
from src.scanner.owasp_asvs_5_scanner import OWASPASVS5Scanner
from src.reporting.asvs_5_csv_exporter import ASVS5CSVExporter
import asyncio

async def asvs_workflow():
    # Step 1: Run ASVS scan
    scanner = OWASPASVS5Scanner(
        "http://target.com",
        "./evidence",
        level=2,  # L1=Basic, L2=Standard (most apps), L3=Advanced
        enable_screenshots=False  # Set True for evidence
    )
    results = await scanner.scan()

    # Step 2: Export to CSV
    exporter = ASVS5CSVExporter()
    csv_file = exporter.export_to_csv(
        results,
        include_passed=True
    )

    print(f"CSV checklist: {csv_file}")
    return results

asyncio.run(asvs_workflow())
```

### Adding a New MCP Tool

1. Add tool definition to `list_tools()` in `secpluger_mcp_server.py`
2. Add handler in `call_tool()` function
3. Return `List[TextContent]` with results
4. Handle errors with try/except

### Adding a New Scanner Module

1. Create module in `src/scanner/`
2. Implement main class with `scan()` or similar method
3. Return Dict with results
4. Accept `evidence_dir` parameter
5. Save outputs to evidence directory
6. Add MCP tool wrapper in server

### Creating Workflow Branches

When you find a vulnerability and want to explore multiple exploitation paths:
```python
# From node 3 (found SQLi), create two branches
branch_a = create_branch(from_node_id="3",
    new_commands=["sqlmap ... --dump"])

branch_b = create_branch(from_node_id="3",
    new_commands=["sqlmap ... --os-shell"])
```

Each branch is independent and can be replayed separately.

### Checking Tool Availability

Before running scans, check which tools are available:

```python
# Check all tools
check_tools()

# Check specific category
check_tools(category="web_scanner")

# Check high-priority tools only
check_tools(priority="high")

# Get info about specific tool
get_tool_info(tool_name="nuclei")

# Get install command for a tool
install_tool(tool_name="nikto")

# Get install commands for all missing high-priority tools
install_missing_tools(priority="high")
```

The tool manager automatically detects 36+ Kali Linux security tools across 12 categories and provides installation guidance.

## Testing Strategy

### Unit Tests
Test individual components in isolation (scanner modules, workflow engine, etc.)

### Integration Tests
Test MCP server → scanner module → evidence collection flow

### Manual Testing
Use safe targets:
- DVWA (Damn Vulnerable Web Application)
- WebGoat
- http://testphp.vulnweb.com (intentionally vulnerable test site)

## Documentation

- `PHASE5_AUTOMATIC_EXPLOITATION.md` - **NEW** Complete Phase 5 exploitation guide
- `PHASE5_TEST_RESULTS.md` - **NEW** Phase 5 test results and demonstration
- `PARALLEL_PENTESTING_GUIDE.md` - Complete parallel scanning documentation
- `ASVS_5_UPGRADE_SUMMARY.md` - OWASP ASVS 5.0 upgrade details
- `docs/SCANNER_GUIDE.md` - Scanner module documentation
- `docs/SCANNER_IMPLEMENTATION.md` - Technical implementation details
- `docs/TOOL_MANAGEMENT.md` - Tool detection and installation guide
- `USAGE_WITH_CLAUDE.md` - How to use with Claude Code
- `QUICKSTART.md` - Quick start guide

## Configuration

### Claude Desktop MCP Setup
```json
{
  "mcpServers": {
    "secpluger": {
      "command": "python3",
      "args": ["/path/to/secpluger-v2/src/mcp/secpluger_mcp_server.py"]
    }
  }
}
```

Location:
- Linux: `~/.config/Claude/claude_desktop_config.json`
- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`

## Performance Notes

- **Crawler**: ~2 pages/second (with politeness delay)
- **Fuzzer**: ~10-20 requests/second (5 threads)
- **Scanner**: 2-15 minutes depending on scan type and target size
- **Workflow Replay**: Same speed as original execution (no AI overhead)
- **Parallel Port Scan**: 27s (rustscan) to 270s (naabu full scan)
- **Parallel Web Fuzz**: 120-140s for common.txt wordlist
- **ASVS 5.0 Scan**: 1-5 minutes depending on level (L1 fastest, L3 slowest)

**Speed Improvements**:
- Parallel scanning: 2.7x faster than linear (tested on 10.10.11.88)
- Tool clustering allows 2-5x overall pentest speedup

## Key Files to Understand First

1. `src/mcp/secpluger_mcp_server.py` - Entry point for Claude Code (31 MCP tools)
2. `src/exploits/exploit_manager.py` - **PHASE 5 NEW**: Automatic exploitation with approval (687 lines)
3. `data/exploit_database.json` - **PHASE 5 NEW**: Extensible exploit database (10+ exploits)
4. `src/scanner/parallel_scanner.py` - Parallel scanning with tool clustering
5. `src/scanner/owasp_asvs_5_scanner.py` - OWASP ASVS 5.0 compliance scanner
6. `src/reporting/asvs_5_csv_exporter.py` - ASVS CSV export with 16 columns
7. `src/mcp/mcp_monitor.py` - Workflow recording logic
8. `src/engine/workflow_engine.py` - Workflow replay logic
9. `src/scanner/vulnerability_scanner.py` - Scanner integration
10. `src/utils/tool_manager.py` - Dynamic tool detection (36+ tools)
11. `requirements.txt` - All dependencies

## Debugging Tips

**MCP Server Issues**:
- Test server directly: `python3 src/mcp/secpluger_mcp_server.py`
- Check imports don't fail
- Verify all dependencies installed

**Workflow Execution Issues**:
- Check workflow JSON syntax
- Verify tools are installed and in PATH
- Check evidence directory permissions
- Review execution_summary.json for errors

**Scanner Module Issues**:
- Run module directly (most have `if __name__ == "__main__"` test code)
- Check tool availability: `which nuclei`, `which wapiti`, etc.
- Review timeout settings if scans hang

**Parallel Scanner Issues**:
- Verify fast tools installed: `which rustscan naabu masscan ffuf gobuster feroxbuster`
- masscan requires sudo (may fail without it)
- Check asyncio compatibility (Python 3.10+)
- Review `parallel_scan_summary.json` for tool performance

**ASVS Scanner Issues**:
- Verify ASVS database exists: `src/scanner/data/asvs_5.0.0.csv`
- Check level parameter (must be 1, 2, or 3 - NO Level 4)
- Playwright requires installation: `playwright install chromium`
- Review `owasp_asvs_5.0_results.json` for scan details

**Import Errors**:
- Check `sys.path.append()` in MCP server
- Ensure modules are in correct directories
- Verify Python version (3.10+)
