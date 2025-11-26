# SecPluger v2 - Simplified Python Version

**AI-Powered Pentesting Workflow Automation for Kali Linux**

SecPluger extends MCP-Kali-Server by adding workflow automation, evidence management, and professional reporting capabilities.

## What SecPluger Adds

### 🎯 Features MCP-Kali-Server Doesn't Have

1. **Workflow Automation** - Save and reuse pentesting workflows as JSON templates
2. **Visual Workflow Builder** - Simple GUI to create multi-step workflows
3. **Evidence Collection** - Auto-save all tool outputs and screenshots
4. **Finding Database** - SQLite database with CVSS scoring and tracking
5. **Professional Reports** - Generate HTML/PDF reports with templates
6. **Multi-Target Support** - Run workflows against multiple targets from CSV
7. **Scheduling** - Run workflows on a schedule or in background
8. **Conditional Logic** - If/else branching in workflows
9. **Error Handling** - Retry logic and graceful error recovery
10. **Built-in Scanner Suite** - Web crawler, fuzzer, and vulnerability scanner (no Burp Suite needed!)
11. **Dynamic Tool Management** - Auto-detects 36+ Kali tools, suggests installations, Claude helps install missing tools

## Architecture

```
SecPluger (Python Application)
├── GUI (tkinter)              - Visual workflow designer
├── Workflow Engine            - Execute workflows with logic
├── MCP Server (built-in)      - Claude can help via MCP
├── Scanner Suite              - Crawler, Fuzzer, Vuln Scanner
├── Proxy (mitmproxy)          - HTTP/HTTPS interception
├── Evidence Manager           - Auto-save outputs
├── Finding Database (SQLite)  - Track vulnerabilities
├── Report Generator           - HTML/PDF reports
└── Kali Tools Integration     - Direct subprocess calls
```

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run SecPluger
python3 src/main.py
```

## Prerequisites

- Python 3.10+
- Kali Linux (or similar with security tools)
- Optional: Claude Desktop for MCP integration

## Project Structure

```
secpluger-v2/
├── src/
│   ├── main.py              # Entry point
│   ├── gui/                 # GUI components
│   │   ├── main_window.py   # Main application window
│   │   ├── workflow_editor.py  # Workflow designer
│   │   ├── evidence_viewer.py  # Evidence browser
│   │   └── report_viewer.py    # Report viewer
│   ├── engine/              # Workflow execution
│   │   ├── workflow_engine.py  # Core execution logic
│   │   ├── node_executor.py    # Node handlers
│   │   └── scheduler.py        # Workflow scheduling
│   ├── mcp/                 # MCP server
│   │   ├── secpluger_mcp_server.py  # MCP protocol implementation
│   │   └── mcp_monitor.py       # Workflow recorder
│   ├── scanner/             # Built-in scanner suite
│   │   ├── web_crawler.py   # Website crawler (like Burp Spider)
│   │   ├── fuzzer.py        # Parameter fuzzer (like Burp Intruder)
│   │   └── vulnerability_scanner.py  # Vuln scanner (nuclei/wapiti/nikto)
│   ├── proxy/               # HTTP/HTTPS proxy
│   │   └── mitmproxy_controller.py  # mitmproxy integration
│   ├── database/            # SQLite database
│   │   ├── models.py        # Data models
│   │   └── db.py            # Database manager
│   └── utils/               # Utilities
│       ├── report_gen.py    # Report generator
│       ├── evidence.py      # Evidence collector
│       └── tools.py         # Kali tool wrappers
├── workflows/               # Saved workflows (JSON)
├── evidence/                # Evidence storage
├── reports/                 # Generated reports
├── templates/               # Report templates
├── docs/                    # Documentation
│   └── SCANNER_GUIDE.md     # Scanner usage guide
└── requirements.txt         # Python dependencies
```

## Usage

### Scanner Tools (NEW!)

SecPluger includes a complete scanner suite for web application testing:

```python
# Via MCP (with Claude Code)
crawl_website(url="http://target.com", max_depth=2, max_pages=50)
scan_vulnerabilities(target="http://target.com", scan_type="quick")
fuzz_parameter(url="http://target.com/page?id=1", parameter="id", attack_type="sqli")

# One-click complete test
full_security_test(target="http://target.com")
```

**Features**:
- Web Crawler - Discover pages, forms, and parameters
- Fuzzer - Test parameters with SQLi, XSS, and other payloads
- Vulnerability Scanner - Integrate nuclei, wapiti, nikto, sqlmap
- Evidence Collection - All results saved automatically

See [docs/SCANNER_GUIDE.md](docs/SCANNER_GUIDE.md) for complete documentation.

### 1. Create a Workflow

Use the GUI to create a workflow visually, or create JSON manually:

```json
{
  "name": "Web Application Scan",
  "description": "Basic web app vulnerability scan",
  "nodes": [
    {"id": "1", "type": "nmap", "data": {"target": "{{TARGET}}", "ports": "80,443"}},
    {"id": "2", "type": "gobuster", "data": {"url": "http://{{TARGET}}"}},
    {"id": "3", "type": "sqlmap", "data": {"url": "http://{{TARGET}}"}}
  ],
  "edges": [
    {"from": "1", "to": "2"},
    {"from": "2", "to": "3"}
  ]
}
```

### 2. Execute Workflow

```python
from src.engine.workflow_engine import WorkflowEngine

engine = WorkflowEngine()
engine.load_workflow("workflows/web_scan.json")
engine.execute(target="example.com")
```

### 3. View Results

- Evidence: `evidence/2025-10-23_example.com/`
- Report: `reports/2025-10-23_example.com_report.html`
- Findings: View in GUI or query SQLite database

## Integration with MCP-Kali-Server

SecPluger can use MCP-Kali-Server as a backend for tool execution:

1. Install MCP-Kali-Server: `sudo apt install mcp-kali-server`
2. Configure SecPluger to use it: Edit `config.json`
3. SecPluger will proxy commands through MCP-Kali-Server

Or use built-in direct execution (no MCP-Kali-Server needed).

## License

MIT License - See LICENSE file

## Attribution

This project is inspired by and designed to work with:
- [MCP-Kali-Server](https://github.com/Wh0am123/MCP-Kali-Server) (MIT License)

---

Built for the cybersecurity community
