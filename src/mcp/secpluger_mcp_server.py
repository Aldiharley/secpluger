#!/usr/bin/env python3
"""
SecPluger MCP Server
Exposes SecPluger functions to Claude Code via MCP protocol

This MCP server provides:
1. Workflow recording (auto-record Claude's actions)
2. Workflow playback (re-run saved workflows)
3. Evidence management
4. Finding tracking
5. Workflow branching
"""

import json
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

from mcp.server import Server
from mcp.types import Tool, TextContent
import mcp.server.stdio
import asyncio

from mcp_monitor import WorkflowRecorder, get_recorder
from engine.workflow_engine import WorkflowEngine
from database.models import Database

# Import mitmproxy controller
sys.path.append(str(Path(__file__).parent.parent / "proxy"))
from mitmproxy_controller import get_controller as get_proxy_controller

# Import scanner modules
sys.path.append(str(Path(__file__).parent.parent / "scanner"))
from web_crawler import WebCrawler
from fuzzer import WebFuzzer, PayloadGenerator
from vulnerability_scanner import VulnerabilityScanner

# Import tool manager
sys.path.append(str(Path(__file__).parent.parent / "utils"))
from tool_manager import get_tool_manager

# Import integrations
sys.path.append(str(Path(__file__).parent.parent / "integrations"))
from burpsuite import BurpSuiteIntegration, BurpConfig, ScanType
from wireshark import WiresharkIntegration, CaptureConfig

# Import exploitation modules
sys.path.append(str(Path(__file__).parent.parent / "exploits"))
from post_exploit import get_post_exploit

# Import auto-orchestrator
from auto_orchestrator import get_orchestrator

# Import additional intelligence modules for auto-init
from knowledge_base import get_knowledge_base
from nvd_api import get_nvd_client
from hacktricks_search import get_hacktricks_search

# Import scanner modules for auto-init
sys.path.append(str(Path(__file__).parent.parent / "scanner"))
from parallel_scanner import ParallelScanner
from owasp_asvs_scanner import get_asvs_scanner  # Use factory function for lazy init

# Import reporting modules for auto-init
sys.path.append(str(Path(__file__).parent.parent / "reporting"))
from professional_report_generator import get_report_generator  # Use factory function
from comprehensive_report_generator import ComprehensiveReportGenerator

# Import utility modules for auto-init
from screenshot_capture import get_screenshot_capture  # Optional screenshot feature
from privilege_helper import get_privilege_helper  # Smart sudo handling


# Load auto-orchestration configuration
CONFIG_PATH = Path(__file__).parent.parent.parent / "config" / "auto_orchestration.json"
AUTO_CONFIG = {}
if CONFIG_PATH.exists():
    with open(CONFIG_PATH, 'r') as f:
        AUTO_CONFIG = json.load(f)
else:
    # Default configuration if file doesn't exist
    AUTO_CONFIG = {
        "auto_features": {
            "parallel_recon": True,
            "cve_lookup": True,
            "hacktricks_research": True,
            "asvs_scan": True,
            "report_generation": True,
            "evidence_collection": True,
            "workflow_recording": True
        },
        "initialization": {
            "auto_init_on_startup": True,
            "log_level": "INFO"
        }
    }

# Initialize components
recorder = get_recorder()
engine = WorkflowEngine()
db = Database()
proxy = get_proxy_controller()
crawler = WebCrawler()
fuzzer = WebFuzzer()
vuln_scanner = VulnerabilityScanner()
tool_manager = get_tool_manager()
burp = None  # Lazy initialization
wireshark = None  # Lazy initialization

# AUTO-ORCHESTRATION: Initialize all features on startup
orchestrator = None
knowledge_base = None
nvd_client = None
hacktricks = None
parallel_scanner = None
asvs_scanner = None  # Lazy init - requires target_url
prof_report_gen = None
comp_report_gen = None
screenshot_capture = None
privilege_helper = None

if AUTO_CONFIG.get("initialization", {}).get("auto_init_on_startup", True):
    print("=" * 80)
    print("SECPLUGER MCP SERVER - AUTO-INITIALIZATION")
    print("=" * 80)

    # Initialize orchestrator
    orchestrator = get_orchestrator()
    init_results = orchestrator.initialize_all_components()

    # Initialize intelligence modules
    if AUTO_CONFIG.get("auto_features", {}).get("cve_lookup", True):
        knowledge_base = get_knowledge_base()
        nvd_client = get_nvd_client()
        print("✅ CVE/NVD Lookup Module initialized")

    if AUTO_CONFIG.get("auto_features", {}).get("hacktricks_research", True):
        hacktricks = get_hacktricks_search()
        print("✅ HackTricks Research Module initialized")

    # Initialize scanner modules
    if AUTO_CONFIG.get("auto_features", {}).get("parallel_recon", True):
        parallel_scanner = ParallelScanner()
        print("✅ Parallel Scanner initialized")

    if AUTO_CONFIG.get("auto_features", {}).get("asvs_scan", True):
        # ASVS Scanner uses lazy initialization (requires target_url)
        # Will be initialized on first use via get_asvs_scanner(target_url)
        print("✅ OWASP ASVS Scanner ready (lazy init)")

    # Initialize reporting modules
    if AUTO_CONFIG.get("auto_features", {}).get("report_generation", True):
        prof_report_gen = get_report_generator()
        comp_report_gen = ComprehensiveReportGenerator()
        print("✅ Professional Report Generators initialized")

    # Initialize utility modules
    if AUTO_CONFIG.get("auto_features", {}).get("screenshot_capture", True):
        screenshot_capture = get_screenshot_capture()
        print("✅ Screenshot Capture initialized (optional feature)")

    if AUTO_CONFIG.get("auto_features", {}).get("privilege_helper", True):
        privilege_helper = get_privilege_helper()
        print("✅ Privilege Helper initialized")

    print()
    print("SECPLUGER MCP SERVER READY")
    print("All features automatically initialized and ready to use!")
    print("=" * 80)
    print()

# Create MCP server
app = Server("secpluger")


@app.list_tools()
async def list_tools() -> list[Tool]:
    """List available SecPluger tools"""
    return [
        Tool(
            name="start_recording",
            description="Start recording a new workflow session. Call this before running pentest commands.",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target system (IP or domain)"
                    }
                }
            }
        ),
        Tool(
            name="record_command",
            description="Record a command execution. SecPluger will auto-save evidence and detect vulnerabilities.",
            inputSchema={
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "The shell command that was executed"
                    },
                    "output": {
                        "type": "object",
                        "description": "Command output with stdout, stderr, exit_code, duration"
                    }
                },
                "required": ["command", "output"]
            }
        ),
        Tool(
            name="save_workflow",
            description="Save the recorded workflow as a reusable template for future pentests.",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Workflow name (e.g., 'web_app_scan')"
                    }
                },
                "required": ["name"]
            }
        ),
        Tool(
            name="replay_workflow",
            description="Re-run a saved workflow against a new target (no Claude tokens needed!).",
            inputSchema={
                "type": "object",
                "properties": {
                    "workflow_path": {
                        "type": "string",
                        "description": "Path to workflow JSON file"
                    },
                    "target": {
                        "type": "string",
                        "description": "New target to scan"
                    }
                },
                "required": ["workflow_path", "target"]
            }
        ),
        Tool(
            name="create_branch",
            description="Create a workflow branch from a specific node to try different approaches.",
            inputSchema={
                "type": "object",
                "properties": {
                    "from_node_id": {
                        "type": "string",
                        "description": "Node ID to branch from"
                    },
                    "new_commands": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "New commands for the branch"
                    }
                },
                "required": ["from_node_id", "new_commands"]
            }
        ),
        Tool(
            name="list_workflows",
            description="List all saved workflows.",
            inputSchema={
                "type": "object",
                "properties": {}
            }
        ),
        Tool(
            name="get_findings",
            description="Get detected vulnerabilities and findings.",
            inputSchema={
                "type": "object",
                "properties": {
                    "severity": {
                        "type": "string",
                        "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                        "description": "Filter by severity"
                    }
                }
            }
        ),
        Tool(
            name="generate_report",
            description="Generate HTML report from evidence.",
            inputSchema={
                "type": "object",
                "properties": {
                    "session_id": {
                        "type": "string",
                        "description": "Session ID to generate report for"
                    }
                }
            }
        ),
        Tool(
            name="capture_screenshot",
            description="Manually capture a screenshot with optional label. Screenshots are automatically captured during command execution, but this allows capturing additional screenshots at any time.",
            inputSchema={
                "type": "object",
                "properties": {
                    "label": {
                        "type": "string",
                        "description": "Optional label for the screenshot (e.g., 'vulnerability_confirmation', 'exploit_success')"
                    }
                }
            }
        ),
        Tool(
            name="start_proxy",
            description="Start mitmproxy HTTP/HTTPS intercepting proxy. Traffic will be automatically captured and saved as evidence.",
            inputSchema={
                "type": "object",
                "properties": {
                    "port": {
                        "type": "number",
                        "description": "Proxy port (default: 8080)"
                    },
                    "mode": {
                        "type": "string",
                        "enum": ["regular", "reverse", "transparent", "socks5"],
                        "description": "Proxy mode (default: regular)"
                    },
                    "target": {
                        "type": "string",
                        "description": "Target URL for reverse proxy mode (e.g., 'http://example.com')"
                    }
                }
            }
        ),
        Tool(
            name="stop_proxy",
            description="Stop running mitmproxy instance and save captured traffic.",
            inputSchema={
                "type": "object",
                "properties": {}
            }
        ),
        Tool(
            name="proxy_status",
            description="Get current proxy status and statistics.",
            inputSchema={
                "type": "object",
                "properties": {}
            }
        ),
        Tool(
            name="crawl_website",
            description="Crawl website to discover pages, forms, and parameters. Essential first step for comprehensive security testing.",
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Starting URL to crawl"
                    },
                    "max_depth": {
                        "type": "number",
                        "description": "Maximum crawl depth (default: 3)"
                    },
                    "max_pages": {
                        "type": "number",
                        "description": "Maximum pages to crawl (default: 100)"
                    }
                },
                "required": ["url"]
            }
        ),
        Tool(
            name="fuzz_parameter",
            description="Fuzz a specific parameter with attack payloads to find vulnerabilities (SQLi, XSS, etc.). Similar to Burp Intruder.",
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Target URL"
                    },
                    "parameter": {
                        "type": "string",
                        "description": "Parameter name to fuzz"
                    },
                    "attack_type": {
                        "type": "string",
                        "enum": ["sqli", "xss", "command_injection", "all"],
                        "description": "Type of attack payloads to use"
                    },
                    "method": {
                        "type": "string",
                        "enum": ["GET", "POST"],
                        "description": "HTTP method (default: GET)"
                    }
                },
                "required": ["url", "parameter"]
            }
        ),
        Tool(
            name="scan_vulnerabilities",
            description="Run comprehensive vulnerability scan using multiple tools (wapiti, nuclei, nikto). This is like Burp Scanner.",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target URL or host"
                    },
                    "scan_type": {
                        "type": "string",
                        "enum": ["quick", "full", "sqli", "xss"],
                        "description": "Type of scan (default: quick)"
                    }
                },
                "required": ["target"]
            }
        ),
        Tool(
            name="full_security_test",
            description="Run complete security assessment: crawl + fuzz + scan + evidence collection. One-stop complete pentest.",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target URL"
                    }
                },
                "required": ["target"]
            }
        ),
        Tool(
            name="check_tools",
            description="Check which security tools are installed on the system. Shows all Kali Linux pentest tools and their availability.",
            inputSchema={
                "type": "object",
                "properties": {
                    "category": {
                        "type": "string",
                        "description": "Filter by category: network_scanner, web_scanner, enumeration, sql_injection, xss, exploitation, proxy, recon, ssl, password, wireless, cms, network_analysis"
                    },
                    "priority": {
                        "type": "string",
                        "enum": ["high", "medium", "low"],
                        "description": "Filter by priority level"
                    }
                }
            }
        ),
        Tool(
            name="get_tool_info",
            description="Get detailed information about a specific security tool including installation command.",
            inputSchema={
                "type": "object",
                "properties": {
                    "tool_name": {
                        "type": "string",
                        "description": "Name of the tool (e.g., nmap, sqlmap, nuclei)"
                    }
                },
                "required": ["tool_name"]
            }
        ),
        Tool(
            name="install_tool",
            description="Get installation command for a security tool. Claude can then help you install it.",
            inputSchema={
                "type": "object",
                "properties": {
                    "tool_name": {
                        "type": "string",
                        "description": "Name of the tool to install"
                    }
                },
                "required": ["tool_name"]
            }
        ),
        Tool(
            name="install_missing_tools",
            description="Get installation commands for all missing tools in a category or priority level.",
            inputSchema={
                "type": "object",
                "properties": {
                    "category": {
                        "type": "string",
                        "description": "Category to install tools for"
                    },
                    "priority": {
                        "type": "string",
                        "enum": ["high", "medium", "low"],
                        "description": "Priority level to install"
                    }
                }
            }
        ),        # === PHASE 5: AUTOMATIC EXPLOITATION WITH APPROVAL ===
        Tool(
            name="match_exploits",
            description="[PHASE 5] Match exploits against scan results automatically. Returns list of potential exploits with confidence scores and risk levels.",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target IP or domain"
                    },
                    "scan_results": {
                        "type": "object",
                        "description": "Scan results with services array containing: port, product, version, service"
                    }
                },
                "required": ["target", "scan_results"]
            }
        ),
        Tool(
            name="approve_exploit",
            description="[PHASE 5] Approve or reject a specific exploit for execution. Use after match_exploits to manually approve individual exploits.",
            inputSchema={
                "type": "object",
                "properties": {
                    "exploit_id": {
                        "type": "string",
                        "description": "Exploit ID from match_exploits result"
                    },
                    "approved": {
                        "type": "boolean",
                        "description": "True to approve, False to reject"
                    }
                },
                "required": ["exploit_id", "approved"]
            }
        ),
        Tool(
            name="execute_exploits",
            description="[PHASE 5] Execute all approved exploits against target. Returns execution results, flags found, and evidence location. Requires human approval for each exploit (interactive mode).",
            inputSchema={
                "type": "object",
                "properties": {
                    "interactive": {
                        "type": "boolean",
                        "description": "If True, requests approval for each exploit before execution (default: True). Safety-first design."
                    }
                }
            }
        ),
        Tool(
            name="get_exploit_report",
            description="[PHASE 5] Generate comprehensive report of matched and executed exploits with risk levels, confidence scores, and execution results.",
            inputSchema={
                "type": "object",
                "properties": {}
            }
        ),

        Tool(
            name="burp_scan",
            description="Start automated BurpSuite Professional scan (crawl + audit). Requires burp-rest-api running.",
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Target URL to scan"
                    },
                    "scan_type": {
                        "type": "string",
                        "enum": ["CrawlAndAudit", "Crawl", "Audit"],
                        "description": "Scan type (default: CrawlAndAudit)"
                    },
                    "wait": {
                        "type": "boolean",
                        "description": "Wait for scan to complete (default: true)"
                    }
                },
                "required": ["url"]
            }
        ),
        Tool(
            name="burp_get_issues",
            description="Get vulnerabilities found by BurpSuite scanner.",
            inputSchema={
                "type": "object",
                "properties": {
                    "url_prefix": {
                        "type": "string",
                        "description": "Filter issues by URL prefix"
                    }
                }
            }
        ),
        Tool(
            name="burp_generate_report",
            description="Generate HTML or XML report from BurpSuite scan results.",
            inputSchema={
                "type": "object",
                "properties": {
                    "report_type": {
                        "type": "string",
                        "enum": ["HTML", "XML"],
                        "description": "Report format (default: HTML)"
                    },
                    "url_prefix": {
                        "type": "string",
                        "description": "Filter report by URL prefix"
                    }
                }
            }
        ),
        Tool(
            name="burp_status",
            description="Check if BurpSuite REST API is available and get connection status.",
            inputSchema={
                "type": "object",
                "properties": {}
            }
        ),
        Tool(
            name="wireshark_start_capture",
            description="Start capturing network traffic with Wireshark/tshark. Traffic saved to PCAP file.",
            inputSchema={
                "type": "object",
                "properties": {
                    "interface": {
                        "type": "string",
                        "description": "Network interface (e.g., eth0, wlan0). Use 'any' for all interfaces."
                    },
                    "duration": {
                        "type": "number",
                        "description": "Capture duration in seconds (omit for continuous capture)"
                    },
                    "capture_filter": {
                        "type": "string",
                        "description": "BPF capture filter (e.g., 'tcp port 80', 'host 10.10.10.1')"
                    }
                },
                "required": ["interface"]
            }
        ),
        Tool(
            name="wireshark_stop_capture",
            description="Stop active packet capture and save PCAP file.",
            inputSchema={
                "type": "object",
                "properties": {}
            }
        ),
        Tool(
            name="wireshark_analyze_pcap",
            description="Analyze PCAP file: extract protocols, HTTP requests, credentials, conversations.",
            inputSchema={
                "type": "object",
                "properties": {
                    "pcap_file": {
                        "type": "string",
                        "description": "Path to PCAP file to analyze"
                    },
                    "display_filter": {
                        "type": "string",
                        "description": "Wireshark display filter (e.g., 'http', 'ftp', 'tcp.port==80')"
                    }
                },
                "required": ["pcap_file"]
            }
        ),
        Tool(
            name="wireshark_list_interfaces",
            description="List available network interfaces for packet capture.",
            inputSchema={
                "type": "object",
                "properties": {}
            }
        ),
        Tool(
            name="parallel_scan",
            description="Run parallel port scanning and web fuzzing (2-5x faster than linear scanning). Uses tool clustering: rustscan+naabu+masscan for ports, ffuf+gobuster+feroxbuster for web directories.",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target IP address or domain"
                    },
                    "include_web": {
                        "type": "boolean",
                        "description": "Include web fuzzing if web services detected (default: True)"
                    },
                    "web_url": {
                        "type": "string",
                        "description": "Optional: Specific web URL to fuzz (if not provided, will detect from ports)"
                    }
                },
                "required": ["target"]
            }
        ),
        Tool(
            name="asvs_scan",
            description="Run OWASP ASVS 5.0 compliance scan (345 security requirements across L1/L2/L3). Generates detailed CSV report with affected URLs and remediation guidance.",
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Target URL to scan"
                    },
                    "level": {
                        "type": "integer",
                        "enum": [1, 2, 3],
                        "description": "ASVS verification level: 1=Basic, 2=Standard (default), 3=Advanced"
                    },
                    "enable_screenshots": {
                        "type": "boolean",
                        "description": "Enable screenshot capture during testing (default: False)"
                    }
                },
                "required": ["url"]
            }
        ),
        Tool(
            name="auto_exploit",
            description="Automatically exploit discovered vulnerabilities to capture flags. Uses sqlmap for SQLi, command injection for RCE, and LFI for file reading. Returns captured flags and credentials.",
            inputSchema={
                "type": "object",
                "properties": {
                    "findings": {
                        "type": "array",
                        "description": "Array of vulnerability findings to exploit. Each finding should have: vulnerability_type, url, parameter (optional)",
                        "items": {
                            "type": "object",
                            "properties": {
                                "vulnerability_type": {
                                    "type": "string",
                                    "enum": ["sqli", "xss", "rce", "lfi", "ssrf", "file_upload", "command_injection"],
                                    "description": "Type of vulnerability"
                                },
                                "url": {
                                    "type": "string",
                                    "description": "Vulnerable URL"
                                },
                                "parameter": {
                                    "type": "string",
                                    "description": "Vulnerable parameter name (optional)"
                                },
                                "confidence": {
                                    "type": "string",
                                    "enum": ["high", "medium", "low"],
                                    "description": "Confidence level (optional)"
                                }
                            },
                            "required": ["vulnerability_type", "url"]
                        }
                    },
                    "lhost": {
                        "type": "string",
                        "description": "Local host for reverse shells (your IP address)"
                    },
                    "lport": {
                        "type": "integer",
                        "description": "Local port for reverse shells (default: 4444)"
                    }
                },
                "required": ["findings"]
            }
        ),
        Tool(
            name="service_exploit",
            description="Exploit network services (SSH, FTP, SMB, databases) using credential bruteforce and service-specific attacks. Automatically detects service type from port and runs appropriate exploitation.",
            inputSchema={
                "type": "object",
                "properties": {
                    "services": {
                        "type": "array",
                        "description": "Array of services to exploit. Each service should have: target, port, service_name (optional)",
                        "items": {
                            "type": "object",
                            "properties": {
                                "target": {
                                    "type": "string",
                                    "description": "Target IP address or hostname"
                                },
                                "port": {
                                    "type": "integer",
                                    "description": "Service port number"
                                },
                                "service_name": {
                                    "type": "string",
                                    "description": "Service name from nmap (optional, e.g., 'ssh', 'ftp', 'microsoft-ds')"
                                }
                            },
                            "required": ["target", "port"]
                        }
                    },
                    "username": {
                        "type": "string",
                        "description": "Specific username to test (optional, uses common usernames if not specified)"
                    },
                    "password_list": {
                        "type": "string",
                        "description": "Path to password wordlist (optional, uses common passwords if not specified)"
                    },
                    "lhost": {
                        "type": "string",
                        "description": "Local host IP for reverse shells (optional)"
                    },
                    "lport": {
                        "type": "integer",
                        "description": "Local port for reverse shells (default: 4444)"
                    }
                },
                "required": ["services"]
            }
        ),
        Tool(
            name="post_exploit",
            description="Complete post-exploitation workflow: find flags, enumerate system, run LinPEAS, and attempt automatic privilege escalation. Use after gaining initial shell access via service_exploit or web_exploit.",
            inputSchema={
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Target IP address or hostname"
                    },
                    "port": {
                        "type": "integer",
                        "description": "SSH port (default: 22)"
                    },
                    "username": {
                        "type": "string",
                        "description": "SSH username (from successful exploitation)"
                    },
                    "password": {
                        "type": "string",
                        "description": "SSH password (from successful exploitation)"
                    },
                    "run_linpeas": {
                        "type": "boolean",
                        "description": "Run LinPEAS for detailed privilege escalation enumeration (default: true)"
                    },
                    "attempt_privesc": {
                        "type": "boolean",
                        "description": "Automatically attempt privilege escalation based on findings (default: true)"
                    }
                },
                "required": ["host", "username", "password"]
            }
        ),
        Tool(
            name="find_flags",
            description="Automatically search for CTF flags on compromised system. Checks common locations (/root/root.txt, /home/*/user.txt), scans all .txt files, and searches for files with 'flag' in name.",
            inputSchema={
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Target IP address or hostname"
                    },
                    "port": {
                        "type": "integer",
                        "description": "SSH port (default: 22)"
                    },
                    "username": {
                        "type": "string",
                        "description": "SSH username"
                    },
                    "password": {
                        "type": "string",
                        "description": "SSH password"
                    }
                },
                "required": ["host", "username", "password"]
            }
        ),
        Tool(
            name="run_linpeas",
            description="Run LinPEAS privilege escalation enumeration script. Automatically downloads latest version, executes it, and parses output for privilege escalation vectors (SUID binaries, sudo rights, capabilities, etc.).",
            inputSchema={
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Target IP address or hostname"
                    },
                    "port": {
                        "type": "integer",
                        "description": "SSH port (default: 22)"
                    },
                    "username": {
                        "type": "string",
                        "description": "SSH username"
                    },
                    "password": {
                        "type": "string",
                        "description": "SSH password"
                    },
                    "download_dir": {
                        "type": "string",
                        "description": "Directory to download LinPEAS to (default: /tmp)"
                    }
                },
                "required": ["host", "username", "password"]
            }
        )
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    """Handle tool calls from Claude"""

    global burp, wireshark

    try:
        if name == "start_recording":
            target = arguments.get("target")
            session_id = recorder.start_session(target=target)

            return [TextContent(
                type="text",
                text=f"✅ Started recording workflow session: {session_id}\n\n"
                     f"Target: {target}\n"
                     f"Evidence will be saved to: evidence/{session_id}/\n\n"
                     f"Now run your pentest commands. I'll record everything automatically!"
            )]

        elif name == "record_command":
            command = arguments["command"]
            output = arguments["output"]

            node_id = recorder.record_command(command, output)

            # Check for findings
            findings_msg = ""
            if recorder.current_session['findings']:
                latest_findings = [f for f in recorder.current_session['findings']
                                 if any(n['id'] == node_id and 'findings' in n
                                       for n in recorder.current_session['nodes'])]
                if latest_findings:
                    findings_msg = "\n\n🔍 **Vulnerabilities Detected:**\n"
                    for finding in latest_findings:
                        findings_msg += f"  • [{finding['severity']}] {finding['type']}: {finding.get('description', 'See evidence')}\n"

            return [TextContent(
                type="text",
                text=f"✅ Recorded command as Node {node_id}\n"
                     f"Tool: {recorder.current_session['nodes'][-1]['type']}\n"
                     f"Duration: {output.get('duration', 0)}s\n"
                     f"Evidence saved: {recorder.current_session['nodes'][-1]['evidence_file']}"
                     f"{findings_msg}"
            )]

        elif name == "save_workflow":
            workflow_name = arguments["name"]
            workflow_path = recorder.save_workflow(workflow_name)

            session = recorder.current_session

            return [TextContent(
                type="text",
                text=f"✅ Workflow saved successfully!\n\n"
                     f"📁 Workflow: {workflow_path}\n"
                     f"📊 Nodes: {len(session['nodes'])}\n"
                     f"🔍 Findings: {len(session['findings'])}\n"
                     f"📄 Evidence: {len(session['evidence_files'])} files\n\n"
                     f"💡 Next time, re-run this workflow with:\n"
                     f"   replay_workflow(workflow_path='{workflow_path}', target='new-target.com')\n\n"
                     f"No Claude tokens needed for replay!"
            )]

        elif name == "replay_workflow":
            workflow_path = arguments["workflow_path"]
            target = arguments["target"]

            # Load and execute workflow
            engine.load_workflow(workflow_path)
            result = engine.execute(target=target)

            return [TextContent(
                type="text",
                text=f"✅ Workflow replayed successfully!\n\n"
                     f"Target: {target}\n"
                     f"Execution ID: {result['execution_id']}\n"
                     f"Nodes completed: {result['nodes_completed']}\n"
                     f"Evidence: {result['evidence_path']}\n\n"
                     f"Check the evidence folder for results!"
            )]

        elif name == "create_branch":
            from_node_id = arguments["from_node_id"]
            new_commands = arguments["new_commands"]

            branch_path = recorder.create_branch(from_node_id, new_commands)

            return [TextContent(
                type="text",
                text=f"✅ Workflow branch created!\n\n"
                     f"Branched from: Node {from_node_id}\n"
                     f"New commands: {len(new_commands)}\n"
                     f"Branch workflow: {branch_path}\n\n"
                     f"You can now execute this branch independently."
            )]

        elif name == "list_workflows":
            workflows_dir = Path("workflows")
            workflows = list(workflows_dir.glob("*.json"))

            if not workflows:
                return [TextContent(
                    type="text",
                    text="No saved workflows found. Start recording one with start_recording()!"
                )]

            workflow_list = "\n".join([f"  • {w.name}" for w in workflows])

            return [TextContent(
                type="text",
                text=f"📁 **Saved Workflows** ({len(workflows)}):\n\n{workflow_list}\n\n"
                     f"Use replay_workflow() to re-run any of these."
            )]

        elif name == "get_findings":
            severity = arguments.get("severity")

            findings = db.get_findings(severity=severity)

            if not findings:
                return [TextContent(
                    type="text",
                    text="No findings found in database."
                )]

            findings_text = ""
            for f in findings[:20]:  # Limit to 20
                findings_text += f"\n[{f['severity']}] {f['title']}\n"
                findings_text += f"  Target: {f['target']}\n"
                if f.get('port'):
                    findings_text += f"  Port: {f['port']}\n"
                findings_text += f"  Status: {f['status']}\n"

            return [TextContent(
                type="text",
                text=f"🔍 **Findings** ({len(findings)} total):\n{findings_text}"
            )]

        elif name == "generate_report":
            from utils.report_gen import ReportGenerator

            session_id = arguments["session_id"]
            evidence_path = Path("evidence") / session_id

            if not evidence_path.exists():
                return [TextContent(
                    type="text",
                    text=f"❌ Evidence not found for session: {session_id}"
                )]

            gen = ReportGenerator(evidence_path, session_id)
            report_path = gen.generate_html_report()

            return [TextContent(
                type="text",
                text=f"✅ Report generated!\n\nReport: {report_path}\n\nOpen in browser to view."
            )]

        elif name == "capture_screenshot":
            label = arguments.get("label")

            screenshot_path = recorder.capture_manual_screenshot(label=label)

            if screenshot_path:
                label_msg = f" (labeled: {label})" if label else ""
                return [TextContent(
                    type="text",
                    text=f"✅ Screenshot captured{label_msg}!\n\n"
                         f"Screenshot: {screenshot_path}\n\n"
                         f"💡 Screenshots are also automatically captured during command execution.\n"
                         f"All screenshots are saved in the evidence folder."
                )]
            else:
                return [TextContent(
                    type="text",
                    text=f"❌ Failed to capture screenshot.\n\n"
                         f"Possible reasons:\n"
                         f"  • No active recording session (use start_recording first)\n"
                         f"  • Screenshot library not available\n"
                         f"  • No display server (headless environment)\n\n"
                         f"Note: Screenshot capture requires a graphical environment."
                )]

        elif name == "start_proxy":
            port = arguments.get("port", 8080)
            mode = arguments.get("mode", "regular")
            target = arguments.get("target")

            # Get current recording session if available
            session_id = recorder.current_session['id'] if recorder.current_session else None

            result = proxy.start_proxy(
                port=port,
                mode=mode,
                target=target,
                session_id=session_id
            )

            if result['success']:
                return [TextContent(
                    type="text",
                    text=f"✅ Proxy started successfully!\n\n"
                         f"**Configuration:**\n"
                         f"  • Port: {result['port']}\n"
                         f"  • Mode: {result['mode']}\n"
                         f"  • Target: {result.get('target', 'N/A')}\n"
                         f"  • Session ID: {result['session_id']}\n\n"
                         f"**Configure your browser/tools:**\n"
                         f"  • HTTP Proxy: 127.0.0.1:{result['port']}\n"
                         f"  • HTTPS Proxy: 127.0.0.1:{result['port']}\n\n"
                         f"**Certificate:**\n"
                         f"  • mitmproxy generates its own CA certificate\n"
                         f"  • Visit http://mitm.it to install certificate\n\n"
                         f"**Traffic capture:**\n"
                         f"  • All traffic automatically saved to: {result['flow_file']}\n"
                         f"  • Evidence folder: evidence/{result['session_id']}/\n\n"
                         f"💡 Use stop_proxy when done to save all captured traffic!"
                )]
            else:
                return [TextContent(
                    type="text",
                    text=f"❌ Failed to start proxy\n\n"
                         f"Error: {result.get('error', 'Unknown error')}\n\n"
                         f"**Troubleshooting:**\n"
                         f"  • Check if port {port} is already in use\n"
                         f"  • Ensure mitmproxy is installed: pip install mitmproxy\n"
                         f"  • Check if another proxy is running: proxy_status"
                )]

        elif name == "stop_proxy":
            result = proxy.stop_proxy()

            if result['success']:
                # Get flow summary
                summary = proxy.get_flow_summary()

                return [TextContent(
                    type="text",
                    text=f"✅ Proxy stopped successfully!\n\n"
                         f"**Traffic captured:**\n"
                         f"  • Flow file: {result.get('flow_file', 'N/A')}\n"
                         f"  • Total flows: {summary.get('flow_count', 0)}\n"
                         f"  • File size: {summary.get('file_size', 0)} bytes\n"
                         f"  • Session ID: {result.get('session_id', 'N/A')}\n\n"
                         f"**Evidence saved to:**\n"
                         f"  • evidence/{result.get('session_id', 'unknown')}/\n\n"
                         f"💡 Traffic logs are saved and ready for analysis!"
                )]
            else:
                return [TextContent(
                    type="text",
                    text=f"❌ Failed to stop proxy\n\n"
                         f"Error: {result.get('error', 'Unknown error')}\n\n"
                         f"**Note:** Proxy may not be running. Check with proxy_status."
                )]

        elif name == "proxy_status":
            status = proxy.get_status()

            if status['running']:
                # Get flow summary if available
                summary = proxy.get_flow_summary()

                return [TextContent(
                    type="text",
                    text=f"✅ Proxy is **RUNNING**\n\n"
                         f"**Status:**\n"
                         f"  • Port: {status['port']}\n"
                         f"  • PID: {status.get('pid', 'N/A')}\n"
                         f"  • Session ID: {status.get('session_id', 'N/A')}\n\n"
                         f"**Traffic:**\n"
                         f"  • Flows captured: {summary.get('flow_count', 0)}\n"
                         f"  • Flow file: {status.get('flow_file', 'N/A')}\n\n"
                         f"**Proxy configuration:**\n"
                         f"  • HTTP Proxy: 127.0.0.1:{status['port']}\n"
                         f"  • HTTPS Proxy: 127.0.0.1:{status['port']}\n\n"
                         f"💡 Use stop_proxy to stop and save captured traffic."
                )]
            else:
                return [TextContent(
                    type="text",
                    text=f"⏹️ Proxy is **NOT RUNNING**\n\n"
                         f"**To start:**\n"
                         f"  • Use start_proxy to start intercepting traffic\n\n"
                         f"**Example:**\n"
                         f"  • Regular proxy: start_proxy(port=8080)\n"
                         f"  • Reverse proxy: start_proxy(mode='reverse', target='http://example.com')"
                )]

        elif name == "crawl_website":
            url = arguments["url"]
            max_depth = arguments.get("max_depth", 3)
            max_pages = arguments.get("max_pages", 100)

            # Get evidence directory from current session
            session_id = recorder.current_session['id'] if recorder.current_session else datetime.now().strftime("%Y%m%d_%H%M%S")
            evidence_dir = Path("evidence") / session_id

            # Set crawler limits
            crawler.max_depth = max_depth
            crawler.max_pages = max_pages

            # Crawl
            results = crawler.crawl(url, evidence_dir)

            return [TextContent(
                type="text",
                text=f"✅ Website crawled successfully!\n\n"
                     f"**Crawl Results:**\n"
                     f"  • Pages crawled: {results['pages_crawled']}\n"
                     f"  • URLs discovered: {results['urls_discovered']}\n"
                     f"  • Forms found: {results['forms_found']}\n"
                     f"  • Parameters found: {results['parameters_found']}\n\n"
                     f"**Evidence saved to:**\n"
                     f"  • {evidence_dir}/crawler_results.json\n"
                     f"  • {evidence_dir}/discovered_urls.txt\n"
                     f"  • {evidence_dir}/discovered_forms.json\n\n"
                     f"💡 Use fuzz_parameter or scan_vulnerabilities to test discovered endpoints!"
            )]

        elif name == "fuzz_parameter":
            url = arguments["url"]
            parameter = arguments["parameter"]
            attack_type = arguments.get("attack_type", "all")
            method = arguments.get("method", "GET")

            # Get evidence directory
            session_id = recorder.current_session['id'] if recorder.current_session else datetime.now().strftime("%Y%m%d_%H%M%S")
            evidence_dir = Path("evidence") / session_id

            # Get payloads based on attack type
            gen = PayloadGenerator()
            if attack_type == "sqli":
                payloads = gen.get_sqli_payloads()
            elif attack_type == "xss":
                payloads = gen.get_xss_payloads()
            elif attack_type == "command_injection":
                payloads = gen.get_command_injection_payloads()
            else:  # all
                payloads = gen.get_all_payloads()

            # Fuzz
            results = fuzzer.fuzz_parameter(url, parameter, payloads, method, evidence_dir)

            vuln_summary = ""
            if results['vulnerabilities']:
                vuln_summary = "\n\n🔍 **Vulnerabilities Found:**\n"
                for vuln in results['vulnerabilities'][:5]:
                    vuln_summary += f"  • [{vuln['vulnerability_type']}] {vuln['payload'][:50]}\n"

            return [TextContent(
                type="text",
                text=f"✅ Parameter fuzzing complete!\n\n"
                     f"**Fuzz Results:**\n"
                     f"  • Parameter: {parameter}\n"
                     f"  • Payloads tested: {results['payloads_tested']}\n"
                     f"  • Vulnerabilities: {len(results['vulnerabilities'])}\n"
                     f"  • Interesting responses: {len(results['interesting_responses'])}\n"
                     f"{vuln_summary}\n"
                     f"**Evidence:** {evidence_dir}/fuzz_{parameter}_*.json"
            )]

        elif name == "scan_vulnerabilities":
            target = arguments["target"]
            scan_type = arguments.get("scan_type", "quick")

            # Get session ID
            session_id = recorder.current_session['id'] if recorder.current_session else None

            # Run scan
            results = vuln_scanner.scan(target, scan_type, session_id)

            # Build vulnerability summary
            vuln_summary = ""
            if results['vulnerabilities']:
                by_severity = {}
                for vuln in results['vulnerabilities']:
                    severity = vuln.get('severity', 'UNKNOWN')
                    by_severity[severity] = by_severity.get(severity, 0) + 1

                vuln_summary = "\n\n🔍 **Vulnerabilities by Severity:**\n"
                for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                    if severity in by_severity:
                        vuln_summary += f"  • {severity}: {by_severity[severity]}\n"

                vuln_summary += "\n**Top Vulnerabilities:**\n"
                for vuln in results['vulnerabilities'][:5]:
                    vuln_summary += f"  • [{vuln['severity']}] {vuln['type']} ({vuln['scanner']})\n"

            return [TextContent(
                type="text",
                text=f"✅ Vulnerability scan complete!\n\n"
                     f"**Scan Results:**\n"
                     f"  • Target: {target}\n"
                     f"  • Scan type: {scan_type}\n"
                     f"  • Scanners used: {', '.join(results['scanners_used'])}\n"
                     f"  • Total vulnerabilities: {len(results['vulnerabilities'])}\n"
                     f"{vuln_summary}\n\n"
                     f"**Evidence:** evidence/{results['session_id']}/vulnerability_scan_results.json"
            )]

        elif name == "full_security_test":
            target = arguments["target"]

            # Start comprehensive test
            from datetime import datetime

            # Start recording if not already
            if not recorder.current_session:
                session_id = recorder.start_session(target=target)
            else:
                session_id = recorder.current_session['id']

            evidence_dir = Path("evidence") / session_id

            status_msg = f"🔍 Running comprehensive security test on {target}\n\n"

            # Step 1: Crawl
            status_msg += "**Step 1/4:** Crawling website...\n"
            crawler.max_depth = 2
            crawler.max_pages = 50
            crawl_results = crawler.crawl(target, evidence_dir)
            status_msg += f"  ✅ Found {crawl_results['pages_crawled']} pages, {crawl_results['forms_found']} forms\n\n"

            # Step 2: Vulnerability Scan
            status_msg += "**Step 2/4:** Running vulnerability scan...\n"
            scan_results = vuln_scanner.scan(target, 'quick', session_id)
            status_msg += f"  ✅ Found {len(scan_results['vulnerabilities'])} vulnerabilities\n\n"

            # Step 3: Fuzz top parameters
            status_msg += "**Step 3/4:** Fuzzing parameters...\n"
            fuzzed = 0
            gen = PayloadGenerator()
            sqli_payloads = gen.get_sqli_payloads()[:20]  # Quick test

            for url, params in list(crawl_results['parameters'].items())[:3]:  # Top 3 URLs
                for param in list(params)[:2]:  # Top 2 params per URL
                    fuzzer.fuzz_parameter(url, param, sqli_payloads, 'GET', evidence_dir)
                    fuzzed += 1

            status_msg += f"  ✅ Fuzzed {fuzzed} parameters\n\n"

            # Step 4: Summary
            status_msg += "**Step 4/4:** Generating summary...\n"
            total_vulns = len(scan_results['vulnerabilities'])

            status_msg += f"\n{'='*50}\n"
            status_msg += f"**COMPLETE SECURITY ASSESSMENT**\n"
            status_msg += f"{'='*50}\n\n"
            status_msg += f"**Target:** {target}\n"
            status_msg += f"**Session:** {session_id}\n\n"
            status_msg += f"**Results:**\n"
            status_msg += f"  • Pages crawled: {crawl_results['pages_crawled']}\n"
            status_msg += f"  • Forms discovered: {crawl_results['forms_found']}\n"
            status_msg += f"  • Parameters fuzzed: {fuzzed}\n"
            status_msg += f"  • Vulnerabilities found: {total_vulns}\n\n"
            status_msg += f"**Evidence Location:**\n"
            status_msg += f"  • evidence/{session_id}/\n\n"
            status_msg += f"💡 Use save_workflow to save this pentest for replay!"

            return [TextContent(
                type="text",
                text=status_msg
            )]

        elif name == "check_tools":
            category = arguments.get("category")
            priority = arguments.get("priority")

            # Get available tools
            if category or priority:
                available = tool_manager.get_available_tools(category=category)
                missing = tool_manager.get_missing_tools(category=category, priority=priority)

                filter_desc = []
                if category:
                    filter_desc.append(f"category={category}")
                if priority:
                    filter_desc.append(f"priority={priority}")

                status_msg = f"**Tool Status** ({', '.join(filter_desc)}):\n\n"
            else:
                available = tool_manager.get_available_tools()
                missing = tool_manager.get_missing_tools()
                status_msg = "**All Security Tools Status:**\n\n"

            # Group by category
            categories = {}
            for tool_name in available.keys():
                tool_info = tool_manager.get_tool_info(tool_name)
                cat = tool_info['category']
                if cat not in categories:
                    categories[cat] = []
                categories[cat].append(tool_name)

            # Build status message
            installed_count = sum(1 for v in available.values() if v)
            total_count = len(available)

            for cat, tools in sorted(categories.items()):
                if category and cat != category:
                    continue

                status_msg += f"**{cat.replace('_', ' ').title()}:**\n"
                for tool in sorted(tools):
                    is_available = available[tool]
                    tool_info = tool_manager.get_tool_info(tool)
                    pri = tool_info['priority']

                    if priority and pri != priority:
                        continue

                    status = "✅" if is_available else "❌"
                    status_msg += f"  {status} {tool} [{pri}] - {tool_info['description']}\n"
                status_msg += "\n"

            status_msg += f"\n**Summary:** {installed_count}/{total_count} tools installed\n"

            if missing:
                status_msg += f"\n**Missing tools:** {len(missing)}\n"
                status_msg += "💡 Use `get_tool_info(tool_name)` or `install_tool(tool_name)` to install missing tools!"

            return [TextContent(
                type="text",
                text=status_msg
            )]

        elif name == "get_tool_info":
            tool_name = arguments["tool_name"]

            tool_info = tool_manager.get_tool_info(tool_name)
            if not tool_info:
                return [TextContent(
                    type="text",
                    text=f"❌ Unknown tool: {tool_name}\n\n"
                         f"Use `check_tools()` to see available tools."
                )]

            is_installed = tool_manager.detected_tools.get(tool_name, False)
            status = "✅ Installed" if is_installed else "❌ Not installed"

            msg = f"**Tool: {tool_name}**\n\n"
            msg += f"**Status:** {status}\n"
            msg += f"**Category:** {tool_info['category']}\n"
            msg += f"**Priority:** {tool_info['priority']}\n"
            msg += f"**Description:** {tool_info['description']}\n\n"

            if is_installed:
                version = tool_manager.tool_versions.get(tool_name, "unknown")
                msg += f"**Version:** {version}\n"
            else:
                msg += f"**Installation command:**\n"
                msg += f"```bash\n{tool_info['install_cmd']}\n```\n\n"
                msg += f"💡 I can help you run this command to install it!"

            return [TextContent(
                type="text",
                text=msg
            )]

        elif name == "install_tool":
            tool_name = arguments["tool_name"]

            tool_info = tool_manager.get_tool_info(tool_name)
            if not tool_info:
                return [TextContent(
                    type="text",
                    text=f"❌ Unknown tool: {tool_name}"
                )]

            is_installed = tool_manager.detected_tools.get(tool_name, False)
            if is_installed:
                return [TextContent(
                    type="text",
                    text=f"✅ {tool_name} is already installed!"
                )]

            install_cmd = tool_info['install_cmd']

            return [TextContent(
                type="text",
                text=f"**Install {tool_name}:**\n\n"
                     f"```bash\n{install_cmd}\n```\n\n"
                     f"I'll help you run this command. Ready to install?"
            )]

        elif name == "install_missing_tools":
            category = arguments.get("category")
            priority = arguments.get("priority")

            missing = tool_manager.get_missing_tools(category=category, priority=priority)

            if not missing:
                filter_msg = ""
                if category:
                    filter_msg = f" in category '{category}'"
                if priority:
                    filter_msg += f" with priority '{priority}'"

                return [TextContent(
                    type="text",
                    text=f"✅ No missing tools{filter_msg}!"
                )]

            install_cmds = tool_manager.get_install_commands(missing)

            filter_desc = []
            if category:
                filter_desc.append(f"category={category}")
            if priority:
                filter_desc.append(f"priority={priority}")

            filter_text = f" ({', '.join(filter_desc)})" if filter_desc else ""

            msg = f"**Missing Tools{filter_text}:** {len(missing)}\n\n"
            msg += "**Tools to install:**\n"
            for tool in missing:
                info = tool_manager.get_tool_info(tool)
                msg += f"  • {tool} [{info['priority']}] - {info['description']}\n"

            msg += f"\n**Installation Commands:**\n\n"
            msg += f"```bash\n{install_cmds}\n```\n\n"
            msg += f"💡 I can help you run these commands one by one!"

            return [TextContent(
                type="text",
                text=msg
            )]

        
        # === PHASE 5: AUTOMATIC EXPLOITATION WITH APPROVAL ===
        elif name == "match_exploits":
            target = arguments.get("target")
            scan_results = arguments.get("scan_results")

            try:
                sys.path.insert(0, str(Path(__file__).parent.parent / "exploits"))
                from exploit_manager import ExploitManager

                em = ExploitManager()
                matches = em.match_exploits(scan_results)

                if not matches:
                    return [TextContent(
                        type="text",
                        text=f"No exploits matched for target {target}. Scan may not have detected vulnerable services."
                    )]

                # Format matched exploits
                result_text = f"🎯 Found {len(matches)} potential exploit(s) for {target}:\n\n"

                for i, match in enumerate(matches, 1):
                    risk_emoji = {"low": "🟢", "medium": "🟡", "high": "🔴", "critical": "🟣"}.get(
                        match.signature.risk_level, "⚪"
                    )

                    result_text += f"{i}. {risk_emoji} {match.signature.name}\n"
                    result_text += f"   ID: {match.signature.exploit_id}\n"
                    result_text += f"   CVE: {match.signature.cve or 'N/A'}\n"
                    result_text += f"   Target: {match.target}:{match.port}\n"
                    result_text += f"   Service: {match.service_info.get('product', 'Unknown')} {match.service_info.get('version', '')}\n"
                    result_text += f"   Confidence: {int(match.confidence * 100)}%\n"
                    result_text += f"   Risk Level: {match.signature.risk_level.upper()}\n"
                    result_text += f"   Description: {match.signature.description}\n"
                    result_text += f"   Requires Auth: {'Yes' if match.signature.requires_auth else 'No'}\n"
                    result_text += f"   Match Reason: {match.match_reason}\n\n"

                result_text += "\n⚠️  Use 'approve_exploit' to approve specific exploits before execution.\n"
                result_text += "⚠️  Or use 'execute_exploits' with interactive=True for approval prompts."

                return [TextContent(type="text", text=result_text)]

            except Exception as e:
                return [TextContent(
                    type="text",
                    text=f"❌ Error matching exploits: {str(e)}\n\n{traceback.format_exc()}"
                )]

        elif name == "approve_exploit":
            exploit_id = arguments.get("exploit_id")
            approved = arguments.get("approved")

            try:
                sys.path.insert(0, str(Path(__file__).parent.parent / "exploits"))
                from exploit_manager import ExploitManager

                em = ExploitManager()

                # Find exploit in matched list
                matched = [m for m in em.matched_exploits if m.signature.exploit_id == exploit_id]

                if not matched:
                    return [TextContent(
                        type="text",
                        text=f"❌ Exploit ID '{exploit_id}' not found in matched exploits. Run 'match_exploits' first."
                    )]

                match = matched[0]
                match.approved = approved

                status = "✅ APPROVED" if approved else "❌ REJECTED"
                return [TextContent(
                    type="text",
                    text=f"{status}: {match.signature.name} ({exploit_id})\n"
                         f"Target: {match.target}:{match.port}\n"
                         f"Risk: {match.signature.risk_level.upper()}\n\n"
                         f"Use 'execute_exploits' to run approved exploits."
                )]

            except Exception as e:
                return [TextContent(
                    type="text",
                    text=f"❌ Error approving exploit: {str(e)}"
                )]

        elif name == "execute_exploits":
            interactive = arguments.get("interactive", True)

            try:
                sys.path.insert(0, str(Path(__file__).parent.parent / "exploits"))
                from exploit_manager import ExploitManager

                em = ExploitManager()

                if not em.matched_exploits:
                    return [TextContent(
                        type="text",
                        text="❌ No exploits matched yet. Run 'match_exploits' first."
                    )]

                # Execute with or without interactive prompts
                summary = em.execute_approved_exploits(interactive=interactive)

                # Format results
                result_text = f"🚀 EXPLOIT EXECUTION SUMMARY\n"
                result_text += f"{'=' * 80}\n\n"
                result_text += f"Total Matched: {summary['total_matched']}\n"
                result_text += f"Approved: {summary['approved']}\n"
                result_text += f"Executed: {summary['executed']}\n"
                result_text += f"Successful: {summary['successful']}\n"
                result_text += f"Failed: {summary['failed']}\n"
                result_text += f"Flags Found: {summary['flags_found']}\n\n"

                if summary['results']:
                    result_text += "EXECUTION RESULTS:\n"
                    result_text += "-" * 80 + "\n\n"

                    for res in summary['results']:
                        status = "✓ SUCCESS" if res['success'] else "✗ FAILED"
                        result_text += f"{status}: {res['exploit_name']}\n"
                        result_text += f"  Target: {res['target']}:{res['port']}\n"
                        result_text += f"  Duration: {res['duration']:.2f}s\n"

                        if res.get('flags'):
                            result_text += f"  🚩 Flags: {', '.join(res['flags'])}\n"

                        if res.get('error'):
                            result_text += f"  Error: {res['error']}\n"

                        result_text += "\n"

                if summary['evidence_dir']:
                    result_text += f"\n📁 Evidence saved to: {summary['evidence_dir']}"

                return [TextContent(type="text", text=result_text)]

            except Exception as e:
                return [TextContent(
                    type="text",
                    text=f"❌ Error executing exploits: {str(e)}\n\n{traceback.format_exc()}"
                )]

        elif name == "get_exploit_report":
            try:
                sys.path.insert(0, str(Path(__file__).parent.parent / "exploits"))
                from exploit_manager import ExploitManager

                em = ExploitManager()
                report = em.get_exploit_report()

                return [TextContent(type="text", text=report)]

            except Exception as e:
                return [TextContent(
                    type="text",
                    text=f"❌ Error generating report: {str(e)}"
                )]

        elif name == "burp_scan":
            url = arguments["url"]
            scan_type_str = arguments.get("scan_type", "CrawlAndAudit")
            wait = arguments.get("wait", True)

            # Initialize BurpSuite integration if needed
            if burp is None:
                session_id = recorder.current_session['id'] if recorder.current_session else "default"
                evidence_dir = Path("evidence") / session_id
                burp = BurpSuiteIntegration(evidence_dir=evidence_dir)

            # Check if Burp is available
            if not burp.check_burp_available():
                return [TextContent(
                    type="text",
                    text=f"❌ BurpSuite REST API not available\n\n"
                         f"**To use BurpSuite integration:**\n\n"
                         f"1. Install BurpSuite Professional\n"
                         f"2. Install burp-rest-api:\n"
                         f"   ```bash\n"
                         f"   git clone https://github.com/vmware/burp-rest-api.git\n"
                         f"   cd burp-rest-api\n"
                         f"   ./gradlew build\n"
                         f"   ```\n\n"
                         f"3. Start burp-rest-api:\n"
                         f"   ```bash\n"
                         f"   java -jar build/libs/burp-rest-api.jar\n"
                         f"   ```\n\n"
                         f"4. Burp REST API should be running on http://127.0.0.1:1337\n\n"
                         f"**Alternatively**, you can use the built-in scanner tools:\n"
                         f"  • scan_vulnerabilities(target='{url}')\n"
                         f"  • crawl_website(url='{url}')"
                )]

            # Start scan
            scan_type = ScanType[scan_type_str.upper().replace("AND", "_")]
            scan_id = burp.scan_url(url, scan_type)

            if not scan_id:
                return [TextContent(
                    type="text",
                    text=f"❌ Failed to start BurpSuite scan\n\n"
                         f"Check that burp-rest-api is running and accessible."
                )]

            msg = f"✅ BurpSuite scan started!\n\n"
            msg += f"**Scan Details:**\n"
            msg += f"  • Target: {url}\n"
            msg += f"  • Scan ID: {scan_id}\n"
            msg += f"  • Scan Type: {scan_type_str}\n\n"

            if wait:
                msg += "⏳ Waiting for scan to complete (this may take several minutes)...\n\n"

                # Wait for scan
                success = burp.wait_for_scan(scan_id, timeout=1800, check_interval=10)

                if success:
                    # Get issues
                    issues = burp.get_issues(url_prefix=url)

                    msg += f"✅ Scan completed!\n\n"
                    msg += f"**Results:**\n"
                    msg += f"  • Issues found: {len(issues)}\n\n"

                    if issues:
                        # Group by severity
                        by_severity = {}
                        for issue in issues:
                            severity = issue.get('severity', 'Unknown')
                            by_severity[severity] = by_severity.get(severity, 0) + 1

                        msg += "**Issues by Severity:**\n"
                        for severity in ['High', 'Medium', 'Low', 'Information']:
                            if severity in by_severity:
                                msg += f"  • {severity}: {by_severity[severity]}\n"

                        msg += "\n💡 Use burp_get_issues() for detailed issue list\n"
                        msg += "💡 Use burp_generate_report() to generate HTML report"
                    else:
                        msg += "No vulnerabilities found."
                else:
                    msg += "❌ Scan failed or timed out\n\n"
                    msg += "Check Burp logs for details."
            else:
                msg += "**Scan started in background**\n\n"
                msg += f"💡 Use burp_get_issues() to check for results later"

            return [TextContent(type="text", text=msg)]

        elif name == "burp_get_issues":
            url_prefix = arguments.get("url_prefix")

            if burp is None:
                session_id = recorder.current_session['id'] if recorder.current_session else "default"
                evidence_dir = Path("evidence") / session_id
                burp = BurpSuiteIntegration(evidence_dir=evidence_dir)

            if not burp.check_burp_available():
                return [TextContent(
                    type="text",
                    text="❌ BurpSuite REST API not available. Use burp_status for setup instructions."
                )]

            issues = burp.get_issues(url_prefix=url_prefix)

            if not issues:
                return [TextContent(
                    type="text",
                    text="No issues found in BurpSuite scanner.\n\n"
                         "Either no scan has been run or no vulnerabilities were detected."
                )]

            msg = f"**BurpSuite Issues** ({len(issues)} total):\n\n"

            # Group by severity
            by_severity = {}
            for issue in issues:
                severity = issue.get('severity', 'Unknown')
                by_severity[severity] = by_severity.get(severity, 0) + 1

            msg += "**Summary by Severity:**\n"
            for severity in ['High', 'Medium', 'Low', 'Information']:
                if severity in by_severity:
                    msg += f"  • {severity}: {by_severity[severity]}\n"

            msg += "\n**Issue Details** (showing first 10):\n\n"

            for i, issue in enumerate(issues[:10], 1):
                msg += f"{i}. **[{issue.get('severity', 'Unknown')}]** {issue.get('issueName', 'Unknown Issue')}\n"
                msg += f"   • URL: {issue.get('url', 'N/A')}\n"

                if issue.get('issueDetail'):
                    detail = issue['issueDetail'][:100]
                    msg += f"   • Detail: {detail}...\n"

                msg += "\n"

            if len(issues) > 10:
                msg += f"... and {len(issues) - 10} more issues\n\n"

            msg += "💡 Use burp_generate_report() to generate full HTML report"

            return [TextContent(type="text", text=msg)]

        elif name == "burp_generate_report":
            report_type = arguments.get("report_type", "HTML")
            url_prefix = arguments.get("url_prefix")

            if burp is None:
                session_id = recorder.current_session['id'] if recorder.current_session else "default"
                evidence_dir = Path("evidence") / session_id
                burp = BurpSuiteIntegration(evidence_dir=evidence_dir)

            if not burp.check_burp_available():
                return [TextContent(
                    type="text",
                    text="❌ BurpSuite REST API not available. Use burp_status for setup instructions."
                )]

            report_content = burp.generate_report(report_type=report_type, url_prefix=url_prefix)

            if not report_content:
                return [TextContent(
                    type="text",
                    text="❌ Failed to generate report.\n\n"
                         "Possible reasons:\n"
                         "  • No scan results available\n"
                         "  • Burp REST API error"
                )]

            # Save report
            from datetime import datetime
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"burp_report_{timestamp}.{'html' if report_type == 'HTML' else 'xml'}"
            report_path = burp.save_report(report_content, filename)

            return [TextContent(
                type="text",
                text=f"✅ BurpSuite report generated!\n\n"
                     f"**Report Details:**\n"
                     f"  • Format: {report_type}\n"
                     f"  • File: {report_path}\n"
                     f"  • Size: {len(report_content)} bytes\n\n"
                     f"Open the report in your browser to view full details!"
            )]

        elif name == "burp_status":
            if burp is None:
                session_id = recorder.current_session['id'] if recorder.current_session else "default"
                evidence_dir = Path("evidence") / session_id
                burp = BurpSuiteIntegration(evidence_dir=evidence_dir)

            if burp.check_burp_available():
                return [TextContent(
                    type="text",
                    text=f"✅ BurpSuite REST API is **AVAILABLE**\n\n"
                         f"**Configuration:**\n"
                         f"  • API URL: {burp.config.api_url}\n"
                         f"  • Proxy Port: {burp.config.proxy_port}\n"
                         f"  • Evidence Dir: {burp.evidence_dir}\n\n"
                         f"**Available Operations:**\n"
                         f"  • burp_scan(url='http://target.com') - Start scan\n"
                         f"  • burp_get_issues() - Get scan results\n"
                         f"  • burp_generate_report() - Generate HTML report\n\n"
                         f"🎯 Ready to scan!"
                )]
            else:
                return [TextContent(
                    type="text",
                    text=f"❌ BurpSuite REST API is **NOT AVAILABLE**\n\n"
                         f"**Setup Instructions:**\n\n"
                         f"1. **Install BurpSuite Professional**\n"
                         f"   • Download from: https://portswigger.net/burp/pro\n\n"
                         f"2. **Install burp-rest-api:**\n"
                         f"   ```bash\n"
                         f"   git clone https://github.com/vmware/burp-rest-api.git\n"
                         f"   cd burp-rest-api\n"
                         f"   ./gradlew build\n"
                         f"   ```\n\n"
                         f"3. **Start burp-rest-api:**\n"
                         f"   ```bash\n"
                         f"   java -jar build/libs/burp-rest-api.jar\n"
                         f"   ```\n\n"
                         f"4. **Verify connection:**\n"
                         f"   • API should be running on http://127.0.0.1:1337\n"
                         f"   • Test: curl http://127.0.0.1:1337/burp/versions\n\n"
                         f"**Alternative:** Use built-in scanners:\n"
                         f"  • scan_vulnerabilities() - Run nuclei, wapiti, nikto\n"
                         f"  • crawl_website() - Discover attack surface"
                )]

        elif name == "wireshark_start_capture":
            from datetime import datetime

            interface = arguments["interface"]
            duration = arguments.get("duration")
            capture_filter = arguments.get("capture_filter")

            # Initialize Wireshark integration if needed
            if wireshark is None:
                session_id = recorder.current_session['id'] if recorder.current_session else datetime.now().strftime("%Y%m%d_%H%M%S")
                evidence_dir = Path("evidence") / session_id
                wireshark = WiresharkIntegration(evidence_dir=evidence_dir)

            # Check if tshark is available
            if not wireshark.tshark_path:
                return [TextContent(
                    type="text",
                    text=f"❌ tshark not found\n\n"
                         f"**Installation:**\n"
                         f"```bash\n"
                         f"sudo apt install -y tshark wireshark\n"
                         f"```\n\n"
                         f"**Grant permissions (required):**\n"
                         f"```bash\n"
                         f"sudo usermod -aG wireshark $USER\n"
                         f"sudo chmod +x /usr/bin/dumpcap\n"
                         f"```\n\n"
                         f"Log out and back in for permissions to take effect."
                )]

            # Create capture config
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = wireshark.evidence_dir / f"capture_{timestamp}.pcap"

            config = CaptureConfig(
                interface=interface,
                output_file=output_file,
                duration=duration,
                capture_filter=capture_filter
            )

            try:
                if duration:
                    # Synchronous capture with timeout
                    pcap_file = wireshark.start_capture(config)

                    return [TextContent(
                        type="text",
                        text=f"✅ Packet capture completed!\n\n"
                             f"**Capture Details:**\n"
                             f"  • Interface: {interface}\n"
                             f"  • Duration: {duration}s\n"
                             f"  • Filter: {capture_filter or 'none'}\n"
                             f"  • PCAP file: {pcap_file}\n\n"
                             f"💡 Use wireshark_analyze_pcap(pcap_file='{pcap_file}') to analyze!"
                    )]
                else:
                    # Background capture
                    pcap_file = wireshark.start_capture_background(config)

                    return [TextContent(
                        type="text",
                        text=f"✅ Packet capture started in background!\n\n"
                             f"**Capture Details:**\n"
                             f"  • Interface: {interface}\n"
                             f"  • Filter: {capture_filter or 'none'}\n"
                             f"  • Output: {pcap_file}\n\n"
                             f"**Capturing traffic...**\n\n"
                             f"💡 Use wireshark_stop_capture() to stop and save\n"
                             f"💡 Capture will continue until stopped manually"
                    )]

            except Exception as e:
                return [TextContent(
                    type="text",
                    text=f"❌ Capture failed: {str(e)}\n\n"
                         f"**Common issues:**\n"
                         f"  • Insufficient permissions (need root or wireshark group)\n"
                         f"  • Invalid interface name (use wireshark_list_interfaces)\n"
                         f"  • Interface not available\n"
                         f"  • tshark not installed"
                )]

        elif name == "wireshark_stop_capture":
            if wireshark is None or not wireshark.capture_process:
                return [TextContent(
                    type="text",
                    text="❌ No active capture running\n\n"
                         "Use wireshark_start_capture() to start a capture first."
                )]

            pcap_file = wireshark.stop_capture()

            if pcap_file:
                # Get file size
                file_size = pcap_file.stat().st_size if pcap_file.exists() else 0

                return [TextContent(
                    type="text",
                    text=f"✅ Capture stopped!\n\n"
                         f"**PCAP File:**\n"
                         f"  • File: {pcap_file}\n"
                         f"  • Size: {file_size:,} bytes\n\n"
                         f"💡 Use wireshark_analyze_pcap(pcap_file='{pcap_file}') to analyze captured traffic!"
                )]
            else:
                return [TextContent(
                    type="text",
                    text="❌ Failed to stop capture\n\n"
                         "The capture may have already stopped or encountered an error."
                )]

        elif name == "wireshark_analyze_pcap":
            from datetime import datetime

            pcap_file = Path(arguments["pcap_file"])
            display_filter = arguments.get("display_filter")

            # Initialize Wireshark if needed
            if wireshark is None:
                session_id = recorder.current_session['id'] if recorder.current_session else datetime.now().strftime("%Y%m%d_%H%M%S")
                evidence_dir = Path("evidence") / session_id
                wireshark = WiresharkIntegration(evidence_dir=evidence_dir)

            if not pcap_file.exists():
                return [TextContent(
                    type="text",
                    text=f"❌ PCAP file not found: {pcap_file}\n\n"
                         f"Make sure the file path is correct."
                )]

            try:
                # Analyze PCAP
                analysis = wireshark.analyze_pcap(pcap_file, display_filter=display_filter)

                msg = f"📊 **PCAP Analysis Results**\n\n"
                msg += f"**File:** {pcap_file}\n"
                msg += f"**Filter:** {display_filter or 'none'}\n\n"

                # Packet count
                msg += f"**Packets:** {analysis['packet_count']:,}\n\n"

                # Protocols
                if analysis.get('protocols'):
                    msg += "**Protocol Hierarchy:**\n"
                    for proto, count in sorted(analysis['protocols'].items(), key=lambda x: x[1], reverse=True)[:10]:
                        msg += f"  • {proto}: {count:,} packets\n"
                    msg += "\n"

                # HTTP requests
                if analysis.get('http_requests'):
                    msg += f"**HTTP Requests:** {len(analysis['http_requests'])}\n"
                    for req in analysis['http_requests'][:5]:
                        msg += f"  • {req.get('method', 'GET')} {req.get('host', 'unknown')}{req.get('uri', '/')}\n"
                    if len(analysis['http_requests']) > 5:
                        msg += f"  ... and {len(analysis['http_requests']) - 5} more\n"
                    msg += "\n"

                # Credentials
                if analysis.get('credentials'):
                    msg += f"**🔑 Credentials Found:** {len(analysis['credentials'])}\n"
                    for cred in analysis['credentials'][:10]:
                        msg += f"  • [{cred['protocol']}] {cred['username']} : {cred['password']}\n"
                    if len(analysis['credentials']) > 10:
                        msg += f"  ... and {len(analysis['credentials']) - 10} more\n"
                    msg += "\n"

                # Conversations
                if analysis.get('conversations'):
                    msg += f"**Top Conversations:**\n"
                    for conv in analysis['conversations'][:5]:
                        msg += f"  • {conv}\n"
                    msg += "\n"

                # Export info
                msg += f"**Analysis exported to:**\n"
                msg += f"  • {wireshark.evidence_dir}/pcap_analysis.json\n\n"
                msg += "💡 Open the PCAP file in Wireshark GUI for detailed inspection!"

                return [TextContent(type="text", text=msg)]

            except Exception as e:
                return [TextContent(
                    type="text",
                    text=f"❌ Analysis failed: {str(e)}\n\n"
                         f"Make sure tshark is installed and the PCAP file is valid."
                )]

        elif name == "wireshark_list_interfaces":
            from datetime import datetime

            # Initialize Wireshark if needed
            if wireshark is None:
                session_id = recorder.current_session['id'] if recorder.current_session else datetime.now().strftime("%Y%m%d_%H%M%S")
                evidence_dir = Path("evidence") / session_id
                wireshark = WiresharkIntegration(evidence_dir=evidence_dir)

            interfaces = wireshark.list_interfaces()

            if not interfaces:
                return [TextContent(
                    type="text",
                    text="❌ No network interfaces found or tshark not available\n\n"
                         f"Make sure tshark is installed and you have permissions."
                )]

            msg = f"**Available Network Interfaces** ({len(interfaces)}):\n\n"

            for iface in interfaces:
                msg += f"**{iface['name']}**\n"
                if iface.get('description'):
                    msg += f"  Description: {iface['description']}\n"
                msg += "\n"

            msg += "💡 Use wireshark_start_capture(interface='<name>') to start capturing!\n"
            msg += "💡 Use 'any' to capture on all interfaces"

            return [TextContent(type="text", text=msg)]

        elif name == "parallel_scan":
            import asyncio
            from datetime import datetime

            target = arguments["target"]
            include_web = arguments.get("include_web", True)
            web_url = arguments.get("web_url")

            # Get session ID
            session_id = recorder.current_session['id'] if recorder.current_session else datetime.now().strftime("%Y%m%d_%H%M%S")
            evidence_dir = Path("evidence") / session_id
            evidence_dir.mkdir(parents=True, exist_ok=True)

            # Import parallel scanner
            sys.path.append(str(Path(__file__).parent.parent / "scanner"))
            from parallel_scanner import ParallelScanner

            # Create scanner
            scanner = ParallelScanner(target, str(evidence_dir))

            # Record this in workflow if recording
            if recorder.current_session:
                recorder.record_command(
                    f"parallel_scan target={target} include_web={include_web}",
                    {"stdout": "Starting parallel scan...", "stderr": "", "exit_code": 0, "duration": 0}
                )

            msg = f"🔍 **Parallel Penetration Test** - {target}\n\n"
            msg += f"**Configuration:**\n"
            msg += f"  • Target: {target}\n"
            msg += f"  • Evidence: {evidence_dir}\n"
            msg += f"  • Available tools: {', '.join(scanner.available_tools)}\n\n"

            try:
                # Phase 1: Port scanning cluster
                msg += "**Phase 1:** Port Scanning (rustscan + naabu + masscan)...\n"

                async def run_port_scan():
                    results = await scanner.port_scan_cluster()
                    ports = scanner._parse_port_results(results)

                    # Service detection
                    if ports:
                        await scanner.service_detection(list(ports))

                    return ports

                discovered_ports = asyncio.run(run_port_scan())

                msg += f"  ✅ Discovered {len(discovered_ports)} open ports: {sorted(list(discovered_ports))}\n\n"

                # Phase 2: Web fuzzing if requested
                web_fuzz_results = {}
                directories = []
                if include_web:
                    # Determine web URL
                    if not web_url:
                        # Auto-detect from discovered ports
                        web_ports = [80, 443, 8080, 8443, 3000, 5000, 8000, 8888]
                        for port in discovered_ports:
                            if port in web_ports:
                                protocol = "https" if port in [443, 8443] else "http"
                                web_url = f"{protocol}://{target}:{port}" if port not in [80, 443] else f"{protocol}://{target}"
                                break

                    if web_url:
                        msg += f"**Phase 2:** Web Fuzzing (ffuf + gobuster + feroxbuster)...\n"
                        msg += f"  • Target URL: {web_url}\n"

                        async def run_web_fuzz():
                            results = await scanner.web_fuzzing_cluster(web_url)
                            dirs = scanner._parse_directory_results(results)
                            return results, dirs

                        web_fuzz_results, directories = asyncio.run(run_web_fuzz())

                        msg += f"  ✅ Discovered {len(directories)} directories\n\n"
                    else:
                        msg += f"**Phase 2:** Web Fuzzing - Skipped (no web services detected)\n\n"

                # Summary
                msg += "**Scan Complete!**\n\n"
                msg += f"**Results Summary:**\n"
                msg += f"  • Open ports: {len(discovered_ports)}\n"
                msg += f"  • Directories: {len(directories) if include_web else 0}\n"
                msg += f"  • Evidence: {evidence_dir}\n\n"

                msg += f"**Evidence Files:**\n"
                evidence_files = list(evidence_dir.glob("*"))
                for f in sorted(evidence_files)[:10]:
                    msg += f"  • {f.name}\n"
                if len(evidence_files) > 10:
                    msg += f"  ... and {len(evidence_files) - 10} more files\n"

                msg += f"\n💡 Performance: 2-5x faster than linear scanning!\n"
                msg += f"💡 Use save_workflow() to record this for future replay"

                return [TextContent(type="text", text=msg)]

            except Exception as e:
                return [TextContent(
                    type="text",
                    text=f"❌ Parallel scan failed: {str(e)}\n\n"
                         f"**Possible issues:**\n"
                         f"  • Required tools not installed (rustscan, naabu, masscan, ffuf, gobuster)\n"
                         f"  • Permission issues (some tools need sudo)\n"
                         f"  • Network connectivity issues\n\n"
                         f"**Evidence:** {evidence_dir}\n"
                         f"Check evidence files for partial results."
                )]

        elif name == "asvs_scan":
            from datetime import datetime

            url = arguments["url"]
            level = arguments.get("level", 2)
            enable_screenshots = arguments.get("enable_screenshots", False)

            # Get session ID
            session_id = recorder.current_session['id'] if recorder.current_session else datetime.now().strftime("%Y%m%d_%H%M%S")
            evidence_dir = Path("evidence") / session_id
            evidence_dir.mkdir(parents=True, exist_ok=True)

            # Import ASVS scanner
            sys.path.append(str(Path(__file__).parent.parent / "scanner"))
            from owasp_asvs_5_scanner import OWASPASVS5Scanner

            # Record this in workflow if recording
            if recorder.current_session:
                recorder.record_command(
                    f"asvs_scan url={url} level={level}",
                    {"stdout": "Starting ASVS 5.0 scan...", "stderr": "", "exit_code": 0, "duration": 0}
                )

            msg = f"🔍 **OWASP ASVS 5.0 Compliance Scan**\n\n"
            msg += f"**Configuration:**\n"
            msg += f"  • Target: {url}\n"
            msg += f"  • Verification Level: L{level}\n"
            msg += f"  • Screenshots: {'Enabled' if enable_screenshots else 'Disabled'}\n"
            msg += f"  • Evidence: {evidence_dir}\n\n"

            try:
                # Create scanner
                scanner = OWASPASVS5Scanner(
                    base_url=url,
                    evidence_dir=str(evidence_dir),
                    verification_level=level,
                    enable_screenshots=enable_screenshots
                )

                msg += "**Running ASVS 5.0 Tests** (345 requirements across 17 chapters)...\n\n"

                # Run scan
                results = scanner.run_full_scan()

                # Generate summary
                total_tests = results['summary']['total_tests']
                passed = results['summary']['passed']
                failed = results['summary']['failed']
                not_applicable = results['summary']['not_applicable']

                msg += f"**Test Results:**\n"
                msg += f"  • Total Tests: {total_tests}\n"
                msg += f"  • ✅ Passed: {passed}\n"
                msg += f"  • ❌ Failed: {failed}\n"
                msg += f"  • ⏭️ Not Applicable: {not_applicable}\n"
                msg += f"  • Compliance Rate: {results['summary']['compliance_percentage']:.1f}%\n\n"

                # Show failures by chapter
                if results['summary']['failures_by_chapter']:
                    msg += f"**Failures by Chapter:**\n"
                    for chapter, count in sorted(results['summary']['failures_by_chapter'].items(),
                                                key=lambda x: x[1], reverse=True)[:5]:
                        msg += f"  • {chapter}: {count} failures\n"
                    msg += "\n"

                # Export CSV
                msg += "**Exporting CSV Report...**\n"

                # Import CSV exporter
                sys.path.append(str(Path(__file__).parent.parent / "reporting"))
                from asvs_5_csv_exporter import ASVS5CSVExporter

                results_file = evidence_dir / "owasp_asvs_5.0_results.json"
                exporter = ASVS5CSVExporter(results_file)
                csv_path = exporter.export_to_csv()
                checklist_path = exporter.export_checklist()

                msg += f"  ✅ CSV Report: {csv_path}\n"
                msg += f"  ✅ Checklist: {checklist_path}\n\n"

                msg += f"**Evidence Location:**\n"
                msg += f"  • JSON Results: {results_file}\n"
                msg += f"  • CSV Report: {csv_path}\n"
                msg += f"  • Checklist: {checklist_path}\n"
                if enable_screenshots:
                    msg += f"  • Screenshots: {evidence_dir}/screenshots/\n"

                msg += f"\n💡 ASVS 5.0 compliance scan complete!\n"
                msg += f"💡 Open CSV report in Excel/LibreOffice for detailed analysis\n"
                msg += f"💡 Use checklist for manual verification tasks"

                return [TextContent(type="text", text=msg)]

            except Exception as e:
                return [TextContent(
                    type="text",
                    text=f"❌ ASVS scan failed: {str(e)}\n\n"
                         f"**Possible issues:**\n"
                         f"  • Target URL not accessible\n"
                         f"  • Missing dependencies (requests, beautifulsoup4, selenium)\n"
                         f"  • Invalid verification level\n\n"
                         f"**Evidence:** {evidence_dir}\n"
                         f"Check evidence files for partial results."
                )]

        elif name == "auto_exploit":
            from datetime import datetime

            findings = arguments["findings"]
            lhost = arguments.get("lhost")
            lport = arguments.get("lport", 4444)

            # Get session ID
            session_id = recorder.current_session['id'] if recorder.current_session else datetime.now().strftime("%Y%m%d_%H%M%S")
            evidence_dir = Path("evidence") / session_id
            evidence_dir.mkdir(parents=True, exist_ok=True)

            # Import auto exploit
            sys.path.append(str(Path(__file__).parent.parent / "exploits"))
            from auto_exploit import AutoExploit

            # Record this in workflow if recording
            if recorder.current_session:
                recorder.record_command(
                    f"auto_exploit findings={len(findings)} lhost={lhost}",
                    {"stdout": "Starting auto exploitation...", "stderr": "", "exit_code": 0, "duration": 0}
                )

            msg = f"🎯 **Automatic Exploitation Engine**\n\n"
            msg += f"**Configuration:**\n"
            msg += f"  • Findings to exploit: {len(findings)}\n"
            msg += f"  • Evidence: {evidence_dir}\n"
            if lhost:
                msg += f"  • Reverse shell: {lhost}:{lport}\n"
            msg += "\n"

            try:
                # Create exploit engine
                exploit_engine = AutoExploit(str(evidence_dir), lhost=lhost, lport=lport)

                msg += "**Exploitation Progress:**\n\n"

                # Exploit each finding
                results = exploit_engine.exploit_all(findings)

                msg += f"**Exploitation Complete!**\n\n"
                msg += f"**Results Summary:**\n"
                msg += f"  • Total findings: {results['total_findings']}\n"
                msg += f"  • Successfully exploited: {results['exploited']}\n"
                msg += f"  • Failed exploitations: {results['failed']}\n"
                msg += f"  • 🚩 Flags captured: {results['flags_captured']}\n\n"

                # Get detailed summary
                summary = exploit_engine.get_summary()

                if summary['total_flags_captured'] > 0:
                    msg += f"**🚩 Captured Flags:**\n"
                    for flag in summary['flag_summary']['flag_list'][:10]:
                        msg += f"  • {flag}\n"

                    if len(summary['flag_summary']['flag_list']) > 10:
                        msg += f"  ... and {len(summary['flag_summary']['flag_list']) - 10} more flags\n"

                    msg += f"\n**Flags exported to:** {evidence_dir}/captured_flags.txt\n\n"

                # Show successful exploits
                if results['exploited'] > 0:
                    msg += f"**Successful Exploits:**\n"
                    for exploit in results['exploits']:
                        if exploit['success']:
                            vuln_type = exploit.get('exploit', 'unknown')
                            flags_found = len(exploit.get('flags', []))
                            msg += f"  • ✅ {vuln_type}: {flags_found} flags found\n"

                msg += f"\n**Evidence Location:**\n"
                msg += f"  • Exploitation log: {evidence_dir}/exploitation_log.json\n"
                msg += f"  • Captured flags: {evidence_dir}/captured_flags.txt\n"
                msg += f"  • Detections: {evidence_dir}/detections_*.json\n\n"

                msg += f"💡 Success rate: {summary['success_rate']:.1f}%\n"

                if results['flags_captured'] > 0:
                    msg += f"💡 **{results['flags_captured']} flags captured!** Check evidence directory for details."
                else:
                    msg += f"💡 No flags captured. Check exploitation_log.json for details."

                return [TextContent(type="text", text=msg)]

            except Exception as e:
                return [TextContent(
                    type="text",
                    text=f"❌ Auto exploitation failed: {str(e)}\n\n"
                         f"**Possible issues:**\n"
                         f"  • SQLMap not installed (sudo apt install sqlmap)\n"
                         f"  • Invalid vulnerability findings format\n"
                         f"  • Network connectivity issues\n"
                         f"  • Target not vulnerable\n\n"
                         f"**Evidence:** {evidence_dir}\n"
                         f"Check evidence files for partial results."
                )]

        elif name == "service_exploit":
            from datetime import datetime

            services = arguments["services"]
            username = arguments.get("username")
            password_list = arguments.get("password_list")
            lhost = arguments.get("lhost")
            lport = arguments.get("lport", 4444)

            # Get session ID
            session_id = recorder.current_session['id'] if recorder.current_session else datetime.now().strftime("%Y%m%d_%H%M%S")
            evidence_dir = Path("evidence") / session_id
            evidence_dir.mkdir(parents=True, exist_ok=True)

            # Import service exploiter
            sys.path.append(str(Path(__file__).parent.parent / "exploits"))
            from service_exploiter import ServiceExploiter

            # Record this in workflow if recording
            if recorder.current_session:
                recorder.record_command(
                    f"service_exploit services={len(services)}",
                    {"stdout": "Starting service exploitation...", "stderr": "", "exit_code": 0, "duration": 0}
                )

            msg = f"🎯 **Service Exploitation Engine**\n\n"
            msg += f"**Configuration:**\n"
            msg += f"  • Services to exploit: {len(services)}\n"
            msg += f"  • Evidence: {evidence_dir}\n"
            if username:
                msg += f"  • Username: {username}\n"
            if password_list:
                msg += f"  • Password list: {password_list}\n"
            if lhost:
                msg += f"  • Reverse shell: {lhost}:{lport}\n"
            msg += "\n"

            try:
                # Create service exploiter
                service_exploiter = ServiceExploiter(str(evidence_dir), lhost=lhost, lport=lport)

                msg += "**Exploitation Progress:**\n\n"

                # Exploit all services
                results = service_exploiter.exploit_all_services(services)

                msg += f"**Exploitation Complete!**\n\n"
                msg += f"**Results Summary:**\n"
                msg += f"  • Total services: {results['total_services']}\n"
                msg += f"  • Successfully exploited: {results['exploited']}\n"
                msg += f"  • 🔑 Credentials found: {results['credentials_found']}\n"
                msg += f"  • 🚩 Flags captured: {results['flags_captured']}\n\n"

                # Show successful exploits per service
                if results['exploited'] > 0:
                    msg += f"**Successful Exploits:**\n"
                    for result in results['results']:
                        if result['success']:
                            service = result.get('service', 'unknown')
                            target = result.get('host', result.get('target', 'unknown'))
                            port = result.get('port', 'N/A')
                            creds_count = len(result.get('credentials', []))
                            msg += f"  • ✅ {service} on {target}:{port} - {creds_count} credentials\n"

                            # Show first credential found
                            if result.get('credentials'):
                                first_cred = result['credentials'][0]
                                msg += f"       → {first_cred['username']}:{first_cred['password']}\n"

                # Show captured flags
                if results['flags_captured'] > 0:
                    msg += f"\n**🚩 Captured Flags:**\n"
                    flag_count = 0
                    for result in results['results']:
                        if result.get('flags'):
                            flags = result['flags'].get('flags', [])
                            for flag in flags[:3]:
                                msg += f"  • {flag}\n"
                                flag_count += 1
                            if len(flags) > 3:
                                msg += f"  ... and {len(flags) - 3} more flags from this service\n"

                msg += f"\n**Evidence Location:**\n"
                msg += f"  • Credentials: {evidence_dir}/credentials_*.json\n"
                msg += f"  • SSH shells: {evidence_dir}/ssh_shell_*.txt\n"
                msg += f"  • FTP listings: {evidence_dir}/ftp_list_*.txt\n"
                msg += f"  • SMB shares: {evidence_dir}/smb_shares_*.txt\n\n"

                if results['exploited'] > 0:
                    msg += f"💡 **{results['exploited']} services exploited!**\n"
                    if results['credentials_found'] > 0:
                        msg += f"💡 **{results['credentials_found']} credentials found!** Use them for further exploitation.\n"
                    if results['flags_captured'] > 0:
                        msg += f"💡 **{results['flags_captured']} flags captured!** Check evidence directory for details."
                else:
                    msg += f"💡 No services successfully exploited. Try different wordlists or manual exploitation."

                return [TextContent(type="text", text=msg)]

            except Exception as e:
                return [TextContent(
                    type="text",
                    text=f"❌ Service exploitation failed: {str(e)}\n\n"
                         f"**Possible issues:**\n"
                         f"  • Hydra not installed (sudo apt install hydra)\n"
                         f"  • Invalid service configuration\n"
                         f"  • Network connectivity issues\n"
                         f"  • Services not vulnerable to bruteforce\n\n"
                         f"**Evidence:** {evidence_dir}\n"
                         f"Check evidence files for partial results."
                )]

        elif name == "post_exploit":
            import paramiko
            from datetime import datetime

            host = arguments["host"]
            port = arguments.get("port", 22)
            username = arguments["username"]
            password = arguments["password"]
            run_linpeas = arguments.get("run_linpeas", True)
            attempt_privesc = arguments.get("attempt_privesc", True)

            # Get session ID
            session_id = recorder.current_session['id'] if recorder.current_session else datetime.now().strftime("%Y%m%d_%H%M%S")
            evidence_dir = Path("evidence") / session_id
            evidence_dir.mkdir(parents=True, exist_ok=True)

            # Record this in workflow if recording
            if recorder.current_session:
                recorder.record_command(
                    f"post_exploit {host}",
                    {"stdout": "Starting post-exploitation...", "stderr": "", "exit_code": 0, "duration": 0}
                )

            msg = f"🎯 **Post-Exploitation Engine**\n\n"
            msg += f"**Target:** {host}:{port}\n"
            msg += f"**User:** {username}\n"
            msg += f"**Evidence:** {evidence_dir}\n\n"

            try:
                # Get post-exploit instance
                post_exploit = get_post_exploit(str(evidence_dir))

                # Connect via SSH
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(host, port=port, username=username, password=password, timeout=15)

                msg += "✅ SSH connection established!\n\n"

                # 1. Stabilize shell
                msg += "**Step 1: Stabilizing shell...**\n"
                stab_result = post_exploit.stabilize_shell(client)
                if stab_result['success']:
                    msg += f"  ✅ Shell stabilized: {stab_result['shell_type']}\n\n"
                else:
                    msg += f"  ⚠️ Shell stabilization skipped\n\n"

                # 2. Find flags
                msg += "**Step 2: Searching for flags...**\n"
                flags_result = post_exploit.find_flags(client)
                if flags_result['success']:
                    total_flags = flags_result['total']
                    msg += f"  🚩 Found {total_flags} flags!\n"
                    for flag in flags_result['flags'][:5]:
                        msg += f"    • {flag['value']} (from {flag['source']})\n"
                    if total_flags > 5:
                        msg += f"    ... and {total_flags - 5} more flags\n"
                    msg += f"  📁 Saved to: {flags_result['output_file']}\n\n"
                else:
                    msg += f"  ⚠️ No flags found\n\n"

                # 3. Quick priv esc check
                msg += "**Step 3: Quick privilege escalation check...**\n"
                privesc_result = post_exploit.quick_privesc_check(client)
                if privesc_result['success']:
                    findings = privesc_result['findings']
                    msg += f"  ✅ Enumeration complete!\n"
                    if findings.get('sudo_rights'):
                        msg += f"    • Sudo rights: {findings['sudo_rights']}\n"
                    if findings.get('suid_binaries'):
                        msg += f"    • SUID binaries: {len(findings['suid_binaries'])} found\n"
                    if findings.get('capabilities'):
                        msg += f"    • Capabilities: {len(findings['capabilities'])} found\n"
                    if findings.get('docker_group'):
                        msg += f"    • Docker group: YES ⚠️\n"
                    if findings.get('lxd_group'):
                        msg += f"    • LXD group: YES ⚠️\n"
                    msg += "\n"

                # 4. Run LinPEAS if requested
                if run_linpeas:
                    msg += "**Step 4: Running LinPEAS...**\n"
                    msg += "  ⏳ This may take 5-10 minutes...\n"
                    linpeas_result = post_exploit.run_linpeas(client)
                    if linpeas_result['success']:
                        findings = linpeas_result['findings']
                        msg += f"  ✅ LinPEAS complete!\n"
                        msg += f"    • Privilege escalation vectors: {len(findings.get('priv_esc_vectors', []))}\n"
                        msg += f"    • SUID binaries: {len(findings.get('suid_binaries', []))}\n"
                        msg += f"    • Interesting files: {len(findings.get('interesting_files', []))}\n"
                        if findings.get('credentials_found'):
                            msg += f"    • 🔑 Credentials found: {len(findings['credentials_found'])}\n"
                        msg += f"  📁 Output: {linpeas_result['output_file']}\n\n"
                    else:
                        msg += f"  ⚠️ LinPEAS failed: {linpeas_result.get('error', 'Unknown error')}\n\n"

                # 5. Attempt automatic privilege escalation if requested
                if attempt_privesc:
                    msg += "**Step 5: Attempting automatic privilege escalation...**\n"

                    # Try methods in order of reliability
                    methods = ['sudo_nopasswd', 'capability', 'docker', 'suid_binary']
                    escalated = False

                    for method in methods:
                        msg += f"  🔍 Trying {method}...\n"
                        priv_result = post_exploit.attempt_privesc(client, method)
                        if priv_result['success']:
                            msg += f"  ✅ Privilege escalation successful via {method}!\n"
                            if priv_result.get('flags'):
                                msg += f"  🚩 Root flag captured!\n"
                                for flag in priv_result['flags'][:3]:
                                    msg += f"    • {flag}\n"
                            escalated = True
                            break

                    if not escalated:
                        msg += f"  ⚠️ Automatic privilege escalation failed\n"
                        msg += f"  💡 Try manual exploitation using LinPEAS findings\n"
                    msg += "\n"

                # Close connection
                client.close()

                msg += "**📊 Post-Exploitation Summary:**\n"
                msg += f"  • Flags found: {flags_result.get('total', 0)}\n"
                msg += f"  • Privilege escalation: {'Success ✅' if escalated else 'Manual required ⚠️'}\n"
                msg += f"  • Evidence location: {evidence_dir}\n\n"
                msg += "💡 Check evidence directory for detailed results and flag files!"

                return [TextContent(type="text", text=msg)]

            except paramiko.AuthenticationException:
                return [TextContent(
                    type="text",
                    text=f"❌ SSH authentication failed for {username}@{host}\n\n"
                         f"**Credentials invalid.** Verify username/password from service_exploit results."
                )]
            except paramiko.SSHException as e:
                return [TextContent(
                    type="text",
                    text=f"❌ SSH connection failed: {str(e)}\n\n"
                         f"**Possible issues:**\n"
                         f"  • Target not reachable\n"
                         f"  • SSH service not running on port {port}\n"
                         f"  • Firewall blocking connection"
                )]
            except Exception as e:
                return [TextContent(
                    type="text",
                    text=f"❌ Post-exploitation failed: {str(e)}\n\n"
                         f"**Evidence:** {evidence_dir}\n"
                         f"Check evidence files for partial results."
                )]

        elif name == "find_flags":
            import paramiko
            from datetime import datetime

            host = arguments["host"]
            port = arguments.get("port", 22)
            username = arguments["username"]
            password = arguments["password"]

            # Get session ID
            session_id = recorder.current_session['id'] if recorder.current_session else datetime.now().strftime("%Y%m%d_%H%M%S")
            evidence_dir = Path("evidence") / session_id
            evidence_dir.mkdir(parents=True, exist_ok=True)

            msg = f"🚩 **Flag Finder**\n\n"
            msg += f"**Target:** {host}:{port}\n"
            msg += f"**User:** {username}\n\n"

            try:
                # Get post-exploit instance
                post_exploit = get_post_exploit(str(evidence_dir))

                # Connect via SSH
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(host, port=port, username=username, password=password, timeout=15)

                msg += "✅ Connected!\n\n"
                msg += "**Searching for flags...**\n"
                msg += "  • Checking common locations (/root/root.txt, /home/*/user.txt)\n"
                msg += "  • Scanning all .txt files\n"
                msg += "  • Finding files with 'flag' in name\n\n"

                # Find flags
                flags_result = post_exploit.find_flags(client)
                client.close()

                if flags_result['success']:
                    total_flags = flags_result['total']
                    msg += f"✅ **Found {total_flags} flags!**\n\n"

                    for flag in flags_result['flags']:
                        msg += f"**Flag:** `{flag['value']}`\n"
                        msg += f"  • Source: {flag['source']}\n"
                        msg += f"  • Type: {flag['type']}\n"
                        if flag.get('location'):
                            msg += f"  • Location: {flag['location']}\n"
                        msg += "\n"

                    msg += f"📁 **Saved to:** {flags_result['output_file']}\n\n"
                    msg += "💡 All flags have been automatically saved to the evidence directory!"
                else:
                    msg += "❌ No flags found\n\n"
                    msg += "**Suggestions:**\n"
                    msg += "  • Try privilege escalation to access /root\n"
                    msg += "  • Search manually for flag locations\n"
                    msg += "  • Check web directories for flags"

                return [TextContent(type="text", text=msg)]

            except Exception as e:
                return [TextContent(
                    type="text",
                    text=f"❌ Flag finding failed: {str(e)}\n\n"
                         f"**Evidence:** {evidence_dir}"
                )]

        elif name == "run_linpeas":
            import paramiko
            from datetime import datetime

            host = arguments["host"]
            port = arguments.get("port", 22)
            username = arguments["username"]
            password = arguments["password"]
            download_dir = arguments.get("download_dir", "/tmp")

            # Get session ID
            session_id = recorder.current_session['id'] if recorder.current_session else datetime.now().strftime("%Y%m%d_%H%M%S")
            evidence_dir = Path("evidence") / session_id
            evidence_dir.mkdir(parents=True, exist_ok=True)

            msg = f"🔍 **LinPEAS Privilege Escalation Scanner**\n\n"
            msg += f"**Target:** {host}:{port}\n"
            msg += f"**User:** {username}\n\n"

            try:
                # Get post-exploit instance
                post_exploit = get_post_exploit(str(evidence_dir))

                # Connect via SSH
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(host, port=port, username=username, password=password, timeout=15)

                msg += "✅ Connected!\n\n"
                msg += "**Running LinPEAS...**\n"
                msg += "  • Downloading latest version from GitHub\n"
                msg += "  • Executing enumeration script\n"
                msg += "  • Parsing results for privilege escalation vectors\n"
                msg += "  ⏳ This may take 5-10 minutes...\n\n"

                # Run LinPEAS
                linpeas_result = post_exploit.run_linpeas(client, download_dir)
                client.close()

                if linpeas_result['success']:
                    findings = linpeas_result['findings']

                    msg += "✅ **LinPEAS Complete!**\n\n"

                    msg += "**📊 Findings Summary:**\n"
                    msg += f"  • Privilege escalation vectors: {len(findings.get('priv_esc_vectors', []))}\n"
                    msg += f"  • SUID binaries: {len(findings.get('suid_binaries', []))}\n"
                    msg += f"  • Writable files: {len(findings.get('writable_files', []))}\n"
                    msg += f"  • Interesting files: {len(findings.get('interesting_files', []))}\n"
                    if findings.get('sudo_rights'):
                        msg += f"  • 🔑 Sudo rights: {findings['sudo_rights']}\n"
                    if findings.get('credentials_found'):
                        msg += f"  • 🔑 Credentials found: {len(findings['credentials_found'])}\n"
                    msg += "\n"

                    # Show top privilege escalation vectors
                    if findings.get('priv_esc_vectors'):
                        msg += "**🎯 Top Privilege Escalation Vectors:**\n"
                        for vector in findings['priv_esc_vectors'][:5]:
                            msg += f"  • {vector}\n"
                        if len(findings['priv_esc_vectors']) > 5:
                            msg += f"  ... and {len(findings['priv_esc_vectors']) - 5} more vectors\n"
                        msg += "\n"

                    # Show interesting SUID binaries
                    if findings.get('suid_binaries'):
                        msg += "**⚠️ Interesting SUID Binaries:**\n"
                        for binary in findings['suid_binaries'][:10]:
                            msg += f"  • {binary}\n"
                        if len(findings['suid_binaries']) > 10:
                            msg += f"  ... and {len(findings['suid_binaries']) - 10} more\n"
                        msg += "\n"

                    msg += f"📁 **Full Output:** {linpeas_result['output_file']}\n"
                    msg += f"📁 **Parsed Findings:** {linpeas_result['json_file']}\n\n"
                    msg += "💡 Use attempt_privesc() with specific methods based on these findings!"
                else:
                    msg += f"❌ LinPEAS failed: {linpeas_result.get('error', 'Unknown error')}\n\n"
                    msg += "**Possible issues:**\n"
                    msg += "  • No internet connection on target (can't download LinPEAS)\n"
                    msg += "  • Insufficient permissions\n"
                    msg += "  • Execution timeout\n\n"
                    msg += "**Try alternative:** Use quick_privesc_check() for offline enumeration"

                return [TextContent(type="text", text=msg)]

            except Exception as e:
                return [TextContent(
                    type="text",
                    text=f"❌ LinPEAS execution failed: {str(e)}\n\n"
                         f"**Evidence:** {evidence_dir}"
                )]

        else:
            return [TextContent(
                type="text",
                text=f"Unknown tool: {name}"
            )]

    except Exception as e:
        return [TextContent(
            type="text",
            text=f"❌ Error: {str(e)}"
        )]


async def main():
    """Run the MCP server"""
    # Use stdin/stdout for MCP communication
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await app.run(
            read_stream,
            write_stream,
            app.create_initialization_options()
        )


if __name__ == "__main__":
    asyncio.run(main())
