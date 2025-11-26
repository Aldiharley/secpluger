# SecPluger Tool Management

SecPluger now includes dynamic tool detection and management for **36 security tools** commonly used in Kali Linux penetration testing.

## Features

✅ **Automatic Tool Detection** - Scans system for 36+ security tools
✅ **Smart Installation** - Provides installation commands for missing tools
✅ **Category-based Organization** - Tools grouped by purpose
✅ **Priority Levels** - High/Medium/Low priority ranking
✅ **MCP Integration** - Claude Code can check and help install tools

## Tool Categories

- **Network Scanners**: nmap, masscan, zmap
- **Web Scanners**: nuclei, wapiti, nikto, whatweb, wafw00f
- **Enumeration**: gobuster, dirb, ffuf, feroxbuster, dirbuster
- **SQL Injection**: sqlmap
- **XSS Testing**: xsser
- **Exploitation**: metasploit-framework, searchsploit
- **Proxy/MITM**: mitmproxy, burpsuite
- **DNS/Recon**: sublist3r, amass, dnsenum, dnsrecon
- **SSL/TLS**: sslscan, sslyze, testssl
- **Password Attacks**: hydra, john, hashcat, medusa
- **Wireless**: aircrack-ng, reaver
- **CMS Testing**: wpscan, joomscan
- **Network Analysis**: wireshark, tcpdump

## Using via Claude Code

### Check All Tools

Ask Claude:
```
"Check what security tools are installed on my system"
```

Claude will use:
```python
check_tools()
```

### Check Specific Category

```
"Show me available web scanners"
```

Claude will use:
```python
check_tools(category="web_scanner")
```

### Check by Priority

```
"What high-priority tools am I missing?"
```

Claude will use:
```python
check_tools(priority="high")
```

### Get Tool Information

```
"Tell me about nikto"
```

Claude will use:
```python
get_tool_info(tool_name="nikto")
```

### Install Missing Tool

```
"I need to install metasploit-framework"
```

Claude will use:
```python
install_tool(tool_name="metasploit-framework")
```

Then Claude will help you run the installation command.

### Install Multiple Tools

```
"Install all missing high-priority web scanners"
```

Claude will use:
```python
install_missing_tools(category="web_scanner", priority="high")
```

## Using Directly in Python

```python
from src.utils.tool_manager import ToolManager

# Initialize
manager = ToolManager()

# Check all tools
print(manager.generate_report())

# Get available tools by category
web_scanners = manager.get_available_tools(category="web_scanner")
print(f"Web scanners: {web_scanners}")

# Get missing tools
missing = manager.get_missing_tools(priority="high")
print(f"Missing high-priority tools: {missing}")

# Get installation commands
install_cmds = manager.get_install_commands(missing)
print(install_cmds)

# Get tool info
info = manager.get_tool_info("nuclei")
print(f"Nuclei: {info['description']}")
print(f"Install: {info['install_cmd']}")
```

## Command Line

```bash
# Activate venv
source venv/bin/activate

# Check all tools
python3 src/utils/tool_manager.py

# This shows:
# - All 36 tools grouped by category
# - Installation status (✅/❌)
# - Priority level
# - Version info for installed tools
# - Summary statistics
```

## Available MCP Tools

### 1. `check_tools(category?, priority?)`

Check which security tools are installed.

**Parameters**:
- `category` (optional): Filter by category
  - `network_scanner`, `web_scanner`, `enumeration`, `sql_injection`, `xss`, `exploitation`, `proxy`, `recon`, `ssl`, `password`, `wireless`, `cms`, `network_analysis`
- `priority` (optional): Filter by priority
  - `high`, `medium`, `low`

**Returns**: List of tools with availability status

**Example**:
```python
# Check all tools
check_tools()

# Check only web scanners
check_tools(category="web_scanner")

# Check high-priority tools
check_tools(priority="high")

# Check high-priority web scanners
check_tools(category="web_scanner", priority="high")
```

### 2. `get_tool_info(tool_name)`

Get detailed information about a specific tool.

**Parameters**:
- `tool_name` (required): Name of the tool

**Returns**: Tool details including:
- Installation status
- Category
- Priority
- Description
- Version (if installed)
- Installation command (if not installed)

**Example**:
```python
get_tool_info(tool_name="sqlmap")
get_tool_info(tool_name="nuclei")
get_tool_info(tool_name="metasploit-framework")
```

### 3. `install_tool(tool_name)`

Get installation command for a specific tool.

**Parameters**:
- `tool_name` (required): Name of the tool to install

**Returns**: Installation command and guidance

**Example**:
```python
install_tool(tool_name="nikto")
install_tool(tool_name="hydra")
```

Claude will then help you run the command:
```bash
sudo apt install -y nikto
```

### 4. `install_missing_tools(category?, priority?)`

Get installation commands for all missing tools in a category or priority level.

**Parameters**:
- `category` (optional): Category to install tools for
- `priority` (optional): Priority level to install

**Returns**: List of missing tools and batch installation commands

**Example**:
```python
# Install all missing tools
install_missing_tools()

# Install missing web scanners
install_missing_tools(category="web_scanner")

# Install missing high-priority tools
install_missing_tools(priority="high")

# Install missing high-priority network scanners
install_missing_tools(category="network_scanner", priority="high")
```

## Tool Registry

All 36 tools in the registry with their metadata:

| Tool | Category | Priority | Description |
|------|----------|----------|-------------|
| nmap | network_scanner | high | Network port scanner |
| masscan | network_scanner | medium | Fast network port scanner |
| zmap | network_scanner | low | Internet-wide network scanner |
| nuclei | web_scanner | high | Fast vulnerability scanner with templates |
| wapiti | web_scanner | high | Web application vulnerability scanner |
| nikto | web_scanner | medium | Web server scanner |
| whatweb | web_scanner | medium | Web technology identifier |
| wafw00f | web_scanner | medium | Web Application Firewall detector |
| gobuster | enumeration | high | Directory/file bruteforcer |
| dirb | enumeration | medium | Web content scanner |
| ffuf | enumeration | high | Fast web fuzzer |
| feroxbuster | enumeration | medium | Fast directory bruteforcer |
| dirbuster | enumeration | low | Web application brute forcer |
| sqlmap | sql_injection | high | SQL injection tool |
| xsser | xss | medium | XSS testing tool |
| metasploit-framework | exploitation | high | Exploitation framework |
| searchsploit | exploitation | high | Exploit database search |
| mitmproxy | proxy | high | Interactive HTTPS proxy |
| burpsuite | proxy | high | Web application security testing |
| sublist3r | recon | medium | Subdomain enumeration |
| amass | recon | medium | Attack surface mapping |
| dnsenum | recon | medium | DNS enumeration |
| dnsrecon | recon | medium | DNS reconnaissance |
| sslscan | ssl | medium | SSL/TLS scanner |
| sslyze | ssl | medium | SSL/TLS configuration analyzer |
| testssl | ssl | medium | SSL/TLS testing |
| hydra | password | medium | Network logon cracker |
| john | password | medium | Password cracker |
| hashcat | password | medium | Advanced password recovery |
| medusa | password | low | Parallel login brute-forcer |
| aircrack-ng | wireless | medium | WiFi security suite |
| reaver | wireless | low | WPS attack tool |
| wpscan | cms | medium | WordPress security scanner |
| joomscan | cms | low | Joomla vulnerability scanner |
| wireshark | network_analysis | medium | Network protocol analyzer |
| tcpdump | network_analysis | medium | Packet analyzer |

## Example Workflows

### Workflow 1: Check Missing Tools Before Pentest

```
You: "I'm about to start a web application pentest. Do I have all the tools I need?"

Claude: Let me check your web scanning tools.
[calls: check_tools(category="web_scanner")]

Claude: "You're missing nikto. Would you like me to install it?"

You: "Yes, install it"

Claude: [calls: install_tool(tool_name="nikto")]
Claude: "I'll run this command for you:"
[runs: sudo apt install -y nikto]
```

### Workflow 2: Install All High-Priority Tools

```
You: "Install all high-priority tools I'm missing"

Claude: [calls: install_missing_tools(priority="high")]
Claude: "You're missing 2 high-priority tools:
  • metasploit-framework
  • nuclei

Would you like me to install them?"

You: "Yes"

Claude: [runs installation commands]
```

### Workflow 3: Category-Specific Setup

```
You: "Set up all password cracking tools"

Claude: [calls: check_tools(category="password")]
Claude: "You have hashcat and john installed.
Missing: hydra, medusa

Install missing tools?"

You: "Just hydra"

Claude: [calls: install_tool(tool_name="hydra")]
```

## Adding New Tools

To add a new tool to the registry, edit `src/utils/tool_manager.py`:

```python
TOOL_REGISTRY = {
    # ... existing tools ...

    'your_tool': {
        'category': 'category_name',
        'install_cmd': 'sudo apt install -y your_tool',
        'check_cmd': 'your_tool --version',
        'description': 'Tool description',
        'priority': 'high'  # or 'medium', 'low'
    },
}
```

Categories:
- `network_scanner`, `web_scanner`, `enumeration`, `sql_injection`, `xss`, `exploitation`, `proxy`, `recon`, `ssl`, `password`, `wireless`, `cms`, `network_analysis`

## Integration with Scanner Modules

The scanner modules (`web_crawler`, `fuzzer`, `vulnerability_scanner`) already use the tool manager internally to:

1. **Detect available tools** at initialization
2. **Report missing tools** in logs
3. **Gracefully handle missing tools** (skip if not available)
4. **Suggest installation** when tools are needed

Example from `vulnerability_scanner.py`:
```python
INFO:vulnerability_scanner:Available scanners:
INFO:vulnerability_scanner:  ✅ wapiti
INFO:vulnerability_scanner:  ✅ nuclei
INFO:vulnerability_scanner:  ✅ nikto
INFO:vulnerability_scanner:  ✅ sqlmap
```

## Benefits

1. **No Manual Tracking**: SecPluger automatically knows what's installed
2. **Claude Assistance**: Claude can help install missing tools
3. **Smart Recommendations**: Only suggests tools relevant to current task
4. **Priority-based**: Focuses on high-priority tools first
5. **Category Organization**: Easy to find tools for specific tasks
6. **Extensible**: Easy to add new tools to registry

## Troubleshooting

### Tool Detected as Missing But It's Installed

Check if tool is in PATH:
```bash
which tool_name
```

If not in PATH, add to PATH or update `check_cmd` in tool registry.

### Installation Fails

Common issues:
1. **Permissions**: Some tools need `sudo`
2. **Repositories**: Update repos first: `sudo apt update`
3. **Dependencies**: Some tools have dependencies
4. **Alternative Sources**: Some tools require pip or go install

### Tool Installed But Not Detected After Installation

Re-scan tools:
```python
from src.utils.tool_manager import get_tool_manager
manager = get_tool_manager()
manager._scan_tools()  # Re-scan
```

Or restart MCP server.

## Future Enhancements

- [ ] Auto-install with confirmation
- [ ] Version checking and updates
- [ ] Tool health checks
- [ ] Performance benchmarking
- [ ] Tool recommendations based on target
- [ ] Custom tool profiles
- [ ] Tool aliases and alternatives

---

**Now SecPluger is truly dynamic - it adapts to whatever tools you have installed and helps you get what's missing!** 🚀
