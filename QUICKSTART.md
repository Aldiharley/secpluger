# SecPluger v2 - Quick Start Guide

## What is SecPluger v2?

SecPluger v2 is a **simplified Python application** that solves the gaps in MCP-Kali-Server:

✅ **Workflow Automation** - Save and reuse pentesting workflows
✅ **Visual GUI** - Simple tkinter interface (no web browser needed)
✅ **Evidence Collection** - Auto-save all tool outputs
✅ **Finding Database** - SQLite database with vulnerability tracking
✅ **Professional Reports** - Generate HTML reports
✅ **Multi-Target Support** - Run workflows against multiple targets
✅ **Conditional Logic** - If/else branching in workflows

## Installation

```bash
cd /home/aldi/project/secpluger-v2

# Install Python dependencies
pip3 install -r requirements.txt

# Run SecPluger
python3 src/main.py
```

## First Run

When you run SecPluger, you'll see a simple GUI with:

1. **Left Panel**: Workflow nodes list
2. **Right Panel**: Node configuration
3. **Bottom Panel**: Execution controls
4. **Output Log**: Real-time execution logs

## Create Your First Workflow

### Method 1: Using the GUI

1. Click "New Workflow"
2. Click "Add Node" to add a workflow step
3. Select node type (nmap, gobuster, sqlmap, etc.)
4. Configure node data in JSON format
5. Click "Update Node"
6. Repeat to add more nodes
7. Click "Save Workflow"

### Method 2: Create JSON Manually

Create `workflows/my_first_workflow.json`:

```json
{
  "name": "Basic Web Scan",
  "description": "Scan web application for vulnerabilities",
  "nodes": [
    {
      "id": "1",
      "type": "nmap",
      "data": {
        "target": "{{TARGET}}",
        "scan_type": "quick"
      }
    },
    {
      "id": "2",
      "type": "gobuster",
      "data": {
        "url": "http://{{TARGET}}",
        "wordlist": "/usr/share/wordlists/dirb/common.txt"
      }
    }
  ],
  "edges": [
    {"from": "1", "to": "2"}
  ]
}
```

Then open it in the GUI with "File > Open Workflow".

## Execute a Workflow

1. **Open or create a workflow**
2. **Enter target**: e.g., `example.com` or `192.168.1.1`
3. **Click "Execute Workflow"**
4. **Watch the output log** for real-time progress
5. **Check results** in the `evidence/` folder

## View Results

After execution, you'll find:

- **Evidence**: `evidence/YYYYMMDD_HHMMSS_target/`
  - Individual node outputs as `.txt` files
  - Execution summary as `execution_summary.json`

- **Report**: `reports/YYYYMMDD_HHMMSS_target_report.html`
  - Professional HTML report
  - Open in web browser

## Example Workflows

### Workflow 1: Quick Network Scan

```json
{
  "name": "Quick Network Scan",
  "nodes": [
    {
      "id": "1",
      "type": "nmap",
      "data": {"target": "{{TARGET}}", "scan_type": "quick"}
    }
  ],
  "edges": []
}
```

**Execute**: Enter `192.168.1.0/24` as target

### Workflow 2: Web Application Test

```json
{
  "name": "Web App Test",
  "nodes": [
    {
      "id": "1",
      "type": "nmap",
      "data": {"target": "{{TARGET}}", "ports": "80,443,8080"}
    },
    {
      "id": "2",
      "type": "gobuster",
      "data": {
        "url": "http://{{TARGET}}",
        "wordlist": "/usr/share/wordlists/dirb/common.txt",
        "extensions": "php,html,js"
      }
    },
    {
      "id": "3",
      "type": "nuclei",
      "data": {"target": "http://{{TARGET}}"}
    }
  ],
  "edges": [
    {"from": "1", "to": "2"},
    {"from": "2", "to": "3"}
  ]
}
```

**Execute**: Enter `example.com` as target

### Workflow 3: With Conditional Logic

```json
{
  "name": "Conditional SQL Test",
  "nodes": [
    {
      "id": "1",
      "type": "nmap",
      "data": {"target": "{{TARGET}}", "ports": "80,443"}
    },
    {
      "id": "2",
      "type": "conditional",
      "data": {
        "operator": "contains",
        "value": "open"
      }
    },
    {
      "id": "3",
      "type": "sqlmap",
      "data": {
        "url": "http://{{TARGET}}",
        "params": "--batch --level=2"
      }
    }
  ],
  "edges": [
    {"from": "1", "to": "2"},
    {"from": "2", "to": "3"}
  ]
}
```

This workflow only runs SQLmap if Nmap finds open ports.

## Available Node Types

| Node Type | Description | Example Data |
|-----------|-------------|--------------|
| `nmap` | Port scanner | `{"target": "{{TARGET}}", "scan_type": "quick"}` |
| `gobuster` | Directory bruteforce | `{"url": "http://{{TARGET}}", "wordlist": "/path/to/wordlist.txt"}` |
| `sqlmap` | SQL injection tester | `{"url": "http://{{TARGET}}", "params": "--batch"}` |
| `nuclei` | Vulnerability scanner | `{"target": "http://{{TARGET}}"}` |
| `conditional` | If/else logic | `{"operator": "contains", "value": "open"}` |
| `sleep` | Delay/wait | `{"duration": 5}` |

## Generate Reports

After workflow execution:

```bash
# Generate HTML report
python3 src/utils/report_gen.py evidence/20251023_120000_example.com

# Report saved to: reports/20251023_120000_example.com_report.html
```

Or the report is auto-generated during execution.

## Tips

1. **Use Variables**: Use `{{TARGET}}` in workflows to make them reusable
2. **Test Locally First**: Test on `127.0.0.1` or safe targets
3. **Check Evidence**: Review outputs in `evidence/` folder
4. **Save Workflows**: Build a library of reusable workflows
5. **Authorized Testing Only**: Only test systems you have permission to test

## Next Steps

1. ✅ Create more workflow templates
2. ✅ Integrate with MCP-Kali-Server (optional)
3. ✅ Add Claude integration via MCP
4. ✅ Build finding parser for vulnerability detection
5. ✅ Add PDF report generation

## Troubleshooting

**GUI doesn't start**:
```bash
# Install tkinter (if not installed)
sudo apt install python3-tk
```

**Tools not found**:
```bash
# Ensure you're on Kali Linux or install tools
sudo apt install nmap gobuster sqlmap nuclei
```

**Permission denied**:
```bash
# Some tools need sudo
sudo python3 src/main.py
```

**Import errors**:
```bash
# Reinstall dependencies
pip3 install -r requirements.txt --force-reinstall
```

---

**You now have a working pentesting workflow automation tool!** 🎉

This solves the 10 gaps we identified in MCP-Kali-Server + Claude Code.
