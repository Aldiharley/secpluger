# SecPluger Quick Reference Card

## Setup Complete ✅

**Location**: `/home/aldi/project/secpluger-v2/`
**Virtual Env**: `venv/`
**Config**: `~/.claude/claude_config.json`

---

## ⚠️ IMPORTANT: Restart Claude Code First!

**You MUST restart Claude Code** for SecPluger to be available:

```bash
exit              # Exit current session
claude-code       # Start new session
```

---

## 📸 NEW: Automatic Screenshot Evidence

**SecPluger now captures screenshots automatically!**

- ✅ Every command execution is screenshotted
- ✅ Manual screenshots on demand
- ✅ Saved to evidence folder with descriptive names
- ✅ Perfect for pentest reports

See `SCREENSHOT_EVIDENCE.md` for full details.

---

## Basic Commands

### 1. Start Recording a Pentest

```
You: "Claude, I have authorization to pentest [target].
     Start recording and help me scan it."

Claude: [Calls start_recording, executes commands, records each one]
```

### 2. Save the Workflow

```
You: "Save this workflow as 'web_app_scan'"

Claude: [Calls save_workflow]
        Saved to: workflows/web_app_scan.json
```

### 3. Replay Workflow (Zero Tokens!)

```
You: "Replay web_app_scan workflow on new-target.com"

Claude: [Calls replay_workflow]
        Evidence: evidence/[timestamp]_new-target.com/
```

### 4. List Available Workflows

```
You: "What workflows do we have saved?"

Claude: [Calls list_workflows]
```

### 5. Create Workflow Branch

```
You: "At node 3, create a branch to try sqlmap dump"

Claude: [Calls create_branch]
        New workflow: workflows/branch_3_[timestamp].json
```

### 6. Capture Screenshot (NEW!)

```
You: "Capture a screenshot showing the SQL injection vulnerability"

Claude: [Calls capture_screenshot(label="sqli_vulnerability")]
        Screenshot: screenshot_154522_sqli_vulnerability.png
```

**Note**: Screenshots are also captured **automatically** on every command!

---

## File Locations

```
/home/aldi/project/secpluger-v2/
├── workflows/           # Saved workflow templates
│   └── *.json
├── evidence/           # All command outputs + screenshots
│   └── [timestamp]_[target]/
│       ├── 01_nmap.txt
│       ├── 01_nmap_screenshot.png          (NEW!)
│       ├── 02_gobuster.txt
│       ├── 02_gobuster_screenshot.png      (NEW!)
│       ├── screenshot_[time]_[label].png   (NEW!)
│       └── execution_summary.json
└── reports/            # Generated HTML reports
    └── *.html
```

---

## Manual Operations (Without Claude)

### Replay Workflow via Python

```bash
cd /home/aldi/project/secpluger-v2

./venv/bin/python3 -c "
from src.engine.workflow_engine import WorkflowEngine
engine = WorkflowEngine()
engine.load_workflow('workflows/web_app_scan.json')
result = engine.execute(target='new-target.com')
print(f'Evidence: {result[\"evidence_path\"]}')
"
```

### Launch GUI

```bash
cd /home/aldi/project/secpluger-v2
./venv/bin/python3 src/main.py
```

### Test MCP Server

```bash
cd /home/aldi/project/secpluger-v2
./venv/bin/python3 src/mcp/secpluger_mcp_server.py
# Ctrl+C to exit
```

---

## Workflow Economics

| Operation | First Time | Replay |
|-----------|------------|--------|
| **Method** | Claude + Recording | Direct execution |
| **Token Cost** | ~3000-5000 | ~15 (just asking) |
| **Time** | Interactive | Automated |
| **Evidence** | ✅ Saved | ✅ Saved |
| **Quality** | AI-guided | Consistent |

**Savings**: ~99% token reduction on repeated pentests!

---

## Example Workflow: Web App Pentest

### First Time (With Claude)

```
You: "Claude, I have authorization to pentest example.com.
     Start recording and run a web app pentest."

Claude: "Starting recording..."
        [start_recording(target="example.com")]

        "Running nmap scan..."
        [execute: nmap -sV example.com]
        [record_command(...)]

        "Found web server. Enumerating directories..."
        [execute: gobuster dir -u http://example.com ...]
        [record_command(...)]

        "Testing for SQLi..."
        [execute: sqlmap -u http://example.com/login.php?id=1]
        [record_command(...)]

You: "Save this as web_app_pentest"

Claude: [save_workflow(name="web_app_pentest")]
        "✅ Saved! 3 nodes, 2 findings"
```

### Next Time (Without Claude Tokens)

```python
# Just run this script:
from src.engine.workflow_engine import WorkflowEngine

targets = ["site1.com", "site2.com", "site3.com"]

for target in targets:
    engine = WorkflowEngine()
    engine.load_workflow("workflows/web_app_pentest.json")
    result = engine.execute(target=target)
    print(f"{target}: {result['nodes_completed']} completed")
```

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| **SecPluger not in Claude** | Restart Claude Code |
| **Import errors** | Check venv: `./venv/bin/pip list` |
| **No workflows folder** | `mkdir -p workflows evidence reports` |
| **MCP won't start** | Test: `./venv/bin/python3 src/mcp/secpluger_mcp_server.py` |
| **Wrong Python** | Use: `./venv/bin/python3` not `python3` |

---

## Key Concepts

**Workflow Recording**: SecPluger monitors MCP commands from Claude and saves them as reusable workflows

**Evidence Collection**: Every command output is automatically saved to organized folders

**Vulnerability Detection**: Auto-detects findings from tool outputs (SQLi, XSS, open ports, etc.)

**Workflow Branching**: Create alternative paths from any node to try different exploitation techniques

**Token Savings**: First pentest uses tokens, replays cost almost zero

---

## Authorization Reminder

✅ **Always Get Permission First!**

SecPluger works with:
- Your own systems
- Authorized pentesting engagements
- CTF competitions
- Practice labs (HackTheBox, TryHackMe)

**Never** test systems without authorization!

---

## Getting Help

- **Full Guide**: `USAGE_WITH_CLAUDE.md`
- **Setup Info**: `SETUP_CLARIFICATION.md`
- **Installation**: `INSTALLATION_COMPLETE.md`
- **Architecture**: `NEW_DESIGN.md`

---

**Remember**: Restart Claude Code before using SecPluger! 🎉
