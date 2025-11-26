# SecPluger MCP - Quick Start Guide

## 🚀 Activate MCP Integration (Choose One)

### Option 1: Register with Claude CLI (Recommended)
```bash
cd /home/aldi/project/secpluger-v2
claude mcp add --scope project --transport stdio secpluger -- python3 src/mcp/secpluger_mcp_server.py
```

### Option 2: Already Done! (.mcp.json created)
The `.mcp.json` file is already in your project root. Just restart Claude Code!

---

## ✅ Verify Installation

```bash
# Check if registered
claude mcp list

# Should show:
# secpluger (stdio) - /home/aldi/project/secpluger-v2/src/mcp/secpluger_mcp_server.py

# In Claude Code chat, type:
/mcp
```

---

## 🎯 Quick Test Commands

Once integrated, try these in Claude Code:

### Test 1: Check Security Tools
```
Use SecPluger to check what security tools I have installed
```

### Test 2: Web Crawling
```
Use SecPluger to crawl http://example.com
```

### Test 3: Full Pentest (with recording)
```
Use SecPluger to pentest 192.168.1.100 and record the workflow
```

---

## 📋 Available Tools (19 Total)

### Workflow Tools
- start_recording
- record_command
- save_workflow
- replay_workflow
- create_branch

### Scanner Tools
- crawl_website
- fuzz_parameter
- scan_vulnerabilities
- full_security_test

### Proxy Tools
- start_proxy
- stop_proxy
- proxy_status

### Tool Management
- check_tools
- get_tool_info
- install_tool
- install_missing_tools

### Reporting
- generate_report
- list_findings
- update_finding

---

## 🐛 Troubleshooting

### MCP server not showing up?
```bash
# Restart Claude Code
exit
claude code

# Or manually check
python3 src/mcp/secpluger_mcp_server.py
```

### Import errors?
All fixed! But if you see errors:
```bash
# Verify __init__.py files
find src -name "__init__.py"

# Should show 6 files
```

---

## 📁 Files Created

- ✅ `.mcp.json` - MCP configuration
- ✅ `MCP_INTEGRATION_GUIDE.md` - Full guide
- ✅ `QUICKSTART_MCP.md` - This file
- ✅ All `__init__.py` files fixed

---

## 🎓 Learn More

See `MCP_INTEGRATION_GUIDE.md` for:
- Detailed troubleshooting
- Example usage scenarios
- Security notes
- File structure

---

**Status**: ✅ Ready to use!
**Next Step**: Run `claude mcp add` command or restart Claude Code
