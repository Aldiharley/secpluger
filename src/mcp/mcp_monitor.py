"""
SecPluger MCP Monitor
Monitors MCP-Kali-Server traffic and records workflows automatically
"""

import json
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
import logging
import re

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

try:
    import mss
    import mss.tools
    SCREENSHOT_AVAILABLE = True
except ImportError:
    SCREENSHOT_AVAILABLE = False
    logger.warning("Screenshot support not available. Install 'mss' package for screenshot capture.")


class WorkflowRecorder:
    """
    Records Claude's actions as a reusable workflow
    Runs in background while Claude Code works
    """

    def __init__(self, evidence_dir: str = "evidence"):
        self.evidence_dir = Path(evidence_dir)
        self.current_session = None
        self.workflows: Dict[str, Dict] = {}
        self.screenshot_enabled = SCREENSHOT_AVAILABLE
        self.auto_screenshot = True  # Automatically capture screenshots

    def start_session(self, target: str = None):
        """Start recording a new workflow session"""
        session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        if target:
            session_id += f"_{target.replace('/', '_').replace(':', '_')}"

        self.current_session = {
            'id': session_id,
            'started_at': datetime.now().isoformat(),
            'target': target,
            'nodes': [],
            'findings': [],
            'evidence_files': []
        }

        # Create evidence directory
        self.session_evidence_dir = self.evidence_dir / session_id
        self.session_evidence_dir.mkdir(parents=True, exist_ok=True)

        logger.info(f"Started workflow recording session: {session_id}")
        return session_id

    def record_command(self, command: str, output: Dict[str, Any]) -> str:
        """
        Record a command execution from MCP-Kali-Server

        Args:
            command: The shell command executed
            output: Dict with {stdout, stderr, exit_code, duration}

        Returns:
            node_id
        """
        if not self.current_session:
            self.start_session()

        node_id = str(len(self.current_session['nodes']) + 1)

        # Detect tool type from command
        tool_type = self._detect_tool_type(command)

        # Create node
        node = {
            'id': node_id,
            'type': tool_type,
            'command': command,
            'timestamp': datetime.now().isoformat(),
            'duration': output.get('duration', 0),
            'success': output.get('exit_code', 1) == 0,
            'output': {
                'stdout': output.get('stdout', ''),
                'stderr': output.get('stderr', ''),
                'exit_code': output.get('exit_code', -1)
            }
        }

        # Save evidence file
        evidence_file = self._save_evidence(node_id, tool_type, output)
        node['evidence_file'] = str(evidence_file)

        # Capture screenshot if enabled
        screenshot_file = None
        if self.auto_screenshot and self.screenshot_enabled:
            screenshot_file = self._capture_screenshot(node_id, tool_type)
            if screenshot_file:
                node['screenshot_file'] = str(screenshot_file)

        # Detect vulnerabilities
        findings = self._detect_vulnerabilities(tool_type, output)
        if findings:
            node['findings'] = findings
            self.current_session['findings'].extend(findings)

        self.current_session['nodes'].append(node)

        logger.info(f"Recorded node {node_id}: {tool_type} - {command[:50]}...")
        if screenshot_file:
            logger.info(f"  Screenshot: {screenshot_file.name}")

        return node_id

    def _detect_tool_type(self, command: str) -> str:
        """Detect tool type from command"""
        command_lower = command.lower()

        if 'nmap' in command_lower:
            return 'nmap'
        elif 'gobuster' in command_lower:
            return 'gobuster'
        elif 'sqlmap' in command_lower:
            return 'sqlmap'
        elif 'nuclei' in command_lower:
            return 'nuclei'
        elif 'nikto' in command_lower:
            return 'nikto'
        elif 'ffuf' in command_lower:
            return 'ffuf'
        elif 'hydra' in command_lower:
            return 'hydra'
        elif 'metasploit' in command_lower or 'msfconsole' in command_lower:
            return 'metasploit'
        elif 'curl' in command_lower:
            return 'curl'
        elif 'wget' in command_lower:
            return 'wget'
        else:
            return 'custom'

    def _save_evidence(self, node_id: str, tool_type: str, output: Dict) -> Path:
        """Save command output as evidence"""
        evidence_file = self.session_evidence_dir / f"{node_id.zfill(2)}_{tool_type}.txt"

        with open(evidence_file, 'w') as f:
            f.write(f"Tool: {tool_type}\n")
            f.write(f"Timestamp: {datetime.now().isoformat()}\n")
            f.write(f"Exit Code: {output.get('exit_code', -1)}\n")
            f.write(f"Duration: {output.get('duration', 0)}s\n")
            f.write("=" * 60 + "\n\n")
            f.write("STDOUT:\n")
            f.write(output.get('stdout', ''))
            f.write("\n\nSTDERR:\n")
            f.write(output.get('stderr', ''))

        self.current_session['evidence_files'].append(str(evidence_file))
        return evidence_file

    def _capture_screenshot(self, node_id: str, tool_type: str) -> Optional[Path]:
        """
        Capture screenshot of current screen

        Args:
            node_id: Node identifier
            tool_type: Type of tool being executed

        Returns:
            Path to screenshot file or None if capture failed
        """
        if not SCREENSHOT_AVAILABLE:
            return None

        try:
            screenshot_file = self.session_evidence_dir / f"{node_id.zfill(2)}_{tool_type}_screenshot.png"

            # Capture screenshot using mss
            with mss.mss() as sct:
                # Capture the primary monitor
                monitor = sct.monitors[1]  # 0 is all monitors, 1 is primary
                screenshot = sct.grab(monitor)

                # Save screenshot
                mss.tools.to_png(screenshot.rgb, screenshot.size, output=str(screenshot_file))

            logger.info(f"Screenshot captured: {screenshot_file.name}")
            return screenshot_file

        except Exception as e:
            logger.warning(f"Failed to capture screenshot: {e}")
            return None

    def capture_manual_screenshot(self, label: str = None) -> Optional[Path]:
        """
        Manually capture a screenshot with custom label

        Args:
            label: Custom label for the screenshot

        Returns:
            Path to screenshot file or None if capture failed
        """
        if not self.current_session:
            logger.warning("No active session for screenshot capture")
            return None

        if not SCREENSHOT_AVAILABLE:
            logger.warning("Screenshot support not available")
            return None

        try:
            timestamp = datetime.now().strftime("%H%M%S")
            label_str = f"_{label}" if label else ""
            screenshot_file = self.session_evidence_dir / f"screenshot_{timestamp}{label_str}.png"

            # Capture screenshot using mss
            with mss.mss() as sct:
                monitor = sct.monitors[1]
                screenshot = sct.grab(monitor)
                mss.tools.to_png(screenshot.rgb, screenshot.size, output=str(screenshot_file))

            # Add to session evidence
            if 'screenshots' not in self.current_session:
                self.current_session['screenshots'] = []

            self.current_session['screenshots'].append({
                'file': str(screenshot_file),
                'label': label,
                'timestamp': datetime.now().isoformat()
            })

            logger.info(f"Manual screenshot captured: {screenshot_file.name}")
            return screenshot_file

        except Exception as e:
            logger.error(f"Failed to capture manual screenshot: {e}")
            return None

    def _detect_vulnerabilities(self, tool_type: str, output: Dict) -> List[Dict]:
        """Auto-detect vulnerabilities from tool output"""
        findings = []
        stdout = output.get('stdout', '')

        if tool_type == 'sqlmap':
            # Detect SQL injection
            if 'vulnerable' in stdout.lower() or 'injectable' in stdout.lower():
                findings.append({
                    'type': 'SQL Injection',
                    'severity': 'CRITICAL',
                    'tool': 'sqlmap',
                    'description': 'SQL injection vulnerability detected',
                    'evidence': 'See sqlmap output for details'
                })

        elif tool_type == 'nmap':
            # Detect open ports
            open_ports = re.findall(r'(\d+)/tcp\s+open', stdout)
            if open_ports:
                for port in open_ports[:5]:  # Limit to first 5
                    findings.append({
                        'type': 'Open Port',
                        'severity': 'INFO',
                        'tool': 'nmap',
                        'port': int(port),
                        'description': f'Port {port} is open'
                    })

        elif tool_type == 'nuclei':
            # Detect nuclei findings
            if '[critical]' in stdout.lower():
                findings.append({
                    'type': 'Nuclei Finding',
                    'severity': 'CRITICAL',
                    'tool': 'nuclei',
                    'description': 'Critical vulnerability detected by Nuclei'
                })
            elif '[high]' in stdout.lower():
                findings.append({
                    'type': 'Nuclei Finding',
                    'severity': 'HIGH',
                    'tool': 'nuclei',
                    'description': 'High severity vulnerability detected'
                })

        elif tool_type == 'gobuster':
            # Detect interesting directories
            interesting_dirs = re.findall(r'Status: (200|301|302).*?(/\S+)', stdout)
            for status, path in interesting_dirs[:10]:  # Limit to first 10
                if any(keyword in path.lower() for keyword in ['admin', 'backup', 'config', 'upload']):
                    findings.append({
                        'type': 'Sensitive Directory',
                        'severity': 'MEDIUM',
                        'tool': 'gobuster',
                        'path': path,
                        'description': f'Potentially sensitive directory found: {path}'
                    })

        return findings

    def save_workflow(self, name: str = None) -> Path:
        """Save recorded workflow as JSON template"""
        if not self.current_session:
            raise ValueError("No active session to save")

        if not name:
            name = f"recorded_workflow_{self.current_session['id']}"

        # Build workflow template
        workflow = {
            'name': name,
            'auto_recorded': True,
            'recorded_at': self.current_session['started_at'],
            'original_target': self.current_session['target'],
            'description': f"Auto-recorded workflow with {len(self.current_session['nodes'])} steps",
            'nodes': [],
            'edges': []
        }

        # Convert recorded nodes to workflow nodes with variable substitution
        target = self.current_session['target']

        for i, node in enumerate(self.current_session['nodes']):
            # Replace actual target with {{TARGET}} variable
            command = node['command']
            if target:
                command = command.replace(target, '{{TARGET}}')

            workflow_node = {
                'id': node['id'],
                'type': node['type'],
                'data': {
                    'command': command
                },
                'metadata': {
                    'recorded_at': node['timestamp'],
                    'original_duration': node['duration'],
                    'success': node['success']
                }
            }

            if node.get('findings'):
                workflow_node['expected_findings'] = node['findings']

            workflow['nodes'].append(workflow_node)

            # Auto-connect sequential nodes
            if i > 0:
                workflow['edges'].append({
                    'from': str(i),
                    'to': str(i + 1)
                })

        # Save workflow JSON
        workflow_path = Path("workflows") / f"{name}.json"
        workflow_path.parent.mkdir(exist_ok=True)

        with open(workflow_path, 'w') as f:
            json.dump(workflow, f, indent=2)

        # Save execution summary
        summary_path = self.session_evidence_dir / "execution_summary.json"
        with open(summary_path, 'w') as f:
            json.dump({
                'session_id': self.current_session['id'],
                'workflow_name': name,
                'target': target,
                'total_nodes': len(self.current_session['nodes']),
                'total_findings': len(self.current_session['findings']),
                'evidence_files': self.current_session['evidence_files'],
                'workflow_file': str(workflow_path)
            }, f, indent=2)

        logger.info(f"Workflow saved: {workflow_path}")
        logger.info(f"Findings: {len(self.current_session['findings'])}")

        return workflow_path

    def create_branch(self, from_node_id: str, new_commands: List[str]) -> Path:
        """
        Create a workflow branch from a specific node

        Args:
            from_node_id: Node to branch from
            new_commands: New commands for the branch

        Returns:
            Path to new workflow file
        """
        if not self.current_session:
            raise ValueError("No active session")

        # Find the node to branch from
        branch_point = None
        for i, node in enumerate(self.current_session['nodes']):
            if node['id'] == from_node_id:
                branch_point = i
                break

        if branch_point is None:
            raise ValueError(f"Node {from_node_id} not found")

        # Create new workflow with nodes up to branch point
        branch_workflow = {
            'name': f"branch_from_node_{from_node_id}",
            'auto_recorded': True,
            'branched_from': self.current_session['id'],
            'branch_point': from_node_id,
            'recorded_at': datetime.now().isoformat(),
            'nodes': self.current_session['nodes'][:branch_point + 1],
            'edges': []
        }

        # Add new command nodes
        next_id = len(branch_workflow['nodes']) + 1
        for cmd in new_commands:
            branch_workflow['nodes'].append({
                'id': str(next_id),
                'type': self._detect_tool_type(cmd),
                'data': {'command': cmd},
                'branched': True
            })
            next_id += 1

        # Connect edges
        for i in range(len(branch_workflow['nodes']) - 1):
            branch_workflow['edges'].append({
                'from': str(i + 1),
                'to': str(i + 2)
            })

        # Save branch workflow
        branch_path = Path("workflows") / f"branch_{from_node_id}_{int(time.time())}.json"
        with open(branch_path, 'w') as f:
            json.dump(branch_workflow, f, indent=2)

        logger.info(f"Created workflow branch: {branch_path}")
        return branch_path


# Singleton instance
_recorder = None

def get_recorder() -> WorkflowRecorder:
    """Get the global workflow recorder instance"""
    global _recorder
    if _recorder is None:
        _recorder = WorkflowRecorder()
    return _recorder


if __name__ == "__main__":
    # Test the recorder
    recorder = WorkflowRecorder()

    # Simulate Claude running commands
    recorder.start_session(target="example.com")

    # Simulate nmap
    recorder.record_command(
        "nmap -sV example.com",
        {
            'stdout': '80/tcp open http\n443/tcp open https',
            'stderr': '',
            'exit_code': 0,
            'duration': 12.5
        }
    )

    # Simulate gobuster
    recorder.record_command(
        "gobuster dir -u http://example.com -w /usr/share/wordlists/dirb/common.txt",
        {
            'stdout': '/admin (Status: 200)\n/backup (Status: 301)',
            'stderr': '',
            'exit_code': 0,
            'duration': 45.2
        }
    )

    # Simulate sqlmap
    recorder.record_command(
        "sqlmap -u 'http://example.com/login.php?id=1' --batch",
        {
            'stdout': 'Parameter is vulnerable to SQL injection',
            'stderr': '',
            'exit_code': 0,
            'duration': 120.8
        }
    )

    # Save workflow
    workflow_path = recorder.save_workflow("example_pentest")
    print(f"\nWorkflow saved: {workflow_path}")
    print(f"Evidence: {recorder.session_evidence_dir}")
    print(f"Findings: {len(recorder.current_session['findings'])}")

    # Create a branch
    branch = recorder.create_branch("3", [
        "sqlmap -u 'http://example.com/login.php?id=1' --dump",
        "sqlmap -u 'http://example.com/login.php?id=1' --os-shell"
    ])
    print(f"\nBranch created: {branch}")
