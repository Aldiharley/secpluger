"""
SecPluger Workflow Engine
Executes multi-step pentesting workflows with conditional logic
"""

import json
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class WorkflowNode:
    """Represents a single node in the workflow"""
    def __init__(self, node_id: str, node_type: str, data: Dict[str, Any]):
        self.id = node_id
        self.type = node_type
        self.data = data
        self.output = None
        self.error = None
        self.status = "pending"  # pending, running, completed, failed


class WorkflowEngine:
    """
    Core workflow execution engine
    Handles:
    - Loading workflows from JSON
    - Executing nodes in order
    - Conditional branching
    - Evidence collection
    - Error handling and retry logic
    """

    def __init__(self, evidence_dir: str = "evidence", use_mcp_server: bool = False):
        self.evidence_dir = Path(evidence_dir)
        self.use_mcp_server = use_mcp_server
        self.mcp_url = "http://localhost:5000"  # MCP-Kali-Server URL

        self.workflow = None
        self.nodes: Dict[str, WorkflowNode] = {}
        self.edges: List[Dict[str, str]] = []
        self.variables: Dict[str, Any] = {}
        self.execution_id = None
        self.evidence_path = None

    def load_workflow(self, workflow_path: str):
        """Load workflow from JSON file"""
        with open(workflow_path, 'r') as f:
            self.workflow = json.load(f)

        # Parse nodes
        self.nodes = {
            node['id']: WorkflowNode(node['id'], node['type'], node.get('data', {}))
            for node in self.workflow.get('nodes', [])
        }

        # Parse edges
        self.edges = self.workflow.get('edges', [])

        logger.info(f"Loaded workflow: {self.workflow.get('name')}")
        logger.info(f"Nodes: {len(self.nodes)}, Edges: {len(self.edges)}")

    def execute(self, **kwargs):
        """
        Execute the workflow
        kwargs: Variables to substitute in workflow (e.g., TARGET="example.com")
        """
        self.variables = kwargs
        self.execution_id = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Create evidence directory
        target = kwargs.get('target', 'unknown')
        self.evidence_path = self.evidence_dir / f"{self.execution_id}_{target}"
        self.evidence_path.mkdir(parents=True, exist_ok=True)

        logger.info(f"Starting execution: {self.execution_id}")
        logger.info(f"Variables: {self.variables}")
        logger.info(f"Evidence: {self.evidence_path}")

        # Get execution order (topological sort)
        execution_order = self._get_execution_order()

        # Execute nodes in order
        for node_id in execution_order:
            node = self.nodes[node_id]
            success = self._execute_node(node)

            if not success and not self.workflow.get('continue_on_error', False):
                logger.error(f"Workflow stopped due to error in node {node_id}")
                break

        logger.info(f"Workflow execution completed: {self.execution_id}")
        self._save_execution_summary()

        return {
            'execution_id': self.execution_id,
            'evidence_path': str(self.evidence_path),
            'nodes_completed': sum(1 for n in self.nodes.values() if n.status == 'completed'),
            'nodes_failed': sum(1 for n in self.nodes.values() if n.status == 'failed')
        }

    def _execute_node(self, node: WorkflowNode) -> bool:
        """Execute a single node"""
        logger.info(f"Executing node {node.id}: {node.type}")
        node.status = "running"

        try:
            # Substitute variables in node data
            node_data = self._substitute_variables(node.data)

            # Execute based on node type
            if node.type == "nmap":
                result = self._execute_nmap(node_data)
            elif node.type == "gobuster":
                result = self._execute_gobuster(node_data)
            elif node.type == "sqlmap":
                result = self._execute_sqlmap(node_data)
            elif node.type == "nuclei":
                result = self._execute_nuclei(node_data)
            elif node.type == "conditional":
                result = self._execute_conditional(node_data, node)
            elif node.type == "sleep":
                result = self._execute_sleep(node_data)
            else:
                # Generic command execution
                result = self._execute_command(node_data.get('command', ''))

            # Save output
            node.output = result
            node.status = "completed"

            # Save evidence
            self._save_evidence(node, result)

            logger.info(f"Node {node.id} completed successfully")
            return True

        except Exception as e:
            logger.error(f"Node {node.id} failed: {e}")
            node.error = str(e)
            node.status = "failed"

            # Retry logic
            retry_count = node.data.get('retry', 0)
            if retry_count > 0:
                logger.info(f"Retrying node {node.id} ({retry_count} attempts left)")
                node.data['retry'] = retry_count - 1
                time.sleep(2)
                return self._execute_node(node)

            return False

    def _execute_nmap(self, data: Dict) -> Dict:
        """Execute Nmap scan"""
        target = data.get('target', '')
        ports = data.get('ports', '1-1000')
        scan_type = data.get('scan_type', 'quick')

        # Build nmap command
        if scan_type == 'quick':
            cmd = f"nmap -T4 -F {target}"
        elif scan_type == 'full':
            cmd = f"nmap -T4 -p {ports} {target}"
        elif scan_type == 'stealth':
            cmd = f"nmap -sS -T2 -p {ports} {target}"
        else:
            cmd = f"nmap {target}"

        return self._execute_command(cmd)

    def _execute_gobuster(self, data: Dict) -> Dict:
        """Execute Gobuster directory brute force"""
        url = data.get('url', '')
        wordlist = data.get('wordlist', '/usr/share/wordlists/dirb/common.txt')
        extensions = data.get('extensions', '')

        cmd = f"gobuster dir -u {url} -w {wordlist}"
        if extensions:
            cmd += f" -x {extensions}"

        return self._execute_command(cmd)

    def _execute_sqlmap(self, data: Dict) -> Dict:
        """Execute SQLmap"""
        url = data.get('url', '')
        params = data.get('params', '--batch --random-agent')

        cmd = f"sqlmap -u '{url}' {params}"
        return self._execute_command(cmd)

    def _execute_nuclei(self, data: Dict) -> Dict:
        """Execute Nuclei vulnerability scanner"""
        target = data.get('target', '')
        templates = data.get('templates', '')

        cmd = f"nuclei -u {target}"
        if templates:
            cmd += f" -t {templates}"

        return self._execute_command(cmd)

    def _execute_conditional(self, data: Dict, node: WorkflowNode) -> Dict:
        """Execute conditional logic (if/else)"""
        condition = data.get('condition', '')
        operator = data.get('operator', 'contains')
        value = data.get('value', '')

        # Get input from previous node
        previous_output = self._get_previous_output(node)

        # Evaluate condition
        result = False
        if operator == 'contains':
            result = value in str(previous_output)
        elif operator == 'equals':
            result = str(previous_output) == value
        elif operator == 'regex':
            import re
            result = bool(re.search(value, str(previous_output)))

        return {
            'condition_met': result,
            'operator': operator,
            'value': value
        }

    def _execute_sleep(self, data: Dict) -> Dict:
        """Sleep/delay"""
        duration = data.get('duration', 1)
        time.sleep(duration)
        return {'slept': duration}

    def _execute_command(self, cmd: str, timeout: int = 300) -> Dict:
        """
        Execute shell command
        Returns: {stdout, stderr, exit_code, duration}
        """
        logger.info(f"Executing: {cmd}")
        start_time = time.time()

        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )

            duration = time.time() - start_time

            return {
                'stdout': result.stdout,
                'stderr': result.stderr,
                'exit_code': result.returncode,
                'duration': round(duration, 2),
                'success': result.returncode == 0
            }

        except subprocess.TimeoutExpired:
            return {
                'stdout': '',
                'stderr': f'Command timed out after {timeout} seconds',
                'exit_code': -1,
                'duration': timeout,
                'success': False
            }
        except Exception as e:
            return {
                'stdout': '',
                'stderr': str(e),
                'exit_code': -1,
                'duration': time.time() - start_time,
                'success': False
            }

    def _substitute_variables(self, data: Dict) -> Dict:
        """Substitute {{VARIABLE}} placeholders with actual values"""
        import json
        import re

        data_str = json.dumps(data)

        # Find all {{VAR}} patterns
        for var_name, var_value in self.variables.items():
            pattern = f"{{{{{var_name}}}}}"
            data_str = data_str.replace(pattern, str(var_value))

        return json.loads(data_str)

    def _get_execution_order(self) -> List[str]:
        """Determine node execution order using topological sort"""
        # Simple implementation: execute nodes in the order they appear
        # TODO: Implement proper topological sort for complex workflows
        return list(self.nodes.keys())

    def _get_previous_output(self, node: WorkflowNode) -> Any:
        """Get output from the previous node"""
        # Find incoming edges
        for edge in self.edges:
            if edge.get('to') == node.id:
                prev_node_id = edge.get('from')
                prev_node = self.nodes.get(prev_node_id)
                if prev_node and prev_node.output:
                    return prev_node.output
        return None

    def _save_evidence(self, node: WorkflowNode, result: Dict):
        """Save node output as evidence"""
        evidence_file = self.evidence_path / f"{node.id}_{node.type}.txt"

        with open(evidence_file, 'w') as f:
            f.write(f"Node: {node.id}\n")
            f.write(f"Type: {node.type}\n")
            f.write(f"Status: {node.status}\n")
            f.write(f"Timestamp: {datetime.now().isoformat()}\n")
            f.write(f"\n{'='*50}\n\n")

            if isinstance(result, dict):
                for key, value in result.items():
                    f.write(f"{key}:\n{value}\n\n")
            else:
                f.write(str(result))

        logger.info(f"Evidence saved: {evidence_file}")

    def _save_execution_summary(self):
        """Save workflow execution summary"""
        summary_file = self.evidence_path / "execution_summary.json"

        summary = {
            'execution_id': self.execution_id,
            'workflow_name': self.workflow.get('name'),
            'timestamp': datetime.now().isoformat(),
            'variables': self.variables,
            'nodes': [
                {
                    'id': node.id,
                    'type': node.type,
                    'status': node.status,
                    'error': node.error
                }
                for node in self.nodes.values()
            ],
            'evidence_path': str(self.evidence_path)
        }

        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2)

        logger.info(f"Execution summary saved: {summary_file}")


if __name__ == "__main__":
    # Test the engine
    engine = WorkflowEngine()

    # Create a simple test workflow
    test_workflow = {
        "name": "Test Workflow",
        "nodes": [
            {"id": "1", "type": "nmap", "data": {"target": "{{TARGET}}", "scan_type": "quick"}},
            {"id": "2", "type": "sleep", "data": {"duration": 2}}
        ],
        "edges": [{"from": "1", "to": "2"}]
    }

    # Save test workflow
    Path("workflows").mkdir(exist_ok=True)
    with open("workflows/test.json", 'w') as f:
        json.dump(test_workflow, f, indent=2)

    # Execute
    engine.load_workflow("workflows/test.json")
    result = engine.execute(target="127.0.0.1")
    print(f"\nExecution Result: {result}")
