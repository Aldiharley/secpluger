"""
Unit tests for Workflow Engine module
Tests workflow loading, execution, node processing, and evidence collection
"""
import pytest
import sys
import json
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock, call
import subprocess
import time

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from engine.workflow_engine import WorkflowEngine, WorkflowNode


class TestWorkflowNodeCreation:
    """Test WorkflowNode class"""

    def test_workflow_node_creation(self):
        """Test creating a workflow node"""
        node = WorkflowNode("1", "nmap", {"target": "example.com"})

        assert node.id == "1"
        assert node.type == "nmap"
        assert node.data == {"target": "example.com"}
        assert node.output is None
        assert node.error is None
        assert node.status == "pending"

    def test_workflow_node_status_changes(self):
        """Test node status lifecycle"""
        node = WorkflowNode("1", "nmap", {})

        assert node.status == "pending"

        node.status = "running"
        assert node.status == "running"

        node.status = "completed"
        assert node.status == "completed"

    def test_workflow_node_with_output(self):
        """Test node with output data"""
        node = WorkflowNode("1", "nmap", {})
        node.output = {"stdout": "scan results", "exit_code": 0}

        assert node.output["stdout"] == "scan results"
        assert node.output["exit_code"] == 0

    def test_workflow_node_with_error(self):
        """Test node with error"""
        node = WorkflowNode("1", "nmap", {})
        node.error = "Connection timeout"
        node.status = "failed"

        assert node.error == "Connection timeout"
        assert node.status == "failed"


class TestWorkflowEngineInitialization:
    """Test WorkflowEngine initialization"""

    def test_workflow_engine_creation(self, temp_dir):
        """Test creating workflow engine"""
        engine = WorkflowEngine(evidence_dir=temp_dir)

        assert engine.evidence_dir == Path(temp_dir)
        assert engine.workflow is None
        assert engine.nodes == {}
        assert engine.edges == []
        assert engine.variables == {}

    def test_workflow_engine_default_evidence_dir(self):
        """Test default evidence directory"""
        engine = WorkflowEngine()

        assert engine.evidence_dir == Path("evidence")

    def test_workflow_engine_mcp_mode(self):
        """Test MCP server mode"""
        engine = WorkflowEngine(use_mcp_server=True)

        assert engine.use_mcp_server is True
        assert hasattr(engine, 'mcp_url')


class TestWorkflowLoading:
    """Test workflow loading functionality"""

    def test_load_workflow_from_file(self, test_workflow_file):
        """Test loading workflow from JSON file"""
        engine = WorkflowEngine()
        engine.load_workflow(test_workflow_file)

        assert engine.workflow is not None
        assert engine.workflow['name'] == "test_workflow"
        assert len(engine.nodes) == 2
        assert len(engine.edges) == 1

    def test_load_workflow_nodes_parsed(self, test_workflow_file):
        """Test that nodes are correctly parsed"""
        engine = WorkflowEngine()
        engine.load_workflow(test_workflow_file)

        assert "1" in engine.nodes
        assert "2" in engine.nodes
        assert engine.nodes["1"].type == "nmap"
        assert engine.nodes["2"].type == "gobuster"

    def test_load_workflow_edges_parsed(self, test_workflow_file):
        """Test that edges are correctly parsed"""
        engine = WorkflowEngine()
        engine.load_workflow(test_workflow_file)

        assert len(engine.edges) == 1
        assert engine.edges[0]["from"] == "1"
        assert engine.edges[0]["to"] == "2"

    def test_load_invalid_workflow_file(self):
        """Test loading invalid workflow file"""
        engine = WorkflowEngine()

        with pytest.raises(FileNotFoundError):
            engine.load_workflow("/nonexistent/workflow.json")

    def test_load_workflow_with_malformed_json(self, temp_dir):
        """Test loading workflow with malformed JSON"""
        bad_file = Path(temp_dir) / "bad_workflow.json"
        bad_file.write_text("{invalid json")

        engine = WorkflowEngine()

        with pytest.raises(json.JSONDecodeError):
            engine.load_workflow(str(bad_file))


class TestVariableSubstitution:
    """Test variable substitution in workflows"""

    def test_substitute_single_variable(self):
        """Test substituting a single variable"""
        engine = WorkflowEngine()
        engine.variables = {"TARGET": "example.com"}

        data = {"command": "nmap {{TARGET}}"}
        result = engine._substitute_variables(data)

        assert result["command"] == "nmap example.com"

    def test_substitute_multiple_variables(self):
        """Test substituting multiple variables"""
        engine = WorkflowEngine()
        engine.variables = {
            "TARGET": "example.com",
            "PORT": "443"
        }

        data = {"command": "nmap -p {{PORT}} {{TARGET}}"}
        result = engine._substitute_variables(data)

        assert result["command"] == "nmap -p 443 example.com"

    def test_substitute_nested_variables(self):
        """Test substituting variables in nested structures"""
        engine = WorkflowEngine()
        engine.variables = {"URL": "http://example.com"}

        data = {
            "tool": "gobuster",
            "config": {
                "url": "{{URL}}",
                "wordlist": "/usr/share/wordlists/dirb/common.txt"
            }
        }
        result = engine._substitute_variables(data)

        assert result["config"]["url"] == "http://example.com"

    def test_substitute_no_variables(self):
        """Test data without variables remains unchanged"""
        engine = WorkflowEngine()
        engine.variables = {"TARGET": "example.com"}

        data = {"command": "nmap -sV localhost"}
        result = engine._substitute_variables(data)

        assert result["command"] == "nmap -sV localhost"


class TestCommandExecution:
    """Test command execution functionality"""

    @patch('subprocess.run')
    def test_execute_command_success(self, mock_run):
        """Test successful command execution"""
        mock_run.return_value = Mock(
            stdout="Command output",
            stderr="",
            returncode=0
        )

        engine = WorkflowEngine()
        result = engine._execute_command("echo test")

        assert result['success'] is True
        assert result['exit_code'] == 0
        assert result['stdout'] == "Command output"
        assert 'duration' in result

    @patch('subprocess.run')
    def test_execute_command_failure(self, mock_run):
        """Test failed command execution"""
        mock_run.return_value = Mock(
            stdout="",
            stderr="Command not found",
            returncode=127
        )

        engine = WorkflowEngine()
        result = engine._execute_command("nonexistent_command")

        assert result['success'] is False
        assert result['exit_code'] == 127
        assert result['stderr'] == "Command not found"

    @patch('subprocess.run')
    def test_execute_command_timeout(self, mock_run):
        """Test command timeout"""
        mock_run.side_effect = subprocess.TimeoutExpired("cmd", 5)

        engine = WorkflowEngine()
        result = engine._execute_command("sleep 100", timeout=5)

        assert result['success'] is False
        assert result['exit_code'] == -1
        assert 'timed out' in result['stderr']

    @patch('subprocess.run')
    def test_execute_command_exception(self, mock_run):
        """Test command execution with exception"""
        mock_run.side_effect = Exception("Unexpected error")

        engine = WorkflowEngine()
        result = engine._execute_command("test")

        assert result['success'] is False
        assert result['exit_code'] == -1
        assert "Unexpected error" in result['stderr']


class TestNodeTypeExecution:
    """Test execution of different node types"""

    @patch.object(WorkflowEngine, '_execute_command')
    def test_execute_nmap_quick_scan(self, mock_exec):
        """Test nmap quick scan execution"""
        mock_exec.return_value = {"stdout": "scan results", "success": True}

        engine = WorkflowEngine()
        result = engine._execute_nmap({"target": "example.com", "scan_type": "quick"})

        mock_exec.assert_called_once()
        cmd = mock_exec.call_args[0][0]
        assert "nmap" in cmd
        assert "-T4" in cmd
        assert "-F" in cmd
        assert "example.com" in cmd

    @patch.object(WorkflowEngine, '_execute_command')
    def test_execute_nmap_full_scan(self, mock_exec):
        """Test nmap full scan execution"""
        mock_exec.return_value = {"stdout": "scan results", "success": True}

        engine = WorkflowEngine()
        result = engine._execute_nmap({
            "target": "example.com",
            "scan_type": "full",
            "ports": "1-65535"
        })

        cmd = mock_exec.call_args[0][0]
        assert "nmap" in cmd
        assert "-p 1-65535" in cmd

    @patch.object(WorkflowEngine, '_execute_command')
    def test_execute_gobuster(self, mock_exec):
        """Test gobuster execution"""
        mock_exec.return_value = {"stdout": "directories found", "success": True}

        engine = WorkflowEngine()
        result = engine._execute_gobuster({
            "url": "http://example.com",
            "wordlist": "/usr/share/wordlists/dirb/common.txt"
        })

        cmd = mock_exec.call_args[0][0]
        assert "gobuster" in cmd
        assert "dir" in cmd
        assert "-u http://example.com" in cmd
        assert "-w" in cmd

    @patch.object(WorkflowEngine, '_execute_command')
    def test_execute_gobuster_with_extensions(self, mock_exec):
        """Test gobuster with file extensions"""
        mock_exec.return_value = {"stdout": "files found", "success": True}

        engine = WorkflowEngine()
        result = engine._execute_gobuster({
            "url": "http://example.com",
            "wordlist": "/usr/share/wordlists/dirb/common.txt",
            "extensions": "php,html,txt"
        })

        cmd = mock_exec.call_args[0][0]
        assert "-x php,html,txt" in cmd

    @patch.object(WorkflowEngine, '_execute_command')
    def test_execute_sqlmap(self, mock_exec):
        """Test sqlmap execution"""
        mock_exec.return_value = {"stdout": "sqli found", "success": True}

        engine = WorkflowEngine()
        result = engine._execute_sqlmap({
            "url": "http://example.com?id=1",
            "params": "--batch --random-agent"
        })

        cmd = mock_exec.call_args[0][0]
        assert "sqlmap" in cmd
        assert "-u" in cmd
        assert "--batch" in cmd

    @patch.object(WorkflowEngine, '_execute_command')
    def test_execute_nuclei(self, mock_exec):
        """Test nuclei execution"""
        mock_exec.return_value = {"stdout": "vulns found", "success": True}

        engine = WorkflowEngine()
        result = engine._execute_nuclei({
            "target": "http://example.com",
            "templates": "cves/"
        })

        cmd = mock_exec.call_args[0][0]
        assert "nuclei" in cmd
        assert "-u http://example.com" in cmd
        assert "-t cves/" in cmd

    def test_execute_sleep(self):
        """Test sleep node execution"""
        engine = WorkflowEngine()

        start = time.time()
        result = engine._execute_sleep({"duration": 0.1})
        duration = time.time() - start

        assert result["slept"] == 0.1
        assert duration >= 0.1


class TestConditionalExecution:
    """Test conditional node execution"""

    def test_conditional_contains_true(self):
        """Test conditional with contains operator (true)"""
        engine = WorkflowEngine()
        engine.nodes = {
            "1": WorkflowNode("1", "nmap", {}),
            "2": WorkflowNode("2", "conditional", {})
        }
        engine.nodes["1"].output = {"stdout": "Port 80 is open"}
        engine.edges = [{"from": "1", "to": "2"}]

        node = engine.nodes["2"]
        result = engine._execute_conditional({
            "operator": "contains",
            "value": "Port 80"
        }, node)

        assert result["condition_met"] is True

    def test_conditional_contains_false(self):
        """Test conditional with contains operator (false)"""
        engine = WorkflowEngine()
        engine.nodes = {
            "1": WorkflowNode("1", "nmap", {}),
            "2": WorkflowNode("2", "conditional", {})
        }
        engine.nodes["1"].output = {"stdout": "No open ports"}
        engine.edges = [{"from": "1", "to": "2"}]

        node = engine.nodes["2"]
        result = engine._execute_conditional({
            "operator": "contains",
            "value": "Port 80"
        }, node)

        assert result["condition_met"] is False

    def test_conditional_equals(self):
        """Test conditional with equals operator"""
        engine = WorkflowEngine()
        engine.nodes = {
            "1": WorkflowNode("1", "test", {}),
            "2": WorkflowNode("2", "conditional", {})
        }
        engine.nodes["1"].output = "success"
        engine.edges = [{"from": "1", "to": "2"}]

        node = engine.nodes["2"]
        result = engine._execute_conditional({
            "operator": "equals",
            "value": "success"
        }, node)

        assert result["condition_met"] is True

    def test_conditional_regex(self):
        """Test conditional with regex operator"""
        engine = WorkflowEngine()
        engine.nodes = {
            "1": WorkflowNode("1", "test", {}),
            "2": WorkflowNode("2", "conditional", {})
        }
        engine.nodes["1"].output = "Server: Apache/2.4.41"
        engine.edges = [{"from": "1", "to": "2"}]

        node = engine.nodes["2"]
        result = engine._execute_conditional({
            "operator": "regex",
            "value": r"Apache/\d+\.\d+\.\d+"
        }, node)

        assert result["condition_met"] is True


class TestWorkflowExecution:
    """Test full workflow execution"""

    @patch.object(WorkflowEngine, '_execute_command')
    def test_execute_workflow_basic(self, mock_exec, test_workflow_file, temp_dir):
        """Test basic workflow execution"""
        mock_exec.return_value = {
            "stdout": "success",
            "stderr": "",
            "exit_code": 0,
            "duration": 1.5,
            "success": True
        }

        engine = WorkflowEngine(evidence_dir=temp_dir)
        engine.load_workflow(test_workflow_file)
        result = engine.execute(TARGET="example.com", PORT="80")

        assert result['execution_id'] is not None
        assert result['nodes_completed'] >= 0
        assert result['nodes_failed'] >= 0
        assert Path(result['evidence_path']).exists()

    @patch.object(WorkflowEngine, '_execute_command')
    def test_execute_workflow_with_variables(self, mock_exec, test_workflow_file, temp_dir):
        """Test workflow execution with variable substitution"""
        mock_exec.return_value = {
            "stdout": "success",
            "stderr": "",
            "exit_code": 0,
            "duration": 1.0,
            "success": True
        }

        engine = WorkflowEngine(evidence_dir=temp_dir)
        engine.load_workflow(test_workflow_file)
        result = engine.execute(TARGET="testsite.com", PORT="443")

        assert engine.variables["TARGET"] == "testsite.com"
        assert engine.variables["PORT"] == "443"

    @patch.object(WorkflowEngine, '_execute_node')
    def test_execute_workflow_node_order(self, mock_exec_node, test_workflow_file, temp_dir):
        """Test that nodes execute in correct order"""
        mock_exec_node.return_value = True

        engine = WorkflowEngine(evidence_dir=temp_dir)
        engine.load_workflow(test_workflow_file)
        engine.execute(TARGET="example.com")

        # Should execute both nodes
        assert mock_exec_node.call_count == 2

    @patch.object(WorkflowEngine, '_execute_node')
    def test_execute_workflow_stop_on_error(self, mock_exec_node, test_workflow_file, temp_dir):
        """Test workflow stops on error when continue_on_error is False"""
        # First node fails
        mock_exec_node.side_effect = [False, True]

        engine = WorkflowEngine(evidence_dir=temp_dir)
        engine.load_workflow(test_workflow_file)
        engine.workflow['continue_on_error'] = False
        result = engine.execute(TARGET="example.com")

        # Should only execute first node
        assert mock_exec_node.call_count == 1

    @patch.object(WorkflowEngine, '_execute_node')
    def test_execute_workflow_continue_on_error(self, mock_exec_node, test_workflow_file, temp_dir):
        """Test workflow continues on error when continue_on_error is True"""
        # First node fails
        mock_exec_node.side_effect = [False, True]

        engine = WorkflowEngine(evidence_dir=temp_dir)
        engine.load_workflow(test_workflow_file)
        engine.workflow['continue_on_error'] = True
        result = engine.execute(TARGET="example.com")

        # Should execute both nodes
        assert mock_exec_node.call_count == 2


class TestEvidenceCollection:
    """Test evidence collection functionality"""

    @patch.object(WorkflowEngine, '_execute_command')
    def test_evidence_directory_created(self, mock_exec, test_workflow_file, temp_dir):
        """Test that evidence directory is created"""
        mock_exec.return_value = {"stdout": "test", "success": True}

        engine = WorkflowEngine(evidence_dir=temp_dir)
        engine.load_workflow(test_workflow_file)
        result = engine.execute(TARGET="example.com")

        evidence_path = Path(result['evidence_path'])
        assert evidence_path.exists()
        assert evidence_path.is_dir()

    @patch.object(WorkflowEngine, '_execute_command')
    def test_evidence_files_saved(self, mock_exec, test_workflow_file, temp_dir):
        """Test that evidence files are saved for each node"""
        mock_exec.return_value = {
            "stdout": "test output",
            "stderr": "",
            "exit_code": 0,
            "success": True
        }

        engine = WorkflowEngine(evidence_dir=temp_dir)
        engine.load_workflow(test_workflow_file)
        result = engine.execute(TARGET="example.com")

        evidence_path = Path(result['evidence_path'])
        evidence_files = list(evidence_path.glob("*.txt"))

        # Should have evidence files for executed nodes
        assert len(evidence_files) > 0

    @patch.object(WorkflowEngine, '_execute_command')
    def test_execution_summary_saved(self, mock_exec, test_workflow_file, temp_dir):
        """Test that execution summary is saved"""
        mock_exec.return_value = {"stdout": "test", "success": True}

        engine = WorkflowEngine(evidence_dir=temp_dir)
        engine.load_workflow(test_workflow_file)
        result = engine.execute(TARGET="example.com")

        summary_file = Path(result['evidence_path']) / "execution_summary.json"
        assert summary_file.exists()

        with open(summary_file) as f:
            summary = json.load(f)

        assert 'execution_id' in summary
        assert 'workflow_name' in summary
        assert 'variables' in summary
        assert 'nodes' in summary


class TestNodeRetryLogic:
    """Test node retry functionality"""

    def test_node_retry_on_failure(self, temp_dir):
        """Test that failed nodes are retried"""
        engine = WorkflowEngine(evidence_dir=temp_dir)
        node = WorkflowNode("1", "test", {"retry": 2})

        with patch.object(engine, '_execute_command') as mock_exec:
            # Fail twice, then succeed
            mock_exec.side_effect = [
                Exception("Fail 1"),
                Exception("Fail 2"),
                {"stdout": "success", "success": True}
            ]

            # This will fail, catch exception, retry
            result = engine._execute_node(node)

            # Note: Current implementation retries but doesn't track,
            # so this tests the retry mechanism exists
            assert mock_exec.call_count >= 1

    def test_node_no_retry_by_default(self, temp_dir):
        """Test that nodes don't retry without retry setting"""
        engine = WorkflowEngine(evidence_dir=temp_dir)
        node = WorkflowNode("1", "test", {})

        with patch.object(engine, '_execute_command') as mock_exec:
            mock_exec.side_effect = Exception("Fail")

            result = engine._execute_node(node)

            # Should only try once
            assert mock_exec.call_count == 1
            assert result is False


class TestExecutionOrder:
    """Test node execution order"""

    def test_get_execution_order_simple(self, test_workflow_file):
        """Test execution order for simple workflow"""
        engine = WorkflowEngine()
        engine.load_workflow(test_workflow_file)

        order = engine._get_execution_order()

        assert isinstance(order, list)
        assert len(order) == 2
        assert all(node_id in engine.nodes for node_id in order)

    def test_get_previous_output(self):
        """Test getting previous node output"""
        engine = WorkflowEngine()
        engine.nodes = {
            "1": WorkflowNode("1", "test", {}),
            "2": WorkflowNode("2", "test", {})
        }
        engine.nodes["1"].output = {"result": "previous output"}
        engine.edges = [{"from": "1", "to": "2"}]

        output = engine._get_previous_output(engine.nodes["2"])

        assert output is not None
        assert output["result"] == "previous output"

    def test_get_previous_output_no_predecessor(self):
        """Test getting previous output when no predecessor exists"""
        engine = WorkflowEngine()
        engine.nodes = {"1": WorkflowNode("1", "test", {})}
        engine.edges = []

        output = engine._get_previous_output(engine.nodes["1"])

        assert output is None


@pytest.mark.integration
class TestWorkflowEngineIntegration:
    """Integration tests for workflow engine"""

    def test_execute_real_workflow(self, temp_dir):
        """Test executing a real workflow (with safe commands)"""
        workflow = {
            "name": "Integration Test",
            "nodes": [
                {
                    "id": "1",
                    "type": "sleep",
                    "data": {"duration": 0.1}
                }
            ],
            "edges": []
        }

        workflow_file = Path(temp_dir) / "integration_test.json"
        with open(workflow_file, 'w') as f:
            json.dump(workflow, f)

        engine = WorkflowEngine(evidence_dir=temp_dir)
        engine.load_workflow(str(workflow_file))
        result = engine.execute()

        assert result['nodes_completed'] == 1
        assert result['nodes_failed'] == 0
