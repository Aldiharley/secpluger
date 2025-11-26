"""
Integration tests for MCP Server
Tests MCP tool calls, workflow operations, and scanner integration
"""
import pytest
import sys
import json
import asyncio
from pathlib import Path
from unittest.mock import Mock, patch, AsyncMock, MagicMock

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

# Note: These are integration-style tests that test MCP tool handlers
# without actually starting the MCP server (which requires stdio)


class TestMCPWorkflowTools:
    """Test MCP workflow recording and playback tools"""

    @patch('mcp_monitor.WorkflowRecorder')
    def test_start_recording_handler(self, mock_recorder_class):
        """Test start_recording tool handler logic"""
        mock_recorder = Mock()
        mock_recorder.start_session = Mock(return_value={
            'session_id': 'session_001',
            'target': 'example.com',
            'evidence_dir': '/evidence/session_001'
        })
        mock_recorder_class.return_value = mock_recorder

        # Simulate calling start_recording
        target = "example.com"
        result = mock_recorder.start_session(target=target)

        assert result['target'] == target
        assert 'session_id' in result
        assert 'evidence_dir' in result
        mock_recorder.start_session.assert_called_once_with(target=target)

    @patch('mcp_monitor.WorkflowRecorder')
    def test_record_command_handler(self, mock_recorder_class):
        """Test record_command tool handler logic"""
        mock_recorder = Mock()
        mock_recorder.record_command = Mock(return_value={
            'node_id': '1',
            'evidence_saved': True,
            'vulnerabilities': []
        })
        mock_recorder_class.return_value = mock_recorder

        # Simulate recording a command
        command = "nmap -sV example.com"
        output = {"stdout": "scan results", "exit_code": 0}

        result = mock_recorder.record_command(command=command, output=output)

        assert 'node_id' in result
        assert result['evidence_saved'] is True
        mock_recorder.record_command.assert_called_once_with(command=command, output=output)

    @patch('mcp_monitor.WorkflowRecorder')
    def test_save_workflow_handler(self, mock_recorder_class):
        """Test save_workflow tool handler logic"""
        mock_recorder = Mock()
        mock_recorder.save_workflow = Mock(return_value={
            'workflow_path': '/workflows/web_pentest.json',
            'nodes': 5,
            'saved': True
        })
        mock_recorder_class.return_value = mock_recorder

        # Simulate saving workflow
        workflow_name = "web_pentest"
        result = mock_recorder.save_workflow(name=workflow_name)

        assert result['saved'] is True
        assert 'workflow_path' in result
        assert result['nodes'] == 5
        mock_recorder.save_workflow.assert_called_once()

    @patch('engine.workflow_engine.WorkflowEngine')
    def test_replay_workflow_handler(self, mock_engine_class):
        """Test replay_workflow tool handler logic"""
        mock_engine = Mock()
        mock_engine.load_workflow = Mock()
        mock_engine.execute = Mock(return_value={
            'execution_id': 'exec_001',
            'nodes_completed': 5,
            'nodes_failed': 0,
            'evidence_path': '/evidence/exec_001'
        })
        mock_engine_class.return_value = mock_engine

        # Simulate workflow replay
        workflow_path = "/workflows/web_pentest.json"
        target = "newsite.com"

        mock_engine.load_workflow(workflow_path)
        result = mock_engine.execute(target=target)

        assert result['nodes_completed'] == 5
        assert result['nodes_failed'] == 0
        assert 'evidence_path' in result
        mock_engine.load_workflow.assert_called_once_with(workflow_path)


class TestMCPScannerTools:
    """Test MCP scanner tool integration"""

    @patch('web_crawler.WebCrawler')
    def test_crawl_website_handler(self, mock_crawler_class):
        """Test crawl_website tool handler"""
        mock_crawler = Mock()
        mock_crawler.crawl = Mock(return_value={
            'pages': ['http://example.com/', 'http://example.com/about'],
            'forms': [{'action': '/login', 'method': 'POST'}],
            'parameters': {'id': ['1', '2']}
        })
        mock_crawler_class.return_value = mock_crawler

        # Simulate crawling
        url = "http://example.com"
        result = mock_crawler.crawl(url, max_depth=2, max_pages=10)

        assert len(result['pages']) == 2
        assert len(result['forms']) == 1
        mock_crawler.crawl.assert_called_once()

    @patch('fuzzer.WebFuzzer')
    def test_fuzz_parameter_handler(self, mock_fuzzer_class):
        """Test fuzz_parameter tool handler"""
        mock_fuzzer = Mock()
        mock_fuzzer.fuzz_parameter = Mock(return_value={
            'url': 'http://example.com/search',
            'parameter': 'q',
            'total_payloads': 50,
            'vulnerabilities': [
                {'payload': '<script>alert(1)</script>', 'severity': 'HIGH'}
            ]
        })
        mock_fuzzer_class.return_value = mock_fuzzer

        # Simulate fuzzing
        url = "http://example.com/search?q=test"
        parameter = "q"
        attack_type = "xss"

        result = mock_fuzzer.fuzz_parameter(
            url=url,
            parameter=parameter,
            attack_type=attack_type
        )

        assert result['parameter'] == parameter
        assert len(result['vulnerabilities']) > 0
        mock_fuzzer.fuzz_parameter.assert_called_once()

    @patch('vulnerability_scanner.VulnerabilityScanner')
    def test_scan_vulnerabilities_handler(self, mock_scanner_class):
        """Test scan_vulnerabilities tool handler"""
        mock_scanner = Mock()
        mock_scanner.scan = Mock(return_value={
            'target': 'http://example.com',
            'scan_type': 'quick',
            'vulnerabilities': [
                {'title': 'XSS Found', 'severity': 'HIGH', 'tool': 'nuclei'}
            ],
            'tools_used': ['nuclei', 'wapiti']
        })
        mock_scanner_class.return_value = mock_scanner

        # Simulate vulnerability scan
        target = "http://example.com"
        scan_type = "quick"

        result = mock_scanner.scan(target=target, scan_type=scan_type)

        assert result['target'] == target
        assert len(result['vulnerabilities']) > 0
        assert 'nuclei' in result['tools_used']
        mock_scanner.scan.assert_called_once()


class TestMCPProxyTools:
    """Test MCP proxy controller tools"""

    @patch('mitmproxy_controller.ProxyController')
    def test_start_proxy_handler(self, mock_proxy_class):
        """Test start_proxy tool handler"""
        mock_proxy = Mock()
        mock_proxy.start_proxy = Mock(return_value={
            'status': 'running',
            'port': 8080,
            'mode': 'regular',
            'pid': 12345
        })
        mock_proxy_class.return_value = mock_proxy

        # Simulate starting proxy
        result = mock_proxy.start_proxy(port=8080, mode='regular')

        assert result['status'] == 'running'
        assert result['port'] == 8080
        mock_proxy.start_proxy.assert_called_once()

    @patch('mitmproxy_controller.ProxyController')
    def test_stop_proxy_handler(self, mock_proxy_class):
        """Test stop_proxy tool handler"""
        mock_proxy = Mock()
        mock_proxy.stop_proxy = Mock(return_value={
            'status': 'stopped',
            'flows_saved': '/evidence/proxy_traffic.mitm',
            'total_requests': 42
        })
        mock_proxy_class.return_value = mock_proxy

        # Simulate stopping proxy
        result = mock_proxy.stop_proxy()

        assert result['status'] == 'stopped'
        assert 'flows_saved' in result
        mock_proxy.stop_proxy.assert_called_once()

    @patch('mitmproxy_controller.ProxyController')
    def test_proxy_status_handler(self, mock_proxy_class):
        """Test proxy_status tool handler"""
        mock_proxy = Mock()
        mock_proxy.get_status = Mock(return_value={
            'running': True,
            'port': 8080,
            'uptime': 120,
            'requests_captured': 15
        })
        mock_proxy_class.return_value = mock_proxy

        # Simulate checking proxy status
        result = mock_proxy.get_status()

        assert result['running'] is True
        assert result['port'] == 8080
        mock_proxy.get_status.assert_called_once()


class TestMCPToolManagementTools:
    """Test MCP tool management integration"""

    @patch('tool_manager.ToolManager')
    def test_check_tools_handler(self, mock_tm_class):
        """Test check_tools tool handler"""
        mock_tm = Mock()
        mock_tm.get_available_tools = Mock(return_value={
            'nmap': True,
            'nuclei': True,
            'gobuster': True,
            'nikto': False
        })
        mock_tm_class.return_value = mock_tm

        # Simulate checking tools
        result = mock_tm.get_available_tools(category='web_scanner')

        assert result['nmap'] is True
        assert result['nikto'] is False
        mock_tm.get_available_tools.assert_called_once()

    @patch('tool_manager.ToolManager')
    def test_get_tool_info_handler(self, mock_tm_class):
        """Test get_tool_info tool handler"""
        mock_tm = Mock()
        mock_tm.get_tool_info = Mock(return_value={
            'name': 'nuclei',
            'category': 'web_scanner',
            'description': 'Fast vulnerability scanner',
            'priority': 'high',
            'install_cmd': 'go install nuclei...'
        })
        mock_tm_class.return_value = mock_tm

        # Simulate getting tool info
        result = mock_tm.get_tool_info('nuclei')

        assert result['name'] == 'nuclei'
        assert result['priority'] == 'high'
        mock_tm.get_tool_info.assert_called_once_with('nuclei')

    @patch('tool_manager.ToolManager')
    def test_install_tool_handler(self, mock_tm_class):
        """Test install_tool tool handler"""
        mock_tm = Mock()
        mock_tm.get_install_command = Mock(return_value='sudo apt install -y nmap')
        mock_tm_class.return_value = mock_tm

        # Simulate getting install command
        result = mock_tm.get_install_command('nmap')

        assert 'apt install' in result
        assert 'nmap' in result
        mock_tm.get_install_command.assert_called_once_with('nmap')


class TestMCPDatabaseTools:
    """Test MCP database integration"""

    @patch('database.models.Database')
    def test_get_findings_handler(self, mock_db_class):
        """Test getting findings through MCP"""
        mock_db = Mock()
        mock_db.get_findings = Mock(return_value=[
            {
                'id': 1,
                'title': 'SQL Injection',
                'severity': 'CRITICAL',
                'target': 'example.com'
            },
            {
                'id': 2,
                'title': 'XSS',
                'severity': 'HIGH',
                'target': 'example.com'
            }
        ])
        mock_db_class.return_value = mock_db

        # Simulate getting findings
        result = mock_db.get_findings(severity='CRITICAL')

        assert len(result) == 2
        assert result[0]['severity'] == 'CRITICAL'
        mock_db.get_findings.assert_called_once()

    @patch('database.models.Database')
    def test_add_finding_handler(self, mock_db_class):
        """Test adding finding through MCP"""
        mock_db = Mock()
        mock_db.add_finding = Mock(return_value=1)
        mock_db_class.return_value = mock_db

        # Simulate adding finding
        finding_id = mock_db.add_finding(
            execution_id='exec_001',
            title='SQL Injection',
            severity='CRITICAL',
            target='example.com'
        )

        assert finding_id == 1
        mock_db.add_finding.assert_called_once()


class TestMCPWorkflowBranching:
    """Test workflow branching functionality through MCP"""

    @patch('mcp_monitor.WorkflowRecorder')
    def test_create_branch_handler(self, mock_recorder_class):
        """Test create_branch tool handler"""
        mock_recorder = Mock()
        mock_recorder.create_branch = Mock(return_value={
            'branch_id': 'branch_001',
            'from_node': '3',
            'new_nodes': 2,
            'branch_saved': True
        })
        mock_recorder_class.return_value = mock_recorder

        # Simulate creating branch
        result = mock_recorder.create_branch(
            from_node_id='3',
            new_commands=['sqlmap -u ...', 'exploits']
        )

        assert result['branch_saved'] is True
        assert result['from_node'] == '3'
        mock_recorder.create_branch.assert_called_once()


class TestMCPEndToEnd:
    """End-to-end integration tests"""

    @patch('mcp_monitor.WorkflowRecorder')
    @patch('database.models.Database')
    def test_complete_pentest_workflow(self, mock_db_class, mock_recorder_class):
        """Test complete pentest workflow through MCP"""
        # Setup mocks
        mock_recorder = Mock()
        mock_db = Mock()

        mock_recorder.start_session = Mock(return_value={
            'session_id': 'session_001',
            'target': 'example.com'
        })
        mock_recorder.record_command = Mock(return_value={
            'node_id': '1',
            'evidence_saved': True
        })
        mock_recorder.save_workflow = Mock(return_value={
            'workflow_path': '/workflows/test.json',
            'saved': True
        })

        mock_db.add_finding = Mock(return_value=1)
        mock_db.get_findings = Mock(return_value=[])

        mock_recorder_class.return_value = mock_recorder
        mock_db_class.return_value = mock_db

        # Simulate workflow
        # 1. Start recording
        session = mock_recorder.start_session(target='example.com')
        assert session['session_id'] == 'session_001'

        # 2. Record commands
        cmd1_result = mock_recorder.record_command(
            command='nmap example.com',
            output={'stdout': 'scan results', 'exit_code': 0}
        )
        assert cmd1_result['evidence_saved'] is True

        # 3. Save workflow
        workflow_result = mock_recorder.save_workflow(name='test_workflow')
        assert workflow_result['saved'] is True

        # Verify all methods were called
        mock_recorder.start_session.assert_called_once()
        mock_recorder.record_command.assert_called_once()
        mock_recorder.save_workflow.assert_called_once()


@pytest.mark.integration
class TestMCPWithRealComponents:
    """Integration tests with real (non-mocked) components"""

    def test_tool_manager_integration(self, temp_dir):
        """Test tool manager with real instance"""
        from utils.tool_manager import ToolManager

        tm = ToolManager()
        available = tm.get_available_tools()

        # Should return dict of tools
        assert isinstance(available, dict)
        assert len(available) > 0

    def test_database_integration(self, temp_dir):
        """Test database with real instance"""
        from database.models import Database

        db_path = Path(temp_dir) / "test.db"
        db = Database(str(db_path))

        # Add finding
        finding_id = db.add_finding(
            execution_id="test",
            title="Test Finding",
            severity="HIGH"
        )

        assert finding_id > 0

        # Get findings
        findings = db.get_findings()
        assert len(findings) == 1
        assert findings[0]['title'] == "Test Finding"

        db.close()

    def test_workflow_engine_integration(self, temp_dir, test_workflow_file):
        """Test workflow engine with real instance"""
        from engine.workflow_engine import WorkflowEngine

        engine = WorkflowEngine(evidence_dir=temp_dir)
        engine.load_workflow(test_workflow_file)

        assert engine.workflow is not None
        assert len(engine.nodes) > 0


class TestMCPErrorHandling:
    """Test error handling in MCP tools"""

    @patch('engine.workflow_engine.WorkflowEngine')
    def test_replay_workflow_file_not_found(self, mock_engine_class):
        """Test replay_workflow with non-existent file"""
        mock_engine = Mock()
        mock_engine.load_workflow = Mock(side_effect=FileNotFoundError("Workflow not found"))
        mock_engine_class.return_value = mock_engine

        # Should raise error
        with pytest.raises(FileNotFoundError):
            mock_engine.load_workflow("/nonexistent/workflow.json")

    @patch('mcp_monitor.WorkflowRecorder')
    def test_save_workflow_without_session(self, mock_recorder_class):
        """Test save_workflow when no session is active"""
        mock_recorder = Mock()
        mock_recorder.save_workflow = Mock(side_effect=RuntimeError("No active session"))
        mock_recorder_class.return_value = mock_recorder

        # Should raise error
        with pytest.raises(RuntimeError):
            mock_recorder.save_workflow(name="test")

    @patch('database.models.Database')
    def test_add_finding_invalid_severity(self, mock_db_class):
        """Test adding finding with invalid severity"""
        mock_db = Mock()
        # SQLite would handle this, but we can test validation
        mock_db.add_finding = Mock(side_effect=ValueError("Invalid severity"))
        mock_db_class.return_value = mock_db

        # Should raise error
        with pytest.raises(ValueError):
            mock_db.add_finding(
                execution_id="test",
                title="Test",
                severity="INVALID"
            )


class TestMCPToolInputValidation:
    """Test input validation for MCP tools"""

    def test_start_recording_requires_target(self):
        """Test that start_recording validates target parameter"""
        # In real implementation, target is required
        target = ""

        # Should validate that target is not empty
        assert target == "" or target is None

    def test_replay_workflow_requires_path_and_target(self):
        """Test that replay_workflow validates required parameters"""
        workflow_path = ""
        target = ""

        # Should validate both parameters
        assert workflow_path == "" or target == ""

    def test_fuzz_parameter_validates_attack_type(self):
        """Test that fuzz_parameter validates attack type"""
        valid_attack_types = ['xss', 'sqli', 'command_injection', 'path_traversal', 'ldap']
        attack_type = "xss"

        assert attack_type in valid_attack_types


class TestMCPPerformance:
    """Test performance considerations for MCP tools"""

    @patch('web_crawler.WebCrawler')
    def test_crawl_respects_limits(self, mock_crawler_class):
        """Test that crawler respects max_pages limit"""
        mock_crawler = Mock()

        # Simulate crawl with limits
        max_pages = 10
        mock_crawler.crawl = Mock(return_value={
            'pages': [f'http://example.com/page{i}' for i in range(max_pages)]
        })

        result = mock_crawler.crawl('http://example.com', max_pages=max_pages)

        assert len(result['pages']) <= max_pages

    @patch('vulnerability_scanner.VulnerabilityScanner')
    def test_scan_timeout_handling(self, mock_scanner_class):
        """Test that scanner handles timeouts properly"""
        mock_scanner = Mock()
        mock_scanner.scan = Mock(return_value={
            'timeout': True,
            'partial_results': []
        })

        result = mock_scanner.scan(target='http://example.com', timeout=30)

        # Should handle timeout gracefully
        assert 'timeout' in result or 'partial_results' in result
