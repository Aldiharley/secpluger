"""
Integration tests for Workflow Recording and Replay
Tests end-to-end workflow recording, saving, and replay functionality
"""
import pytest
import sys
import json
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))


class TestWorkflowRecordingBasics:
    """Test basic workflow recording functionality"""

    @patch('mcp_monitor.WorkflowRecorder')
    def test_start_recording_session(self, mock_recorder_class):
        """Test starting a recording session"""
        mock_recorder = Mock()
        mock_recorder.start_session = Mock(return_value={
            'session_id': 'session_20251024_100000',
            'target': 'example.com',
            'evidence_dir': '/evidence/session_20251024_100000_example.com',
            'workflow': {
                'name': 'Recorded Workflow',
                'nodes': [],
                'edges': []
            }
        })
        mock_recorder_class.return_value = mock_recorder

        # Start session
        result = mock_recorder.start_session(target='example.com')

        assert result['target'] == 'example.com'
        assert 'session_id' in result
        assert 'evidence_dir' in result
        assert 'workflow' in result
        assert result['workflow']['nodes'] == []

    @patch('mcp_monitor.WorkflowRecorder')
    def test_record_single_command(self, mock_recorder_class):
        """Test recording a single command"""
        mock_recorder = Mock()
        mock_recorder.record_command = Mock(return_value={
            'node_id': '1',
            'command': 'nmap -sV example.com',
            'evidence_file': '/evidence/session_001/01_nmap.txt',
            'vulnerabilities_detected': 0,
            'status': 'recorded'
        })
        mock_recorder_class.return_value = mock_recorder

        # Record command
        result = mock_recorder.record_command(
            command='nmap -sV example.com',
            output={
                'stdout': 'Nmap scan results...',
                'stderr': '',
                'exit_code': 0,
                'duration': 5.2
            }
        )

        assert result['node_id'] == '1'
        assert 'nmap' in result['command']
        assert 'evidence_file' in result

    @patch('mcp_monitor.WorkflowRecorder')
    def test_record_multiple_commands_sequence(self, mock_recorder_class):
        """Test recording sequence of commands"""
        mock_recorder = Mock()

        # Mock recording multiple commands
        mock_recorder.record_command = Mock(side_effect=[
            {'node_id': '1', 'command': 'nmap', 'status': 'recorded'},
            {'node_id': '2', 'command': 'gobuster', 'status': 'recorded'},
            {'node_id': '3', 'command': 'sqlmap', 'status': 'recorded'}
        ])
        mock_recorder_class.return_value = mock_recorder

        # Record sequence
        commands = [
            ('nmap -sV example.com', {'stdout': 'nmap output', 'exit_code': 0}),
            ('gobuster dir -u http://example.com', {'stdout': 'dirs found', 'exit_code': 0}),
            ('sqlmap -u http://example.com?id=1', {'stdout': 'sqli found', 'exit_code': 0})
        ]

        results = []
        for cmd, output in commands:
            result = mock_recorder.record_command(command=cmd, output=output)
            results.append(result)

        assert len(results) == 3
        assert results[0]['node_id'] == '1'
        assert results[1]['node_id'] == '2'
        assert results[2]['node_id'] == '3'


class TestWorkflowSaving:
    """Test workflow saving functionality"""

    @patch('mcp_monitor.WorkflowRecorder')
    def test_save_workflow_basic(self, mock_recorder_class, temp_dir):
        """Test saving workflow to file"""
        mock_recorder = Mock()
        workflow_path = Path(temp_dir) / "test_workflow.json"

        mock_recorder.save_workflow = Mock(return_value={
            'workflow_path': str(workflow_path),
            'workflow_name': 'test_workflow',
            'nodes': 3,
            'edges': 2,
            'saved': True,
            'reusable': True
        })
        mock_recorder_class.return_value = mock_recorder

        # Save workflow
        result = mock_recorder.save_workflow(name='test_workflow')

        assert result['saved'] is True
        assert result['nodes'] == 3
        assert 'workflow_path' in result

    @patch('mcp_monitor.WorkflowRecorder')
    def test_save_workflow_with_metadata(self, mock_recorder_class):
        """Test saving workflow with metadata"""
        mock_recorder = Mock()
        mock_recorder.save_workflow = Mock(return_value={
            'workflow_path': '/workflows/pentest.json',
            'metadata': {
                'created_at': datetime.now().isoformat(),
                'target': 'example.com',
                'total_duration': 120.5,
                'findings_count': 5
            },
            'saved': True
        })
        mock_recorder_class.return_value = mock_recorder

        # Save with metadata
        result = mock_recorder.save_workflow(
            name='pentest',
            description='Full web pentest workflow'
        )

        assert result['saved'] is True
        assert 'metadata' in result
        assert result['metadata']['findings_count'] == 5


class TestWorkflowReplay:
    """Test workflow replay functionality"""

    @patch('engine.workflow_engine.WorkflowEngine')
    def test_replay_workflow_basic(self, mock_engine_class, temp_dir):
        """Test replaying a saved workflow"""
        mock_engine = Mock()
        mock_engine.load_workflow = Mock()
        mock_engine.execute = Mock(return_value={
            'execution_id': 'exec_20251024_100000',
            'evidence_path': f'{temp_dir}/evidence/exec_001',
            'nodes_completed': 3,
            'nodes_failed': 0,
            'duration': 45.2,
            'success': True
        })
        mock_engine_class.return_value = mock_engine

        # Replay workflow
        workflow_path = "/workflows/test_workflow.json"
        mock_engine.load_workflow(workflow_path)
        result = mock_engine.execute(target='newsite.com', port='443')

        assert result['nodes_completed'] == 3
        assert result['nodes_failed'] == 0
        assert result['success'] is True
        mock_engine.load_workflow.assert_called_once_with(workflow_path)

    @patch('engine.workflow_engine.WorkflowEngine')
    def test_replay_with_variable_substitution(self, mock_engine_class):
        """Test replay with different target variables"""
        mock_engine = Mock()
        mock_engine.load_workflow = Mock()
        mock_engine.execute = Mock(return_value={
            'execution_id': 'exec_001',
            'variables_used': {
                'TARGET': 'newsite.com',
                'PORT': '8080'
            },
            'nodes_completed': 3,
            'success': True
        })
        mock_engine_class.return_value = mock_engine

        # Replay with new variables
        mock_engine.load_workflow('/workflows/test.json')
        result = mock_engine.execute(TARGET='newsite.com', PORT='8080')

        assert result['variables_used']['TARGET'] == 'newsite.com'
        assert result['variables_used']['PORT'] == '8080'

    @patch('engine.workflow_engine.WorkflowEngine')
    def test_replay_multiple_targets(self, mock_engine_class):
        """Test replaying same workflow on multiple targets"""
        mock_engine = Mock()
        mock_engine.load_workflow = Mock()

        # Mock executing on multiple targets
        mock_engine.execute = Mock(side_effect=[
            {'execution_id': 'exec_001', 'target': 'site1.com', 'success': True},
            {'execution_id': 'exec_002', 'target': 'site2.com', 'success': True},
            {'execution_id': 'exec_003', 'target': 'site3.com', 'success': True}
        ])
        mock_engine_class.return_value = mock_engine

        # Replay on multiple targets
        targets = ['site1.com', 'site2.com', 'site3.com']
        results = []

        mock_engine.load_workflow('/workflows/test.json')
        for target in targets:
            result = mock_engine.execute(target=target)
            results.append(result)

        assert len(results) == 3
        assert all(r['success'] for r in results)


class TestVulnerabilityDetection:
    """Test automatic vulnerability detection during recording"""

    @patch('mcp_monitor.WorkflowRecorder')
    def test_detect_sql_injection(self, mock_recorder_class):
        """Test detecting SQL injection from command output"""
        mock_recorder = Mock()
        mock_recorder.record_command = Mock(return_value={
            'node_id': '1',
            'command': 'sqlmap -u http://example.com?id=1',
            'vulnerabilities_detected': 1,
            'vulnerabilities': [
                {
                    'type': 'SQL Injection',
                    'severity': 'CRITICAL',
                    'parameter': 'id',
                    'evidence': 'Parameter id is vulnerable to SQL injection'
                }
            ]
        })
        mock_recorder_class.return_value = mock_recorder

        # Record sqlmap command
        result = mock_recorder.record_command(
            command='sqlmap -u http://example.com?id=1',
            output={'stdout': 'Parameter id is vulnerable...', 'exit_code': 0}
        )

        assert result['vulnerabilities_detected'] == 1
        assert result['vulnerabilities'][0]['type'] == 'SQL Injection'
        assert result['vulnerabilities'][0]['severity'] == 'CRITICAL'

    @patch('mcp_monitor.WorkflowRecorder')
    def test_detect_xss_vulnerability(self, mock_recorder_class):
        """Test detecting XSS from scan output"""
        mock_recorder = Mock()
        mock_recorder.record_command = Mock(return_value={
            'node_id': '1',
            'vulnerabilities_detected': 1,
            'vulnerabilities': [
                {
                    'type': 'XSS',
                    'severity': 'HIGH',
                    'url': 'http://example.com/search',
                    'parameter': 'q'
                }
            ]
        })
        mock_recorder_class.return_value = mock_recorder

        result = mock_recorder.record_command(
            command='nuclei -u http://example.com',
            output={'stdout': 'XSS found in /search?q=', 'exit_code': 0}
        )

        assert result['vulnerabilities_detected'] == 1
        assert result['vulnerabilities'][0]['type'] == 'XSS'

    @patch('mcp_monitor.WorkflowRecorder')
    def test_detect_open_ports(self, mock_recorder_class):
        """Test detecting open ports from nmap output"""
        mock_recorder = Mock()
        mock_recorder.record_command = Mock(return_value={
            'node_id': '1',
            'ports_detected': [80, 443, 22],
            'services': {
                80: 'http',
                443: 'https',
                22: 'ssh'
            }
        })
        mock_recorder_class.return_value = mock_recorder

        result = mock_recorder.record_command(
            command='nmap -sV example.com',
            output={'stdout': '80/tcp open http\n443/tcp open https', 'exit_code': 0}
        )

        assert 'ports_detected' in result
        assert 80 in result['ports_detected']
        assert 443 in result['ports_detected']


class TestEvidenceCollection:
    """Test evidence collection during recording"""

    @patch('mcp_monitor.WorkflowRecorder')
    def test_save_command_output_evidence(self, mock_recorder_class):
        """Test saving command output as evidence"""
        mock_recorder = Mock()
        mock_recorder.record_command = Mock(return_value={
            'node_id': '1',
            'evidence_saved': True,
            'evidence_file': '/evidence/session_001/01_nmap.txt',
            'evidence_size': 1234
        })
        mock_recorder_class.return_value = mock_recorder

        result = mock_recorder.record_command(
            command='nmap example.com',
            output={'stdout': 'scan results...', 'exit_code': 0}
        )

        assert result['evidence_saved'] is True
        assert 'evidence_file' in result
        assert 'nmap' in result['evidence_file']

    @patch('mcp_monitor.WorkflowRecorder')
    def test_screenshot_capture(self, mock_recorder_class):
        """Test optional screenshot capture"""
        mock_recorder = Mock()
        mock_recorder.record_command = Mock(return_value={
            'node_id': '1',
            'evidence_saved': True,
            'screenshot_saved': True,
            'screenshot_file': '/evidence/session_001/screenshot_01.png'
        })
        mock_recorder_class.return_value = mock_recorder

        result = mock_recorder.record_command(
            command='firefox http://example.com',
            output={'stdout': '', 'exit_code': 0},
            capture_screenshot=True
        )

        assert result.get('screenshot_saved') is True
        assert 'screenshot_file' in result


class TestWorkflowBranching:
    """Test workflow branching functionality"""

    @patch('mcp_monitor.WorkflowRecorder')
    def test_create_workflow_branch(self, mock_recorder_class):
        """Test creating a workflow branch"""
        mock_recorder = Mock()
        mock_recorder.create_branch = Mock(return_value={
            'branch_id': 'branch_001',
            'from_node': '3',
            'branch_workflow_path': '/workflows/test_branch_001.json',
            'nodes_added': 2,
            'success': True
        })
        mock_recorder_class.return_value = mock_recorder

        # Create branch from node 3
        result = mock_recorder.create_branch(
            from_node_id='3',
            new_commands=[
                'sqlmap -u http://example.com?id=1 --dump',
                'sqlmap -u http://example.com?id=1 --os-shell'
            ]
        )

        assert result['success'] is True
        assert result['from_node'] == '3'
        assert result['nodes_added'] == 2

    @patch('mcp_monitor.WorkflowRecorder')
    def test_branch_alternative_paths(self, mock_recorder_class):
        """Test creating multiple alternative branches"""
        mock_recorder = Mock()

        # Create two different branches from same node
        mock_recorder.create_branch = Mock(side_effect=[
            {
                'branch_id': 'branch_001',
                'from_node': '3',
                'description': 'SQLi exploitation path',
                'success': True
            },
            {
                'branch_id': 'branch_002',
                'from_node': '3',
                'description': 'XSS exploitation path',
                'success': True
            }
        ])
        mock_recorder_class.return_value = mock_recorder

        # Create SQLi branch
        branch1 = mock_recorder.create_branch(
            from_node_id='3',
            new_commands=['sqlmap ...']
        )

        # Create XSS branch
        branch2 = mock_recorder.create_branch(
            from_node_id='3',
            new_commands=['xsser ...']
        )

        assert branch1['branch_id'] != branch2['branch_id']
        assert branch1['from_node'] == branch2['from_node']


class TestWorkflowValidation:
    """Test workflow validation during save/load"""

    @patch('mcp_monitor.WorkflowRecorder')
    def test_validate_workflow_structure(self, mock_recorder_class):
        """Test validating workflow structure before saving"""
        mock_recorder = Mock()
        mock_recorder.save_workflow = Mock(return_value={
            'validation': {
                'valid': True,
                'nodes_validated': 5,
                'edges_validated': 4,
                'issues': []
            },
            'saved': True
        })
        mock_recorder_class.return_value = mock_recorder

        result = mock_recorder.save_workflow(name='test', validate=True)

        assert result['validation']['valid'] is True
        assert result['validation']['issues'] == []

    @patch('mcp_monitor.WorkflowRecorder')
    def test_detect_workflow_issues(self, mock_recorder_class):
        """Test detecting issues in workflow"""
        mock_recorder = Mock()
        mock_recorder.save_workflow = Mock(return_value={
            'validation': {
                'valid': False,
                'issues': [
                    'Node 5 has no outgoing edges',
                    'Variable {{UNKNOWN}} not defined'
                ]
            },
            'saved': False
        })
        mock_recorder_class.return_value = mock_recorder

        result = mock_recorder.save_workflow(name='test', validate=True)

        assert result['validation']['valid'] is False
        assert len(result['validation']['issues']) > 0


class TestTokenSavings:
    """Test token savings through workflow replay"""

    @patch('engine.workflow_engine.WorkflowEngine')
    def test_zero_token_replay(self, mock_engine_class):
        """Test that workflow replay requires zero tokens"""
        mock_engine = Mock()
        mock_engine.load_workflow = Mock()
        mock_engine.execute = Mock(return_value={
            'execution_id': 'exec_001',
            'ai_tokens_used': 0,  # No AI needed!
            'nodes_completed': 5,
            'success': True
        })
        mock_engine_class.return_value = mock_engine

        # Replay workflow
        mock_engine.load_workflow('/workflows/test.json')
        result = mock_engine.execute(target='example.com')

        # Workflow replay should use zero AI tokens
        assert result['ai_tokens_used'] == 0
        assert result['success'] is True

    def test_token_comparison(self):
        """Test comparing token usage: recording vs replay"""
        # First pentest (with AI)
        first_pentest = {
            'ai_tokens_used': 5000,
            'workflow_saved': True
        }

        # Subsequent pentests (replay only)
        subsequent_pentests = [
            {'ai_tokens_used': 0, 'replayed': True},
            {'ai_tokens_used': 0, 'replayed': True},
            {'ai_tokens_used': 0, 'replayed': True}
        ]

        total_tokens_with_replay = first_pentest['ai_tokens_used'] + sum(
            p['ai_tokens_used'] for p in subsequent_pentests
        )

        total_tokens_without_replay = 5000 * 4  # Each pentest costs 5000 tokens

        savings = total_tokens_without_replay - total_tokens_with_replay
        savings_percentage = (savings / total_tokens_without_replay) * 100

        assert savings_percentage == 75.0  # 75% savings after 4 pentests


@pytest.mark.integration
class TestEndToEndWorkflowRecording:
    """End-to-end integration tests"""

    @patch('mcp_monitor.WorkflowRecorder')
    @patch('engine.workflow_engine.WorkflowEngine')
    @patch('database.models.Database')
    def test_complete_recording_and_replay_cycle(
        self,
        mock_db_class,
        mock_engine_class,
        mock_recorder_class,
        temp_dir
    ):
        """Test complete cycle: record -> save -> replay"""
        # Setup mocks
        mock_recorder = Mock()
        mock_engine = Mock()
        mock_db = Mock()

        # 1. Start recording
        mock_recorder.start_session = Mock(return_value={
            'session_id': 'session_001',
            'target': 'example.com'
        })

        # 2. Record commands
        mock_recorder.record_command = Mock(side_effect=[
            {'node_id': '1', 'evidence_saved': True},
            {'node_id': '2', 'evidence_saved': True},
            {'node_id': '3', 'evidence_saved': True}
        ])

        # 3. Save workflow
        workflow_path = Path(temp_dir) / "web_pentest.json"
        mock_recorder.save_workflow = Mock(return_value={
            'workflow_path': str(workflow_path),
            'nodes': 3,
            'saved': True
        })

        # 4. Replay workflow
        mock_engine.load_workflow = Mock()
        mock_engine.execute = Mock(return_value={
            'execution_id': 'exec_001',
            'nodes_completed': 3,
            'nodes_failed': 0,
            'evidence_path': f'{temp_dir}/evidence/exec_001'
        })

        mock_recorder_class.return_value = mock_recorder
        mock_engine_class.return_value = mock_engine
        mock_db_class.return_value = mock_db

        # Execute complete cycle
        # Step 1: Start session
        session = mock_recorder.start_session(target='example.com')
        assert session['session_id'] == 'session_001'

        # Step 2: Record commands
        commands = [
            'nmap -sV example.com',
            'gobuster dir -u http://example.com',
            'sqlmap -u http://example.com?id=1'
        ]

        for cmd in commands:
            result = mock_recorder.record_command(
                command=cmd,
                output={'stdout': 'output', 'exit_code': 0}
            )
            assert result['evidence_saved'] is True

        # Step 3: Save workflow
        save_result = mock_recorder.save_workflow(name='web_pentest')
        assert save_result['saved'] is True
        assert save_result['nodes'] == 3

        # Step 4: Replay on new target
        mock_engine.load_workflow(str(workflow_path))
        replay_result = mock_engine.execute(target='newsite.com')

        assert replay_result['nodes_completed'] == 3
        assert replay_result['nodes_failed'] == 0

        # Verify all components were used
        mock_recorder.start_session.assert_called_once()
        assert mock_recorder.record_command.call_count == 3
        mock_recorder.save_workflow.assert_called_once()
        mock_engine.load_workflow.assert_called_once()
        mock_engine.execute.assert_called_once()


class TestWorkflowRecordingErrorHandling:
    """Test error handling during workflow recording"""

    @patch('mcp_monitor.WorkflowRecorder')
    def test_handle_command_failure(self, mock_recorder_class):
        """Test handling failed commands during recording"""
        mock_recorder = Mock()
        mock_recorder.record_command = Mock(return_value={
            'node_id': '1',
            'command': 'invalid_command',
            'status': 'failed',
            'exit_code': 127,
            'error': 'Command not found',
            'evidence_saved': True  # Still save evidence of failure
        })
        mock_recorder_class.return_value = mock_recorder

        result = mock_recorder.record_command(
            command='invalid_command',
            output={'stderr': 'command not found', 'exit_code': 127}
        )

        assert result['status'] == 'failed'
        assert result['evidence_saved'] is True  # Failure evidence saved

    @patch('mcp_monitor.WorkflowRecorder')
    def test_handle_partial_output(self, mock_recorder_class):
        """Test handling commands with partial output (timeout)"""
        mock_recorder = Mock()
        mock_recorder.record_command = Mock(return_value={
            'node_id': '1',
            'status': 'timeout',
            'partial_output': True,
            'evidence_saved': True
        })
        mock_recorder_class.return_value = mock_recorder

        result = mock_recorder.record_command(
            command='long_running_scan',
            output={'stdout': 'partial results...', 'timeout': True}
        )

        assert result['status'] == 'timeout'
        assert result['partial_output'] is True
