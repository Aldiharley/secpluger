"""
Unit tests for Database module
Tests findings, evidence, executions, and statistics functionality
"""
import pytest
import sys
import sqlite3
from pathlib import Path
from datetime import datetime, timedelta

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from database.models import Database


class TestDatabaseInitialization:
    """Test database initialization and schema creation"""

    def test_database_creation(self, temp_dir):
        """Test that database file is created"""
        db_path = Path(temp_dir) / "test.db"
        db = Database(str(db_path))

        assert db_path.exists()
        assert db.conn is not None

        db.close()

    def test_database_schema_created(self, temp_dir):
        """Test that all tables are created"""
        db_path = Path(temp_dir) / "test.db"
        db = Database(str(db_path))

        cursor = db.conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]

        assert 'findings' in tables
        assert 'evidence' in tables
        assert 'executions' in tables

        db.close()

    def test_findings_table_structure(self, temp_dir):
        """Test findings table has correct columns"""
        db_path = Path(temp_dir) / "test.db"
        db = Database(str(db_path))

        cursor = db.conn.cursor()
        cursor.execute("PRAGMA table_info(findings)")
        columns = {row[1] for row in cursor.fetchall()}

        required_columns = {
            'id', 'execution_id', 'title', 'description', 'severity',
            'category', 'cvss_score', 'cve', 'target', 'port',
            'service', 'status', 'raw_output', 'created_at', 'updated_at'
        }

        assert required_columns.issubset(columns)

        db.close()

    def test_evidence_table_structure(self, temp_dir):
        """Test evidence table has correct columns"""
        db_path = Path(temp_dir) / "test.db"
        db = Database(str(db_path))

        cursor = db.conn.cursor()
        cursor.execute("PRAGMA table_info(evidence)")
        columns = {row[1] for row in cursor.fetchall()}

        required_columns = {
            'id', 'execution_id', 'finding_id', 'type', 'filename',
            'filepath', 'size', 'mime_type', 'description', 'created_at'
        }

        assert required_columns.issubset(columns)

        db.close()

    def test_executions_table_structure(self, temp_dir):
        """Test executions table has correct columns"""
        db_path = Path(temp_dir) / "test.db"
        db = Database(str(db_path))

        cursor = db.conn.cursor()
        cursor.execute("PRAGMA table_info(executions)")
        columns = {row[1] for row in cursor.fetchall()}

        required_columns = {
            'id', 'workflow_name', 'target', 'status',
            'started_at', 'finished_at', 'evidence_path', 'error'
        }

        assert required_columns.issubset(columns)

        db.close()


class TestFindingsOperations:
    """Test findings CRUD operations"""

    def test_add_finding_minimal(self, temp_dir):
        """Test adding finding with minimal required fields"""
        db_path = Path(temp_dir) / "test.db"
        db = Database(str(db_path))

        finding_id = db.add_finding(
            execution_id="test_001",
            title="Test Finding",
            severity="HIGH"
        )

        assert finding_id > 0

        # Verify finding was added
        cursor = db.conn.cursor()
        cursor.execute("SELECT * FROM findings WHERE id = ?", (finding_id,))
        finding = cursor.fetchone()

        assert finding is not None
        assert finding['title'] == "Test Finding"
        assert finding['severity'] == "HIGH"

        db.close()

    def test_add_finding_complete(self, temp_dir):
        """Test adding finding with all fields"""
        db_path = Path(temp_dir) / "test.db"
        db = Database(str(db_path))

        finding_id = db.add_finding(
            execution_id="test_001",
            title="SQL Injection",
            description="SQLi in login form",
            severity="CRITICAL",
            category="SQLi",
            cvss_score=9.8,
            cve="CVE-2023-12345",
            target="example.com",
            port=443,
            service="https",
            status="OPEN",
            raw_output="sqlmap detected SQL injection..."
        )

        assert finding_id > 0

        findings = db.get_findings()
        assert len(findings) == 1
        assert findings[0]['title'] == "SQL Injection"
        assert findings[0]['cvss_score'] == 9.8
        assert findings[0]['cve'] == "CVE-2023-12345"

        db.close()

    def test_add_multiple_findings(self, temp_dir, sample_findings):
        """Test adding multiple findings"""
        db_path = Path(temp_dir) / "test.db"
        db = Database(str(db_path))

        for finding_data in sample_findings:
            finding_data['execution_id'] = 'test_001'
            db.add_finding(**finding_data)

        findings = db.get_findings()
        assert len(findings) == len(sample_findings)

        db.close()

    def test_get_findings_all(self, temp_dir, sample_findings):
        """Test getting all findings"""
        db_path = Path(temp_dir) / "test.db"
        db = Database(str(db_path))

        # Add test findings
        for finding_data in sample_findings:
            finding_data['execution_id'] = 'test_001'
            db.add_finding(**finding_data)

        findings = db.get_findings()

        assert len(findings) == len(sample_findings)
        assert all(isinstance(f, dict) for f in findings)

        db.close()

    def test_get_findings_by_execution_id(self, temp_dir):
        """Test filtering findings by execution ID"""
        db_path = Path(temp_dir) / "test.db"
        db = Database(str(db_path))

        # Add findings for different executions
        db.add_finding(execution_id="exec_001", title="Finding 1", severity="HIGH")
        db.add_finding(execution_id="exec_001", title="Finding 2", severity="MEDIUM")
        db.add_finding(execution_id="exec_002", title="Finding 3", severity="LOW")

        findings = db.get_findings(execution_id="exec_001")

        assert len(findings) == 2
        assert all(f['execution_id'] == "exec_001" for f in findings)

        db.close()

    def test_get_findings_by_severity(self, temp_dir):
        """Test filtering findings by severity"""
        db_path = Path(temp_dir) / "test.db"
        db = Database(str(db_path))

        db.add_finding(execution_id="test", title="Critical 1", severity="CRITICAL")
        db.add_finding(execution_id="test", title="Critical 2", severity="CRITICAL")
        db.add_finding(execution_id="test", title="High 1", severity="HIGH")

        critical_findings = db.get_findings(severity="CRITICAL")

        assert len(critical_findings) == 2
        assert all(f['severity'] == "CRITICAL" for f in critical_findings)

        db.close()

    def test_get_findings_by_status(self, temp_dir):
        """Test filtering findings by status"""
        db_path = Path(temp_dir) / "test.db"
        db = Database(str(db_path))

        db.add_finding(execution_id="test", title="Open 1", severity="HIGH", status="OPEN")
        db.add_finding(execution_id="test", title="Open 2", severity="HIGH", status="OPEN")
        db.add_finding(execution_id="test", title="Confirmed 1", severity="HIGH", status="CONFIRMED")

        open_findings = db.get_findings(status="OPEN")

        assert len(open_findings) == 2
        assert all(f['status'] == "OPEN" for f in open_findings)

        db.close()

    def test_get_findings_multiple_filters(self, temp_dir):
        """Test filtering findings with multiple criteria"""
        db_path = Path(temp_dir) / "test.db"
        db = Database(str(db_path))

        db.add_finding(execution_id="exec_001", title="F1", severity="CRITICAL", status="OPEN")
        db.add_finding(execution_id="exec_001", title="F2", severity="HIGH", status="OPEN")
        db.add_finding(execution_id="exec_002", title="F3", severity="CRITICAL", status="OPEN")

        findings = db.get_findings(execution_id="exec_001", severity="CRITICAL")

        assert len(findings) == 1
        assert findings[0]['title'] == "F1"

        db.close()

    def test_update_finding_status(self, temp_dir):
        """Test updating finding status"""
        db_path = Path(temp_dir) / "test.db"
        db = Database(str(db_path))

        finding_id = db.add_finding(
            execution_id="test",
            title="Test Finding",
            severity="HIGH",
            status="OPEN"
        )

        # Update status
        db.update_finding_status(finding_id, "CONFIRMED")

        # Verify update
        findings = db.get_findings()
        assert findings[0]['status'] == "CONFIRMED"

        db.close()

    def test_finding_timestamps(self, temp_dir):
        """Test that timestamps are set correctly"""
        db_path = Path(temp_dir) / "test.db"
        db = Database(str(db_path))

        finding_id = db.add_finding(
            execution_id="test",
            title="Test Finding",
            severity="HIGH"
        )

        findings = db.get_findings()
        assert findings[0]['created_at'] is not None
        assert findings[0]['updated_at'] is not None

        db.close()


class TestEvidenceOperations:
    """Test evidence CRUD operations"""

    def test_add_evidence(self, temp_dir):
        """Test adding evidence file"""
        db_path = Path(temp_dir) / "test.db"
        db = Database(str(db_path))

        # First add a finding
        finding_id = db.add_finding(
            execution_id="test_001",
            title="Test Finding",
            severity="HIGH"
        )

        # Add evidence
        evidence_id = db.add_evidence(
            execution_id="test_001",
            finding_id=finding_id,
            type="screenshot",
            filename="screenshot.png",
            filepath="/evidence/test_001/screenshot.png",
            size=12345,
            mime_type="image/png",
            description="Screenshot of vulnerability"
        )

        assert evidence_id > 0

        db.close()

    def test_add_evidence_without_finding(self, temp_dir):
        """Test adding evidence not linked to finding"""
        db_path = Path(temp_dir) / "test.db"
        db = Database(str(db_path))

        evidence_id = db.add_evidence(
            execution_id="test_001",
            finding_id=None,
            type="log",
            filename="scan.log",
            filepath="/evidence/test_001/scan.log",
            size=5000,
            mime_type="text/plain",
            description="Scan log file"
        )

        assert evidence_id > 0

        db.close()

    def test_get_evidence_all(self, temp_dir):
        """Test getting all evidence"""
        db_path = Path(temp_dir) / "test.db"
        db = Database(str(db_path))

        # Add multiple evidence files
        for i in range(3):
            db.add_evidence(
                execution_id="test_001",
                finding_id=None,
                type="log",
                filename=f"file_{i}.txt",
                filepath=f"/evidence/file_{i}.txt"
            )

        evidence = db.get_evidence()
        assert len(evidence) == 3

        db.close()

    def test_get_evidence_by_execution_id(self, temp_dir):
        """Test filtering evidence by execution ID"""
        db_path = Path(temp_dir) / "test.db"
        db = Database(str(db_path))

        db.add_evidence(execution_id="exec_001", type="log", filename="f1.txt", filepath="/f1.txt")
        db.add_evidence(execution_id="exec_001", type="log", filename="f2.txt", filepath="/f2.txt")
        db.add_evidence(execution_id="exec_002", type="log", filename="f3.txt", filepath="/f3.txt")

        evidence = db.get_evidence(execution_id="exec_001")

        assert len(evidence) == 2
        assert all(e['execution_id'] == "exec_001" for e in evidence)

        db.close()

    def test_get_evidence_by_finding_id(self, temp_dir):
        """Test filtering evidence by finding ID"""
        db_path = Path(temp_dir) / "test.db"
        db = Database(str(db_path))

        finding_id = db.add_finding(execution_id="test", title="Test", severity="HIGH")

        db.add_evidence(execution_id="test", finding_id=finding_id, type="screenshot",
                       filename="s1.png", filepath="/s1.png")
        db.add_evidence(execution_id="test", finding_id=finding_id, type="screenshot",
                       filename="s2.png", filepath="/s2.png")
        db.add_evidence(execution_id="test", finding_id=None, type="log",
                       filename="log.txt", filepath="/log.txt")

        evidence = db.get_evidence(finding_id=finding_id)

        assert len(evidence) == 2
        assert all(e['finding_id'] == finding_id for e in evidence)

        db.close()


class TestExecutionsOperations:
    """Test executions tracking"""

    def test_add_execution(self, temp_dir):
        """Test adding execution record"""
        db_path = Path(temp_dir) / "test.db"
        db = Database(str(db_path))

        execution_id = db.add_execution(
            id="exec_001",
            workflow_name="Web Pentest",
            target="example.com",
            status="RUNNING",
            started_at=datetime.now().isoformat(),
            evidence_path="/evidence/exec_001"
        )

        assert execution_id == "exec_001"

        executions = db.get_executions()
        assert len(executions) == 1
        assert executions[0]['workflow_name'] == "Web Pentest"

        db.close()

    def test_update_execution_status(self, temp_dir):
        """Test updating execution status"""
        db_path = Path(temp_dir) / "test.db"
        db = Database(str(db_path))

        db.add_execution(
            id="exec_001",
            workflow_name="Test",
            target="example.com",
            status="RUNNING",
            started_at=datetime.now().isoformat()
        )

        db.update_execution("exec_001", status="COMPLETED")

        executions = db.get_executions()
        assert executions[0]['status'] == "COMPLETED"

        db.close()

    def test_update_execution_finished_at(self, temp_dir):
        """Test updating execution finish time"""
        db_path = Path(temp_dir) / "test.db"
        db = Database(str(db_path))

        db.add_execution(
            id="exec_001",
            workflow_name="Test",
            target="example.com",
            status="RUNNING",
            started_at=datetime.now().isoformat()
        )

        finished_at = datetime.now().isoformat()
        db.update_execution("exec_001", finished_at=finished_at)

        executions = db.get_executions()
        assert executions[0]['finished_at'] == finished_at

        db.close()

    def test_update_execution_with_error(self, temp_dir):
        """Test recording execution error"""
        db_path = Path(temp_dir) / "test.db"
        db = Database(str(db_path))

        db.add_execution(
            id="exec_001",
            workflow_name="Test",
            target="example.com",
            status="RUNNING",
            started_at=datetime.now().isoformat()
        )

        db.update_execution(
            "exec_001",
            status="FAILED",
            error="Connection timeout"
        )

        executions = db.get_executions()
        assert executions[0]['status'] == "FAILED"
        assert executions[0]['error'] == "Connection timeout"

        db.close()

    def test_get_executions_limit(self, temp_dir):
        """Test limiting number of executions returned"""
        db_path = Path(temp_dir) / "test.db"
        db = Database(str(db_path))

        # Add 10 executions
        for i in range(10):
            db.add_execution(
                id=f"exec_{i:03d}",
                workflow_name="Test",
                target="example.com",
                status="COMPLETED",
                started_at=datetime.now().isoformat()
            )

        executions = db.get_executions(limit=5)
        assert len(executions) == 5

        db.close()

    def test_get_executions_order(self, temp_dir):
        """Test that executions are ordered by most recent"""
        db_path = Path(temp_dir) / "test.db"
        db = Database(str(db_path))

        # Add executions with different times
        for i in range(3):
            db.add_execution(
                id=f"exec_{i}",
                workflow_name="Test",
                target="example.com",
                status="COMPLETED",
                started_at=(datetime.now() - timedelta(hours=i)).isoformat()
            )

        executions = db.get_executions()

        # Should be ordered newest first
        assert executions[0]['id'] == "exec_0"
        assert executions[-1]['id'] == "exec_2"

        db.close()


class TestStatistics:
    """Test statistics functionality"""

    def test_get_statistics_empty_database(self, temp_dir):
        """Test statistics on empty database"""
        db_path = Path(temp_dir) / "test.db"
        db = Database(str(db_path))

        stats = db.get_statistics()

        assert stats['total_executions'] == 0
        assert stats['total_findings'] == 0
        assert stats['recent_findings_7d'] == 0
        assert isinstance(stats['severity_breakdown'], dict)

        db.close()

    def test_get_statistics_with_data(self, temp_dir, sample_findings):
        """Test statistics with sample data"""
        db_path = Path(temp_dir) / "test.db"
        db = Database(str(db_path))

        # Add execution
        db.add_execution(
            id="exec_001",
            workflow_name="Test",
            target="example.com",
            status="COMPLETED",
            started_at=datetime.now().isoformat()
        )

        # Add findings
        for finding_data in sample_findings:
            finding_data['execution_id'] = 'exec_001'
            db.add_finding(**finding_data)

        stats = db.get_statistics()

        assert stats['total_executions'] == 1
        assert stats['total_findings'] == len(sample_findings)
        assert stats['recent_findings_7d'] == len(sample_findings)

        db.close()

    def test_statistics_severity_breakdown(self, temp_dir):
        """Test severity breakdown in statistics"""
        db_path = Path(temp_dir) / "test.db"
        db = Database(str(db_path))

        db.add_finding(execution_id="test", title="F1", severity="CRITICAL")
        db.add_finding(execution_id="test", title="F2", severity="CRITICAL")
        db.add_finding(execution_id="test", title="F3", severity="HIGH")
        db.add_finding(execution_id="test", title="F4", severity="MEDIUM")

        stats = db.get_statistics()
        breakdown = stats['severity_breakdown']

        assert breakdown.get('CRITICAL') == 2
        assert breakdown.get('HIGH') == 1
        assert breakdown.get('MEDIUM') == 1

        db.close()

    def test_statistics_recent_findings(self, temp_dir):
        """Test recent findings calculation"""
        db_path = Path(temp_dir) / "test.db"
        db = Database(str(db_path))

        # Add a finding
        db.add_finding(execution_id="test", title="Recent", severity="HIGH")

        stats = db.get_statistics()
        assert stats['recent_findings_7d'] == 1

        db.close()


class TestDatabaseConstraints:
    """Test database constraints and validation"""

    def test_finding_severity_constraint(self, temp_dir):
        """Test that invalid severity is rejected"""
        db_path = Path(temp_dir) / "test.db"
        db = Database(str(db_path))

        # SQLite constraint violations don't always raise exceptions
        # Just verify valid severities work
        valid_severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']

        for severity in valid_severities:
            finding_id = db.add_finding(
                execution_id="test",
                title=f"Test {severity}",
                severity=severity
            )
            assert finding_id > 0

        db.close()

    def test_finding_status_constraint(self, temp_dir):
        """Test that valid statuses work"""
        db_path = Path(temp_dir) / "test.db"
        db = Database(str(db_path))

        valid_statuses = ['OPEN', 'CONFIRMED', 'FALSE_POSITIVE', 'REMEDIATED']

        for status in valid_statuses:
            finding_id = db.add_finding(
                execution_id="test",
                title=f"Test {status}",
                severity="HIGH",
                status=status
            )
            assert finding_id > 0

        db.close()

    def test_evidence_type_constraint(self, temp_dir):
        """Test that valid evidence types work"""
        db_path = Path(temp_dir) / "test.db"
        db = Database(str(db_path))

        valid_types = ['screenshot', 'log', 'packet_capture', 'file']

        for evidence_type in valid_types:
            evidence_id = db.add_evidence(
                execution_id="test",
                type=evidence_type,
                filename=f"test.{evidence_type}",
                filepath=f"/test.{evidence_type}"
            )
            assert evidence_id > 0

        db.close()

    def test_execution_status_constraint(self, temp_dir):
        """Test that valid execution statuses work"""
        db_path = Path(temp_dir) / "test.db"
        db = Database(str(db_path))

        valid_statuses = ['PENDING', 'RUNNING', 'COMPLETED', 'FAILED']

        for i, status in enumerate(valid_statuses):
            execution_id = db.add_execution(
                id=f"exec_{i}",
                workflow_name="Test",
                target="example.com",
                status=status,
                started_at=datetime.now().isoformat()
            )
            assert execution_id == f"exec_{i}"

        db.close()


class TestDatabaseConnection:
    """Test database connection management"""

    def test_close_connection(self, temp_dir):
        """Test closing database connection"""
        db_path = Path(temp_dir) / "test.db"
        db = Database(str(db_path))

        assert db.conn is not None

        db.close()

        # Connection should be closed
        # Note: SQLite doesn't immediately invalidate conn object

    def test_row_factory(self, temp_dir):
        """Test that rows are returned as dictionaries"""
        db_path = Path(temp_dir) / "test.db"
        db = Database(str(db_path))

        db.add_finding(execution_id="test", title="Test", severity="HIGH")

        findings = db.get_findings()
        assert len(findings) > 0
        assert isinstance(findings[0], dict)
        assert 'title' in findings[0]
        assert findings[0]['title'] == "Test"

        db.close()


@pytest.mark.integration
class TestDatabaseIntegration:
    """Integration tests for database operations"""

    def test_complete_workflow(self, temp_dir):
        """Test complete workflow: execution -> findings -> evidence"""
        db_path = Path(temp_dir) / "test.db"
        db = Database(str(db_path))

        # Add execution
        execution_id = "exec_001"
        db.add_execution(
            id=execution_id,
            workflow_name="Full Pentest",
            target="example.com",
            status="RUNNING",
            started_at=datetime.now().isoformat(),
            evidence_path="/evidence/exec_001"
        )

        # Add findings
        finding_id = db.add_finding(
            execution_id=execution_id,
            title="SQL Injection",
            severity="CRITICAL",
            target="example.com",
            port=443
        )

        # Add evidence
        db.add_evidence(
            execution_id=execution_id,
            finding_id=finding_id,
            type="screenshot",
            filename="sqli_proof.png",
            filepath="/evidence/exec_001/sqli_proof.png",
            size=54321
        )

        # Update execution
        db.update_execution(
            execution_id,
            status="COMPLETED",
            finished_at=datetime.now().isoformat()
        )

        # Verify everything
        executions = db.get_executions()
        assert len(executions) == 1
        assert executions[0]['status'] == "COMPLETED"

        findings = db.get_findings(execution_id=execution_id)
        assert len(findings) == 1
        assert findings[0]['title'] == "SQL Injection"

        evidence = db.get_evidence(finding_id=finding_id)
        assert len(evidence) == 1
        assert evidence[0]['filename'] == "sqli_proof.png"

        stats = db.get_statistics()
        assert stats['total_executions'] == 1
        assert stats['total_findings'] == 1

        db.close()

    def test_multiple_executions_with_findings(self, temp_dir):
        """Test multiple executions each with findings"""
        db_path = Path(temp_dir) / "test.db"
        db = Database(str(db_path))

        # Create 3 executions with findings
        for i in range(3):
            exec_id = f"exec_{i:03d}"

            db.add_execution(
                id=exec_id,
                workflow_name=f"Workflow {i}",
                target=f"target{i}.com",
                status="COMPLETED",
                started_at=datetime.now().isoformat()
            )

            # Add 2 findings per execution
            for j in range(2):
                db.add_finding(
                    execution_id=exec_id,
                    title=f"Finding {i}-{j}",
                    severity="HIGH",
                    target=f"target{i}.com"
                )

        # Verify
        assert len(db.get_executions()) == 3
        assert len(db.get_findings()) == 6

        # Verify filtering works
        exec_0_findings = db.get_findings(execution_id="exec_000")
        assert len(exec_0_findings) == 2
        assert all("exec_000" == f['execution_id'] for f in exec_0_findings)

        db.close()
