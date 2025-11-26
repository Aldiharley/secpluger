"""
SecPluger Database Models
SQLite database for findings and evidence tracking
"""

import sqlite3
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any
import json


class Database:
    """Simple SQLite database manager"""

    def __init__(self, db_path: str = "secpluger.db"):
        self.db_path = db_path
        self.conn = None
        self.init_database()

    def init_database(self):
        """Initialize database schema"""
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row  # Return rows as dictionaries

        cursor = self.conn.cursor()

        # Findings table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                execution_id TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                severity TEXT CHECK(severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')),
                category TEXT,
                cvss_score REAL,
                cve TEXT,
                target TEXT,
                port INTEGER,
                service TEXT,
                status TEXT CHECK(status IN ('OPEN', 'CONFIRMED', 'FALSE_POSITIVE', 'REMEDIATED')) DEFAULT 'OPEN',
                raw_output TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Evidence table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                execution_id TEXT NOT NULL,
                finding_id INTEGER,
                type TEXT CHECK(type IN ('screenshot', 'log', 'packet_capture', 'file')),
                filename TEXT NOT NULL,
                filepath TEXT NOT NULL,
                size INTEGER,
                mime_type TEXT,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE CASCADE
            )
        ''')

        # Executions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS executions (
                id TEXT PRIMARY KEY,
                workflow_name TEXT,
                target TEXT,
                status TEXT CHECK(status IN ('PENDING', 'RUNNING', 'COMPLETED', 'FAILED')),
                started_at TIMESTAMP,
                finished_at TIMESTAMP,
                evidence_path TEXT,
                error TEXT
            )
        ''')

        self.conn.commit()

    def add_finding(self, **kwargs) -> int:
        """Add a new finding"""
        cursor = self.conn.cursor()

        fields = ['execution_id', 'title', 'description', 'severity', 'category',
                 'cvss_score', 'cve', 'target', 'port', 'service', 'status', 'raw_output']

        values = [kwargs.get(field) for field in fields]
        placeholders = ', '.join(['?' for _ in fields])

        cursor.execute(f'''
            INSERT INTO findings ({', '.join(fields)})
            VALUES ({placeholders})
        ''', values)

        self.conn.commit()
        return cursor.lastrowid

    def get_findings(self, execution_id: Optional[str] = None,
                    severity: Optional[str] = None,
                    status: Optional[str] = None) -> List[Dict]:
        """Get findings with optional filters"""
        cursor = self.conn.cursor()

        query = "SELECT * FROM findings WHERE 1=1"
        params = []

        if execution_id:
            query += " AND execution_id = ?"
            params.append(execution_id)

        if severity:
            query += " AND severity = ?"
            params.append(severity)

        if status:
            query += " AND status = ?"
            params.append(status)

        query += " ORDER BY severity ASC, created_at DESC"

        cursor.execute(query, params)
        return [dict(row) for row in cursor.fetchall()]

    def update_finding_status(self, finding_id: int, status: str):
        """Update finding status"""
        cursor = self.conn.cursor()
        cursor.execute('''
            UPDATE findings
            SET status = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (status, finding_id))
        self.conn.commit()

    def add_evidence(self, **kwargs) -> int:
        """Add evidence file"""
        cursor = self.conn.cursor()

        cursor.execute('''
            INSERT INTO evidence (execution_id, finding_id, type, filename, filepath, size, mime_type, description)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            kwargs.get('execution_id'),
            kwargs.get('finding_id'),
            kwargs.get('type'),
            kwargs.get('filename'),
            kwargs.get('filepath'),
            kwargs.get('size'),
            kwargs.get('mime_type'),
            kwargs.get('description')
        ))

        self.conn.commit()
        return cursor.lastrowid

    def get_evidence(self, execution_id: Optional[str] = None,
                    finding_id: Optional[int] = None) -> List[Dict]:
        """Get evidence files"""
        cursor = self.conn.cursor()

        query = "SELECT * FROM evidence WHERE 1=1"
        params = []

        if execution_id:
            query += " AND execution_id = ?"
            params.append(execution_id)

        if finding_id:
            query += " AND finding_id = ?"
            params.append(finding_id)

        query += " ORDER BY created_at DESC"

        cursor.execute(query, params)
        return [dict(row) for row in cursor.fetchall()]

    def add_execution(self, **kwargs) -> str:
        """Record workflow execution"""
        cursor = self.conn.cursor()

        cursor.execute('''
            INSERT INTO executions (id, workflow_name, target, status, started_at, evidence_path)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            kwargs.get('id'),
            kwargs.get('workflow_name'),
            kwargs.get('target'),
            kwargs.get('status', 'PENDING'),
            kwargs.get('started_at'),
            kwargs.get('evidence_path')
        ))

        self.conn.commit()
        return kwargs.get('id')

    def update_execution(self, execution_id: str, **kwargs):
        """Update execution record"""
        cursor = self.conn.cursor()

        updates = []
        params = []

        if 'status' in kwargs:
            updates.append("status = ?")
            params.append(kwargs['status'])

        if 'finished_at' in kwargs:
            updates.append("finished_at = ?")
            params.append(kwargs['finished_at'])

        if 'error' in kwargs:
            updates.append("error = ?")
            params.append(kwargs['error'])

        if updates:
            params.append(execution_id)
            query = f"UPDATE executions SET {', '.join(updates)} WHERE id = ?"
            cursor.execute(query, params)
            self.conn.commit()

    def get_executions(self, limit: int = 100) -> List[Dict]:
        """Get recent executions"""
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT * FROM executions
            ORDER BY started_at DESC
            LIMIT ?
        ''', (limit,))
        return [dict(row) for row in cursor.fetchall()]

    def get_statistics(self) -> Dict[str, Any]:
        """Get database statistics"""
        cursor = self.conn.cursor()

        # Total findings by severity
        cursor.execute('''
            SELECT severity, COUNT(*) as count
            FROM findings
            GROUP BY severity
        ''')
        severity_counts = {row['severity']: row['count'] for row in cursor.fetchall()}

        # Total executions
        cursor.execute('SELECT COUNT(*) as count FROM executions')
        total_executions = cursor.fetchone()['count']

        # Recent findings
        cursor.execute('''
            SELECT COUNT(*) as count
            FROM findings
            WHERE created_at > datetime('now', '-7 days')
        ''')
        recent_findings = cursor.fetchone()['count']

        return {
            'total_executions': total_executions,
            'total_findings': sum(severity_counts.values()),
            'recent_findings_7d': recent_findings,
            'severity_breakdown': severity_counts
        }

    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()


if __name__ == "__main__":
    # Test the database
    db = Database("test.db")

    # Add a test finding
    finding_id = db.add_finding(
        execution_id="test_001",
        title="SQL Injection Found",
        description="SQL injection vulnerability in login form",
        severity="CRITICAL",
        category="SQLi",
        cvss_score=9.8,
        target="example.com",
        port=80,
        service="http",
        raw_output="sqlmap output here..."
    )

    print(f"Created finding: {finding_id}")

    # Get findings
    findings = db.get_findings()
    print(f"\nFindings: {len(findings)}")
    for f in findings:
        print(f"  - {f['title']} ({f['severity']})")

    # Get statistics
    stats = db.get_statistics()
    print(f"\nStatistics: {stats}")

    db.close()
