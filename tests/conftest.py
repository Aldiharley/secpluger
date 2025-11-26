"""
Pytest configuration and shared fixtures for SecPluger v2 tests
"""
import pytest
import sys
import tempfile
import shutil
from pathlib import Path
import json
import sqlite3
from datetime import datetime

# Add src directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files"""
    temp = tempfile.mkdtemp()
    yield temp
    shutil.rmtree(temp, ignore_errors=True)


@pytest.fixture
def evidence_dir(temp_dir):
    """Create a temporary evidence directory"""
    evidence = Path(temp_dir) / "evidence"
    evidence.mkdir(parents=True, exist_ok=True)
    return str(evidence)


@pytest.fixture
def test_workflow():
    """Sample workflow JSON for testing"""
    return {
        "name": "test_workflow",
        "description": "Test workflow for unit tests",
        "variables": {
            "TARGET": "example.com",
            "PORT": "80"
        },
        "nodes": [
            {
                "id": "1",
                "type": "nmap",
                "data": {
                    "command": "nmap -p {{PORT}} {{TARGET}}",
                    "description": "Port scan"
                }
            },
            {
                "id": "2",
                "type": "gobuster",
                "data": {
                    "command": "gobuster dir -u http://{{TARGET}}",
                    "description": "Directory enumeration"
                }
            }
        ],
        "edges": [
            {"from": "1", "to": "2"}
        ]
    }


@pytest.fixture
def test_workflow_file(temp_dir, test_workflow):
    """Create a temporary workflow JSON file"""
    workflow_path = Path(temp_dir) / "test_workflow.json"
    with open(workflow_path, 'w') as f:
        json.dump(test_workflow, f, indent=2)
    return str(workflow_path)


@pytest.fixture
def mock_database(temp_dir):
    """Create a temporary SQLite database for testing"""
    db_path = Path(temp_dir) / "test_findings.db"
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()

    # Create findings table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            severity TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            target TEXT,
            port INTEGER,
            cvss_score REAL,
            status TEXT DEFAULT 'NEW',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()

    return str(db_path)


@pytest.fixture
def sample_findings():
    """Sample findings data for testing"""
    return [
        {
            "severity": "CRITICAL",
            "title": "SQL Injection",
            "description": "SQL injection vulnerability found in login form",
            "target": "example.com",
            "port": 443,
            "cvss_score": 9.8,
            "status": "OPEN"
        },
        {
            "severity": "HIGH",
            "title": "XSS Vulnerability",
            "description": "Reflected XSS in search parameter",
            "target": "example.com",
            "port": 443,
            "cvss_score": 7.5,
            "status": "OPEN"
        },
        {
            "severity": "MEDIUM",
            "title": "Directory Listing",
            "description": "Directory listing enabled on /uploads/",
            "target": "example.com",
            "port": 80,
            "cvss_score": 5.3,
            "status": "OPEN"
        }
    ]


@pytest.fixture
def mock_nmap_output():
    """Mock nmap command output"""
    return """Starting Nmap 7.94 ( https://nmap.org ) at 2025-10-24 10:00 UTC
Nmap scan report for example.com (93.184.216.34)
Host is up (0.050s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT    STATE SERVICE
80/tcp  open  http
443/tcp open  https

Nmap done: 1 IP address (1 host up) scanned in 5.23 seconds"""


@pytest.fixture
def mock_gobuster_output():
    """Mock gobuster command output"""
    return """===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://example.com
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
===============================================================
2025/10/24 10:00:00 Starting gobuster in directory enumeration mode
===============================================================
/admin                (Status: 302) [Size: 0] [--> /admin/login]
/uploads              (Status: 200) [Size: 1234]
/api                  (Status: 200) [Size: 42]
===============================================================
2025/10/24 10:00:05 Finished
==============================================================="""


@pytest.fixture
def mock_sqlmap_output():
    """Mock sqlmap command output"""
    return """[*] starting @ 10:00:00
[INFO] testing connection to the target URL
[INFO] testing if the target URL content is stable
[INFO] testing if GET parameter 'id' is dynamic
[INFO] GET parameter 'id' appears to be dynamic
[INFO] heuristic (basic) test shows that GET parameter 'id' might be injectable
[INFO] testing for SQL injection on GET parameter 'id'
[INFO] GET parameter 'id' is 'MySQL >= 5.0 AND error-based - WHERE' injectable
GET parameter 'id' is vulnerable. Do you want to keep testing the others (if any)? [y/N]
sqlmap identified the following injection point(s):
---
Parameter: id (GET)
    Type: error-based
    Title: MySQL >= 5.0 AND error-based - WHERE
    Payload: id=1 AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x7e,0x27,0x7e))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)
---
[*] shutting down at 10:00:15"""


@pytest.fixture
def mock_nuclei_output():
    """Mock nuclei command output (JSON format)"""
    return json.dumps([
        {
            "template-id": "CVE-2021-41773",
            "info": {
                "name": "Apache HTTP Server 2.4.49 - Path Traversal",
                "severity": "critical",
                "description": "Apache HTTP Server 2.4.49 is susceptible to a path traversal vulnerability"
            },
            "type": "http",
            "host": "http://example.com",
            "matched-at": "http://example.com/cgi-bin/.%2e/%2e%2e/%2e%2e/etc/passwd",
            "timestamp": "2025-10-24T10:00:00Z"
        },
        {
            "template-id": "ssl-tls-version",
            "info": {
                "name": "Deprecated TLS Version Detected",
                "severity": "medium",
                "description": "Outdated TLS version in use"
            },
            "type": "ssl",
            "host": "https://example.com:443",
            "matched-at": "https://example.com:443",
            "timestamp": "2025-10-24T10:00:01Z"
        }
    ])


@pytest.fixture
def mock_crawler_results():
    """Mock web crawler results"""
    return {
        "pages": [
            "http://example.com/",
            "http://example.com/about",
            "http://example.com/contact",
            "http://example.com/products"
        ],
        "forms": [
            {
                "action": "http://example.com/login",
                "method": "POST",
                "inputs": [
                    {"name": "username", "type": "text"},
                    {"name": "password", "type": "password"}
                ]
            },
            {
                "action": "http://example.com/search",
                "method": "GET",
                "inputs": [
                    {"name": "q", "type": "text"}
                ]
            }
        ],
        "parameters": {
            "http://example.com/products": ["id", "category"],
            "http://example.com/search": ["q"]
        }
    }


@pytest.fixture
def mock_fuzzer_results():
    """Mock fuzzer results"""
    return {
        "url": "http://example.com/search",
        "parameter": "q",
        "attack_type": "xss",
        "total_payloads": 100,
        "vulnerabilities": [
            {
                "payload": "<script>alert('XSS')</script>",
                "response_code": 200,
                "evidence": "Payload reflected in response",
                "severity": "HIGH"
            }
        ],
        "timestamp": datetime.now().isoformat()
    }


@pytest.fixture(autouse=True)
def reset_singletons():
    """Reset singleton instances between tests"""
    # This ensures clean state for each test
    yield
    # Cleanup code if needed


@pytest.fixture
def mock_tool_registry():
    """Mock tool registry for testing tool manager"""
    return {
        'nmap': {
            'category': 'network_scanner',
            'install_cmd': 'sudo apt install -y nmap',
            'check_cmd': 'nmap --version',
            'description': 'Network port scanner',
            'priority': 'high'
        },
        'nuclei': {
            'category': 'web_scanner',
            'install_cmd': 'go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest',
            'check_cmd': 'nuclei --version',
            'description': 'Fast vulnerability scanner',
            'priority': 'high'
        },
        'gobuster': {
            'category': 'enumeration',
            'install_cmd': 'sudo apt install -y gobuster',
            'check_cmd': 'gobuster version',
            'description': 'Directory/file brute-forcer',
            'priority': 'high'
        },
        'testool': {
            'category': 'web_scanner',
            'install_cmd': 'sudo apt install -y testool',
            'check_cmd': 'testool --version',
            'description': 'Test tool for unit tests',
            'priority': 'medium'
        }
    }
