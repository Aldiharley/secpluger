"""
SecPluger Report Generator
Generate HTML/PDF reports from workflow executions
"""

from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any
import json


class ReportGenerator:
    """Generate professional pentesting reports"""

    def __init__(self, evidence_path: Path, execution_id: str):
        self.evidence_path = Path(evidence_path)
        self.execution_id = execution_id

    def generate_html_report(self, output_path: str = None) -> str:
        """Generate HTML report"""
        if not output_path:
            output_path = f"reports/{self.execution_id}_report.html"

        # Load execution summary
        summary_file = self.evidence_path / "execution_summary.json"
        if summary_file.exists():
            with open(summary_file, 'r') as f:
                summary = json.load(f)
        else:
            summary = {}

        # Load all evidence files
        evidence_files = list(self.evidence_path.glob("*.txt"))

        # Generate HTML
        html = self._generate_html_template(summary, evidence_files)

        # Save report
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            f.write(html)

        return output_path

    def _generate_html_template(self, summary: Dict, evidence_files: List[Path]) -> str:
        """Generate HTML report template"""
        workflow_name = summary.get('workflow_name', 'Unknown')
        timestamp = summary.get('timestamp', datetime.now().isoformat())
        variables = summary.get('variables', {})
        nodes = summary.get('nodes', [])

        completed = sum(1 for n in nodes if n.get('status') == 'completed')
        failed = sum(1 for n in nodes if n.get('status') == 'failed')

        html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>SecPluger Report - {workflow_name}</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 20px;
        }}
        .header h1 {{
            margin: 0;
            font-size: 2.5em;
        }}
        .header .subtitle {{
            margin-top: 10px;
            opacity: 0.9;
        }}
        .section {{
            background: white;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .section h2 {{
            color: #667eea;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
            margin-top: 0;
        }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }}
        .stat-box {{
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            border-left: 4px solid #667eea;
        }}
        .stat-label {{
            color: #6c757d;
            font-size: 0.9em;
            margin-bottom: 5px;
        }}
        .stat-value {{
            font-size: 1.8em;
            font-weight: bold;
            color: #333;
        }}
        .node {{
            background: #f8f9fa;
            padding: 15px;
            margin: 10px 0;
            border-radius: 5px;
            border-left: 4px solid #28a745;
        }}
        .node.failed {{
            border-left-color: #dc3545;
        }}
        .node-header {{
            font-weight: bold;
            margin-bottom: 5px;
        }}
        .node-status {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 3px;
            font-size: 0.85em;
            margin-left: 10px;
        }}
        .status-completed {{
            background: #d4edda;
            color: #155724;
        }}
        .status-failed {{
            background: #f8d7da;
            color: #721c24;
        }}
        .evidence {{
            background: #e9ecef;
            padding: 10px;
            margin: 10px 0;
            border-radius: 5px;
            font-family: monospace;
            font-size: 0.9em;
        }}
        .evidence-title {{
            font-weight: bold;
            margin-bottom: 5px;
        }}
        pre {{
            background: #f1f3f5;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            font-size: 0.85em;
        }}
        .footer {{
            text-align: center;
            padding: 20px;
            color: #6c757d;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>SecPluger Penetration Test Report</h1>
        <div class="subtitle">{workflow_name}</div>
        <div class="subtitle">Generated: {timestamp}</div>
    </div>

    <div class="section">
        <h2>Executive Summary</h2>
        <div class="stats">
            <div class="stat-box">
                <div class="stat-label">Target</div>
                <div class="stat-value">{variables.get('target', 'N/A')}</div>
            </div>
            <div class="stat-box">
                <div class="stat-label">Total Nodes</div>
                <div class="stat-value">{len(nodes)}</div>
            </div>
            <div class="stat-box">
                <div class="stat-label">Completed</div>
                <div class="stat-value" style="color: #28a745;">{completed}</div>
            </div>
            <div class="stat-box">
                <div class="stat-label">Failed</div>
                <div class="stat-value" style="color: #dc3545;">{failed}</div>
            </div>
        </div>
    </div>

    <div class="section">
        <h2>Workflow Execution</h2>
"""

        # Add nodes
        for node in nodes:
            status_class = 'completed' if node.get('status') == 'completed' else 'failed'
            node_class = '' if node.get('status') == 'completed' else 'failed'

            html += f"""
        <div class="node {node_class}">
            <div class="node-header">
                Node {node.get('id')}: {node.get('type')}
                <span class="node-status status-{status_class}">{node.get('status', 'unknown').upper()}</span>
            </div>
"""

            if node.get('error'):
                html += f"            <div style='color: #dc3545; margin-top: 5px;'>Error: {node.get('error')}</div>\n"

            html += "        </div>\n"

        html += "    </div>\n"

        # Add evidence
        if evidence_files:
            html += """
    <div class="section">
        <h2>Evidence</h2>
"""

            for evidence_file in evidence_files:
                with open(evidence_file, 'r') as f:
                    content = f.read()

                html += f"""
        <div class="evidence">
            <div class="evidence-title">{evidence_file.name}</div>
            <pre>{content[:2000]}{'...' if len(content) > 2000 else ''}</pre>
        </div>
"""

            html += "    </div>\n"

        # Footer
        html += """
    <div class="footer">
        Generated by SecPluger - AI-Powered Pentesting Workflow Automation<br>
        For authorized security testing only
    </div>
</body>
</html>
"""

        return html


if __name__ == "__main__":
    # Test report generation
    import sys
    if len(sys.argv) > 1:
        evidence_path = sys.argv[1]
        execution_id = Path(evidence_path).name

        gen = ReportGenerator(evidence_path, execution_id)
        report_path = gen.generate_html_report()
        print(f"Report generated: {report_path}")
    else:
        print("Usage: python report_gen.py <evidence_path>")
