"""
SecPluger mitmproxy Addon
Integrates mitmproxy with SecPluger workflow recording
"""

from mitmproxy import http, ctx
from pathlib import Path
import json
from datetime import datetime
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SecPlugerAddon:
    """
    mitmproxy addon that logs HTTP traffic to SecPluger evidence
    """

    def __init__(self):
        self.evidence_dir = None
        self.session_id = None
        self.request_count = 0
        self.vulnerabilities = []

    def configure(self, updated):
        """
        Called when configuration changes
        """
        if "evidence_dir" in updated:
            self.evidence_dir = Path(ctx.options.evidence_dir)
            self.evidence_dir.mkdir(parents=True, exist_ok=True)
            logger.info(f"Evidence directory: {self.evidence_dir}")

        if "session_id" in updated:
            self.session_id = ctx.options.session_id
            logger.info(f"Session ID: {self.session_id}")

    def request(self, flow: http.HTTPFlow):
        """
        Called when a request is received
        """
        self.request_count += 1

        # Log request
        logger.info(f"Request #{self.request_count}: {flow.request.method} {flow.request.pretty_url}")

    def response(self, flow: http.HTTPFlow):
        """
        Called when a response is received
        """
        # Save detailed request/response evidence
        if self.evidence_dir:
            self._save_flow_evidence(flow)

        # Check for vulnerabilities
        vulns = self._detect_vulnerabilities(flow)
        if vulns:
            self.vulnerabilities.extend(vulns)
            for vuln in vulns:
                logger.warning(f"🔍 Vulnerability detected: {vuln['type']}")

    def _save_flow_evidence(self, flow: http.HTTPFlow):
        """
        Save flow as evidence file
        """
        try:
            evidence_file = self.evidence_dir / f"flow_{self.request_count:04d}.json"

            flow_data = {
                'request_count': self.request_count,
                'timestamp': datetime.now().isoformat(),
                'request': {
                    'method': flow.request.method,
                    'url': flow.request.pretty_url,
                    'http_version': flow.request.http_version,
                    'headers': dict(flow.request.headers),
                    'content': flow.request.text if flow.request.text else None,
                },
                'response': {
                    'status_code': flow.response.status_code,
                    'reason': flow.response.reason,
                    'http_version': flow.response.http_version,
                    'headers': dict(flow.response.headers),
                    'content_length': len(flow.response.content) if flow.response.content else 0,
                    'content_type': flow.response.headers.get('content-type', 'unknown'),
                    # Save response text for text-based content
                    'content': flow.response.text[:5000] if flow.response.text and len(flow.response.text) < 10000 else None,
                } if flow.response else None,
                'duration': flow.response.timestamp_end - flow.request.timestamp_start if flow.response else None,
            }

            with open(evidence_file, 'w') as f:
                json.dump(flow_data, f, indent=2)

        except Exception as e:
            logger.error(f"Failed to save flow evidence: {e}")

    def _detect_vulnerabilities(self, flow: http.HTTPFlow) -> list:
        """
        Auto-detect potential vulnerabilities from HTTP traffic
        """
        if not flow.response:
            return []

        vulnerabilities = []

        # Check for SQL injection patterns in responses
        if 'sql' in flow.response.text.lower() or 'mysql' in flow.response.text.lower():
            if 'error' in flow.response.text.lower() or 'syntax' in flow.response.text.lower():
                vulnerabilities.append({
                    'type': 'Potential SQL Injection',
                    'severity': 'HIGH',
                    'url': flow.request.pretty_url,
                    'evidence': 'SQL error messages in response'
                })

        # Check for sensitive information disclosure
        if any(keyword in flow.response.text.lower() for keyword in ['password', 'api_key', 'secret', 'token']):
            vulnerabilities.append({
                'type': 'Sensitive Information Disclosure',
                'severity': 'MEDIUM',
                'url': flow.request.pretty_url,
                'evidence': 'Sensitive keywords found in response'
            })

        # Check for missing security headers
        if flow.response.status_code == 200:
            missing_headers = []
            security_headers = [
                'X-Frame-Options',
                'X-Content-Type-Options',
                'X-XSS-Protection',
                'Strict-Transport-Security',
                'Content-Security-Policy'
            ]
            for header in security_headers:
                if header not in flow.response.headers:
                    missing_headers.append(header)

            if missing_headers:
                vulnerabilities.append({
                    'type': 'Missing Security Headers',
                    'severity': 'LOW',
                    'url': flow.request.pretty_url,
                    'evidence': f'Missing: {", ".join(missing_headers)}'
                })

        # Check for error pages with stack traces
        if flow.response.status_code >= 500:
            if any(keyword in flow.response.text for keyword in ['Traceback', 'Exception', 'Stack trace']):
                vulnerabilities.append({
                    'type': 'Information Leakage',
                    'severity': 'MEDIUM',
                    'url': flow.request.pretty_url,
                    'evidence': 'Server error with stack trace'
                })

        return vulnerabilities

    def done(self):
        """
        Called when mitmproxy is shutting down
        """
        # Save vulnerability summary
        if self.vulnerabilities and self.evidence_dir:
            summary_file = self.evidence_dir / "vulnerability_summary.json"
            with open(summary_file, 'w') as f:
                json.dump({
                    'session_id': self.session_id,
                    'total_requests': self.request_count,
                    'vulnerabilities': self.vulnerabilities,
                    'timestamp': datetime.now().isoformat()
                }, f, indent=2)

            logger.info(f"Saved vulnerability summary: {summary_file}")
            logger.info(f"Total requests: {self.request_count}")
            logger.info(f"Vulnerabilities found: {len(self.vulnerabilities)}")


# mitmproxy addon entry point
addons = [SecPlugerAddon()]
