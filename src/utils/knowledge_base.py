"""
SecPluger Knowledge Base and Auto-Research Module
==================================================

This module provides intelligent auto-research capabilities that activate
when pentesting gets stuck. It automatically searches:
- NVD for CVE information
- HackTricks for methodology and techniques
- ExploitDB references
- Known attack patterns

When stuck (multiple failed attempts), it automatically suggests next steps.
"""

import logging
from typing import Dict, List, Optional, Tuple
from pathlib import Path
import json
import re

try:
    from .nvd_api import get_nvd_client
    from .hacktricks_search import get_hacktricks_search
except ImportError:
    import sys
    sys.path.append(str(Path(__file__).parent))
    from nvd_api import get_nvd_client
    from hacktricks_search import get_hacktricks_search

logger = logging.getLogger(__name__)


class KnowledgeBase:
    """
    Intelligent knowledge base that provides context-aware suggestions
    and automatically researches when stuck
    """

    def __init__(self):
        self.nvd = get_nvd_client()
        self.hacktricks = get_hacktricks_search()

        # Track failures to detect "stuck" state
        self.failure_count = {}  # {context: count}
        self.stuck_threshold = 3

        # Common vulnerability patterns
        self.vuln_patterns = {
            'ldap injection': r'ldap|directory|bind',
            'sql injection': r'sql|mysql|mssql|postgresql|oracle',
            'xss': r'script|javascript|cross.site',
            'command injection': r'command|exec|shell|rce',
            'file inclusion': r'file|include|require|lfi|rfi',
            'ssrf': r'request|fetch|url|http',
            'xxe': r'xml|entity|dtd',
            'ssti': r'template|jinja|twig',
            'deserialization': r'serial|pickle|unmarshal',
            'path traversal': r'path|directory|\.\./',
        }

    def detect_vulnerability_type(self, context: str) -> List[str]:
        """
        Detect potential vulnerability types from context

        Args:
            context: Context string (error message, response, etc.)

        Returns:
            List of potential vulnerability types
        """
        detected = []
        context_lower = context.lower()

        for vuln_type, pattern in self.vuln_patterns.items():
            if re.search(pattern, context_lower):
                detected.append(vuln_type)

        return detected

    def research_service(self, service: str, version: Optional[str] = None, port: Optional[int] = None) -> Dict:
        """
        Research a service for vulnerabilities and attack methods

        Args:
            service: Service name (e.g., 'IIS', 'Apache', 'SMB')
            version: Service version (e.g., '10.0')
            port: Service port

        Returns:
            Dict with CVEs, attack methods, and suggestions
        """
        logger.info(f"[*] Researching {service} {version or ''} on port {port or 'unknown'}")

        results = {
            'service': service,
            'version': version,
            'port': port,
            'cves': [],
            'attack_methods': [],
            'hacktricks_url': None,
            'suggestions': []
        }

        # Search NVD for CVEs
        if version:
            search_term = f"{service} {version}"
        else:
            search_term = service

        try:
            cves = self.nvd.search_by_keyword(search_term, max_results=5)
            results['cves'] = cves
            logger.info(f"[+] Found {len(cves)} CVEs for {service}")
        except Exception as e:
            logger.error(f"[-] NVD search error: {e}")

        # Search HackTricks for methodology
        try:
            hacktricks_result = self.hacktricks.search(service.lower())
            if hacktricks_result:
                results['hacktricks_url'] = hacktricks_result['url']
                results['attack_methods'] = hacktricks_result.get('commands', [])
                logger.info(f"[+] Found HackTricks methodology")
        except Exception as e:
            logger.error(f"[-] HackTricks search error: {e}")

        # Get port-based suggestions
        if port:
            try:
                suggestions = self.hacktricks.get_suggestions(service, port)
                results['suggestions'] = suggestions
            except Exception as e:
                logger.error(f"[-] Error getting suggestions: {e}")

        return results

    def research_cve(self, cve_id: str) -> Optional[Dict]:
        """
        Get detailed information about a CVE

        Args:
            cve_id: CVE identifier (e.g., 'CVE-2024-26219')

        Returns:
            Dict with CVE details
        """
        logger.info(f"[*] Researching {cve_id}")

        try:
            cve_data = self.nvd.get_cve(cve_id)
            return cve_data
        except Exception as e:
            logger.error(f"[-] Error fetching CVE: {e}")
            return None

    def research_attack(self, attack_type: str) -> Optional[str]:
        """
        Get methodology for a specific attack type

        Args:
            attack_type: Attack type (e.g., 'LDAP injection', 'Kerberoasting')

        Returns:
            Formatted methodology text
        """
        logger.info(f"[*] Researching attack: {attack_type}")

        try:
            methodology = self.hacktricks.get_methodology(attack_type)
            return methodology
        except Exception as e:
            logger.error(f"[-] Error fetching methodology: {e}")
            return None

    def record_failure(self, context: str):
        """
        Record a failed attempt

        Args:
            context: Context identifier (e.g., 'login_bruteforce', 'sqli_test')
        """
        if context not in self.failure_count:
            self.failure_count[context] = 0

        self.failure_count[context] += 1

        logger.debug(f"[*] Failure count for '{context}': {self.failure_count[context]}")

    def is_stuck(self, context: str) -> bool:
        """
        Check if we're stuck (too many failures)

        Args:
            context: Context identifier

        Returns:
            True if stuck, False otherwise
        """
        return self.failure_count.get(context, 0) >= self.stuck_threshold

    def auto_research(self, context: str, details: Dict) -> Dict:
        """
        Automatically research when stuck

        Args:
            context: What we're stuck on
            details: Dict with context details (service, version, errors, etc.)

        Returns:
            Dict with research results and suggestions
        """
        logger.info(f"[!] Auto-research activated for: {context}")

        results = {
            'context': context,
            'stuck_count': self.failure_count.get(context, 0),
            'cves': [],
            'methodologies': [],
            'suggestions': [],
            'next_steps': []
        }

        # Extract relevant information from details
        service = details.get('service')
        version = details.get('version')
        port = details.get('port')
        error_msg = details.get('error')
        vuln_type = details.get('vulnerability_type')

        # Research service if provided
        if service:
            service_research = self.research_service(service, version, port)
            results['cves'].extend(service_research['cves'])
            results['suggestions'].extend(service_research['suggestions'])

            if service_research['hacktricks_url']:
                results['methodologies'].append({
                    'type': f'{service} pentesting',
                    'url': service_research['hacktricks_url'],
                    'commands': service_research['attack_methods']
                })

        # Detect vulnerability type from error message
        if error_msg:
            detected_vulns = self.detect_vulnerability_type(error_msg)
            for vuln in detected_vulns:
                methodology = self.research_attack(vuln)
                if methodology:
                    results['methodologies'].append({
                        'type': vuln,
                        'content': methodology
                    })

        # Research specific vulnerability type if provided
        if vuln_type:
            methodology = self.research_attack(vuln_type)
            if methodology:
                results['methodologies'].append({
                    'type': vuln_type,
                    'content': methodology
                })

        # Generate next steps based on what we found
        results['next_steps'] = self._generate_next_steps(context, details, results)

        logger.info(f"[+] Auto-research complete: {len(results['cves'])} CVEs, {len(results['methodologies'])} methodologies")

        return results

    def _generate_next_steps(self, context: str, details: Dict, research_results: Dict) -> List[str]:
        """Generate suggested next steps based on research"""
        next_steps = []

        # Based on CVEs found
        if research_results['cves']:
            high_severity_cves = [cve for cve in research_results['cves']
                                   if cve['severity'] in ['CRITICAL', 'HIGH']]
            if high_severity_cves:
                for cve in high_severity_cves[:3]:
                    next_steps.append(f"Test for {cve['id']} ({cve['severity']}): {cve['description'][:100]}")

        # Based on suggestions
        if research_results['suggestions']:
            for suggestion in research_results['suggestions'][:5]:
                next_steps.append(f"Try: {suggestion}")

        # Context-specific suggestions
        if 'login' in context.lower():
            next_steps.extend([
                "Try default credentials for the service",
                "Check for username enumeration via timing attacks",
                "Test for SQL injection in login form",
                "Look for password reset functionality",
                "Check for OAuth/SSO misconfigurations"
            ])
        elif 'privesc' in context.lower() or 'privilege' in context.lower():
            next_steps.extend([
                "Run automated enumeration (LinPEAS/WinPEAS)",
                "Check for SUID binaries (Linux) or weak service permissions (Windows)",
                "Look for kernel exploits matching OS version",
                "Check sudo/admin group memberships",
                "Search for credentials in config files"
            ])
        elif 'web' in context.lower() or 'http' in context.lower():
            next_steps.extend([
                "Run vulnerability scanner (nuclei/wapiti)",
                "Check robots.txt and sitemap.xml",
                "Fuzz for hidden directories and files",
                "Test common injection points (SQL, XSS, command)",
                "Check for known CVEs in detected frameworks/versions"
            ])

        # If we found HackTricks methodologies
        if research_results['methodologies']:
            for method in research_results['methodologies'][:2]:
                next_steps.append(f"Review methodology: {method['type']}")

        return next_steps[:10]  # Limit to top 10 suggestions

    def format_research_report(self, research: Dict) -> str:
        """Format research results into readable report"""
        lines = []
        lines.append("=" * 70)
        lines.append("SECPLUGER AUTO-RESEARCH REPORT")
        lines.append("=" * 70)
        lines.append(f"\nContext: {research['context']}")
        lines.append(f"Stuck Count: {research['stuck_count']}")

        if research['cves']:
            lines.append(f"\n{'=' * 70}")
            lines.append("RELEVANT CVEs:")
            lines.append("=" * 70)
            for cve in research['cves']:
                lines.append(f"\n{cve['id']} - {cve['severity']}")
                lines.append(f"  {cve['description'][:200]}...")
                if cve['cvss_v3']:
                    lines.append(f"  CVSS: {cve['cvss_v3'].get('baseScore', 'N/A')}")
                if cve['exploit_available']:
                    lines.append(f"  ⚠️  PUBLIC EXPLOIT AVAILABLE")

        if research['methodologies']:
            lines.append(f"\n{'=' * 70}")
            lines.append("ATTACK METHODOLOGIES:")
            lines.append("=" * 70)
            for method in research['methodologies']:
                lines.append(f"\n{method['type'].upper()}:")
                if 'url' in method:
                    lines.append(f"  URL: {method['url']}")
                if 'commands' in method and method['commands']:
                    lines.append(f"  Key Commands:")
                    for cmd in method['commands'][:5]:
                        lines.append(f"    - {cmd}")

        if research['next_steps']:
            lines.append(f"\n{'=' * 70}")
            lines.append("SUGGESTED NEXT STEPS:")
            lines.append("=" * 70)
            for i, step in enumerate(research['next_steps'], 1):
                lines.append(f"\n{i}. {step}")

        lines.append(f"\n{'=' * 70}")

        return '\n'.join(lines)

    def reset_context(self, context: str):
        """Reset failure count for a context"""
        if context in self.failure_count:
            del self.failure_count[context]
        logger.debug(f"[*] Reset failure count for '{context}'")


# Singleton instance
_knowledge_base = None

def get_knowledge_base() -> KnowledgeBase:
    """Get or create knowledge base singleton"""
    global _knowledge_base
    if _knowledge_base is None:
        _knowledge_base = KnowledgeBase()
    return _knowledge_base


# CLI interface for testing
if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO)

    kb = get_knowledge_base()

    if len(sys.argv) > 2:
        command = sys.argv[1]

        if command == 'service':
            service = sys.argv[2]
            version = sys.argv[3] if len(sys.argv) > 3 else None
            port = int(sys.argv[4]) if len(sys.argv) > 4 else None

            results = kb.research_service(service, version, port)
            print(json.dumps(results, indent=2))

        elif command == 'cve':
            cve_id = sys.argv[2]
            cve_data = kb.research_cve(cve_id)
            if cve_data:
                print(kb.nvd.format_cve_report(cve_data))

        elif command == 'attack':
            attack_type = ' '.join(sys.argv[2:])
            methodology = kb.research_attack(attack_type)
            if methodology:
                print(methodology)

        elif command == 'stuck':
            # Simulate being stuck
            context = sys.argv[2]
            details = {
                'service': sys.argv[3] if len(sys.argv) > 3 else None,
                'version': sys.argv[4] if len(sys.argv) > 4 else None,
            }

            # Simulate failures
            for i in range(3):
                kb.record_failure(context)

            # Auto-research
            research = kb.auto_research(context, details)
            print(kb.format_research_report(research))

    else:
        print("Usage:")
        print("  python3 knowledge_base.py service <name> [version] [port]")
        print("  python3 knowledge_base.py cve <CVE-ID>")
        print("  python3 knowledge_base.py attack <attack_type>")
        print("  python3 knowledge_base.py stuck <context> [service] [version]")
        print("\nExamples:")
        print("  python3 knowledge_base.py service IIS 10.0 443")
        print("  python3 knowledge_base.py cve CVE-2024-26219")
        print("  python3 knowledge_base.py attack 'LDAP injection'")
        print("  python3 knowledge_base.py stuck login_attempts IIS 10.0")
