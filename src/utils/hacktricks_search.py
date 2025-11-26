"""
HackTricks Knowledge Base Search
=================================

This module provides search and lookup functionality for the HackTricks
penetration testing knowledge base (https://book.hacktricks.xyz).

HackTricks is a comprehensive pentesting methodology wiki covering:
- Web exploitation techniques
- Active Directory attacks
- Linux/Windows privilege escalation
- Network pentesting
- And much more
"""

import requests
import re
from typing import List, Dict, Optional
from bs4 import BeautifulSoup
import logging
from pathlib import Path
import json
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


class HackTricksSearch:
    """Search and retrieve content from HackTricks"""

    def __init__(self):
        self.base_url = "https://book.hacktricks.xyz"
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) SecPluger/2.0'
        })

        # Cache directory
        self.cache_dir = Path("cache/hacktricks")
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_expiry = timedelta(days=30)  # Cache for 30 days

        # Common attack patterns mapped to HackTricks pages
        self.attack_map = {
            # Web Attacks
            'sql injection': '/pentesting-web/sql-injection',
            'sqli': '/pentesting-web/sql-injection',
            'xss': '/pentesting-web/xss-cross-site-scripting',
            'cross-site scripting': '/pentesting-web/xss-cross-site-scripting',
            'csrf': '/pentesting-web/csrf-cross-site-request-forgery',
            'ssrf': '/pentesting-web/ssrf-server-side-request-forgery',
            'xxe': '/pentesting-web/xxe-xee-xml-external-entity',
            'ssti': '/pentesting-web/ssti-server-side-template-injection',
            'ldap injection': '/pentesting-web/ldap-injection',
            'command injection': '/pentesting-web/command-injection',
            'file upload': '/pentesting-web/file-upload',
            'file inclusion': '/pentesting-web/file-inclusion',
            'lfi': '/pentesting-web/file-inclusion',
            'rfi': '/pentesting-web/file-inclusion',
            'path traversal': '/pentesting-web/file-inclusion',
            'idor': '/pentesting-web/idor',
            'deserialization': '/pentesting-web/deserialization',

            # Active Directory
            'active directory': '/windows-hardening/active-directory-methodology',
            'ad': '/windows-hardening/active-directory-methodology',
            'kerberos': '/windows-hardening/active-directory-methodology/kerberos-authentication',
            'kerberoasting': '/windows-hardening/active-directory-methodology/kerberoast',
            'as-rep roasting': '/windows-hardening/active-directory-methodology/asreproast',
            'asreproast': '/windows-hardening/active-directory-methodology/asreproast',
            'golden ticket': '/windows-hardening/active-directory-methodology/golden-ticket',
            'silver ticket': '/windows-hardening/active-directory-methodology/silver-ticket',
            'dcsync': '/windows-hardening/active-directory-methodology/dcsync',
            'pass the hash': '/windows-hardening/ntlm/pass-the-hash',
            'pass the ticket': '/windows-hardening/active-directory-methodology/pass-the-ticket',
            'bloodhound': '/windows-hardening/active-directory-methodology/bloodhound',
            'mimikatz': '/windows-hardening/stealing-credentials',
            'ad cs': '/windows-hardening/active-directory-methodology/ad-certificates',
            'certificate': '/windows-hardening/active-directory-methodology/ad-certificates',
            'rbcd': '/windows-hardening/active-directory-methodology/resource-based-constrained-delegation',
            'delegation': '/windows-hardening/active-directory-methodology/constrained-delegation',

            # Linux PrivEsc
            'linux privilege escalation': '/linux-hardening/privilege-escalation',
            'linux privesc': '/linux-hardening/privilege-escalation',
            'suid': '/linux-hardening/privilege-escalation#suid',
            'sudo': '/linux-hardening/privilege-escalation#sudo-and-suid',
            'capabilities': '/linux-hardening/privilege-escalation/linux-capabilities',
            'cron': '/linux-hardening/privilege-escalation#cron-jobs',

            # Windows PrivEsc
            'windows privilege escalation': '/windows-hardening/windows-local-privilege-escalation',
            'windows privesc': '/windows-hardening/windows-local-privilege-escalation',
            'uac bypass': '/windows-hardening/authentication-credentials-uac-and-efs#uac',
            'token impersonation': '/windows-hardening/windows-local-privilege-escalation/privilege-escalation-abusing-tokens',

            # Network Services
            'smb': '/network-services-pentesting/pentesting-smb',
            'ftp': '/network-services-pentesting/pentesting-ftp',
            'ssh': '/network-services-pentesting/pentesting-ssh',
            'rdp': '/network-services-pentesting/pentesting-rdp',
            'winrm': '/network-services-pentesting/5985-5986-pentesting-winrm',
            'ldap': '/network-services-pentesting/pentesting-ldap',
            'nfs': '/network-services-pentesting/nfs-service-pentesting',
            'mysql': '/network-services-pentesting/pentesting-mysql',
            'mssql': '/network-services-pentesting/pentesting-mssql-microsoft-sql-server',
            'postgresql': '/network-services-pentesting/pentesting-postgresql',
            'redis': '/network-services-pentesting/6379-pentesting-redis',
            'mongodb': '/network-services-pentesting/27017-27018-mongodb',

            # Web Servers
            'iis': '/network-services-pentesting/pentesting-web/iis-internet-information-services',
            'apache': '/network-services-pentesting/pentesting-web/apache',
            'nginx': '/network-services-pentesting/pentesting-web/nginx',
            'tomcat': '/network-services-pentesting/pentesting-web/tomcat',

            # Misc
            'reverse shell': '/generic-methodologies-and-resources/shells/reverse-shell',
            'shell': '/generic-methodologies-and-resources/shells',
            'pivoting': '/generic-methodologies-and-resources/tunneling-and-port-forwarding',
            'port forwarding': '/generic-methodologies-and-resources/tunneling-and-port-forwarding',
        }

    def _get_cache_path(self, query: str) -> Path:
        """Get cache file path for a search query"""
        safe_query = re.sub(r'[^\w\-]', '_', query.lower())
        return self.cache_dir / f"{safe_query}.json"

    def _load_from_cache(self, query: str) -> Optional[Dict]:
        """Load search results from cache if not expired"""
        cache_path = self._get_cache_path(query)

        if not cache_path.exists():
            return None

        cache_age = datetime.now() - datetime.fromtimestamp(cache_path.stat().st_mtime)
        if cache_age > self.cache_expiry:
            return None

        try:
            with open(cache_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"[-] Error loading cache: {e}")
            return None

    def _save_to_cache(self, query: str, data: Dict):
        """Save search results to cache"""
        cache_path = self._get_cache_path(query)

        try:
            with open(cache_path, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"[-] Error saving cache: {e}")

    def search(self, query: str) -> Optional[Dict]:
        """
        Search HackTricks for relevant content

        Args:
            query: Search term or attack type

        Returns:
            Dict with url, title, and content summary
        """
        query_lower = query.lower()

        # Check cache first
        cached = self._load_from_cache(query)
        if cached:
            logger.info(f"[+] Loaded HackTricks result from cache")
            return cached

        # Check if we have a direct mapping
        path = None
        for keyword, mapped_path in self.attack_map.items():
            if keyword in query_lower:
                path = mapped_path
                break

        if not path:
            # Try fuzzy search
            logger.info(f"[*] No direct mapping for '{query}', trying search...")
            return self._google_search(query)

        # Fetch the page
        url = f"{self.base_url}{path}"
        return self._fetch_page(url, query)

    def _fetch_page(self, url: str, query: str) -> Optional[Dict]:
        """Fetch and parse a HackTricks page"""
        try:
            logger.info(f"[*] Fetching {url}...")
            response = self.session.get(url, timeout=15)

            if response.status_code != 200:
                logger.error(f"[-] Failed to fetch page: {response.status_code}")
                return None

            soup = BeautifulSoup(response.text, 'html.parser')

            # Extract title
            title = soup.find('h1')
            title_text = title.get_text().strip() if title else "HackTricks"

            # Extract main content
            content = soup.find('article') or soup.find('main') or soup.find('body')

            if not content:
                return None

            # Get text content
            text = content.get_text(separator='\n', strip=True)

            # Extract key sections (first 2000 characters for summary)
            summary = text[:2000] + "..." if len(text) > 2000 else text

            # Extract code blocks
            code_blocks = content.find_all('code')
            commands = [code.get_text().strip() for code in code_blocks[:10]]

            result = {
                'url': url,
                'title': title_text,
                'summary': summary,
                'commands': commands,
                'query': query,
                'fetched_at': datetime.now().isoformat()
            }

            # Cache the result
            self._save_to_cache(query, result)

            logger.info(f"[+] Successfully fetched HackTricks content")
            return result

        except Exception as e:
            logger.error(f"[-] Error fetching page: {e}")
            return None

    def _google_search(self, query: str) -> Optional[Dict]:
        """
        Fallback: Search Google for HackTricks pages
        Note: This returns a constructed search URL, not actual results
        """
        search_url = f"https://www.google.com/search?q=site:book.hacktricks.xyz+{query.replace(' ', '+')}"

        result = {
            'url': search_url,
            'title': f"HackTricks Search: {query}",
            'summary': f"Search HackTricks for '{query}' at: {search_url}",
            'commands': [],
            'query': query,
            'fetched_at': datetime.now().isoformat()
        }

        return result

    def get_methodology(self, attack_type: str) -> Optional[str]:
        """
        Get attack methodology for a specific attack type

        Args:
            attack_type: Type of attack (e.g., 'LDAP injection', 'Kerberoasting')

        Returns:
            Formatted methodology text or None
        """
        result = self.search(attack_type)

        if not result:
            return None

        output = []
        output.append(f"{'='*70}")
        output.append(f"HackTricks: {result['title']}")
        output.append(f"{'='*70}")
        output.append(f"\nURL: {result['url']}")
        output.append(f"\n{result['summary']}")

        if result['commands']:
            output.append(f"\n\nKey Commands/Techniques:")
            for i, cmd in enumerate(result['commands'][:10], 1):
                output.append(f"\n{i}. {cmd}")

        output.append(f"\n{'='*70}")

        return '\n'.join(output)

    def get_suggestions(self, service: str, port: int) -> List[str]:
        """
        Get pentesting suggestions based on service and port

        Args:
            service: Service name (e.g., 'SMB', 'HTTP', 'LDAP')
            port: Port number

        Returns:
            List of suggested attack vectors
        """
        suggestions = []
        service_lower = service.lower()

        # Map common services to attack vectors
        service_attacks = {
            'smb': ['SMB enumeration', 'Null session', 'Share enumeration', 'SMB relay'],
            'http': ['SQL injection', 'XSS', 'File upload', 'Directory traversal', 'SSRF'],
            'https': ['SQL injection', 'XSS', 'File upload', 'Directory traversal', 'SSRF'],
            'ldap': ['LDAP injection', 'Anonymous bind', 'LDAP enumeration'],
            'ssh': ['SSH brute force', 'SSH key theft', 'SSH tunneling'],
            'ftp': ['Anonymous login', 'FTP bounce', 'FTP brute force'],
            'rdp': ['RDP brute force', 'BlueKeep', 'RDP MitM'],
            'winrm': ['WinRM brute force', 'PSRemoting', 'Evil-WinRM'],
            'mssql': ['MSSQL injection', 'xp_cmdshell', 'MSSQL enumeration'],
            'mysql': ['MySQL injection', 'MySQL UDF', 'MySQL file read'],
        }

        if service_lower in service_attacks:
            suggestions = service_attacks[service_lower]

        # Port-specific checks
        if port == 88:
            suggestions.extend(['Kerberoasting', 'AS-REP roasting'])
        elif port == 389 or port == 3268:
            suggestions.extend(['LDAP enumeration', 'LDAP injection'])
        elif port == 445:
            suggestions.extend(['EternalBlue', 'SMB signing disabled'])

        return suggestions


# Singleton instance
_hacktricks_search = None

def get_hacktricks_search() -> HackTricksSearch:
    """Get or create HackTricks search singleton"""
    global _hacktricks_search
    if _hacktricks_search is None:
        _hacktricks_search = HackTricksSearch()
    return _hacktricks_search


# CLI interface for testing
if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO)

    search = get_hacktricks_search()

    if len(sys.argv) > 1:
        query = ' '.join(sys.argv[1:])
        print(f"\n[*] Searching HackTricks for: {query}\n")

        methodology = search.get_methodology(query)
        if methodology:
            print(methodology)
        else:
            print(f"[-] No results found for '{query}'")
    else:
        print("Usage: python3 hacktricks_search.py <query>")
        print("\nExamples:")
        print("  python3 hacktricks_search.py 'LDAP injection'")
        print("  python3 hacktricks_search.py 'Kerberoasting'")
        print("  python3 hacktricks_search.py 'SMB enumeration'")
