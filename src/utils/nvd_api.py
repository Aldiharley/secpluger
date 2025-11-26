"""
NVD (National Vulnerability Database) API Integration
=====================================================

This module provides integration with the NVD API for CVE lookup,
vulnerability analysis, and cross-referencing security findings.

API Documentation: https://nvd.nist.gov/developers/vulnerabilities
"""

import os
import requests
import time
import json
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from pathlib import Path
import logging

# Try to import python-dotenv
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    print("[!] python-dotenv not installed. Install with: pip3 install python-dotenv")

logger = logging.getLogger(__name__)


class NVDClient:
    """Client for interacting with the NVD API"""

    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize NVD API client

        Args:
            api_key: NVD API key (optional, but increases rate limits)
        """
        self.api_key = api_key or os.getenv('NVD_API_KEY')
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

        # Rate limiting
        if self.api_key:
            self.rate_limit = 50  # requests per 30 seconds with API key
            self.sleep_time = 0.6  # 30/50 = 0.6 seconds between requests
        else:
            self.rate_limit = 5  # requests per 30 seconds without API key
            self.sleep_time = 6  # 30/5 = 6 seconds between requests
            logger.warning("[!] No NVD API key found. Rate limited to 5 requests/30s")

        self.last_request_time = 0
        self.session = requests.Session()

        # Cache directory
        self.cache_dir = Path("cache/nvd")
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_expiry = timedelta(days=7)  # Cache for 7 days

    def _rate_limit(self):
        """Implement rate limiting"""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time

        if time_since_last < self.sleep_time:
            sleep_duration = self.sleep_time - time_since_last
            logger.debug(f"[*] Rate limiting: sleeping {sleep_duration:.2f}s")
            time.sleep(sleep_duration)

        self.last_request_time = time.time()

    def _get_cache_path(self, cve_id: str) -> Path:
        """Get cache file path for a CVE"""
        return self.cache_dir / f"{cve_id}.json"

    def _load_from_cache(self, cve_id: str) -> Optional[Dict]:
        """Load CVE data from cache if not expired"""
        cache_path = self._get_cache_path(cve_id)

        if not cache_path.exists():
            return None

        # Check if cache is expired
        cache_age = datetime.now() - datetime.fromtimestamp(cache_path.stat().st_mtime)
        if cache_age > self.cache_expiry:
            logger.debug(f"[*] Cache expired for {cve_id}")
            return None

        try:
            with open(cache_path, 'r') as f:
                logger.debug(f"[+] Loaded {cve_id} from cache")
                return json.load(f)
        except Exception as e:
            logger.error(f"[-] Error loading cache for {cve_id}: {e}")
            return None

    def _save_to_cache(self, cve_id: str, data: Dict):
        """Save CVE data to cache"""
        cache_path = self._get_cache_path(cve_id)

        try:
            with open(cache_path, 'w') as f:
                json.dump(data, f, indent=2)
            logger.debug(f"[+] Saved {cve_id} to cache")
        except Exception as e:
            logger.error(f"[-] Error saving cache for {cve_id}: {e}")

    def get_cve(self, cve_id: str) -> Optional[Dict]:
        """
        Get detailed information about a specific CVE

        Args:
            cve_id: CVE identifier (e.g., "CVE-2024-26219")

        Returns:
            Dict with CVE details or None if not found
        """
        # Check cache first
        cached_data = self._load_from_cache(cve_id)
        if cached_data:
            return cached_data

        # Rate limit
        self._rate_limit()

        # Build headers
        headers = {}
        if self.api_key:
            headers['apiKey'] = self.api_key

        try:
            logger.info(f"[*] Fetching {cve_id} from NVD...")
            response = self.session.get(
                f"{self.base_url}",
                params={'cveId': cve_id},
                headers=headers,
                timeout=30
            )

            if response.status_code == 200:
                data = response.json()

                if data.get('vulnerabilities'):
                    cve_data = self._parse_cve_response(data['vulnerabilities'][0])
                    self._save_to_cache(cve_id, cve_data)
                    logger.info(f"[+] Successfully fetched {cve_id}")
                    return cve_data
                else:
                    logger.warning(f"[-] {cve_id} not found in NVD")
                    return None
            elif response.status_code == 403:
                logger.error("[-] NVD API access forbidden. Check your API key.")
                return None
            elif response.status_code == 404:
                logger.warning(f"[-] {cve_id} not found")
                return None
            else:
                logger.error(f"[-] NVD API error: {response.status_code}")
                return None

        except Exception as e:
            logger.error(f"[-] Error fetching {cve_id}: {e}")
            return None

    def _parse_cve_response(self, vuln_data: Dict) -> Dict:
        """Parse NVD API response into simplified format"""
        cve = vuln_data.get('cve', {})
        cve_id = cve.get('id', 'Unknown')

        # Get descriptions
        descriptions = cve.get('descriptions', [])
        description = next((d['value'] for d in descriptions if d['lang'] == 'en'), 'No description available')

        # Get CVSS scores
        metrics = cve.get('metrics', {})
        cvss_v3 = None
        cvss_v2 = None

        if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
            cvss_v3 = metrics['cvssMetricV31'][0].get('cvssData', {})
        elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
            cvss_v3 = metrics['cvssMetricV30'][0].get('cvssData', {})

        if 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
            cvss_v2 = metrics['cvssMetricV2'][0].get('cvssData', {})

        # Get references
        references = cve.get('references', [])
        ref_list = [{'url': r.get('url'), 'source': r.get('source')} for r in references[:10]]

        # Get CWE (weakness enumeration)
        weaknesses = cve.get('weaknesses', [])
        cwe_list = []
        for weakness in weaknesses:
            for desc in weakness.get('description', []):
                if desc.get('lang') == 'en':
                    cwe_list.append(desc.get('value'))

        # Get published and modified dates
        published = cve.get('published', 'Unknown')
        last_modified = cve.get('lastModified', 'Unknown')

        # Get vendor/product information
        configurations = cve.get('configurations', [])
        affected_products = []
        for config in configurations:
            for node in config.get('nodes', []):
                for match in node.get('cpeMatch', []):
                    if match.get('vulnerable'):
                        cpe = match.get('criteria', '')
                        affected_products.append(cpe)

        return {
            'id': cve_id,
            'description': description,
            'published': published,
            'last_modified': last_modified,
            'cvss_v3': cvss_v3,
            'cvss_v2': cvss_v2,
            'severity': self._get_severity(cvss_v3, cvss_v2),
            'cwe': cwe_list,
            'references': ref_list,
            'affected_products': affected_products[:10],  # Limit to 10
            'exploit_available': self._check_exploit_references(references)
        }

    def _get_severity(self, cvss_v3: Optional[Dict], cvss_v2: Optional[Dict]) -> str:
        """Determine severity based on CVSS score"""
        if cvss_v3:
            score = cvss_v3.get('baseScore', 0)
        elif cvss_v2:
            score = cvss_v2.get('baseScore', 0)
        else:
            return "UNKNOWN"

        if score >= 9.0:
            return "CRITICAL"
        elif score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        elif score > 0:
            return "LOW"
        else:
            return "UNKNOWN"

    def _check_exploit_references(self, references: List[Dict]) -> bool:
        """Check if any references indicate exploit availability"""
        exploit_keywords = ['exploit', 'poc', 'proof-of-concept', 'metasploit', 'exploit-db']

        for ref in references:
            url = ref.get('url', '').lower()
            tags = ref.get('tags', [])

            if any(keyword in url for keyword in exploit_keywords):
                return True
            if 'Exploit' in tags:
                return True

        return False

    def search_by_keyword(self, keyword: str, max_results: int = 10) -> List[Dict]:
        """
        Search for CVEs by keyword

        Args:
            keyword: Search term (e.g., "IIS", "LDAP injection")
            max_results: Maximum number of results to return

        Returns:
            List of CVE dictionaries
        """
        self._rate_limit()

        headers = {}
        if self.api_key:
            headers['apiKey'] = self.api_key

        try:
            logger.info(f"[*] Searching NVD for: {keyword}")
            response = self.session.get(
                f"{self.base_url}",
                params={
                    'keywordSearch': keyword,
                    'resultsPerPage': min(max_results, 20)
                },
                headers=headers,
                timeout=30
            )

            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get('vulnerabilities', [])

                results = []
                for vuln in vulnerabilities[:max_results]:
                    results.append(self._parse_cve_response(vuln))

                logger.info(f"[+] Found {len(results)} CVEs for '{keyword}'")
                return results
            else:
                logger.error(f"[-] Search failed: {response.status_code}")
                return []

        except Exception as e:
            logger.error(f"[-] Error searching NVD: {e}")
            return []

    def get_recent_cves(self, days: int = 7, max_results: int = 20) -> List[Dict]:
        """
        Get recently published CVEs

        Args:
            days: Number of days to look back
            max_results: Maximum number of results

        Returns:
            List of recent CVEs
        """
        self._rate_limit()

        # Calculate date range
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)

        headers = {}
        if self.api_key:
            headers['apiKey'] = self.api_key

        try:
            logger.info(f"[*] Fetching CVEs from last {days} days...")
            response = self.session.get(
                f"{self.base_url}",
                params={
                    'pubStartDate': start_date.strftime('%Y-%m-%dT%H:%M:%S.000'),
                    'pubEndDate': end_date.strftime('%Y-%m-%dT%H:%M:%S.000'),
                    'resultsPerPage': min(max_results, 20)
                },
                headers=headers,
                timeout=30
            )

            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get('vulnerabilities', [])

                results = []
                for vuln in vulnerabilities[:max_results]:
                    results.append(self._parse_cve_response(vuln))

                logger.info(f"[+] Found {len(results)} recent CVEs")
                return results
            else:
                logger.error(f"[-] Request failed: {response.status_code}")
                return []

        except Exception as e:
            logger.error(f"[-] Error fetching recent CVEs: {e}")
            return []

    def format_cve_report(self, cve_data: Dict) -> str:
        """Format CVE data into a readable report"""
        if not cve_data:
            return "No CVE data available"

        report = []
        report.append(f"{'='*70}")
        report.append(f"CVE ID: {cve_data['id']}")
        report.append(f"{'='*70}")
        report.append(f"\nSeverity: {cve_data['severity']}")

        if cve_data['cvss_v3']:
            score = cve_data['cvss_v3'].get('baseScore', 'N/A')
            vector = cve_data['cvss_v3'].get('vectorString', 'N/A')
            report.append(f"CVSS v3 Score: {score}")
            report.append(f"CVSS v3 Vector: {vector}")

        report.append(f"\nPublished: {cve_data['published']}")
        report.append(f"Last Modified: {cve_data['last_modified']}")

        report.append(f"\nDescription:")
        report.append(f"{cve_data['description']}")

        if cve_data['cwe']:
            report.append(f"\nWeakness Types (CWE):")
            for cwe in cve_data['cwe']:
                report.append(f"  - {cwe}")

        if cve_data['exploit_available']:
            report.append(f"\n⚠️  PUBLIC EXPLOIT AVAILABLE")

        if cve_data['affected_products']:
            report.append(f"\nAffected Products (sample):")
            for product in cve_data['affected_products'][:5]:
                report.append(f"  - {product}")

        if cve_data['references']:
            report.append(f"\nReferences:")
            for ref in cve_data['references'][:5]:
                report.append(f"  - {ref['url']}")

        report.append(f"\n{'='*70}")

        return '\n'.join(report)


# Singleton instance
_nvd_client = None

def get_nvd_client() -> NVDClient:
    """Get or create NVD client singleton"""
    global _nvd_client
    if _nvd_client is None:
        _nvd_client = NVDClient()
    return _nvd_client


# CLI interface for testing
if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO)

    client = get_nvd_client()

    if len(sys.argv) > 1:
        cve_id = sys.argv[1]
        print(f"\n[*] Looking up {cve_id}...\n")

        cve_data = client.get_cve(cve_id)
        if cve_data:
            print(client.format_cve_report(cve_data))
        else:
            print(f"[-] Could not find {cve_id}")
    else:
        print("Usage: python3 nvd_api.py CVE-YYYY-NNNNN")
        print("\nExample:")
        print("  python3 nvd_api.py CVE-2024-26219")
