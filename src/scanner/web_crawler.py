"""
SecPluger Web Crawler
Crawls websites to discover pages, forms, and parameters for security testing
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
from typing import Set, Dict, List, Optional
import logging
from pathlib import Path
import json
from datetime import datetime
import time

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class WebCrawler:
    """
    Web crawler to discover pages, forms, and parameters
    Similar to Burp Spider but in Python
    """

    def __init__(self, max_depth: int = 3, max_pages: int = 100, timeout: int = 10):
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.timeout = timeout
        self.visited_urls: Set[str] = set()
        self.discovered_urls: Set[str] = set()
        self.forms: List[Dict] = []
        self.parameters: Dict[str, Set[str]] = {}  # URL -> set of parameters
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'SecPluger/2.0 (Pentest Scanner)'
        })

    def crawl(self, start_url: str, evidence_dir: Optional[Path] = None,
              max_depth: Optional[int] = None, max_pages: Optional[int] = None) -> Dict:
        """
        Crawl website starting from given URL

        Args:
            start_url: Starting URL to crawl
            evidence_dir: Directory to save crawl results
            max_depth: Override max crawl depth (optional)
            max_pages: Override max pages to crawl (optional)

        Returns:
            Dict with crawl results
        """
        # Override depth/pages if provided
        original_max_depth = self.max_depth
        original_max_pages = self.max_pages

        if max_depth is not None:
            self.max_depth = max_depth
        if max_pages is not None:
            self.max_pages = max_pages

        logger.info(f"Starting crawl of {start_url} (max_depth={self.max_depth}, max_pages={self.max_pages})")

        # Normalize URL
        if not start_url.startswith(('http://', 'https://')):
            start_url = 'http://' + start_url

        base_domain = urlparse(start_url).netloc

        # Start crawling
        self._crawl_recursive(start_url, base_domain, depth=0)

        # Restore original values
        self.max_depth = original_max_depth
        self.max_pages = original_max_pages

        # Generate results
        results = {
            'start_url': start_url,
            'timestamp': datetime.now().isoformat(),
            'pages_crawled': len(self.visited_urls),
            'urls_discovered': len(self.discovered_urls),
            'forms_found': len(self.forms),
            'parameters_found': sum(len(params) for params in self.parameters.values()),
            'urls': list(self.discovered_urls),
            'forms': self.forms,
            'parameters': {url: list(params) for url, params in self.parameters.items()}
        }

        # Save results if evidence directory provided
        if evidence_dir:
            self._save_results(results, evidence_dir)

        logger.info(f"Crawl complete: {results['pages_crawled']} pages, "
                   f"{results['forms_found']} forms, "
                   f"{results['parameters_found']} parameters")

        return results

    def _crawl_recursive(self, url: str, base_domain: str, depth: int):
        """
        Recursively crawl pages

        Args:
            url: URL to crawl
            base_domain: Base domain to stay within
            depth: Current depth
        """
        # Check limits
        if depth > self.max_depth:
            return
        if len(self.visited_urls) >= self.max_pages:
            return
        if url in self.visited_urls:
            return

        # Check if same domain
        if urlparse(url).netloc != base_domain:
            return

        # Mark as visited
        self.visited_urls.add(url)
        logger.info(f"Crawling [{depth}]: {url}")

        try:
            # Fetch page
            response = self.session.get(url, timeout=self.timeout, allow_redirects=True)

            # Check content type
            content_type = response.headers.get('Content-Type', '')
            if 'text/html' not in content_type:
                return

            # Parse HTML
            soup = BeautifulSoup(response.text, 'html.parser')

            # Extract parameters from current URL
            self._extract_parameters(url)

            # Find forms
            self._extract_forms(url, soup)

            # Find links
            links = self._extract_links(url, soup, base_domain)

            # Crawl discovered links
            for link in links:
                if link not in self.visited_urls:
                    self.discovered_urls.add(link)
                    time.sleep(0.5)  # Be polite
                    self._crawl_recursive(link, base_domain, depth + 1)

        except requests.RequestException as e:
            logger.warning(f"Error crawling {url}: {e}")
        except Exception as e:
            logger.error(f"Unexpected error crawling {url}: {e}")

    def _extract_links(self, current_url: str, soup: BeautifulSoup, base_domain: str) -> List[str]:
        """Extract all links from page"""
        links = []

        for tag in soup.find_all(['a', 'link']):
            href = tag.get('href')
            if not href:
                continue

            # Convert to absolute URL
            absolute_url = urljoin(current_url, href)

            # Parse URL
            parsed = urlparse(absolute_url)

            # Filter
            if parsed.netloc != base_domain:
                continue
            if parsed.scheme not in ['http', 'https']:
                continue
            if any(ext in parsed.path.lower() for ext in ['.jpg', '.png', '.gif', '.pdf', '.zip']):
                continue

            # Remove fragment
            clean_url = absolute_url.split('#')[0]

            links.append(clean_url)

        return links

    def _extract_forms(self, url: str, soup: BeautifulSoup):
        """Extract all forms from page"""
        for form in soup.find_all('form'):
            form_data = {
                'url': url,
                'action': urljoin(url, form.get('action', '')),
                'method': form.get('method', 'get').upper(),
                'inputs': []
            }

            # Extract form inputs
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_data = {
                    'type': input_tag.get('type', 'text'),
                    'name': input_tag.get('name'),
                    'value': input_tag.get('value', ''),
                }

                if input_data['name']:  # Only if input has name
                    form_data['inputs'].append(input_data)

            if form_data['inputs']:  # Only if form has inputs
                self.forms.append(form_data)
                logger.info(f"Found form: {form_data['method']} {form_data['action']} "
                           f"({len(form_data['inputs'])} inputs)")

    def _extract_parameters(self, url: str):
        """Extract GET parameters from URL"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if params:
            if url not in self.parameters:
                self.parameters[url] = set()

            for param_name in params.keys():
                self.parameters[url].add(param_name)

            logger.info(f"Found {len(params)} parameters in {url}")

    def _save_results(self, results: Dict, evidence_dir: Path):
        """Save crawl results to evidence directory"""
        evidence_dir.mkdir(parents=True, exist_ok=True)

        # Save full results as JSON
        results_file = evidence_dir / "crawler_results.json"
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2)

        # Save URLs list
        urls_file = evidence_dir / "discovered_urls.txt"
        with open(urls_file, 'w') as f:
            for url in sorted(self.discovered_urls):
                f.write(f"{url}\n")

        # Save forms
        if self.forms:
            forms_file = evidence_dir / "discovered_forms.json"
            with open(forms_file, 'w') as f:
                json.dump(self.forms, f, indent=2)

        # Save parameters
        if self.parameters:
            params_file = evidence_dir / "discovered_parameters.json"
            with open(params_file, 'w') as f:
                json.dump({url: list(params) for url, params in self.parameters.items()},
                         f, indent=2)

        logger.info(f"Crawl results saved to {evidence_dir}")

    def get_attack_surface(self) -> Dict:
        """
        Get attack surface summary

        Returns:
            Dict with attack surface details
        """
        return {
            'total_urls': len(self.discovered_urls),
            'total_forms': len(self.forms),
            'total_parameters': sum(len(params) for params in self.parameters.values()),
            'get_parameters': {url: list(params) for url, params in self.parameters.items() if params},
            'post_forms': [f for f in self.forms if f['method'] == 'POST'],
            'get_forms': [f for f in self.forms if f['method'] == 'GET']
        }


if __name__ == "__main__":
    # Test crawler
    crawler = WebCrawler(max_depth=2, max_pages=20)

    print("=== Testing Web Crawler ===\n")
    print("Enter a URL to crawl (e.g., http://testphp.vulnweb.com):")
    print("(Press Ctrl+C to skip test)\n")

    try:
        test_url = input("URL: ").strip()
        if test_url:
            results = crawler.crawl(test_url)

            print(f"\n=== Crawl Results ===")
            print(f"Pages crawled: {results['pages_crawled']}")
            print(f"URLs discovered: {results['urls_discovered']}")
            print(f"Forms found: {results['forms_found']}")
            print(f"Parameters found: {results['parameters_found']}")

            if results['forms_found'] > 0:
                print(f"\nExample form:")
                print(json.dumps(results['forms'][0], indent=2))

    except KeyboardInterrupt:
        print("\nTest skipped")
    except Exception as e:
        print(f"\nTest error: {e}")
