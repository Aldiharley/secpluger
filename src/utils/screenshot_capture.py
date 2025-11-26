#!/usr/bin/env python3
"""
Screenshot Capture Module for SecPluger v2
Automated screenshot capture using headless Chrome (optional feature)
"""

from pathlib import Path
from datetime import datetime
from typing import Optional
import logging

logger = logging.getLogger(__name__)


class ScreenshotCapture:
    """
    Automated screenshot capture for evidence collection

    Requirements:
    - selenium (pip install selenium)
    - chromium-driver (sudo apt install chromium-driver)

    Features:
    - Headless Chrome browser
    - Configurable window size
    - Automatic filename generation
    - Evidence directory integration
    """

    def __init__(self, evidence_dir: str = "evidence", headless: bool = True):
        self.evidence_dir = Path(evidence_dir)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.headless = headless
        self.driver = None
        self._selenium_available = False

        try:
            from selenium import webdriver
            from selenium.webdriver.chrome.options import Options
            from selenium.webdriver.chrome.service import Service
            self._selenium_available = True
            self._webdriver = webdriver
            self._Options = Options
            self._Service = Service
            logger.info("Selenium available - screenshot capture enabled")
        except ImportError:
            logger.warning("Selenium not installed - screenshot capture disabled")
            logger.warning("Install with: pip install selenium")

    def _init_driver(self):
        """Initialize Chrome WebDriver (lazy initialization)"""
        if self.driver or not self._selenium_available:
            return

        try:
            chrome_options = self._Options()

            if self.headless:
                chrome_options.add_argument('--headless')

            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--window-size=1920,1080')
            chrome_options.add_argument('--ignore-certificate-errors')
            chrome_options.add_argument('--disable-web-security')

            self.driver = self._webdriver.Chrome(options=chrome_options)
            logger.info("Chrome WebDriver initialized successfully")

        except Exception as e:
            logger.error(f"Failed to initialize Chrome WebDriver: {e}")
            logger.error("Make sure chromium-driver is installed: sudo apt install chromium-driver")
            self._selenium_available = False

    def capture(self, url: str, filename: Optional[str] = None) -> Optional[str]:
        """
        Capture screenshot of URL

        Args:
            url: URL to capture
            filename: Optional custom filename (without extension)

        Returns:
            str: Path to saved screenshot, or None if failed
        """
        if not self._selenium_available:
            logger.warning(f"Screenshot capture unavailable for {url}")
            return None

        self._init_driver()

        if not self.driver:
            return None

        try:
            # Generate filename if not provided
            if filename is None:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                safe_url = url.replace('://', '_').replace('/', '_')[:50]
                filename = f"screenshot_{safe_url}_{timestamp}"

            output_path = self.evidence_dir / f"{filename}.png"

            # Navigate and capture
            logger.info(f"Capturing screenshot of {url}")
            self.driver.get(url)
            self.driver.save_screenshot(str(output_path))

            logger.info(f"Screenshot saved: {output_path}")
            return str(output_path)

        except Exception as e:
            logger.error(f"Failed to capture screenshot of {url}: {e}")
            return None

    def capture_multiple(self, urls: list) -> dict:
        """
        Capture screenshots of multiple URLs

        Args:
            urls: List of URLs to capture

        Returns:
            dict: Mapping of URL to screenshot path
        """
        results = {}

        for url in urls:
            screenshot_path = self.capture(url)
            results[url] = screenshot_path

        return results

    def close(self):
        """Clean up resources"""
        if self.driver:
            try:
                self.driver.quit()
                logger.info("Chrome WebDriver closed")
            except Exception as e:
                logger.error(f"Error closing WebDriver: {e}")
            finally:
                self.driver = None

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()


# ============================================================================
# SINGLETON PATTERN FOR AUTO-INIT
# ============================================================================

_screenshot_capture_instance = None


def get_screenshot_capture(evidence_dir: str = "evidence", headless: bool = True):
    """
    Factory function for singleton screenshot capture

    Args:
        evidence_dir: Directory for screenshots
        headless: Run in headless mode

    Returns:
        ScreenshotCapture: Singleton instance
    """
    global _screenshot_capture_instance

    if _screenshot_capture_instance is None:
        _screenshot_capture_instance = ScreenshotCapture(evidence_dir, headless)

    return _screenshot_capture_instance


# CLI interface
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    print("=" * 70)
    print("SCREENSHOT CAPTURE - TEST MODE")
    print("=" * 70)
    print()

    # Test with context manager
    test_urls = [
        "http://example.com",
        "https://www.google.com"
    ]

    with get_screenshot_capture(evidence_dir="evidence/test_screenshots") as capture:
        print(f"Selenium available: {capture._selenium_available}")

        if capture._selenium_available:
            print(f"\nCapturing {len(test_urls)} test URLs...")

            for url in test_urls:
                result = capture.capture(url)
                if result:
                    print(f"✅ {url} -> {result}")
                else:
                    print(f"❌ {url} -> Failed")
        else:
            print("\n⚠️  Screenshot capture unavailable")
            print("Install dependencies:")
            print("  pip install selenium")
            print("  sudo apt install chromium-driver chromium-browser")

    print("\n" + "=" * 70)
    print("TEST COMPLETE")
    print("=" * 70)
