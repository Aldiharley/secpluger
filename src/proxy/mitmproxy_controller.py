"""
SecPluger mitmproxy Controller
Controls mitmproxy instances for HTTP/HTTPS interception
"""

import subprocess
import os
import signal
import json
import time
from pathlib import Path
from typing import Optional, Dict, List
from datetime import datetime
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class MitmproxyController:
    """
    Manages mitmproxy instances for pentesting
    Supports starting/stopping proxy, traffic capture, and evidence collection
    """

    def __init__(self, evidence_dir: str = "evidence"):
        self.evidence_dir = Path(evidence_dir)
        self.proxy_process: Optional[subprocess.Popen] = None
        self.proxy_port = 8080
        self.is_running = False
        self.flow_file: Optional[Path] = None
        self.current_session: Optional[str] = None
        self.addon_script: Optional[Path] = None

    def start_proxy(
        self,
        port: int = 8080,
        mode: str = "regular",
        target: Optional[str] = None,
        session_id: Optional[str] = None,
        ssl_insecure: bool = True
    ) -> Dict:
        """
        Start mitmproxy instance

        Args:
            port: Proxy port (default 8080)
            mode: Proxy mode - "regular", "reverse", "transparent", "socks5"
            target: Target URL for reverse proxy mode
            session_id: Session ID for evidence collection
            ssl_insecure: Allow insecure SSL connections

        Returns:
            Dict with status and proxy details
        """
        if self.is_running:
            return {
                'success': False,
                'error': 'Proxy already running',
                'port': self.proxy_port
            }

        self.proxy_port = port
        self.current_session = session_id or datetime.now().strftime("%Y%m%d_%H%M%S")

        # Create session evidence directory
        session_dir = self.evidence_dir / self.current_session
        session_dir.mkdir(parents=True, exist_ok=True)

        # Flow file for traffic capture
        self.flow_file = session_dir / "proxy_traffic.mitm"

        # Build mitmproxy command
        cmd = [
            "mitmdump",  # Use mitmdump (CLI version) instead of mitmproxy (TUI)
            "--listen-port", str(port),
            "--flow-detail", "3",  # Maximum detail
            "--save-stream-file", str(self.flow_file),
        ]

        # SSL configuration
        if ssl_insecure:
            cmd.append("--ssl-insecure")

        # Proxy mode
        if mode == "reverse" and target:
            cmd.extend(["--mode", f"reverse:{target}"])
        elif mode == "transparent":
            cmd.extend(["--mode", "transparent"])
        elif mode == "socks5":
            cmd.extend(["--mode", "socks5"])
        # Regular mode is default

        # Add addon script if available
        if self.addon_script and self.addon_script.exists():
            cmd.extend(["-s", str(self.addon_script)])

        try:
            # Start mitmproxy process
            self.proxy_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                preexec_fn=os.setsid  # Create new process group
            )

            # Wait a moment to ensure it started
            time.sleep(2)

            # Check if process is still running
            if self.proxy_process.poll() is not None:
                # Process died
                stdout, stderr = self.proxy_process.communicate()
                return {
                    'success': False,
                    'error': f'Proxy failed to start: {stderr}',
                }

            self.is_running = True

            logger.info(f"mitmproxy started on port {port}")

            return {
                'success': True,
                'port': port,
                'mode': mode,
                'target': target,
                'session_id': self.current_session,
                'flow_file': str(self.flow_file),
                'pid': self.proxy_process.pid,
                'message': f'Proxy started on port {port}'
            }

        except Exception as e:
            logger.error(f"Failed to start mitmproxy: {e}")
            return {
                'success': False,
                'error': str(e)
            }

    def stop_proxy(self) -> Dict:
        """
        Stop running mitmproxy instance

        Returns:
            Dict with status
        """
        if not self.is_running or not self.proxy_process:
            return {
                'success': False,
                'error': 'No proxy running'
            }

        try:
            # Send SIGTERM to process group
            os.killpg(os.getpgid(self.proxy_process.pid), signal.SIGTERM)

            # Wait for process to terminate
            self.proxy_process.wait(timeout=5)

            self.is_running = False
            self.proxy_process = None

            logger.info("mitmproxy stopped")

            return {
                'success': True,
                'message': 'Proxy stopped',
                'flow_file': str(self.flow_file) if self.flow_file else None,
                'session_id': self.current_session
            }

        except subprocess.TimeoutExpired:
            # Force kill if it didn't stop
            os.killpg(os.getpgid(self.proxy_process.pid), signal.SIGKILL)
            self.proxy_process.wait()
            self.is_running = False
            self.proxy_process = None

            return {
                'success': True,
                'message': 'Proxy force stopped',
                'flow_file': str(self.flow_file) if self.flow_file else None
            }

        except Exception as e:
            logger.error(f"Failed to stop proxy: {e}")
            return {
                'success': False,
                'error': str(e)
            }

    def get_status(self) -> Dict:
        """
        Get current proxy status

        Returns:
            Dict with status information
        """
        if not self.is_running or not self.proxy_process:
            return {
                'running': False,
                'port': None,
                'session_id': None
            }

        # Check if process is still alive
        if self.proxy_process.poll() is not None:
            # Process died
            self.is_running = False
            return {
                'running': False,
                'port': self.proxy_port,
                'error': 'Proxy process died unexpectedly'
            }

        return {
            'running': True,
            'port': self.proxy_port,
            'session_id': self.current_session,
            'flow_file': str(self.flow_file) if self.flow_file else None,
            'pid': self.proxy_process.pid
        }

    def export_flows_json(self, output_file: Optional[Path] = None) -> Dict:
        """
        Export captured flows to JSON format

        Args:
            output_file: Output file path (default: session_dir/flows.json)

        Returns:
            Dict with export status
        """
        if not self.flow_file or not self.flow_file.exists():
            return {
                'success': False,
                'error': 'No flow file available'
            }

        if not output_file:
            output_file = self.flow_file.parent / "flows.json"

        try:
            # Use mitmproxy's mitmdump to convert flows to JSON
            result = subprocess.run(
                ["mitmdump", "-nr", str(self.flow_file), "-w", str(output_file), "--set", "flow_detail=3"],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                return {
                    'success': True,
                    'output_file': str(output_file),
                    'message': f'Flows exported to {output_file}'
                }
            else:
                return {
                    'success': False,
                    'error': result.stderr
                }

        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    def get_flow_summary(self) -> Dict:
        """
        Get summary of captured flows

        Returns:
            Dict with flow statistics
        """
        if not self.flow_file or not self.flow_file.exists():
            return {
                'success': False,
                'error': 'No flow file available'
            }

        try:
            # Count flows using mitmdump
            result = subprocess.run(
                ["mitmdump", "-nr", str(self.flow_file), "--set", "flow_detail=0"],
                capture_output=True,
                text=True,
                timeout=10
            )

            # Parse output to count flows
            flow_count = len([line for line in result.stdout.split('\n') if line.strip()])

            return {
                'success': True,
                'flow_file': str(self.flow_file),
                'flow_count': flow_count,
                'file_size': self.flow_file.stat().st_size
            }

        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    def set_addon_script(self, script_path: Path):
        """
        Set custom mitmproxy addon script

        Args:
            script_path: Path to Python addon script
        """
        self.addon_script = script_path
        logger.info(f"Addon script set: {script_path}")

    def __del__(self):
        """Cleanup: Stop proxy on deletion"""
        if self.is_running:
            self.stop_proxy()


# Singleton instance
_controller = None

def get_controller() -> MitmproxyController:
    """Get global mitmproxy controller instance"""
    global _controller
    if _controller is None:
        _controller = MitmproxyController()
    return _controller


if __name__ == "__main__":
    # Test the controller
    controller = MitmproxyController()

    print("=== Testing mitmproxy Controller ===\n")

    # Start proxy
    print("1. Starting proxy...")
    result = controller.start_proxy(port=8080, session_id="test_session")
    print(f"   Result: {json.dumps(result, indent=2)}")

    if result['success']:
        # Get status
        print("\n2. Getting status...")
        status = controller.get_status()
        print(f"   Status: {json.dumps(status, indent=2)}")

        # Wait a bit
        print("\n3. Waiting 5 seconds (send some traffic to http://example.com via proxy)...")
        time.sleep(5)

        # Stop proxy
        print("\n4. Stopping proxy...")
        result = controller.stop_proxy()
        print(f"   Result: {json.dumps(result, indent=2)}")

    print("\n=== Test Complete ===")
