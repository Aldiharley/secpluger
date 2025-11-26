"""
Wireshark/tshark Integration for SecPluger
Provides Python interface to tshark for packet capture and analysis
Supports live capture, PCAP analysis, and protocol dissection
"""

import logging
import subprocess
import shutil
import json
from pathlib import Path
from typing import Optional, Dict, List, Any, Tuple
from dataclasses import dataclass
from datetime import datetime
import re

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class CaptureConfig:
    """Packet capture configuration"""
    interface: str = "any"
    capture_filter: Optional[str] = None
    display_filter: Optional[str] = None
    packet_count: Optional[int] = None
    duration: Optional[int] = None  # seconds
    output_file: Optional[Path] = None


class WiresharkIntegration:
    """
    Wireshark/tshark integration for packet capture and analysis

    Supports:
    - Live packet capture
    - PCAP file analysis
    - Protocol dissection
    - Statistics generation
    - Traffic filtering
    - Credential extraction

    Requirements:
    - tshark (part of Wireshark)
    - Optional: pyshark for Python packet parsing
    """

    def __init__(self, evidence_dir: Optional[Path] = None):
        """
        Initialize Wireshark integration

        Args:
            evidence_dir: Directory to save captures and analysis
        """
        self.evidence_dir = Path(evidence_dir) if evidence_dir else Path("evidence/wireshark")
        self.evidence_dir.mkdir(parents=True, exist_ok=True)

        self.tshark_path = shutil.which("tshark")
        if not self.tshark_path:
            logger.warning("❌ tshark not found in PATH")

        self.capture_process = None

        logger.info(f"Wireshark integration initialized (evidence: {self.evidence_dir})")

    def check_tshark_available(self) -> bool:
        """Check if tshark is available"""
        if self.tshark_path:
            try:
                result = subprocess.run(
                    [self.tshark_path, "--version"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0:
                    version = result.stdout.split('\n')[0]
                    logger.info(f"✅ {version}")
                    return True
            except Exception as e:
                logger.error(f"❌ tshark check failed: {e}")
        return False

    def list_interfaces(self) -> List[Dict[str, str]]:
        """
        List available network interfaces

        Returns:
            List of interfaces with names and descriptions
        """
        if not self.tshark_path:
            return []

        try:
            result = subprocess.run(
                [self.tshark_path, "-D"],
                capture_output=True,
                text=True,
                timeout=10
            )

            interfaces = []
            for line in result.stdout.strip().split('\n'):
                # Parse format: "1. eth0 (Ethernet adapter)"
                match = re.match(r'(\d+)\.\s+(\S+)\s+\(([^)]+)\)', line)
                if match:
                    interfaces.append({
                        "number": match.group(1),
                        "name": match.group(2),
                        "description": match.group(3)
                    })

            logger.info(f"✅ Found {len(interfaces)} interfaces")
            return interfaces

        except Exception as e:
            logger.error(f"❌ Failed to list interfaces: {e}")
            return []

    def start_capture(self, config: CaptureConfig) -> Optional[Path]:
        """
        Start live packet capture

        Args:
            config: Capture configuration

        Returns:
            Path to PCAP file or None if failed
        """
        if not self.tshark_path:
            logger.error("❌ tshark not available")
            return None

        # Generate output file if not specified
        if not config.output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            config.output_file = self.evidence_dir / f"capture_{timestamp}.pcap"

        cmd = [
            self.tshark_path,
            "-i", config.interface,
            "-w", str(config.output_file)
        ]

        # Add capture filter
        if config.capture_filter:
            cmd.extend(["-f", config.capture_filter])

        # Add packet count limit
        if config.packet_count:
            cmd.extend(["-c", str(config.packet_count)])

        # Add duration limit
        if config.duration:
            cmd.extend(["-a", f"duration:{config.duration}"])

        try:
            logger.info(f"📡 Starting capture on {config.interface}...")
            logger.info(f"📁 Output: {config.output_file}")

            if config.duration or config.packet_count:
                # Synchronous capture (with limit)
                subprocess.run(cmd, check=True, timeout=config.duration + 10 if config.duration else 300)
                logger.info(f"✅ Capture complete: {config.output_file}")
                return config.output_file
            else:
                # Asynchronous capture (background)
                self.capture_process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                logger.info(f"✅ Capture started in background (PID: {self.capture_process.pid})")
                logger.info("   Call stop_capture() to stop")
                return config.output_file

        except Exception as e:
            logger.error(f"❌ Capture failed: {e}")
            return None

    def stop_capture(self) -> bool:
        """
        Stop background packet capture

        Returns:
            True if stopped successfully
        """
        if self.capture_process:
            try:
                self.capture_process.terminate()
                self.capture_process.wait(timeout=10)
                logger.info("✅ Capture stopped")
                return True
            except Exception as e:
                logger.error(f"❌ Failed to stop capture: {e}")
                return False
        else:
            logger.warning("⚠️ No active capture to stop")
            return False

    def analyze_pcap(self, pcap_file: Path, display_filter: Optional[str] = None) -> Dict[str, Any]:
        """
        Analyze PCAP file and extract statistics

        Args:
            pcap_file: Path to PCAP file
            display_filter: Optional display filter

        Returns:
            Analysis results
        """
        if not self.tshark_path or not pcap_file.exists():
            return {}

        analysis = {
            "file": str(pcap_file),
            "size_bytes": pcap_file.stat().st_size,
            "packet_count": 0,
            "protocols": {},
            "conversations": [],
            "http_requests": [],
            "credentials": []
        }

        try:
            # Get packet count
            analysis["packet_count"] = self._get_packet_count(pcap_file, display_filter)

            # Get protocol hierarchy
            analysis["protocols"] = self._get_protocol_hierarchy(pcap_file, display_filter)

            # Get conversations
            analysis["conversations"] = self._get_conversations(pcap_file)

            # Extract HTTP requests
            analysis["http_requests"] = self._extract_http_requests(pcap_file)

            # Extract potential credentials
            analysis["credentials"] = self._extract_credentials(pcap_file)

            logger.info(f"✅ Analysis complete: {analysis['packet_count']} packets")
            return analysis

        except Exception as e:
            logger.error(f"❌ Analysis failed: {e}")
            return analysis

    def _get_packet_count(self, pcap_file: Path, display_filter: Optional[str] = None) -> int:
        """Get total packet count"""
        cmd = [self.tshark_path, "-r", str(pcap_file)]

        if display_filter:
            cmd.extend(["-Y", display_filter])

        cmd.extend(["-T", "fields", "-e", "frame.number"])

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            return len(result.stdout.strip().split('\n')) if result.stdout.strip() else 0
        except:
            return 0

    def _get_protocol_hierarchy(self, pcap_file: Path, display_filter: Optional[str] = None) -> Dict[str, int]:
        """Get protocol hierarchy statistics"""
        cmd = [self.tshark_path, "-r", str(pcap_file), "-qz", "io,phs"]

        if display_filter:
            cmd.extend(["-Y", display_filter])

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            protocols = {}

            for line in result.stdout.split('\n'):
                match = re.search(r'(\w+)\s+frames:(\d+)', line)
                if match:
                    protocols[match.group(1)] = int(match.group(2))

            return protocols
        except:
            return {}

    def _get_conversations(self, pcap_file: Path, limit: int = 10) -> List[Dict[str, Any]]:
        """Get top conversations"""
        cmd = [self.tshark_path, "-r", str(pcap_file), "-qz", "conv,ip"]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            conversations = []

            for line in result.stdout.split('\n'):
                # Parse conversation format
                match = re.search(r'(\d+\.\d+\.\d+\.\d+)\s+<->\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+(\d+)', line)
                if match:
                    conversations.append({
                        "src": match.group(1),
                        "dst": match.group(2),
                        "packets": int(match.group(3)),
                        "bytes": int(match.group(4))
                    })

            return conversations[:limit]
        except:
            return []

    def _extract_http_requests(self, pcap_file: Path) -> List[Dict[str, str]]:
        """Extract HTTP requests"""
        cmd = [
            self.tshark_path, "-r", str(pcap_file),
            "-Y", "http.request",
            "-T", "fields",
            "-e", "http.request.method",
            "-e", "http.host",
            "-e", "http.request.uri"
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            requests = []

            for line in result.stdout.strip().split('\n'):
                if line:
                    parts = line.split('\t')
                    if len(parts) >= 3:
                        requests.append({
                            "method": parts[0],
                            "host": parts[1],
                            "uri": parts[2],
                            "url": f"http://{parts[1]}{parts[2]}"
                        })

            logger.info(f"✅ Extracted {len(requests)} HTTP requests")
            return requests
        except:
            return []

    def _extract_credentials(self, pcap_file: Path) -> List[Dict[str, str]]:
        """Extract potential credentials from cleartext protocols"""
        credentials = []

        # FTP credentials
        ftp_creds = self._extract_ftp_credentials(pcap_file)
        credentials.extend(ftp_creds)

        # HTTP Basic Auth
        http_creds = self._extract_http_auth(pcap_file)
        credentials.extend(http_creds)

        # Telnet (harder to extract, would need pyshark)

        if credentials:
            logger.warning(f"⚠️ Found {len(credentials)} potential credentials!")

        return credentials

    def _extract_ftp_credentials(self, pcap_file: Path) -> List[Dict[str, str]]:
        """Extract FTP credentials"""
        credentials = []

        # Extract FTP USER commands
        cmd_user = [
            self.tshark_path, "-r", str(pcap_file),
            "-Y", "ftp.request.command == \"USER\"",
            "-T", "fields",
            "-e", "ftp.request.arg"
        ]

        # Extract FTP PASS commands
        cmd_pass = [
            self.tshark_path, "-r", str(pcap_file),
            "-Y", "ftp.request.command == \"PASS\"",
            "-T", "fields",
            "-e", "ftp.request.arg"
        ]

        try:
            result_user = subprocess.run(cmd_user, capture_output=True, text=True, timeout=30)
            result_pass = subprocess.run(cmd_pass, capture_output=True, text=True, timeout=30)

            users = result_user.stdout.strip().split('\n') if result_user.stdout.strip() else []
            passwords = result_pass.stdout.strip().split('\n') if result_pass.stdout.strip() else []

            for user, password in zip(users, passwords):
                credentials.append({
                    "protocol": "FTP",
                    "username": user,
                    "password": password
                })

        except:
            pass

        return credentials

    def _extract_http_auth(self, pcap_file: Path) -> List[Dict[str, str]]:
        """Extract HTTP Basic Authentication"""
        cmd = [
            self.tshark_path, "-r", str(pcap_file),
            "-Y", "http.authorization",
            "-T", "fields",
            "-e", "http.authorization"
        ]

        credentials = []

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            for auth_header in result.stdout.strip().split('\n'):
                if auth_header.startswith("Basic "):
                    credentials.append({
                        "protocol": "HTTP Basic Auth",
                        "auth_header": auth_header,
                        "note": "Base64 encoded - decode to extract username:password"
                    })

        except:
            pass

        return credentials

    def apply_display_filter(self, pcap_file: Path, display_filter: str, output_file: Optional[Path] = None) -> Optional[Path]:
        """
        Apply display filter and save filtered packets

        Args:
            pcap_file: Input PCAP file
            display_filter: Wireshark display filter
            output_file: Output PCAP file

        Returns:
            Path to filtered PCAP or None if failed
        """
        if not output_file:
            output_file = self.evidence_dir / f"filtered_{pcap_file.name}"

        cmd = [
            self.tshark_path,
            "-r", str(pcap_file),
            "-Y", display_filter,
            "-w", str(output_file)
        ]

        try:
            subprocess.run(cmd, check=True, timeout=120)
            logger.info(f"✅ Filtered PCAP saved: {output_file}")
            return output_file
        except Exception as e:
            logger.error(f"❌ Filtering failed: {e}")
            return None

    def export_to_json(self, pcap_file: Path, display_filter: Optional[str] = None) -> Path:
        """
        Export packets to JSON format

        Args:
            pcap_file: Input PCAP file
            display_filter: Optional display filter

        Returns:
            Path to JSON file
        """
        json_file = self.evidence_dir / f"{pcap_file.stem}.json"

        cmd = [self.tshark_path, "-r", str(pcap_file), "-T", "json"]

        if display_filter:
            cmd.extend(["-Y", display_filter])

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

            with open(json_file, 'w') as f:
                f.write(result.stdout)

            logger.info(f"✅ JSON export: {json_file}")
            return json_file

        except Exception as e:
            logger.error(f"❌ JSON export failed: {e}")
            return None

    def save_analysis_report(self, analysis: Dict[str, Any], filename: str = "wireshark_analysis.json"):
        """
        Save analysis results to JSON

        Args:
            analysis: Analysis results
            filename: Output filename
        """
        report_path = self.evidence_dir / filename

        with open(report_path, 'w') as f:
            json.dump(analysis, f, indent=2)

        logger.info(f"✅ Analysis report saved: {report_path}")
        return report_path


# Standalone usage example
if __name__ == "__main__":
    import sys

    # Check tshark availability
    if not shutil.which("tshark"):
        print("❌ tshark not found. Install Wireshark:")
        print("   sudo apt install tshark")
        sys.exit(1)

    # Initialize
    evidence_dir = Path("evidence/wireshark_test")
    wireshark = WiresharkIntegration(evidence_dir=evidence_dir)

    # Check availability
    if not wireshark.check_tshark_available():
        print("❌ tshark not available")
        sys.exit(1)

    # List interfaces
    print("\n📡 Available interfaces:")
    interfaces = wireshark.list_interfaces()
    for iface in interfaces:
        print(f"   {iface['number']}. {iface['name']} - {iface['description']}")

    # Example 1: Analyze existing PCAP
    if len(sys.argv) > 1 and sys.argv[1].endswith('.pcap'):
        pcap_file = Path(sys.argv[1])

        if pcap_file.exists():
            print(f"\n🔍 Analyzing: {pcap_file}\n")

            analysis = wireshark.analyze_pcap(pcap_file)

            print(f"📊 Packet count: {analysis['packet_count']}")
            print(f"📦 File size: {analysis['size_bytes']} bytes")
            print(f"🔬 Protocols: {analysis['protocols']}")
            print(f"🌐 HTTP requests: {len(analysis['http_requests'])}")
            print(f"🔑 Credentials found: {len(analysis['credentials'])}")

            if analysis['credentials']:
                print("\n⚠️ CREDENTIALS FOUND:")
                for cred in analysis['credentials']:
                    print(f"   {cred}")

            # Save analysis
            wireshark.save_analysis_report(analysis)

    # Example 2: Live capture
    else:
        print("\nUsage:")
        print("  Analyze PCAP: python wireshark.py capture.pcap")
        print("  Live capture: python wireshark.py capture <interface> <duration>")

        if len(sys.argv) > 2 and sys.argv[1] == "capture":
            interface = sys.argv[2] if len(sys.argv) > 2 else "any"
            duration = int(sys.argv[3]) if len(sys.argv) > 3 else 10

            config = CaptureConfig(
                interface=interface,
                duration=duration
            )

            print(f"\n📡 Starting {duration}s capture on {interface}...")

            pcap_file = wireshark.start_capture(config)

            if pcap_file:
                print(f"✅ Capture saved: {pcap_file}")

                # Analyze it
                print("\n🔍 Analyzing capture...")
                analysis = wireshark.analyze_pcap(pcap_file)
                print(f"✅ Captured {analysis['packet_count']} packets")
