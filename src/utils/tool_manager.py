"""
SecPluger Tool Manager
Dynamically detects, manages, and installs security tools on Kali Linux
"""

import subprocess
import shutil
import logging
from typing import Dict, List, Optional, Tuple
from pathlib import Path
import json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ToolManager:
    """
    Manages security tools for SecPluger
    - Detects installed tools
    - Provides installation instructions
    - Can auto-install tools (with permission)
    """

    # Comprehensive tool registry for Kali Linux
    TOOL_REGISTRY = {
        # Network Scanners
        'nmap': {
            'category': 'network_scanner',
            'install_cmd': 'sudo apt install -y nmap',
            'check_cmd': 'nmap --version',
            'description': 'Network port scanner',
            'priority': 'high'
        },
        'masscan': {
            'category': 'network_scanner',
            'install_cmd': 'sudo apt install -y masscan',
            'check_cmd': 'masscan --version',
            'description': 'Fast network port scanner',
            'priority': 'medium'
        },
        'zmap': {
            'category': 'network_scanner',
            'install_cmd': 'sudo apt install -y zmap',
            'check_cmd': 'zmap --version',
            'description': 'Internet-wide network scanner',
            'priority': 'low'
        },

        # Web Scanners
        'nuclei': {
            'category': 'web_scanner',
            'install_cmd': 'go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest',
            'check_cmd': 'nuclei -version',
            'description': 'Fast vulnerability scanner with templates',
            'priority': 'high'
        },
        'wapiti': {
            'category': 'web_scanner',
            'install_cmd': 'sudo apt install -y wapiti',
            'check_cmd': 'wapiti --version',
            'description': 'Web application vulnerability scanner',
            'priority': 'high'
        },
        'nikto': {
            'category': 'web_scanner',
            'install_cmd': 'sudo apt install -y nikto',
            'check_cmd': 'nikto -Version',
            'description': 'Web server scanner',
            'priority': 'medium'
        },
        'whatweb': {
            'category': 'web_scanner',
            'install_cmd': 'sudo apt install -y whatweb',
            'check_cmd': 'whatweb --version',
            'description': 'Web technology identifier',
            'priority': 'medium'
        },
        'wafw00f': {
            'category': 'web_scanner',
            'install_cmd': 'sudo apt install -y wafw00f',
            'check_cmd': 'wafw00f --version',
            'description': 'Web Application Firewall detector',
            'priority': 'medium'
        },

        # Directory/File Enumeration
        'gobuster': {
            'category': 'enumeration',
            'install_cmd': 'sudo apt install -y gobuster',
            'check_cmd': 'gobuster version',
            'description': 'Directory/file bruteforcer',
            'priority': 'high'
        },
        'dirb': {
            'category': 'enumeration',
            'install_cmd': 'sudo apt install -y dirb',
            'check_cmd': 'dirb',
            'description': 'Web content scanner',
            'priority': 'medium'
        },
        'dirbuster': {
            'category': 'enumeration',
            'install_cmd': 'sudo apt install -y dirbuster',
            'check_cmd': 'dirbuster --help',
            'description': 'Web application brute forcer',
            'priority': 'low'
        },
        'ffuf': {
            'category': 'enumeration',
            'install_cmd': 'sudo apt install -y ffuf',
            'check_cmd': 'ffuf -V',
            'description': 'Fast web fuzzer',
            'priority': 'high'
        },
        'feroxbuster': {
            'category': 'enumeration',
            'install_cmd': 'sudo apt install -y feroxbuster',
            'check_cmd': 'feroxbuster --version',
            'description': 'Fast directory bruteforcer',
            'priority': 'medium'
        },

        # SQL Injection
        'sqlmap': {
            'category': 'sql_injection',
            'install_cmd': 'sudo apt install -y sqlmap',
            'check_cmd': 'sqlmap --version',
            'description': 'SQL injection tool',
            'priority': 'high'
        },

        # XSS Testing
        'xsser': {
            'category': 'xss',
            'install_cmd': 'sudo apt install -y xsser',
            'check_cmd': 'xsser --version',
            'description': 'XSS testing tool',
            'priority': 'medium'
        },

        # Exploitation
        'metasploit-framework': {
            'category': 'exploitation',
            'install_cmd': 'sudo apt install -y metasploit-framework',
            'check_cmd': 'msfconsole --version',
            'description': 'Exploitation framework',
            'priority': 'high'
        },
        'searchsploit': {
            'category': 'exploitation',
            'install_cmd': 'sudo apt install -y exploitdb',
            'check_cmd': 'searchsploit --help',
            'description': 'Exploit database search',
            'priority': 'high'
        },

        # Proxy/MITM
        'mitmproxy': {
            'category': 'proxy',
            'install_cmd': 'pip3 install mitmproxy',
            'check_cmd': 'mitmdump --version',
            'description': 'Interactive HTTPS proxy',
            'priority': 'high'
        },
        'burpsuite': {
            'category': 'proxy',
            'install_cmd': 'sudo apt install -y burpsuite',
            'check_cmd': 'burpsuite --version',
            'description': 'Web application security testing',
            'priority': 'high'
        },

        # WebDAV Testing
        'davtest': {
            'category': 'webdav',
            'install_cmd': 'sudo apt install -y davtest',
            'check_cmd': 'davtest --version',
            'description': 'WebDAV vulnerability scanner and file upload tester',
            'priority': 'medium'
        },
        'cadaver': {
            'category': 'webdav',
            'install_cmd': 'sudo apt install -y cadaver',
            'check_cmd': 'cadaver --version',
            'description': 'Command-line WebDAV client for file operations',
            'priority': 'medium'
        },

        # DNS/Subdomain
        'sublist3r': {
            'category': 'recon',
            'install_cmd': 'sudo apt install -y sublist3r',
            'check_cmd': 'sublist3r --help',
            'description': 'Subdomain enumeration',
            'priority': 'medium'
        },
        'amass': {
            'category': 'recon',
            'install_cmd': 'sudo apt install -y amass',
            'check_cmd': 'amass version',
            'description': 'Attack surface mapping',
            'priority': 'medium'
        },
        'dnsenum': {
            'category': 'recon',
            'install_cmd': 'sudo apt install -y dnsenum',
            'check_cmd': 'dnsenum --help',
            'description': 'DNS enumeration',
            'priority': 'medium'
        },
        'dnsrecon': {
            'category': 'recon',
            'install_cmd': 'sudo apt install -y dnsrecon',
            'check_cmd': 'dnsrecon --help',
            'description': 'DNS reconnaissance',
            'priority': 'medium'
        },

        # SSL/TLS
        'sslscan': {
            'category': 'ssl',
            'install_cmd': 'sudo apt install -y sslscan',
            'check_cmd': 'sslscan --version',
            'description': 'SSL/TLS scanner',
            'priority': 'medium'
        },
        'sslyze': {
            'category': 'ssl',
            'install_cmd': 'sudo apt install -y sslyze',
            'check_cmd': 'sslyze --version',
            'description': 'SSL/TLS configuration analyzer',
            'priority': 'medium'
        },
        'testssl': {
            'category': 'ssl',
            'install_cmd': 'sudo apt install -y testssl.sh',
            'check_cmd': 'testssl.sh --version',
            'description': 'SSL/TLS testing',
            'priority': 'medium'
        },

        # Password Attacks
        'hydra': {
            'category': 'password',
            'install_cmd': 'sudo apt install -y hydra',
            'check_cmd': 'hydra -h',
            'description': 'Network logon cracker',
            'priority': 'medium'
        },
        'john': {
            'category': 'password',
            'install_cmd': 'sudo apt install -y john',
            'check_cmd': 'john --version',
            'description': 'Password cracker',
            'priority': 'medium'
        },
        'hashcat': {
            'category': 'password',
            'install_cmd': 'sudo apt install -y hashcat',
            'check_cmd': 'hashcat --version',
            'description': 'Advanced password recovery',
            'priority': 'medium'
        },
        'medusa': {
            'category': 'password',
            'install_cmd': 'sudo apt install -y medusa',
            'check_cmd': 'medusa -h',
            'description': 'Parallel login brute-forcer',
            'priority': 'low'
        },

        # Wireless
        'aircrack-ng': {
            'category': 'wireless',
            'install_cmd': 'sudo apt install -y aircrack-ng',
            'check_cmd': 'aircrack-ng --help',
            'description': 'WiFi security suite',
            'priority': 'medium'
        },
        'reaver': {
            'category': 'wireless',
            'install_cmd': 'sudo apt install -y reaver',
            'check_cmd': 'reaver -h',
            'description': 'WPS attack tool',
            'priority': 'low'
        },

        # CMSs
        'wpscan': {
            'category': 'cms',
            'install_cmd': 'sudo apt install -y wpscan',
            'check_cmd': 'wpscan --version',
            'description': 'WordPress security scanner',
            'priority': 'medium'
        },
        'joomscan': {
            'category': 'cms',
            'install_cmd': 'sudo apt install -y joomscan',
            'check_cmd': 'joomscan --version',
            'description': 'Joomla vulnerability scanner',
            'priority': 'low'
        },

        # Other
        'wireshark': {
            'category': 'network_analysis',
            'install_cmd': 'sudo apt install -y wireshark',
            'check_cmd': 'tshark --version',
            'description': 'Network protocol analyzer',
            'priority': 'medium'
        },
        'tcpdump': {
            'category': 'network_analysis',
            'install_cmd': 'sudo apt install -y tcpdump',
            'check_cmd': 'tcpdump --version',
            'description': 'Packet analyzer',
            'priority': 'medium'
        },
    }

    def __init__(self):
        self.detected_tools: Dict[str, bool] = {}
        self.tool_versions: Dict[str, str] = {}
        self._scan_tools()

    def _scan_tools(self):
        """Scan system for available tools"""
        logger.info("Scanning for installed security tools...")

        for tool_name, tool_info in self.TOOL_REGISTRY.items():
            is_available = shutil.which(tool_name.replace('metasploit-framework', 'msfconsole')) is not None
            self.detected_tools[tool_name] = is_available

            if is_available:
                version = self._get_tool_version(tool_name, tool_info.get('check_cmd'))
                self.tool_versions[tool_name] = version

    def _get_tool_version(self, tool_name: str, check_cmd: Optional[str]) -> str:
        """Get version of installed tool"""
        if not check_cmd:
            return "unknown"

        try:
            result = subprocess.run(
                check_cmd.split(),
                capture_output=True,
                text=True,
                timeout=5
            )
            # Parse version from output (simple approach)
            output = result.stdout + result.stderr
            lines = output.split('\n')
            if lines:
                return lines[0][:100]  # First line, max 100 chars
            return "installed"
        except Exception:
            return "installed"

    def get_available_tools(self, category: Optional[str] = None) -> Dict[str, bool]:
        """Get available tools, optionally filtered by category"""
        if not category:
            return self.detected_tools.copy()

        return {
            name: available
            for name, available in self.detected_tools.items()
            if self.TOOL_REGISTRY[name]['category'] == category
        }

    def get_missing_tools(self, category: Optional[str] = None, priority: Optional[str] = None) -> List[str]:
        """Get list of missing tools"""
        missing = []
        for name, available in self.detected_tools.items():
            if not available:
                tool_info = self.TOOL_REGISTRY[name]

                # Filter by category if specified
                if category and tool_info['category'] != category:
                    continue

                # Filter by priority if specified
                if priority and tool_info['priority'] != priority:
                    continue

                missing.append(name)

        return missing

    def get_tool_info(self, tool_name: str) -> Optional[Dict]:
        """Get information about a specific tool"""
        return self.TOOL_REGISTRY.get(tool_name)

    def install_tool(self, tool_name: str, auto_confirm: bool = False) -> Tuple[bool, str]:
        """
        Install a specific tool

        Args:
            tool_name: Name of tool to install
            auto_confirm: Auto-confirm installation without prompting

        Returns:
            Tuple of (success, message)
        """
        if tool_name not in self.TOOL_REGISTRY:
            return False, f"Unknown tool: {tool_name}"

        if self.detected_tools.get(tool_name):
            return True, f"{tool_name} is already installed"

        tool_info = self.TOOL_REGISTRY[tool_name]
        install_cmd = tool_info['install_cmd']

        logger.info(f"Installing {tool_name}...")
        logger.info(f"Command: {install_cmd}")

        if not auto_confirm:
            logger.warning("Auto-confirm is False. Returning install command for manual execution.")
            return False, f"Please run manually: {install_cmd}"

        try:
            # Run installation command
            result = subprocess.run(
                install_cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=300  # 5 minutes max
            )

            if result.returncode == 0:
                # Re-check if tool is now available
                self._scan_tools()
                if self.detected_tools.get(tool_name):
                    return True, f"Successfully installed {tool_name}"
                else:
                    return False, f"Installation completed but {tool_name} not found in PATH"
            else:
                return False, f"Installation failed: {result.stderr}"

        except subprocess.TimeoutExpired:
            return False, f"Installation timed out after 5 minutes"
        except Exception as e:
            return False, f"Installation error: {str(e)}"

    def get_install_commands(self, tools: List[str]) -> str:
        """Get installation commands for multiple tools"""
        commands = []
        for tool in tools:
            if tool in self.TOOL_REGISTRY:
                commands.append(f"# Install {tool}")
                commands.append(self.TOOL_REGISTRY[tool]['install_cmd'])
                commands.append("")

        return "\n".join(commands)

    def generate_report(self) -> str:
        """Generate a report of available tools"""
        report = []
        report.append("=" * 80)
        report.append("SecPluger Tool Availability Report")
        report.append("=" * 80)
        report.append("")

        # Group by category
        categories = {}
        for tool_name, tool_info in self.TOOL_REGISTRY.items():
            category = tool_info['category']
            if category not in categories:
                categories[category] = []
            categories[category].append(tool_name)

        for category, tools in sorted(categories.items()):
            report.append(f"\n{category.upper().replace('_', ' ')}:")
            report.append("-" * 80)

            for tool in sorted(tools):
                available = self.detected_tools.get(tool, False)
                status = "✅" if available else "❌"
                priority = self.TOOL_REGISTRY[tool]['priority']
                description = self.TOOL_REGISTRY[tool]['description']

                version = ""
                if available and tool in self.tool_versions:
                    version = f" ({self.tool_versions[tool][:50]})"

                report.append(f"  {status} {tool:<20} [{priority:>6}] {description}{version}")

        # Summary
        total = len(self.TOOL_REGISTRY)
        installed = sum(1 for v in self.detected_tools.values() if v)
        missing = total - installed

        report.append("")
        report.append("=" * 80)
        report.append(f"SUMMARY: {installed}/{total} tools installed ({missing} missing)")
        report.append("=" * 80)

        return "\n".join(report)

    def save_report(self, output_file: str = "tool_report.txt"):
        """Save tool report to file"""
        report = self.generate_report()
        with open(output_file, 'w') as f:
            f.write(report)
        logger.info(f"Tool report saved to {output_file}")


# Singleton instance
_tool_manager_instance = None

def get_tool_manager() -> ToolManager:
    """Get singleton ToolManager instance"""
    global _tool_manager_instance
    if _tool_manager_instance is None:
        _tool_manager_instance = ToolManager()
    return _tool_manager_instance


if __name__ == "__main__":
    # Test tool manager
    manager = ToolManager()

    print("\n" + manager.generate_report())

    # Show missing high-priority tools
    missing_high = manager.get_missing_tools(priority='high')
    if missing_high:
        print("\n\nMISSING HIGH-PRIORITY TOOLS:")
        print("=" * 80)
        for tool in missing_high:
            info = manager.get_tool_info(tool)
            print(f"  • {tool} - {info['description']}")
            print(f"    Install: {info['install_cmd']}")
            print()
