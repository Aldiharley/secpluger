#!/usr/bin/env python3
"""
Privilege Helper Module for SecPluger v2
Handles privilege escalation for tools requiring root access
"""

import subprocess
import logging
from typing import List, Optional, Tuple

logger = logging.getLogger(__name__)


class PrivilegeHelper:
    """
    Helper for running privileged commands

    Features:
    - Automatic sudo detection
    - Non-interactive sudo execution
    - Fallback to non-privileged alternatives
    - Comprehensive error handling

    Configuration (optional):
    Add to /etc/sudoers.d/secpluger for passwordless sudo:
        aldi ALL=(root) NOPASSWD: /usr/bin/nmap
        aldi ALL=(root) NOPASSWD: /usr/bin/ntpdate
        aldi ALL=(root) NOPASSWD: /usr/bin/tcpdump
    """

    # Tools that commonly need root
    PRIVILEGED_TOOLS = {
        'nmap': {
            'requires_root': ['- sS', '-sU', '-O', '--script'],
            'alternatives': {'-sS': '-sT'}  # TCP SYN -> TCP Connect
        },
        'ntpdate': {
            'requires_root': True,
            'alternatives': None
        },
        'tcpdump': {
            'requires_root': True,
            'alternatives': None
        }
    }

    def __init__(self):
        self.sudo_available = self._check_sudo()

    def _check_sudo(self) -> bool:
        """Check if sudo is available and configured"""
        try:
            result = subprocess.run(
                ['sudo', '-n', 'true'],
                capture_output=True,
                timeout=5
            )
            available = (result.returncode == 0)

            if available:
                logger.info("Passwordless sudo available")
            else:
                logger.warning("Sudo requires password - some tools may fail")
                logger.warning("Configure /etc/sudoers.d/secpluger for best results")

            return available

        except Exception as e:
            logger.warning(f"Sudo not available: {e}")
            return False

    def run_privileged(self,
                      command: List[str],
                      timeout: int = 30) -> Tuple[int, str, str]:
        """
        Run command with privilege escalation if needed

        Args:
            command: Command as list of strings
            timeout: Command timeout in seconds

        Returns:
            Tuple of (returncode, stdout, stderr)
        """
        if not command:
            return (1, "", "Empty command")

        tool_name = command[0].split('/')[-1]

        # Check if tool needs root
        needs_root = self._needs_root(command)

        if needs_root:
            if self.sudo_available:
                return self._run_with_sudo(command, timeout)
            else:
                # Try alternative if available
                alt_command = self._get_alternative(command)
                if alt_command:
                    logger.info(f"Using non-privileged alternative: {' '.join(alt_command)}")
                    return self._run_without_sudo(alt_command, timeout)
                else:
                    logger.error(f"{tool_name} requires root - configure sudo")
                    return (1, "", f"{tool_name} requires root privileges")
        else:
            return self._run_without_sudo(command, timeout)

    def _needs_root(self, command: List[str]) -> bool:
        """Check if command requires root privileges"""
        if not command:
            return False

        tool_name = command[0].split('/')[-1]

        if tool_name not in self.PRIVILEGED_TOOLS:
            return False

        tool_config = self.PRIVILEGED_TOOLS[tool_name]

        # If always requires root
        if isinstance(tool_config.get('requires_root'), bool):
            return tool_config['requires_root']

        # If requires root for specific flags
        if isinstance(tool_config.get('requires_root'), list):
            command_str = ' '.join(command)
            for flag in tool_config['requires_root']:
                if flag in command_str:
                    return True

        return False

    def _get_alternative(self, command: List[str]) -> Optional[List[str]]:
        """Get non-privileged alternative command"""
        if not command:
            return None

        tool_name = command[0].split('/')[-1]

        if tool_name not in self.PRIVILEGED_TOOLS:
            return None

        alternatives = self.PRIVILEGED_TOOLS[tool_name].get('alternatives')

        if not alternatives:
            return None

        # Apply substitutions
        alt_command = command.copy()
        for i, arg in enumerate(alt_command):
            if arg in alternatives:
                alt_command[i] = alternatives[arg]
                logger.info(f"Substituted {arg} -> {alternatives[arg]}")

        return alt_command

    def _run_with_sudo(self,
                      command: List[str],
                      timeout: int) -> Tuple[int, str, str]:
        """Run command with sudo"""
        sudo_command = ['sudo', '-n'] + command

        try:
            logger.info(f"Running with sudo: {' '.join(command)}")

            result = subprocess.run(
                sudo_command,
                capture_output=True,
                text=True,
                timeout=timeout
            )

            return (result.returncode, result.stdout, result.stderr)

        except subprocess.TimeoutExpired:
            logger.error(f"Command timed out after {timeout}s")
            return (1, "", f"Timeout after {timeout}s")

        except Exception as e:
            logger.error(f"Sudo execution failed: {e}")
            return (1, "", str(e))

    def _run_without_sudo(self,
                         command: List[str],
                         timeout: int) -> Tuple[int, str, str]:
        """Run command without sudo"""
        try:
            logger.info(f"Running without sudo: {' '.join(command)}")

            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout
            )

            return (result.returncode, result.stdout, result.stderr)

        except subprocess.TimeoutExpired:
            logger.error(f"Command timed out after {timeout}s")
            return (1, "", f"Timeout after {timeout}s")

        except Exception as e:
            logger.error(f"Command execution failed: {e}")
            return (1, "", str(e))


# ============================================================================
# SINGLETON PATTERN FOR AUTO-INIT
# ============================================================================

_privilege_helper_instance = None


def get_privilege_helper():
    """
    Factory function for singleton privilege helper

    Returns:
        PrivilegeHelper: Singleton instance
    """
    global _privilege_helper_instance

    if _privilege_helper_instance is None:
        _privilege_helper_instance = PrivilegeHelper()

    return _privilege_helper_instance


# CLI interface
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    print("=" * 70)
    print("PRIVILEGE HELPER - TEST MODE")
    print("=" * 70)
    print()

    helper = get_privilege_helper()

    print(f"Sudo available: {helper.sudo_available}")
    print()

    # Test commands
    test_commands = [
        (['nmap', '-sT', 'localhost'], "Non-privileged nmap scan"),
        (['nmap', '-sS', 'localhost'], "Privileged nmap scan (SYN)"),
        (['ntpdate', '-q', 'pool.ntp.org'], "NTP query (requires root)"),
    ]

    for command, description in test_commands:
        print(f"[TEST] {description}")
        print(f"Command: {' '.join(command)}")

        returncode, stdout, stderr = helper.run_privileged(command, timeout=10)

        print(f"Return code: {returncode}")
        if stdout:
            print(f"Output: {stdout[:200]}")
        if stderr:
            print(f"Error: {stderr[:200]}")
        print()

    print("=" * 70)
    print("CONFIGURATION GUIDE")
    print("=" * 70)
    print()
    print("For passwordless sudo, create /etc/sudoers.d/secpluger:")
    print()
    print("  sudo visudo -f /etc/sudoers.d/secpluger")
    print()
    print("Add these lines (replace 'aldi' with your username):")
    print()
    print("  aldi ALL=(root) NOPASSWD: /usr/bin/nmap")
    print("  aldi ALL=(root) NOPASSWD: /usr/bin/ntpdate")
    print("  aldi ALL=(root) NOPASSWD: /usr/bin/tcpdump")
    print()
    print("=" * 70)
