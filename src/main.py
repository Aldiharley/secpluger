#!/usr/bin/env python3
"""
SecPluger - AI-Powered Pentesting Workflow Automation
Main entry point
"""

import sys
from pathlib import Path

# Add src to path
sys.path.append(str(Path(__file__).parent))

from gui.main_window import main as gui_main


def main():
    """Main entry point"""
    print("="*60)
    print(" SecPluger - Pentesting Workflow Automation")
    print("="*60)
    print()

    # Create required directories
    Path("workflows").mkdir(exist_ok=True)
    Path("evidence").mkdir(exist_ok=True)
    Path("reports").mkdir(exist_ok=True)

    # Launch GUI
    gui_main()


if __name__ == "__main__":
    main()
