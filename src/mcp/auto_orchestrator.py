#!/usr/bin/env python3
"""
Auto-Orchestrator for SecPluger MCP
Automatically initializes and coordinates all pentesting features:
- Parallel reconnaissance scanning
- NVD/CVE database lookups
- HackTricks research
- ASVS compliance testing
- Evidence collection
- PDF report generation
"""

import os
import sys
import json
import logging
import asyncio
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime

# Add paths for imports
sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent))

from mcp_monitor import get_recorder
from engine.workflow_engine import WorkflowEngine
from database.models import Database
from utils.tool_manager import get_tool_manager
from utils.nvd_api import get_nvd_client
from utils.hacktricks_search import get_hacktricks_search
from utils.knowledge_base import get_knowledge_base
from scanner.parallel_scanner import ParallelScanner
from scanner.web_crawler import WebCrawler
from scanner.fuzzer import WebFuzzer
from scanner.vulnerability_scanner import VulnerabilityScanner
from scanner.owasp_asvs_scanner import OwaspAVSVScanner
from reporting.professional_report_generator import ProfessionalReportGenerator
from reporting.comprehensive_report_generator import ComprehensiveReportGenerator

logger = logging.getLogger(__name__)

class AutoOrchestrator:
    """
    Automatic orchestration system that coordinates all SecPluger features.

    This class serves as the central coordinator that:
    1. Initializes all components on MCP startup
    2. Triggers automatic CVE/NVD lookups
    3. Performs HackTricks research when vulnerabilities detected
    4. Generates ASVS CSV reports for web targets
    5. Creates comprehensive PDF reports
    6. Orchestrates parallel reconnaissance
    """

    _instance = None

    def __new__(cls):
        """Singleton pattern to ensure only one orchestrator instance"""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        """Initialize the auto-orchestrator (called only once due to singleton)"""
        if self._initialized:
            return

        logger.info("🚀 Initializing Auto-Orchestrator...")

        # Core components
        self.recorder = None
        self.engine = None
        self.database = None

        # Scanners
        self.parallel_scanner = None
        self.crawler = None
        self.fuzzer = None
        self.vuln_scanner = None
        self.asvs_scanner = None

        # Research & Intelligence
        self.tool_manager = None
        self.nvd_client = None
        self.hacktricks = None
        self.knowledge_base = None

        # Reporting
        self.prof_report_gen = None
        self.comp_report_gen = None

        # Session state
        self.current_target = None
        self.current_session_id = None
        self.evidence_dir = None
        self.auto_mode_enabled = True
        self.web_target_detected = False

        # Auto-research configuration
        self.auto_cve_lookup = True
        self.auto_hacktricks = True
        self.auto_parallel_recon = True
        self.auto_asvs = True
        self.auto_report = True

        # Tracking
        self.discovered_services = []
        self.detected_vulnerabilities = []
        self.executed_scans = []

        self._initialized = True
        logger.info("✅ Auto-Orchestrator initialized")

    def initialize_all_components(self) -> Dict[str, bool]:
        """
        Initialize all SecPluger components on MCP startup.

        Returns:
            Dict mapping component names to initialization status
        """
        logger.info("🔧 Initializing all SecPluger components...")

        status = {}

        try:
            # Core components
            logger.info("  → Initializing workflow recorder...")
            self.recorder = get_recorder()
            status['recorder'] = True

            logger.info("  → Initializing workflow engine...")
            self.engine = WorkflowEngine()
            status['engine'] = True

            logger.info("  → Initializing database...")
            self.database = Database()
            status['database'] = True

            # Tool management
            logger.info("  → Initializing tool manager...")
            self.tool_manager = get_tool_manager()
            status['tool_manager'] = True

            # Intelligence & Research
            logger.info("  → Initializing NVD client...")
            self.nvd_client = get_nvd_client()
            status['nvd_client'] = True

            logger.info("  → Initializing HackTricks search...")
            self.hacktricks = get_hacktricks_search()
            status['hacktricks'] = True

            logger.info("  → Initializing knowledge base...")
            self.knowledge_base = get_knowledge_base()
            status['knowledge_base'] = True

            # Scanners
            logger.info("  → Initializing parallel scanner...")
            self.parallel_scanner = ParallelScanner()
            status['parallel_scanner'] = True

            logger.info("  → Initializing web crawler...")
            self.crawler = WebCrawler()
            status['crawler'] = True

            logger.info("  → Initializing fuzzer...")
            self.fuzzer = WebFuzzer()
            status['fuzzer'] = True

            logger.info("  → Initializing vulnerability scanner...")
            self.vuln_scanner = VulnerabilityScanner()
            status['vuln_scanner'] = True

            # ASVS scanner will be initialized when web target detected
            status['asvs_scanner'] = False  # Lazy init

            # Report generators (lazy init when needed)
            status['prof_report_gen'] = False
            status['comp_report_gen'] = False

            logger.info("✅ All components initialized successfully")

        except Exception as e:
            logger.error(f"❌ Error initializing components: {e}")
            status['error'] = str(e)

        return status

    def start_pentest_session(self, target: str, auto_recon: bool = True) -> Dict[str, Any]:
        """
        Start a new penetration test session with automatic initialization.

        Args:
            target: Target IP/domain
            auto_recon: Automatically trigger parallel reconnaissance

        Returns:
            Session information dictionary
        """
        logger.info(f"🎯 Starting pentest session for target: {target}")

        self.current_target = target
        self.current_session_id = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{target}"
        self.evidence_dir = Path(f"evidence/{self.current_session_id}")
        self.evidence_dir.mkdir(parents=True, exist_ok=True)

        # Start workflow recording
        if self.recorder:
            self.recorder.start_session(target)
            logger.info("📼 Workflow recording started")

        session_info = {
            'target': target,
            'session_id': self.current_session_id,
            'evidence_dir': str(self.evidence_dir),
            'start_time': datetime.now().isoformat(),
            'auto_recon': auto_recon,
            'auto_cve_lookup': self.auto_cve_lookup,
            'auto_hacktricks': self.auto_hacktricks,
            'auto_asvs': self.auto_asvs,
            'auto_report': self.auto_report
        }

        # Save session info
        session_file = self.evidence_dir / "session_info.json"
        with open(session_file, 'w') as f:
            json.dump(session_info, f, indent=2)

        logger.info(f"📁 Evidence directory: {self.evidence_dir}")

        # Trigger automatic parallel reconnaissance if enabled
        if auto_recon and self.auto_parallel_recon:
            logger.info("🔍 Triggering automatic parallel reconnaissance...")
            recon_result = self.run_parallel_reconnaissance(target)
            session_info['recon_result'] = recon_result

        return session_info

    def run_parallel_reconnaissance(self, target: str) -> Dict[str, Any]:
        """
        Run parallel reconnaissance using all available scanners.

        Args:
            target: Target IP/domain

        Returns:
            Reconnaissance results
        """
        logger.info(f"⚡ Running parallel reconnaissance on {target}...")

        if not self.parallel_scanner:
            logger.warning("Parallel scanner not initialized, initializing now...")
            self.parallel_scanner = ParallelScanner()

        try:
            # Define reconnaissance workflow
            scan_configs = [
                {
                    'tool': 'nmap',
                    'args': f"-p- --min-rate 5000 -T4 {target}",
                    'output_file': str(self.evidence_dir / "01_ports.txt")
                },
                {
                    'tool': 'nmap',
                    'args': f"-sV -sC -A {target}",
                    'output_file': str(self.evidence_dir / "02_services.txt")
                }
            ]

            # Add web enumeration if HTTP/HTTPS detected
            if self._is_web_target(target):
                self.web_target_detected = True
                scan_configs.extend([
                    {
                        'tool': 'whatweb',
                        'args': f"http://{target}",
                        'output_file': str(self.evidence_dir / "03_whatweb.txt")
                    },
                    {
                        'tool': 'nikto',
                        'args': f"-h http://{target}",
                        'output_file': str(self.evidence_dir / "04_nikto.txt")
                    }
                ])

            # Execute scans in parallel
            results = self.parallel_scanner.run_scans(scan_configs)

            # Process results and trigger auto-research
            self._process_recon_results(results)

            logger.info("✅ Parallel reconnaissance completed")
            return results

        except Exception as e:
            logger.error(f"❌ Error in parallel reconnaissance: {e}")
            return {'error': str(e)}

    def _is_web_target(self, target: str) -> bool:
        """Check if target is a web server (quick port check)"""
        import socket

        web_ports = [80, 443, 8080, 8443]
        for port in web_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((target, port))
                sock.close()
                if result == 0:
                    return True
            except:
                continue
        return False

    def _process_recon_results(self, results: Dict[str, Any]):
        """
        Process reconnaissance results and trigger automatic research.

        Args:
            results: Scan results from parallel scanner
        """
        logger.info("📊 Processing reconnaissance results...")

        # Extract services
        services = self._extract_services_from_results(results)
        self.discovered_services.extend(services)

        # Trigger automatic CVE lookup for each service
        if self.auto_cve_lookup and services:
            logger.info(f"🔍 Auto-triggering CVE lookup for {len(services)} services...")
            for service in services:
                self.lookup_cve_for_service(service)

        # Trigger HackTricks research for detected attack vectors
        if self.auto_hacktricks:
            attack_vectors = self._identify_attack_vectors(services)
            if attack_vectors:
                logger.info(f"📚 Auto-triggering HackTricks research for {len(attack_vectors)} attack vectors...")
                for vector in attack_vectors:
                    self.research_hacktricks(vector)

        # Trigger ASVS scan if web target
        if self.auto_asvs and self.web_target_detected:
            logger.info("🔒 Auto-triggering ASVS compliance scan...")
            self.run_asvs_scan(f"http://{self.current_target}")

    def _extract_services_from_results(self, results: Dict[str, Any]) -> List[Dict[str, str]]:
        """Extract service information from scan results"""
        services = []

        # Parse nmap output for services
        for scan_name, scan_data in results.items():
            if 'nmap' in scan_name and scan_data.get('output'):
                output = scan_data['output']
                # Simple parsing - look for lines with port/service info
                for line in output.split('\n'):
                    if '/tcp' in line or '/udp' in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            port = parts[0].split('/')[0]
                            service = parts[2] if len(parts) > 2 else 'unknown'
                            version = ' '.join(parts[3:]) if len(parts) > 3 else ''

                            services.append({
                                'port': port,
                                'service': service,
                                'version': version,
                                'protocol': 'tcp' if '/tcp' in line else 'udp'
                            })

        return services

    def _identify_attack_vectors(self, services: List[Dict[str, str]]) -> List[str]:
        """Identify potential attack vectors from discovered services"""
        vectors = []

        for service in services:
            service_name = service.get('service', '').lower()
            port = service.get('port', '')

            # Map common services to attack vectors
            if 'http' in service_name or port in ['80', '443', '8080', '8443']:
                vectors.append('web')
            elif 'ssh' in service_name or port == '22':
                vectors.append('ssh')
            elif 'smb' in service_name or port in ['139', '445']:
                vectors.append('smb')
            elif 'ftp' in service_name or port == '21':
                vectors.append('ftp')
            elif 'sql' in service_name or port in ['3306', '1433', '5432']:
                vectors.append('database')
            elif 'ldap' in service_name or port in ['389', '636']:
                vectors.append('ldap')

        return list(set(vectors))  # Remove duplicates

    def lookup_cve_for_service(self, service: Dict[str, str]) -> Dict[str, Any]:
        """
        Automatically lookup CVEs for a discovered service.

        Args:
            service: Service information dict

        Returns:
            CVE lookup results
        """
        service_name = service.get('service', '')
        version = service.get('version', '')

        logger.info(f"🔍 Looking up CVEs for {service_name} {version}...")

        if not self.nvd_client:
            self.nvd_client = get_nvd_client()

        try:
            # Search NVD
            keyword = f"{service_name} {version}".strip()
            cves = self.nvd_client.search_cves(keyword=keyword, results_per_page=10)

            if cves:
                logger.info(f"✅ Found {len(cves)} CVEs for {service_name}")

                # Save to evidence
                cve_file = self.evidence_dir / f"cve_{service_name.replace(' ', '_')}.json"
                with open(cve_file, 'w') as f:
                    json.dump(cves, f, indent=2)

                # Add high-severity CVEs to vulnerabilities
                for cve in cves:
                    if cve.get('severity') in ['CRITICAL', 'HIGH']:
                        self.detected_vulnerabilities.append({
                            'type': 'cve',
                            'cve_id': cve.get('id'),
                            'service': service_name,
                            'severity': cve.get('severity'),
                            'description': cve.get('description')
                        })
            else:
                logger.info(f"ℹ️  No CVEs found for {service_name} {version}")

            return {'service': service, 'cves': cves}

        except Exception as e:
            logger.error(f"❌ Error looking up CVEs: {e}")
            return {'service': service, 'error': str(e)}

    def research_hacktricks(self, attack_vector: str) -> Dict[str, Any]:
        """
        Automatically research HackTricks for an attack vector.

        Args:
            attack_vector: Attack vector name (e.g., 'web', 'ssh', 'smb')

        Returns:
            HackTricks research results
        """
        logger.info(f"📚 Researching HackTricks for {attack_vector}...")

        if not self.hacktricks:
            self.hacktricks = get_hacktricks_search()

        try:
            results = self.hacktricks.search(attack_vector)

            if results:
                logger.info(f"✅ Found {len(results)} HackTricks articles for {attack_vector}")

                # Save to evidence
                ht_file = self.evidence_dir / f"hacktricks_{attack_vector}.json"
                with open(ht_file, 'w') as f:
                    json.dump(results, f, indent=2)
            else:
                logger.info(f"ℹ️  No HackTricks articles found for {attack_vector}")

            return {'attack_vector': attack_vector, 'results': results}

        except Exception as e:
            logger.error(f"❌ Error researching HackTricks: {e}")
            return {'attack_vector': attack_vector, 'error': str(e)}

    def run_asvs_scan(self, url: str) -> Dict[str, Any]:
        """
        Automatically run ASVS compliance scan for web targets.

        Args:
            url: Target URL

        Returns:
            ASVS scan results
        """
        logger.info(f"🔒 Running ASVS compliance scan on {url}...")

        if not self.asvs_scanner:
            self.asvs_scanner = OwaspAVSVScanner()

        try:
            # Run ASVS 5.0 scan
            results = self.asvs_scanner.scan(url, str(self.evidence_dir))

            logger.info(f"✅ ASVS scan completed: {results.get('summary', {})}")

            return results

        except Exception as e:
            logger.error(f"❌ Error running ASVS scan: {e}")
            return {'error': str(e)}

    def generate_reports(self, format: str = 'both') -> Dict[str, str]:
        """
        Automatically generate comprehensive reports.

        Args:
            format: 'pdf', 'csv', or 'both'

        Returns:
            Dict with paths to generated reports
        """
        logger.info(f"📄 Generating {format} reports...")

        reports = {}

        try:
            # Professional PDF Report
            if format in ['pdf', 'both']:
                if not self.prof_report_gen:
                    self.prof_report_gen = ProfessionalReportGenerator()

                pdf_path = self.evidence_dir / f"pentest_report_{self.current_session_id}.pdf"

                # Gather findings from database
                findings = self.database.get_all_findings() if self.database else []

                self.prof_report_gen.generate_report(
                    target=self.current_target,
                    findings=findings,
                    output_path=str(pdf_path)
                )

                reports['pdf'] = str(pdf_path)
                logger.info(f"✅ PDF report generated: {pdf_path}")

            # CSV Export (ASVS results)
            if format in ['csv', 'both']:
                csv_files = list(self.evidence_dir.glob("asvs_*.csv"))
                if csv_files:
                    reports['csv'] = [str(f) for f in csv_files]
                    logger.info(f"✅ CSV reports: {len(csv_files)} files")
                else:
                    logger.info("ℹ️  No ASVS CSV files found (web target required)")

            # Comprehensive Report Generator
            if format in ['comprehensive', 'both']:
                if not self.comp_report_gen:
                    self.comp_report_gen = ComprehensiveReportGenerator()

                comp_pdf_path = self.evidence_dir / f"comprehensive_report_{self.current_session_id}.pdf"

                self.comp_report_gen.generate_report(
                    target=self.current_target,
                    session_id=self.current_session_id,
                    output_path=str(comp_pdf_path)
                )

                reports['comprehensive_pdf'] = str(comp_pdf_path)
                logger.info(f"✅ Comprehensive PDF generated: {comp_pdf_path}")

            return reports

        except Exception as e:
            logger.error(f"❌ Error generating reports: {e}")
            return {'error': str(e)}

    def finalize_session(self) -> Dict[str, Any]:
        """
        Finalize the pentesting session with automatic report generation.

        Returns:
            Session summary
        """
        logger.info("🏁 Finalizing pentesting session...")

        # Save workflow if recording
        if self.recorder:
            workflow_path = self.evidence_dir / "workflow.json"
            self.recorder.save_workflow(str(workflow_path))
            logger.info(f"📼 Workflow saved: {workflow_path}")

        # Generate reports if enabled
        reports = {}
        if self.auto_report:
            reports = self.generate_reports(format='both')

        # Create session summary
        summary = {
            'session_id': self.current_session_id,
            'target': self.current_target,
            'evidence_dir': str(self.evidence_dir),
            'end_time': datetime.now().isoformat(),
            'services_discovered': len(self.discovered_services),
            'vulnerabilities_found': len(self.detected_vulnerabilities),
            'scans_executed': len(self.executed_scans),
            'reports_generated': list(reports.keys()),
            'web_target': self.web_target_detected
        }

        # Save summary
        summary_file = self.evidence_dir / "session_summary.json"
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2)

        logger.info("✅ Session finalized")
        logger.info(f"📊 Summary: {summary['services_discovered']} services, "
                   f"{summary['vulnerabilities_found']} vulnerabilities")

        return summary


# Singleton accessor
_orchestrator_instance = None

def get_orchestrator() -> AutoOrchestrator:
    """Get the singleton AutoOrchestrator instance"""
    global _orchestrator_instance
    if _orchestrator_instance is None:
        _orchestrator_instance = AutoOrchestrator()
    return _orchestrator_instance


# CLI testing
if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    print("=" * 80)
    print("AUTO-ORCHESTRATOR TEST")
    print("=" * 80)
    print()

    # Initialize orchestrator
    orchestrator = get_orchestrator()

    # Test 1: Initialize all components
    print("[TEST 1] Initializing all components...")
    status = orchestrator.initialize_all_components()
    print(f"✅ Components initialized: {sum(1 for v in status.values() if v)}/{len(status)}")
    for component, init_status in status.items():
        status_icon = "✅" if init_status else "❌"
        print(f"  {status_icon} {component}: {init_status}")
    print()

    # Test 2: Start pentest session (without actual target)
    print("[TEST 2] Testing session initialization...")
    test_target = "192.168.1.100"
    session_info = orchestrator.start_pentest_session(test_target, auto_recon=False)
    print(f"✅ Session started: {session_info['session_id']}")
    print(f"   Evidence dir: {session_info['evidence_dir']}")
    print(f"   Auto features enabled:")
    print(f"     - CVE Lookup: {session_info['auto_cve_lookup']}")
    print(f"     - HackTricks: {session_info['auto_hacktricks']}")
    print(f"     - ASVS: {session_info['auto_asvs']}")
    print(f"     - Reports: {session_info['auto_report']}")
    print()

    # Test 3: Finalize session
    print("[TEST 3] Testing session finalization...")
    summary = orchestrator.finalize_session()
    print(f"✅ Session finalized")
    print(f"   Services discovered: {summary['services_discovered']}")
    print(f"   Vulnerabilities found: {summary['vulnerabilities_found']}")
    print()

    print("=" * 80)
    print("AUTO-ORCHESTRATOR TEST COMPLETE")
    print("=" * 80)
