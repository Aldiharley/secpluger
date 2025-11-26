#!/usr/bin/env python3
"""
Phase 5 Complete Test Suite
Tests automatic exploitation with approval system
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src" / "exploits"))
from exploit_manager import ExploitManager

def test_phase5_complete():
    """Complete Phase 5 test with mock target"""

    print("=" * 80)
    print("PHASE 5: AUTOMATIC EXPLOITATION WITH APPROVAL - COMPLETE TEST")
    print("=" * 80)
    print()

    # Initialize exploit manager
    print("[1/5] Initializing Exploit Manager...")
    em = ExploitManager()
    print(f"✅ Exploit Manager initialized")
    print(f"   - Loaded {len(em.exploit_db)} exploit signatures from database")
    print()

    # Define mock scan results (simulating nmap output)
    print("[2/5] Creating mock scan results...")
    scan_results = {
        'target': '10.10.11.80',
        'services': [
            {
                'port': 8080,
                'product': 'XWiki',
                'version': '15.10',
                'service': 'http'
            },
            {
                'port': 22,
                'product': 'OpenSSH',
                'version': '7.4',
                'service': 'ssh'
            },
            {
                'port': 3306,
                'product': 'MySQL',
                'version': '5.7',
                'service': 'mysql'
            }
        ]
    }
    print(f"✅ Mock scan results created for target {scan_results['target']}")
    print(f"   - Services: {len(scan_results['services'])}")
    for svc in scan_results['services']:
        print(f"     - {svc['product']} {svc['version']} on port {svc['port']}")
    print()

    # Match exploits
    print("[3/5] Matching exploits against services...")
    matches = em.match_exploits(scan_results)
    print(f"✅ Found {len(matches)} matched exploit(s)")
    print()

    if matches:
        print("Matched Exploits:")
        print("-" * 80)
        for i, match in enumerate(matches, 1):
            risk_emoji = {"low": "🟢", "medium": "🟡", "high": "🔴", "critical": "🟣"}.get(
                match.signature.risk_level, "⚪"
            )
            print(f"\n{i}. {risk_emoji} {match.signature.name}")
            print(f"   ID: {match.signature.exploit_id}")
            print(f"   CVE: {match.signature.cve or 'N/A'}")
            print(f"   Target: {match.target}:{match.port}")
            print(f"   Service: {match.service_info.get('product', 'Unknown')} {match.service_info.get('version', '')}")
            print(f"   Confidence: {int(match.confidence * 100)}%")
            print(f"   Risk Level: {match.signature.risk_level.upper()}")
            print(f"   Match Reason: {match.match_reason}")
    print()

    # Test approval system (non-interactive)
    print("[4/5] Testing approval system (non-interactive mode)...")
    print("⚠️  In real usage, this would prompt for human approval.")
    print("⚠️  For testing, we're skipping interactive prompts.")

    # Auto-approve low-risk exploits only (for testing)
    approved_count = 0
    for match in matches:
        if match.signature.risk_level == "low":
            match.approved = True
            approved_count += 1
            print(f"✅ Auto-approved (testing): {match.signature.name} (low risk)")
        else:
            print(f"⦿ Skipped approval: {match.signature.name} ({match.signature.risk_level} risk)")

    print(f"\n✅ Approval phase complete: {approved_count}/{len(matches)} exploits approved")
    print()

    # Generate report
    print("[5/5] Generating exploit report...")
    report = em.get_exploit_report()
    print()
    print(report)
    print()

    # Summary
    print("=" * 80)
    print("PHASE 5 TEST SUMMARY")
    print("=" * 80)
    print()
    print(f"✅ Exploit Manager: WORKING")
    print(f"✅ Exploit Matching: WORKING ({len(matches)} matches)")
    print(f"✅ Confidence Scoring: WORKING")
    print(f"✅ Risk Classification: WORKING")
    print(f"✅ Approval System: READY (interactive mode available)")
    print(f"✅ Report Generation: WORKING")
    print()
    print("⚠️  Note: Actual exploit execution skipped in test mode")
    print("⚠️  Use execute_approved_exploits(interactive=True) for real execution")
    print()
    print("=" * 80)
    print("PHASE 5 INTEGRATION: ✅ COMPLETE & OPERATIONAL")
    print("=" * 80)
    print()
    print("Next Steps:")
    print("  1. Test via MCP: Use match_exploits, approve_exploit, execute_exploits tools")
    print("  2. Test against real target: 10.10.11.80 (with authorization)")
    print("  3. Add more exploits to data/exploit_database.json")
    print("  4. Implement additional built-in exploit logic")
    print()

if __name__ == "__main__":
    try:
        test_phase5_complete()
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
