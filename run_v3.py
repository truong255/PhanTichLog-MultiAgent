#!/usr/bin/env python3
"""
Full Pentest Run - Phase 1 + Phase 2 + Phase 3
Run: python run_v3.py
"""

import os
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from orchestrator_v3 import Phase1Phase2Phase3Orchestrator
from generate_html_dashboard import HTMLDashboardGenerator


def main():
    """Run complete 3-phase pentest"""
    
    print("\n" + "="*70)
    print("  COMPLETE PENTEST SYSTEM")
    print("  Phase 1: Reconnaissance (Active + Passive)")
    print("  Phase 2: Vulnerability Assessment")
    print("  Phase 3: Report & Defense Rules")
    print("="*70 + "\n")
    
    # Configuration
    target = "localhost"  # Can be: localhost, 127.0.0.1, hostname, or IP
    log_file = 'data/sample_logs/access.log'
    output_dir = 'reports'
    
    os.makedirs(output_dir, exist_ok=True)
    
    print(f"Target: {target}")
    print(f"Log File: {log_file}")
    print(f"Output Directory: {output_dir}\n")
    
    # Run orchestrator
    orchestrator = Phase1Phase2Phase3Orchestrator(target=target, verbose=True)
    results = orchestrator.run_full_pentest(log_file=log_file, output_dir=output_dir)
    
    # Print summary
    print("\n" + "="*70)
    print("  PENTEST SUMMARY")
    print("="*70)
    print(f"\nPhase 1 Reconnaissance:")
    print(f"  - Vulnerabilities found: {results['analysis_results']['phase1_findings']}")
    print(f"\nPhase 2 Vulnerability Assessment:")
    print(f"  - Threats detected: {results['analysis_results']['phase2_threats']}")
    print(f"\nPhase 3 Reports Generated:")
    print(f"  - Phase 1: {results['phase1_recon']}")
    print(f"  - Phase 2 Technical: {results['phase2_technical']}")
    print(f"  - Phase 2 Executive: {results['phase2_executive']}")
    print(f"  - Rules: {results['rules_path']}")
    print(f"  - Memory Log: {results['memory_log']}")
    
    # Generate HTML Dashboard
    print("\n[...] Generating Interactive HTML Dashboard...")
    dashboard_generator = HTMLDashboardGenerator(report_dir=output_dir)
    dashboard_file = dashboard_generator.generate_file()
    if dashboard_file:
        print(f"  - Dashboard: {dashboard_file}")
    
    print("\n" + "="*70 + "\n")


if __name__ == '__main__':
    main()
