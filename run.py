"""
Quick Start Entry Point - Run this to execute the full CrewAI analysis
python run.py
"""

import os
import sys

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from main import MultiAgentLogAnalyzer

def main():
    """Run the CrewAI-powered analysis"""
    print("\n" + "="*70)
    print("  MULTI-AGENT LOG ANALYSIS SYSTEM")
    print("  Website Security Threat Detection & Reporting")
    print("  Powered by: CrewAI Framework")
    print("="*70 + "\n")
    
    # Check if sample logs exist
    log_file = 'data/sample_logs/access.log'
    if not os.path.exists(log_file):
        print(f"ERROR: Sample log file not found: {log_file}")
        print("Please ensure sample logs exist in data/sample_logs/")
        sys.exit(1)
    
    # Run analysis using CrewAI
    analyzer = MultiAgentLogAnalyzer()
    analyzer.run_full_analysis(log_file)
    
    print("\n✓ Analysis complete! Check 'reports' directory for outputs.\n")

if __name__ == '__main__':
    main()
