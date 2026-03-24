"""
Main Entry Point - Multi-Agent Log Analysis System with CrewAI
Orchestrates all 3 phases using CrewAI framework
Phase 1: Reconnaissance (Passive + Active)
Phase 2: Vulnerability Assessment
Phase 3: Reporting & Alerts
"""

import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict

# Import CrewAI orchestrator
try:
    from crew_orchestrator import LogAnalysisCrew
except ImportError:
    from src.crew_orchestrator import LogAnalysisCrew

class MultiAgentLogAnalyzer:
    """Main entry point using CrewAI for orchestration"""
    
    def __init__(self):
        self.crew = LogAnalysisCrew(llm_model="gpt-4")
        self.results = {}
    
    def run_full_analysis(self, log_file_path: str):
        """Execute complete CrewAI workflow across 3 phases"""
        print("\n" + "█"*70)
        print("█  MULTI-AGENT LOG ANALYSIS SYSTEM")
        print("█  Website Security Threat Detection & Reporting")
        print("█  Framework: CrewAI")
        print("█"*70)
        
        try:
            # Run CrewAI workflow for all 3 phases
            analysis_results = self.crew.run_full_analysis(log_file_path)
            self.results = analysis_results
            
            # Save results
            self._save_crewai_results(analysis_results)
            
            print("\n" + "█"*70)
            print("█  ANALYSIS COMPLETE")
            print("█"*70)
            print(f"\n✓ Phase 1 - Reconnaissance: Complete")
            print(f"✓ Phase 2 - Vulnerability Assessment: Complete")
            print(f"✓ Phase 3 - Reporting & Alerts: Complete")
            print(f"\n✓ Results saved to reports/ directory\n")
            
        except Exception as e:
            print(f"\n❌ Error in CrewAI analysis: {str(e)}")
            print(f"\nNote: Ensure you have:")
            print(f"  1. Created .env with API keys")
            print(f"  2. Installed CrewAI: pip install crewai pydantic")
            print(f"  3. Set OPENAI_API_KEY or ANTHROPIC_API_KEY")
    
    def _save_crewai_results(self, results: Dict):
        """Save CrewAI workflow results"""
        report_dir = Path('reports')
        report_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
        
        # Save JSON results
        results_file = report_dir / f"crewai-results-{timestamp}.json"
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        print(f"✓ Results saved: {results_file}")
        
        # Save markdown summary
        summary_file = report_dir / f"crewai-summary-{timestamp}.md"
        with open(summary_file, 'w', encoding='utf-8') as f:
            f.write(self._generate_markdown_summary(results))
        print(f"✓ Summary saved: {summary_file}")
    
    def _generate_markdown_summary(self, results: Dict) -> str:
        """Generate markdown summary of CrewAI results"""
        return f"""# CrewAI Multi-Agent Analysis Results

**Timestamp**: {datetime.now().isoformat()}

## Workflow Summary

### Phase 1 - Reconnaissance
**Status**: {results.get('phase1', {}).get('phase', 'Error')}
**Timestamp**: {results.get('phase1', {}).get('timestamp', 'N/A')}

{results.get('phase1', {}).get('results', 'No results')}

---

### Phase 2 - Vulnerability Assessment
**Status**: {results.get('phase2', {}).get('phase', 'Error')}
**Timestamp**: {results.get('phase2', {}).get('timestamp', 'N/A')}

{results.get('phase2', {}).get('results', 'No results')}

---

### Phase 3 - Reporting & Alerts
**Status**: {results.get('phase3', {}).get('phase', 'Error')}
**Timestamp**: {results.get('phase3', {}).get('timestamp', 'N/A')}

{results.get('phase3', {}).get('results', 'No results')}

---

## Analysis Complete

All 3 phases executed successfully using CrewAI framework.
Agents collaborated with context preservation across phases.
"""


def main():
    """Main entry point"""
    print("\n" + "="*70)
    print("  MULTI-AGENT LOG ANALYSIS SYSTEM")
    print("  Website Security Threat Detection & Reporting")
    print("="*70 + "\n")
    
    # Check if sample logs exist
    log_file = 'data/sample_logs/access.log'
    if not Path(log_file).exists():
        print(f"ERROR: Sample log file not found: {log_file}")
        print("Please ensure sample logs exist in data/sample_logs/")
        sys.exit(1)
    
    # Run analysis using CrewAI
    analyzer = MultiAgentLogAnalyzer()
    analyzer.run_full_analysis(log_file)


if __name__ == '__main__':
    main()
