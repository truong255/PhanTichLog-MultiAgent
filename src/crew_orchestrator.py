"""
CrewAI Orchestrator - Multi-Agent Workflow with Google Gemini
Manages 3 phases: Reconnaissance, Vulnerability Assessment, Reporting
"""

from crewai import Crew, Process
from agents import WebLogAnalysisAgents
from tasks import WebLogAnalysisTasks
from dotenv import load_dotenv
import json
from datetime import datetime
import os

# Load environment variables
load_dotenv()

class LogAnalysisCrew:
    """Orchestrates CrewAI multi-agent workflow with Google Gemini"""
    
    def __init__(self, llm_model=None):
        # Use Gemini from .env or default
        self.llm_model = llm_model or os.getenv("CREWAI_LLM_MODEL", "gemini-1.5-pro")
        
        # Initialize agents with Gemini LLM
        self.agents_factory = WebLogAnalysisAgents(llm_model=self.llm_model)
        self.tasks_factory = WebLogAnalysisTasks()
        self.analysis_results = {}
        
        # Verify API key
        api_key = os.getenv("GOOGLE_API_KEY")
        if not api_key or api_key == "AIza_YOUR_KEY_HERE":
            print("\n⚠️  WARNING: GOOGLE_API_KEY not configured in .env")
            print("   Get key from: https://ai.google.dev/")
    
    def run_phase1_reconnaissance_crew(self, log_file_path: str):
        """PHASE 1: RECONNAISSANCE (Passive + Active)"""
        print("\n" + "█"*70)
        print("█  PHASE 1: RECONNAISSANCE (CrewAI)")
        print("█"*70)
        
        agents = [
            self.agents_factory.log_collector_agent(),
            self.agents_factory.pattern_analyzer_agent(),
        ]
        
        tasks = [
            self.tasks_factory.log_parsing_task(agents[0], log_file_path),
            self.tasks_factory.pattern_analysis_task(agents[1]),
        ]
        
        crew = Crew(
            agents=agents,
            tasks=tasks,
            process=Process.sequential,
            verbose=True,
            memory=True,
        )
        
        print("\n[CrewAI] Executing Phase 1 agents...")
        phase1_results = crew.kickoff()
        
        return {
            'phase': 'RECONNAISSANCE',
            'results': str(phase1_results),
            'timestamp': datetime.now().isoformat()
        }
    
    def run_phase2_vulnerability_crew(self, log_file_path: str, phase1_context: dict):
        """PHASE 2: VULNERABILITY ASSESSMENT"""
        print("\n" + "█"*70)
        print("█  PHASE 2: VULNERABILITY ASSESSMENT (CrewAI)")
        print("█"*70)
        
        agents = [
            self.agents_factory.threat_detector_agent(),
            self.agents_factory.vulnerability_classifier_agent(),
        ]
        
        tasks = [
            self.tasks_factory.threat_detection_task(agents[0], log_file_path, phase1_context),
            self.tasks_factory.vulnerability_classification_task(agents[1], phase1_context),
        ]
        
        crew = Crew(
            agents=agents,
            tasks=tasks,
            process=Process.sequential,
            verbose=True,
            memory=True,
        )
        
        print("\n[CrewAI] Executing Phase 2 agents...")
        phase2_results = crew.kickoff()
        
        return {
            'phase': 'VULNERABILITY_ASSESSMENT',
            'results': str(phase2_results),
            'timestamp': datetime.now().isoformat()
        }
    
    def run_phase3_reporting_crew(self, phase1_context: dict, phase2_context: dict):
        """PHASE 3: REPORTING & ALERTS"""
        print("\n" + "█"*70)
        print("█  PHASE 3: REPORTING & ALERTS (CrewAI)")
        print("█"*70)
        
        agents = [
            self.agents_factory.report_generator_agent(),
            self.agents_factory.alert_manager_agent(),
        ]
        
        tasks = [
            self.tasks_factory.report_generation_task(agents[0], phase1_context, phase2_context),
            self.tasks_factory.alert_generation_task(agents[1], phase1_context, phase2_context),
        ]
        
        crew = Crew(
            agents=agents,
            tasks=tasks,
            process=Process.sequential,
            verbose=True,
            memory=True,
        )
        
        print("\n[CrewAI] Executing Phase 3 agents...")
        phase3_results = crew.kickoff()
        
        return {
            'phase': 'REPORTING_ALERTS',
            'results': str(phase3_results),
            'timestamp': datetime.now().isoformat()
        }
    
    def run_full_analysis(self, log_file_path: str):
        """Execute complete 3-phase analysis using CrewAI"""
        print("\n" + "█"*70)
        print("█  MULTI-AGENT LOG ANALYSIS SYSTEM")
        print("█  Website Security Threat Detection & Reporting")
        print("█  Framework: CrewAI + Google Gemini")
        print("█"*70)
        
        try:
            # Phase 1: Reconnaissance
            phase1_result = self.run_phase1_reconnaissance_crew(log_file_path)
            self.analysis_results['phase1'] = phase1_result
            
            # Phase 2: Vulnerability Assessment
            phase2_result = self.run_phase2_vulnerability_crew(log_file_path, phase1_result)
            self.analysis_results['phase2'] = phase2_result
            
            # Phase 3: Reporting
            phase3_result = self.run_phase3_reporting_crew(phase1_result, phase2_result)
            self.analysis_results['phase3'] = phase3_result
            
            print("\n" + "█"*70)
            print("█  ANALYSIS COMPLETE")
            print("█"*70)
            print(f"\n✓ Phase 1 - Reconnaissance: Complete")
            print(f"✓ Phase 2 - Vulnerability Assessment: Complete")
            print(f"✓ Phase 3 - Reporting & Alerts: Complete")
            
            return self.analysis_results
            
        except Exception as e:
            print(f"\n❌ Error in CrewAI workflow: {str(e)}")
            return {
                'error': str(e),
                'partial_results': self.analysis_results
            }


if __name__ == "__main__":
    crew = LogAnalysisCrew()
    results = crew.run_full_analysis("data/sample_logs/access.log")
    print("\n" + "="*70)
    print("FINAL RESULTS")
    print("="*70)
    print(json.dumps(results, indent=2, default=str))
