"""
Multi-Agent Task Definitions for Website Log Analysis System
Defines specific tasks for each agent to execute in 3 phases
"""

from crewai import Task
from datetime import datetime

class WebLogAnalysisTasks:
    """Defines all tasks for the multi-agent log analysis system"""
    
    # ===== PHASE 1: RECONNAISSANCE =====
    
    def log_parsing_task(self, log_analyzer_agent, log_file_path: str):
        """Task 1: Parse and normalize web server logs from file"""
        return Task(
            description=f"""
            Parse and normalize web server logs from: {log_file_path}
            
            Analyze Apache/Nginx/IIS logs and extract:
            1. Timestamp (ISO 8601 format)
            2. Source IP address
            3. HTTP method (GET, POST, etc.)
            4. Resource URI
            5. HTTP status code
            6. Response size
            7. User-Agent
            8. Query parameters
            
            Output: Normalized JSON with parsing quality metrics
            """,
            agent=log_analyzer_agent,
            expected_output="Parsed log entries with metadata"
        )
    
    def pattern_analysis_task(self, pattern_analyzer_agent):
        """Task 2: Analyze patterns and establish traffic baselines"""
        return Task(
            description="""
            Analyze parsed logs to identify patterns:
            
            1. TEMPORAL: Peak hours, traffic trends
            2. GEOGRAPHIC: IP distribution, countries
            3. BEHAVIORAL: Request patterns, anomalies
            4. STATISTICAL: Baselines for normal traffic
            
            Establish traffic baseline metrics.
            """,
            agent=pattern_analyzer_agent,
            expected_output="Pattern analysis with baselines"
        )
    
    # ===== PHASE 2: VULNERABILITY ASSESSMENT =====
    
    def threat_detection_task(self, threat_detector_agent, log_file_path: str, phase1_context: dict):
        """Task 3: Detect threats using Phase 1 reconnaissance data"""
        return Task(
            description=f"""
            Using Phase 1 context (server info, baselines), detect threats in: {log_file_path}
            
            Detect:
            1. SQL Injection attempts
            2. XSS attacks
            3. Path traversal
            4. Command injection
            5. DDoS patterns
            6. Brute force attempts
            7. Scanner activity
            
            Phase 1 Server Info: {phase1_context.get('server_info', {})}
            """,
            agent=threat_detector_agent,
            expected_output="List of detected threats with type, severity, source"
        )
    
    def vulnerability_classification_task(self, vulnerability_classifier_agent, phase1_context: dict):
        """Task 4: Classify vulnerabilities with CVSS scores"""
        return Task(
            description=f"""
            Classify all detected vulnerabilities using CVSS v3.1:
            
            For each threat:
            1. Assign CVSS base score (0.0-10.0)
            2. Determine severity (Low/Medium/High/Critical)
            3. Map to CWE identifiers
            4. Suggest remediation
            
            Server Context: {phase1_context}
            """,
            agent=vulnerability_classifier_agent,
            expected_output="Classified vulnerabilities with CVSS scores"
        )
    
    # ===== PHASE 3: REPORTING & ALERTS =====
    
    def report_generation_task(self, report_generator_agent, phase1_context: dict, phase2_context: dict):
        """Task 5: Generate comprehensive security report"""
        return Task(
            description=f"""
            Generate comprehensive security analysis report using Phase 1 & 2 data:
            
            Report sections:
            1. Executive Summary
            2. Reconnaissance Findings (server info, endpoints)
            3. Vulnerability Assessment (threats detected)
            4. Risk Assessment (overall risk score)
            5. Remediation Recommendations
            6. Technical Details
            
            Phase 1 Data: {phase1_context}
            Phase 2 Data: {phase2_context}
            """,
            agent=report_generator_agent,
            expected_output="Professional security report in markdown and JSON"
        )
    
    def alert_generation_task(self, alert_manager_agent, phase1_context: dict, phase2_context: dict):
        """Task 6: Generate security alerts based on findings"""
        return Task(
            description=f"""
            Generate security alerts for SOC/incident response team:
            
            For each High/Critical vulnerability:
            1. Create alert
            2. Assign severity
            3. Provide detection evidence
            4. Suggest immediate actions
            5. Track affected resources
            
            Data from Phase 1 & 2: 
            Phase 1: {phase1_context}
            Phase 2: {phase2_context}
            """,
            agent=alert_manager_agent,
            expected_output="Structured alerts ready for SIEM/email distribution"
        )
