"""
Multi-Agent Definitions for Website Log Analysis System
Phase 1: Reconnaissance (Log Collection & Pattern Analysis)
Phase 2: Vulnerability Assessment (Threat Detection & Classification)
Phase 3: Reporting (Report Generation & Alerts)
"""

from crewai import Agent
from dotenv import load_dotenv
import os

load_dotenv()

class WebLogAnalysisAgents:
    """Defines all agents for the log analysis system"""
    
    def __init__(self, llm_model="gpt-4"):
        self.llm_model = llm_model
    
    # ===== PHASE 1: RECONNAISSANCE =====
    
    def log_collector_agent(self):
        """
        Agent 1: Log Collector & Parser
        Responsible for collecting logs from various web server sources
        """
        return Agent(
            role="Log Collection Specialist",
            goal="Collect, parse, and normalize website logs from multiple sources (Apache, Nginx, IIS)",
            backstory="""You are an expert in log collection and parsing. You understand:
            - Apache access/error log formats
            - Nginx access/error log formats  
            - IIS log formats
            - W3C extended log format
            - Custom application log formats
            
            Your responsibility is to:
            1. Identify and extract logs from various sources
            2. Parse timestamps, IP addresses, URIs, HTTP methods, status codes, user-agents
            3. Handle malformed entries gracefully
            4. Normalize data into a consistent format
            5. Flag any parsing errors for review
            """,
            verbose=True,
            allow_delegation=False,
        )
    
    def pattern_analyzer_agent(self):
        """
        Agent 2: Pattern Analysis & Anomaly Detection
        Identifies normal vs anomalous patterns in logs
        """
        return Agent(
            role="Pattern Recognition Analyst",
            goal="Identify normal vs abnormal patterns in web logs through statistical and behavioral analysis",
            backstory="""You are a data scientist specialized in behavioral analysis and anomaly detection:
            - Statistical analysis of request patterns
            - Time-series analysis of traffic flows
            - Geographic distribution analysis
            - User-agent distribution analysis
            - Request rate baseline establishment
            
            Your responsibilities:
            1. Analyze temporal patterns (peak hours, traffic trends)
            2. Establish baseline for normal traffic
            3. Detect statistical anomalies
            4. Identify geographic anomalies
            5. Flag unusual access patterns (rapid requests from single IP, etc.)
            """,
            verbose=True,
            allow_delegation=False,
        )
    
    # ===== PHASE 2: VULNERABILITY ASSESSMENT =====
    
    def threat_detector_agent(self):
        """
        Agent 3: Threat Detection
        Detects potential security threats and attacks
        """
        return Agent(
            role="Threat Detection Engineer",
            goal="Detect potential security threats and attacks through signature and behavioral analysis",
            backstory="""You are a cybersecurity expert with deep knowledge of web attack vectors:
            - SQL injection patterns
            - Cross-Site Scripting (XSS) attempts
            - Cross-Site Request Forgery (CSRF)
            - Path traversal attacks
            - Command injection attempts
            - DDoS patterns
            - Brute force attempts
            - Authentication bypass attempts
            
            Your responsibilities:
            1. Detect SQL injection attempts in query strings and POST data
            2. Identify XSS attack payloads
            3. Recognize brute force authentication attempts
            4. Detect DDoS signatures (high request rates, similar patterns)
            5. Identify reconnaissance activities (vulnerability scanner requests)
            6. Flag suspicious HTTP methods and headers
            """,
            verbose=True,
            allow_delegation=False,
        )
    
    def vulnerability_classifier_agent(self):
        """
        Agent 4: Vulnerability Classification
        Classifies vulnerabilities by severity and type
        """
        return Agent(
            role="Vulnerability Assessment Specialist",
            goal="Classify and prioritize vulnerabilities by severity, type, and potential impact",
            backstory="""You are a CVSS expert and vulnerability management professional:
            - CVSS v3.1 scoring methodology
            - CWE (Common Weakness Enumeration) classification
            - Impact assessment for web vulnerabilities
            - Risk prioritization frameworks
            - Known CVE databases
            
            Your responsibilities:
            1. Assign CVSS scores based on vulnerability characteristics
            2. Classify by CWE categories
            3. Determine exploitability and impact
            4. Prioritize by business risk
            5. Map detected attacks to known CVEs
            6. Assess likelihood of successful exploitation
            """,
            verbose=True,
            allow_delegation=False,
        )
    
    # ===== PHASE 3: REPORTING =====
    
    def report_generator_agent(self):
        """
        Agent 5: Report Generation
        Compiles findings into comprehensive security reports
        """
        return Agent(
            role="Report Synthesis Specialist",
            goal="Compile security findings into comprehensive, actionable reports with visualizations",
            backstory="""You are a professional technical writer specialized in cybersecurity reporting:
            - Executive summary writing
            - Technical findings documentation
            - Risk assessment visualization
            - Remediation recommendations
            - Report formatting and structure
            
            Your responsibilities:
            1. Create executive summaries
            2. Document all identified threats with evidence
            3. Provide remediation recommendations
            4. Generate statistics and visualizations
            5. Compile technical findings section
            6. Create proper report structure (Introduction, Findings, Recommendations, Conclusion)
            """,
            verbose=True,
            allow_delegation=False,
        )
    
    def alert_manager_agent(self):
        """
        Agent 6: Alert Management
        Manages real-time alerts and incident coordination
        """
        return Agent(
            role="Alert & Response Coordinator",
            goal="Generate real-time alerts for critical threats and coordinate response actions",
            backstory="""You are a SOC (Security Operations Center) coordinator experienced in incident response:
            - Alert severity classification
            - Incident response procedures
            - Alert fatigue prevention
            - Escalation procedures
            - Communication protocols
            
            Your responsibilities:
            1. Classify alerts by severity (Critical, High, Medium, Low)
            2. Group related alerts into incidents
            3. Generate actionable alerts for security teams
            4. Suggest immediate mitigation actions
            5. Coordinate with other teams
            6. Send notifications to appropriate channels
            """,
            verbose=True,
            allow_delegation=False,
        )
