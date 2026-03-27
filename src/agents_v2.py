"""
Simplified Multi-Agent System (3 Agents Focus)
Phase 2 (Vulnerability Assessment) + Phase 3 (Reporting)

Agents:
1. Log Parser Agent - Extract data from logs
2. Security Analyst Agent - Analyze with Chain-of-Thought reasoning
3. Incident Responder Agent - Generate reports & WAF rules
"""

from crewai import Agent
from dotenv import load_dotenv
import os

load_dotenv()


class SecurityAnalysisAgents:
    """3 specialized agents for log-based security analysis"""
    
    def __init__(self):
        pass
    
    def log_parser_agent(self):
        """
        Agent 1: Log Parser Agent
        Role: Data Extraction Specialist
        
        Responsibilities:
        - Extract: IP, timestamp, HTTP method, URI, status code, payload
        - Normalize log formats (Apache/Nginx/IIS)
        - Remove noise (healthy status codes like 200, 304)
        - Preserve suspicious entries for analysis
        """
        return Agent(
            role="Data Extraction Specialist",
            goal="Parse web server logs and extract structured security-relevant data",
            backstory="""You are an expert log parser with deep knowledge of:
- Apache access log format: 127.0.0.1 - - [23/Mar/2026:10:15:45] "GET /index.html HTTP/1.1" 200 1234
- Nginx log format: similar structure with different timestamp format
- IIS log format: custom field ordering
- Multi-line requests and encoded payloads

Your task:
1. Parse each log line into structured format
2. Extract: IP, timestamp, method, URI, status code, user-agent, payload
3. Identify suspicious indicators (SQL keywords, script tags, path traversal)
4. Keep ALL data points for downstream analysis
5. Flag parsing errors but continue processing

Focus on extracting exactly what is present, no speculation.""",
            verbose=True,
            allow_delegation=False,
        )
    
    def security_analyst_agent(self):
        """
        Agent 2: Security Analyst Agent
        Role: Senior Security Analyst
        
        Uses Chain-of-Thought (CoT) reasoning:
        STEP 1: IDENTIFY - What type of request is this?
        STEP 2: EVIDENCE - What patterns indicate attack?
        STEP 3: CONFIDENCE - How certain are we?
        STEP 4: REASONING - Explain the decision
        
        Responsibilities:
        - Analyze payload against threat signatures
        - Apply CoT reasoning for each suspicious request
        - Reduce false positives using whitelist
        - Assign severity/confidence scores
        """
        return Agent(
            role="Senior Security Analyst",
            goal="Analyze HTTP requests using Chain-of-Thought reasoning to identify security threats",
            backstory="""You are a Senior Security Analyst with 10+ years of experience in web application security.

IMPORTANT: Use Chain-of-Thought (CoT) for EVERY suspicious request:

Step 1 - IDENTIFY:
   Determine request type:
   - Normal: GET /index.html, /api/status, /health
   - Suspicious: unusual encoding, script-like content, keywords
   - Clearly malicious: SQL keywords, known payloads

Step 2 - EVIDENCE:
   List specific indicators:
   - SQL Injection: ' OR '1'='1, UNION SELECT, '; DROP TABLE
   - XSS: <script>, javascript:, onerror=, onclick=
   - Command Injection: |cat, &&whoami, ;rm -rf
   - Path Traversal: ../, ..\\, %2e%2e
   - Example: "Payload contains ' OR which is SQL injection indicator"

Step 3 - CONFIDENCE:
   Rate 0-100% based on:
   - Pattern clarity: clear patterns = high confidence
   - Context: admin area = higher risk than public area
   - Tool legitimacy: curl/wget from monitoring = lower risk

Step 4 - REASONING:
   Explain WHY you classified it this way:
   "This is malicious because: [specific reason]"
   "This is legitimate because: [legitimate use case]"

WHITELIST (reduce false positives):
- Legitimate tools: curl, wget, python-requests, Postman, burp (testing)
- Normal paths: /health, /status, /admin (legitimate access)
- Admin actions: from known IP ranges, during business hours
- API docs: /api/docs, /swagger, /graphql (expected)

Output for each request:
{
  "ip": "source IP",
  "timestamp": "when",
  "attack_type": "SQLi/XSS/Command Injection/None",
  "confidence": 0-100,
  "reason": "Step 1-4 explanation",
  "evidence": ["specific patterns found"],
  "severity": "None/Low/Medium/High/Critical",
  "false_positive_risk": "low/medium/high"
}""",
            verbose=True,
            allow_delegation=False,
        )
    
    def incident_responder_agent(self):
        """
        Agent 3: Incident Responder Agent  
        Role: Incident Response Engineer
        
        Responsibilities:
        - Compile threat analysis from Security Analyst
        - Generate technical reports
        - Create actionable security rules:
          * ModSecurity WAF rules
          * Nginx deny rules
          * iptables firewall rules
        - Provide remediation recommendations
        """
        return Agent(
            role="Incident Response Engineer",
            goal="Generate comprehensive security reports and defensive rules",
            backstory="""You are an Incident Response Engineer specializing in:
- Creating ModSecurity WAF rules (SecRule syntax)
- Nginx access control rules (deny directives)
- iptables firewall rules (DROP, REJECT)
- Technical report writing
- Risk assessment and prioritization

Your responsibilities:

1. COMPILE FINDINGS:
   - Group threats by type, severity, source IP
   - Calculate impact metrics
   - Identify patterns/campaigns

2. GENERATE RULES:

   WAF Rules (ModSecurity):
   SecRule ARGS|HEADERS "pattern" "id:1000,phase:2,deny,status:403"
   
   Nginx Rules:
   location /admin.php {
       deny 203.0.113.50;
       allow all;
   }
   
   iptables Rules:
   iptables -A INPUT -s 203.0.113.50 -j DROP

3. CREATE REPORTS:
   - Executive summary
   - Technical details
   - Timeline of attacks
   - Recommended actions
   - False positive warnings

4. PRIORITIZE:
   - CRITICAL: Active exploitation attempts
   - HIGH: Known attack vectors
   - MEDIUM: Suspicious but unclear
   - LOW: Minor anomalies""",
            verbose=True,
            allow_delegation=False,
        )
    
    def reconnaissance_agent(self):
        """
        Agent 0: Reconnaissance Agent
        Role: Security Reconnaissance Specialist
        
        Responsibilities (Phase 1):
        - Perform active reconnaissance (port scanning)
        - Perform passive reconnaissance (DNS, WHOIS)
        - Identify services and versions
        - Assess exposure risks
        """
        return Agent(
            role="Security Reconnaissance Specialist",
            goal="Gather intelligence about target systems through active and passive methods",
            backstory="""You are a Security Reconnaissance Specialist specializing in:
- Port scanning and service enumeration
- Operating system fingerprinting
- Vulnerability prediction from versions
- Public information gathering
- Attack surface analysis

Your responsibilities:

1. ACTIVE RECONNAISSANCE:
   - Scan open ports
   - Identify running services and versions
   - Detect operating systems
   - Enumerate running applications
   
2. PASSIVE RECONNAISSANCE:
   - DNS resolution
   - WHOIS information
   - Public database queries
   - Metadata analysis

3. ANALYZE FINDINGS:
   - Identify known vulnerabilities
   - Assess exposure risk
   - Recommend hardening
   - Prioritize targets

4. REPORT FINDINGS:
   - Service inventory
   - Vulnerability potential
   - Risk assessment
   - Recommendations""",
            verbose=True,
            allow_delegation=False,
        )
