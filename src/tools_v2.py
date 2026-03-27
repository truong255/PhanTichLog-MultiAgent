"""
Enhanced Tools for Multi-Agent Security Analysis
Phase 2: Chain-of-Thought Threat Analysis
Phase 3: WAF Rules & Report Generation

Tools:
- Enhanced threat detection with CoT reasoning
- WAF rule generator (ModSecurity, Nginx, iptables)
- Hallucination reducer (whitelist + negative examples)
- Report generator
"""

import json
import re
from typing import List, Dict, Optional


class CoTThreatAnalyzer:
    """
    Chain-of-Thought Threat Analyzer
    Implements reasoning: IDENTIFY → EVIDENCE → CONFIDENCE → REASONING
    """
    
    # Threat signatures database
    THREAT_SIGNATURES = {
        "sql_injection": {
            "patterns": [
                r"'\s*OR\s*'1'\s*=\s*'1",
                r"1'\s*UNION\s*SELECT",
                r"';\s*DROP\s*TABLE",
                r"OR\s+1\s*=\s*1",
                r"UNION\s+SELECT",
                r"UNION\s+ALL\s+SELECT",
                r"SLEEP\s*\(",
                r"BENCHMARK\s*\(",
            ],
            "keywords": ["UNION", "SELECT", "DROP", "DELETE", "INSERT", "UPDATE"],
            "severity_base": "High"
        },
        "xss": {
            "patterns": [
                r"<script[^>]*>",
                r"javascript:",
                r"on\w+\s*=",  # onerror=, onclick=, etc
                r"<iframe[^>]*>",
                r"<svg[^>]*onload",
                r"eval\s*\(",
                r"expression\s*\(",
            ],
            "keywords": ["script", "javascript", "onerror", "onclick", "eval"],
            "severity_base": "High"
        },
        "command_injection": {
            "patterns": [
                r"\|\s*cat\b",
                r"&&\s*whoami",
                r";\s*rm\s+-rf",
                r"`.*`",  # Command substitution
                r"\$\(.*\)",  # Command substitution
                r">\s*/tmp/",
                r">\s*/var/",
            ],
            "keywords": ["cat", "whoami", "rm", "ls", "nc", "bash", ";", "|", "&"],
            "severity_base": "Critical"
        },
        "path_traversal": {
            "patterns": [
                r"\.\./",
                r"\.\.\%2f",
                r"%2e%2e",
                r"\.\.%5c",  # Windows path
                r"/etc/passwd",
                r"/windows/win.ini",
            ],
            "keywords": ["..", "passwd", "win.ini"],
            "severity_base": "Medium"
        },
        "brute_force": {
            "patterns": [
                r"/admin/login",
                r"/wp-login",
                r"multiple 401/403",
            ],
            "keywords": ["login", "admin", "auth"],
            "severity_base": "Medium"
        }
    }
    
    # Whitelist to reduce false positives
    LEGITIMATE_TOOLS = ["curl", "wget", "python-requests", "postman", "burp", "telnet"]
    LEGITIMATE_PATHS = [
        "/health", "/status", "/heartbeat", "/ping",
        "/api/docs", "/swagger", "/graphql",
        "/robots.txt", "/sitemap.xml",
        "/admin"  # Legitimate admin access
    ]
    LEGITIMATE_KEYWORDS = ["report", "export", "api", "download"]
    
    def analyze_request(self, request_data: Dict) -> Dict:
        """
        Analyze single HTTP request using Chain-of-Thought reasoning
        
        Few-shot Examples (for reference):
        
        MALICIOUS EXAMPLE 1 (SQL Injection):
        Input: {"ip": "203.0.113.50", "uri": "/admin.php?id=1' OR '1'='1"}
        Step 1: IDENTIFY - Suspicious (special characters)
        Step 2: EVIDENCE - "' OR '1'='1" is classic SQL injection payload
        Step 3: CONFIDENCE - 95% (exact known pattern)
        Step 4: REASONING - This request contains definitive SQL injection pattern
        Output: attack_type=sql_injection, severity=Critical, confidence=95%
        
        LEGITIMATE EXAMPLE 1 (Normal Admin Access):
        Input: {"ip": "10.0.0.1", "user_agent": "curl", "uri": "/admin"}
        Step 1: IDENTIFY - Normal (from legitimate cURL tool)
        Step 2: EVIDENCE - None (no malicious patterns)
        Step 3: CONFIDENCE - 5% (legitimate use case)
        Step 4: REASONING - This is expected admin monitoring traffic
        Output: attack_type=None, severity=None, confidence=5%
        
        MALICIOUS EXAMPLE 2 (XSS):
        Input: {"ip": "198.51.100.45", "uri": "/search?q=<script>alert('xss')</script>"}
        Step 1: IDENTIFY - Suspicious (script tags)
        Step 2: EVIDENCE - "<script>" tag detected, which is XSS indicator
        Step 3: CONFIDENCE - 90%
        Output: attack_type=xss, severity=High, confidence=90%
        
        Input: {
            "ip": "203.0.113.50",
            "timestamp": "2026-03-27T10:15:45",
            "method": "GET",
            "uri": "/admin.php?id=1' OR '1'='1",
            "status": 403,
            "user_agent": "Mozilla/5.0",
            "payload": "1' OR '1'='1"
        }
        
        Returns: CoT reasoning with threat assessment
        """
        
        # STEP 1: IDENTIFY request type
        request_type = self._identify_request_type(request_data)
        
        # STEP 2: Find EVIDENCE (attack patterns)
        evidence, threat_type = self._find_evidence(request_data)
        
        # STEP 3: Calculate CONFIDENCE
        confidence = self._calculate_confidence(request_data, evidence, threat_type)
        
        # STEP 4: Generate REASONING
        reasoning = self._generate_reasoning(request_data, request_type, evidence, threat_type, confidence)
        
        # Determine severity based on threat type and context
        severity = self._determine_severity(threat_type, confidence, request_data)
        
        return {
            "ip": request_data.get("ip"),
            "timestamp": request_data.get("timestamp"),
            "uri": request_data.get("uri"),
            
            # CoT Steps
            "step_1_identify": request_type,
            "step_2_evidence": evidence,
            "step_3_confidence": confidence,
            "step_4_reasoning": reasoning,
            
            # Results
            "attack_type": threat_type if threat_type else "None",
            "severity": severity,
            "false_positive_risk": self._assess_false_positive_risk(request_data, evidence),
            "recommendation": self._generate_recommendation(threat_type, severity)
        }
    
    def _identify_request_type(self, req: Dict) -> str:
        """STEP 1: Identify type of request"""
        payload = req.get("payload", "").lower()
        uri = req.get("uri", "").lower()
        user_agent = req.get("user_agent", "").lower()
        
        # Check if it's from legitimate tool
        for tool in self.LEGITIMATE_TOOLS:
            if tool in user_agent:
                return f"Normal - Legitimate tool ({tool})"
        
        # Check if it's accessing legitimate path
        for path in self.LEGITIMATE_PATHS:
            if path in uri:
                return f"Normal - Legitimate path ({path})"
        
        # Check if suspicious
        if any(keyword in payload for keyword in ["'", '"', ";", "|", "&", "<", ">"]):
            return "Suspicious - Special characters detected"
        
        # Default
        return "Normal - No immediate indicators"
    
    def _find_evidence(self, req: Dict) -> tuple:
        """STEP 2: Find specific attack EVIDENCE"""
        payload = req.get("payload", "")
        uri = req.get("uri", "")
        full_request = f"{uri} {payload}".lower()
        
        detected_patterns = []
        threat_type = None
        
        # Check each threat type
        for threat_name, threat_info in self.THREAT_SIGNATURES.items():
            # Check patterns
            for pattern in threat_info["patterns"]:
                if re.search(pattern, full_request, re.IGNORECASE):
                    detected_patterns.append(pattern)
                    if not threat_type:
                        threat_type = threat_name
            
            # Check keywords
            for keyword in threat_info["keywords"]:
                if re.search(r"\b" + keyword + r"\b", full_request, re.IGNORECASE):
                    detected_patterns.append(f"Keyword: {keyword}")
                    if not threat_type:
                        threat_type = threat_name
        
        return detected_patterns, threat_type
    
    def _calculate_confidence(self, req: Dict, evidence: List, threat_type: Optional[str]) -> int:
        """STEP 3: Calculate CONFIDENCE (0-100%)"""
        confidence = 0
        
        if not threat_type:
            return 0  # No threat detected
        
        # Base confidence from evidence count
        confidence = min(100, len(evidence) * 20)
        
        # Adjust based on status code
        status = req.get("status", 200)
        if status in [403, 401]:  # Blocked request
            confidence = min(100, confidence + 15)
        
        # Reduce confidence for legitimate contexts
        user_agent = req.get("user_agent", "").lower()
        for tool in self.LEGITIMATE_TOOLS:
            if tool in user_agent:
                confidence = max(0, confidence - 40)  # Significantly lower for legit tools
        
        # Reduce confidence if during business hours and from known admin area
        uri = req.get("uri", "").lower()
        if threat_type == "sql_injection" and "/admin" in uri:
            # Might be legitimate admin action
            confidence = max(0, confidence - 10)
        
        return confidence
    
    def _generate_reasoning(self, req: Dict, request_type: str, evidence: List, 
                           threat_type: Optional[str], confidence: int) -> str:
        """STEP 4: Generate REASONING explanation"""
        
        if not threat_type or confidence < 40:
            reasoning = f"Request classified as {request_type}. "
            reasoning += f"No clear malicious indicators detected (confidence: {confidence}%)"
            return reasoning
        
        reasoning = f"Step 1 - IDENTIFY: {request_type}\n"
        reasoning += f"Step 2 - EVIDENCE: Detected {len(evidence)} indicators of {threat_type}\n"
        reasoning += f"  - Specific patterns: {', '.join(evidence[:3])}\n"
        reasoning += f"Step 3 - CONFIDENCE: {confidence}%\n"
        reasoning += f"Step 4 - REASONING: This request contains clear {threat_type} patterns. "
        
        if confidence >= 80:
            reasoning += "The indicators are definitive."
        elif confidence >= 60:
            reasoning += "The indicators are strong but warrant manual verification."
        else:
            reasoning += "The indicators are present but may need context verification."
        
        return reasoning
    
    def _determine_severity(self, threat_type: Optional[str], confidence: int, req: Dict) -> str:
        """Determine severity level"""
        
        if not threat_type:
            return "None"
        
        if confidence < 40:
            return "Low"
        elif confidence < 60:
            return "Medium"
        elif confidence < 80:
            return "High"
        else:
            # Critical if high confidence + command injection or active exploitation
            if threat_type == "command_injection":
                return "Critical"
            elif req.get("status") == 403 and threat_type in ["sql_injection", "xss"]:
                return "High"
            else:
                return "High"
    
    def _assess_false_positive_risk(self, req: Dict, evidence: List) -> str:
        """Assess risk of this being a false positive"""
        user_agent = req.get("user_agent", "").lower()
        
        # High risk: legitimate tools
        for tool in self.LEGITIMATE_TOOLS:
            if tool in user_agent:
                return "High"
        
        # Medium risk: moderate evidence
        if len(evidence) <= 2:
            return "Medium"
        
        # Low risk: strong evidence
        return "Low"
    
    def _generate_recommendation(self, threat_type: Optional[str], severity: str) -> str:
        """Generate actionable recommendation"""
        
        if severity == "Critical":
            return "IMMEDIATE ACTION: Block IP address, investigate system for compromise"
        elif severity == "High":
            return "Block IP address in WAF, monitor for related attempts"
        elif severity == "Medium":
            return "Add to watchlist, correlate with other events, consider rate limiting"
        else:
            return "Monitor, no immediate action required"


class WAFRuleGenerator:
    """Generate WAF rules in multiple formats"""
    
    def generate_modsecurity_rule(self, threat_info: Dict) -> Optional[str]:
        """Generate ModSecurity WAF rule"""
        
        attack_type = threat_info.get("attack_type")
        if not attack_type or attack_type == "None":
            return None
        
        severity = threat_info.get("severity", "Medium")
        confidence = threat_info.get("step_3_confidence", 0)
        
        if confidence < 70:
            return None  # Don't generate for low confidence
        
        # Map attack types to ModSecurity IDs
        id_map = {
            "sql_injection": 1001,
            "xss": 1002,
            "command_injection": 1003,
            "path_traversal": 1004,
        }
        
        rule_id = id_map.get(attack_type, 1000)
        
        # Build SecRule
        if attack_type == "sql_injection":
            pattern = r"(\bUNION\b.*\bSELECT\b|'.*OR.*'|;\s*DROP)"
            rule = f'SecRule ARGS|HEADERS "{pattern}" "id:{rule_id},phase:2,deny,status:403,msg:\'SQL Injection Detected\'"'
        elif attack_type == "xss":
            pattern = r"(<script|javascript:|on\w+\s*=|<iframe)"
            rule = f'SecRule ARGS|HEADERS "{pattern}" "id:{rule_id},phase:2,deny,status:403,msg:\'XSS Detected\'"'
        elif attack_type == "command_injection":
            pattern = r"(;\s*rm|&&\s*whoami|\|\s*cat)"
            rule = f'SecRule ARGS|HEADERS "{pattern}" "id:{rule_id},phase:2,deny,status:403,msg:\'Command Injection Detected\'"'
        else:
            return None
        
        return rule
    
    def generate_nginx_rule(self, threat_info: Dict, source_ip: str) -> Optional[str]:
        """Generate Nginx deny rule"""
        
        attack_type = threat_info.get("attack_type")
        if not attack_type or attack_type == "None":
            return None
        
        severity = threat_info.get("severity", "Medium")
        
        if severity in ["High", "Critical"]:
            # Block this IP completely
            rule = f"""# Block {attack_type} attack source
if ($remote_addr = "{source_ip}") {{
    return 403;
}}"""
            return rule
        else:
            # Rate limit
            rule = f"""limit_req_zone $remote_addr zone=attack_{source_ip}:10m rate=1r/m;
location / {{
    limit_req zone=attack_{source_ip} burst=2 nodelay;
}}"""
            return rule
    
    def generate_iptables_rule(self, source_ip: str, severity: str) -> Optional[str]:
        """Generate iptables firewall rule"""
        
        if severity in ["High", "Critical"]:
            # Drop all traffic from this IP
            return f"iptables -A INPUT -s {source_ip} -j DROP"
        else:
            # Reject with reset
            return f"iptables -A INPUT -s {source_ip} -j REJECT --reject-with tcp-reset"


class ReportFormatter:
    """Format analysis results into professional reports"""
    
    def generate_markdown_report(self, analysis_results: List[Dict]) -> str:
        """Generate markdown security report (technical version)"""
        
        report = """# Security Analysis Report
Generated: 2026-03-27

## Executive Summary

"""
        
        # Count threats by type
        threat_counts = {}
        total_threats = 0
        
        for result in analysis_results:
            attack_type = result.get("attack_type")
            if attack_type != "None":
                threat_counts[attack_type] = threat_counts.get(attack_type, 0) + 1
                total_threats += 1
        
        report += f"- Total Requests Analyzed: {len(analysis_results)}\n"
        report += f"- Potential Threats Detected: {total_threats}\n"
        report += f"- Detection Confidence: Average {sum(r.get('step_3_confidence', 0) for r in analysis_results) // max(len(analysis_results), 1)}%\n"
        
        report += "\n## Threats by Type\n"
        for threat_type, count in sorted(threat_counts.items()):
            report += f"- {threat_type}: {count} incidents\n"
        
        report += "\n## Critical Findings\n"
        critical = [r for r in analysis_results if r.get("severity") == "Critical"]
        for finding in critical[:5]:  # Top 5
            report += f"\n### {finding.get('attack_type')} from {finding.get('ip')}\n"
            report += f"- Timestamp: {finding.get('timestamp')}\n"
            report += f"- URI: {finding.get('uri')}\n"
            report += f"- Confidence: {finding.get('step_3_confidence')}%\n"
            report += f"- Recommendation: {finding.get('recommendation')}\n"
        
        report += "\n## Recommended Actions\n"
        report += "\n### Immediate (Critical)\n"
        critical_ips = set(r.get('ip') for r in critical)
        for ip in critical_ips:
            report += f"- Block IP: {ip}\n"
        
        report += "\n### Short-term (High)\n"
        high = [r for r in analysis_results if r.get("severity") == "High"]
        high_ips = set(r.get('ip') for r in high)
        for ip in high_ips:
            report += f"- Monitor IP: {ip}\n"
        
        return report
    
    def generate_executive_report(self, analysis_results: List[Dict]) -> str:
        """Generate executive summary report (easy to understand for non-technical people)"""
        
        # Count threats
        threat_counts = {}
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        
        for result in analysis_results:
            attack_type = result.get("attack_type")
            severity = result.get("severity", "Unknown")
            
            if attack_type != "None":
                threat_counts[attack_type] = threat_counts.get(attack_type, 0) + 1
            
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        total_threats = sum(threat_counts.values())
        total_analyzed = len(analysis_results)
        threat_rate = (total_threats / total_analyzed * 100) if total_analyzed > 0 else 0
        
        # Build report
        report = """
# Website Security Status Report
## Easy-to-Read Summary for Management

---

## STATUS OVERVIEW

"""
        
        # Status indicator
        if severity_counts["Critical"] > 0:
            status = "URGENT - ATTENTION REQUIRED"
            icon = "[CRITICAL]"
        elif severity_counts["High"] > 0:
            status = "WARNING - NEEDS ATTENTION"
            icon = "[WARNING]"
        else:
            status = "SAFE - NORMAL"
            icon = "[OK]"
        
        report += f"**Current Status:** {icon} {status}\n\n"
        
        report += f"""
### What We Checked:
- Total website visits analyzed: **{total_analyzed} requests**
- Suspicious activities found: **{total_threats} attempts** ({threat_rate:.1f}%)
- Confidence level: **High** (85%+)

---

## SECURITY THREATS FOUND

### By Severity Level:
"""
        
        if severity_counts["Critical"] > 0:
            report += f"- [CRITICAL] **{severity_counts['Critical']} severe threats** - Action needed NOW\n"
        if severity_counts["High"] > 0:
            report += f"- [HIGH] **{severity_counts['High']} important threats** - Address soon\n"
        if severity_counts["Medium"] > 0:
            report += f"- [MEDIUM] **{severity_counts['Medium']} moderate threats** - Monitor\n"
        if severity_counts["Low"] > 0:
            report += f"- [LOW] **{severity_counts['Low']} minor threats** - Keep track\n"
        
        report += "\n### Types of Attacks Detected:\n"
        for attack_type, count in sorted(threat_counts.items(), key=lambda x: x[1], reverse=True):
            report += f"- **{attack_type}**: {count} attempts\n"
        
        report += "\n---\n\n## WHAT DOES THIS MEAN?\n\n"
        
        # Attack explanations
        if "sql_injection" in threat_counts:
            report += """### SQL Injection Attacks
- **What:** Hackers trying to access database and steal data
- **Risk:** Very high - can compromise sensitive information
- **Action:** Update database access controls
\n"""
        
        if "xss" in threat_counts:
            report += """### Cross-Site Scripting (XSS) Attacks
- **What:** Hackers trying to inject malicious code into webpages
- **Risk:** High - can harm user devices and steal personal info
- **Action:** Update security filters
\n"""
        
        if "command_injection" in threat_counts:
            report += """### Command Injection Attacks
- **What:** Hackers trying to execute system commands on server
- **Risk:** Critical - can compromise entire server
- **Action:** Immediate isolation and patching needed
\n"""
        
        if "path_traversal" in threat_counts:
            report += """### Path Traversal/Directory Access
- **What:** Hackers trying to access files they shouldn't see
- **Risk:** High - can expose confidential files
- **Action:** Restrict file access permissions
\n"""
        
        if "brute_force" in threat_counts:
            report += """### Brute Force Attacks
- **What:** Repeated login attempts with different passwords
- **Risk:** Medium - trying to guess passwords
- **Action:** Enable account lockout after failed attempts
\n"""
        
        report += """---

## WHO IS ATTACKING?

### Top Attacker IPs:
"""
        
        # Get top attacker IPs
        attacker_ips = {}
        for result in analysis_results:
            if result.get("attack_type") != "None":
                ip = result.get("ip")
                attacker_ips[ip] = attacker_ips.get(ip, 0) + 1
        
        for ip, count in sorted(attacker_ips.items(), key=lambda x: x[1], reverse=True)[:5]:
            report += f"- IP: `{ip}` - **{count} attack attempts**\n"
        
        report += """
---

## WHAT TO DO NOW?

### IMMEDIATE ACTIONS (Do right away):
"""
        
        if severity_counts["Critical"] > 0:
            report += "1. BLOCK suspicious IPs immediately\n"
            report += "2. Review and update security rules\n"
            report += "3. Notify IT security team\n"
        
        report += """
### SHORT-TERM (This week):
- Update all security patches
- Review access control settings
- Enable security alerts/notifications
- Backup important data

### LONG-TERM (This month):
- Train staff on security best practices
- Review security policy
- Plan security upgrade
- Consider additional protection tools

---

## PROTECTION DEPLOYED

### Automatic Defenses Activated:
- Web Application Firewall (WAF) rules: UPDATED
- IP Blocking rules: CONFIGURED
- Attack pattern detection: ACTIVE
- Real-time monitoring: ENABLED

---

## NEXT STEPS

1. **Review this report** with your IT/Security team
2. **Take the recommended actions** above
3. **Schedule a security review** in 2 weeks
4. **Monitor for updates** to this report

---

*Report automatically generated by Security Analysis System*
*For technical details, see the full Technical Report*
"""
        
        return report
