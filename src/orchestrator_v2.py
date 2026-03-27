"""
Simplified Orchestrator - Phase 2 + Phase 3 Focus

Phase 2: Vulnerability Assessment (using CoT reasoning)
Phase 3: Report & WAF Rules Generation

Multi-Agent Flow:
  Log Parser Agent → Security Analyst Agent → Incident Responder Agent
  (Parse log)       (CoT analysis)           (Generate report + rules)
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
import os

from src.agents_v2 import SecurityAnalysisAgents
from src.tools_v2 import CoTThreatAnalyzer, WAFRuleGenerator, ReportFormatter


class Phase2Phase3Orchestrator:
    """
    Simplified orchestrator for Phase 2 + Phase 3
    
    Phase 2: Vulnerability Assessment
    - Parse logs
    - Apply CoT reasoning
    - Detect threats with high precision
    
    Phase 3: Reporting & Defense
    - Generate comprehensive report
    - Create WAF rules
    - Provide remediation steps
    
    Agent Memory (for context preservation):
    - Phase 1 Memory: parsed_logs
    - Phase 2 Memory: threat_analysis (inherits parsed_logs)
    - Phase 3 Memory: report + rules (inherits all previous)
    """
    
    def __init__(self, verbose=True):
        self.agents = SecurityAnalysisAgents()
        self.cot_analyzer = CoTThreatAnalyzer()
        self.waf_generator = WAFRuleGenerator()
        self.report_formatter = ReportFormatter()
        self.results = {}
        self.verbose = verbose
        self.memory_log = []  # Track context preservation
    
    def _log_memory(self, phase: str, agent: str, data_summary: Dict):
        """Log context/memory at each phase for verification"""
        entry = {
            'phase': phase,
            'agent': agent,
            'timestamp': datetime.now().isoformat(),
            'data': data_summary
        }
        self.memory_log.append(entry)
        if self.verbose:
            print(f"[MEMORY] {phase} - {agent}: {data_summary}")
    
    def get_memory_log(self) -> str:
        """Get formatted memory preservation log"""
        output = "\n" + "="*70 + "\n"
        output += "AGENT MEMORY PRESERVATION LOG\n"
        output += "="*70 + "\n\n"
        
        for entry in self.memory_log:
            output += f"[{entry['phase']}] {entry['agent']}\n"
            output += f"  Timestamp: {entry['timestamp']}\n"
            output += f"  Data: {entry['data']}\n"
            output += "\n"
        
        output += "="*70 + "\n"
        return output
    
    def run_full_analysis(self, log_file_path: str, output_dir: str = 'reports') -> Dict:
        """
        Run complete Phase 2 + Phase 3 analysis
        
        Flow:
        1. Parse logs
        2. Apply CoT reasoning (Phase 2)
        3. Generate report + WAF rules (Phase 3)
        """
        
        print("\n" + "="*70)
        print("  PHASE 2 + PHASE 3: VULNERABILITY ASSESSMENT & REPORTING")
        print("  Using Chain-of-Thought (CoT) Reasoning")
        print("="*70 + "\n")
        
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
        
        # PHASE 2: Parse and Analyze Logs
        print("[PHASE 2] Vulnerability Assessment - CoT Reasoning")
        print("-" * 70)
        
        # Step 1: Parse logs
        print("[...] Step 1: Parsing logs...")
        parsed_logs = self._parse_logs(log_file_path)
        print(f"[OK] Parsed {len(parsed_logs)} log entries")
        
        # Log Phase 1 Memory
        self._log_memory("Phase 1", "Log Parser Agent", {
            "logs_parsed": len(parsed_logs),
            "sample_data": parsed_logs[0] if parsed_logs else None
        })
        
        # Step 2: Apply CoT Threat Analysis
        print("[...] Step 2: Applying Chain-of-Thought analysis...")
        threat_analysis = self._analyze_threats_with_cot(parsed_logs)
        print(f"[OK] Detected {len([t for t in threat_analysis if t['attack_type'] != 'None'])} potential threats")
        
        # Log Phase 2 Memory (with inherited Phase 1 context)
        self._log_memory("Phase 2", "Security Analyst Agent", {
            "inherited_from": "Phase 1 (parsed_logs)",
            "threats_detected": len([t for t in threat_analysis if t['attack_type'] != 'None']),
            "total_analyzed": len(threat_analysis),
            "sample_threat": threat_analysis[0] if threat_analysis else None
        })
        
        # Store Phase 2 results in context
        self.results['phase_2'] = {
            'parsed_logs': parsed_logs,
            'threat_analysis': threat_analysis,
            'timestamp': datetime.now().isoformat()
        }
        
        # PHASE 3: Generate Report + Rules
        print("\n[PHASE 3] Reporting & Defense Recommendations")
        print("-" * 70)
        
        print("[...] Step 1: Generating technical report...")
        report = self.report_formatter.generate_markdown_report(threat_analysis)
        
        print("[...] Step 1b: Generating executive summary (easy to read)...")
        executive_report = self.report_formatter.generate_executive_report(threat_analysis)
        
        print("[...] Step 2: Generating WAF/iptables rules...")
        rules = self._generate_defense_rules(threat_analysis, parsed_logs)
        
        print("[...] Step 3: Creating JSON exports...")
        json_report = self._create_json_report(threat_analysis)
        
        # Store Phase 3 results
        self.results['phase_3'] = {
            'report': report,
            'rules': rules,
            'json_report': json_report,
            'timestamp': datetime.now().isoformat()
        }
        
        # Log Phase 3 Memory (with inherited context from Phase 1 + 2)
        self._log_memory("Phase 3", "Incident Responder Agent", {
            "inherited_from": "Phase 1 + Phase 2 (parsed_logs + threat_analysis)",
            "rules_generated": {
                "modsecurity": len(rules['modsecurity']),
                "nginx": len(rules['nginx']),
                "iptables": len(rules['iptables'])
            },
            "report_generated": True
        })
        
        # Save outputs
        print("\n[...] Saving outputs...")
        report_path_technical = self._save_report(report, output_dir, report_type="technical")
        report_path_executive = self._save_report(executive_report, output_dir, report_type="executive")
        json_path = self._save_json_report(json_report, output_dir)
        rules_path = self._save_rules(rules, output_dir)
        memory_path = self._save_memory_log(output_dir)
        
        print(f"[OK] Reports generated in: {output_dir}/")
        print(f"     - Executive Summary: {report_path_executive}")
        print(f"     - Technical Report: {report_path_technical}")
        print(f"     - JSON: {json_path}")
        print(f"     - Rules: {rules_path}")
        print(f"     - Memory Log: {memory_path}")
        
        print("\n" + "="*70)
        print("[OK] Analysis complete!")
        print("="*70 + "\n")
        
        return {
            'logs_analyzed': len(parsed_logs),
            'threats_detected': len([t for t in threat_analysis if t['attack_type'] != 'None']),
            'report_path_technical': report_path_technical,
            'report_path_executive': report_path_executive,
            'json_path': json_path,
            'rules_path': rules_path,
            'analysis_results': threat_analysis
        }
    
    def _parse_logs(self, log_file_path: str) -> List[Dict]:
        """
        Parse log file into structured format
        Agent: Log Parser Agent
        """
        
        logs = []
        
        try:
            with open(log_file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            # Parse each line
            for line in lines:
                if not line.strip():
                    continue
                
                # Simple Apache log parsing
                # Format: IP - - [timestamp] "METHOD URI HTTP/VERSION" STATUS SIZE "REFERER" "USER-AGENT"
                parsed = self._parse_log_line(line)
                if parsed:
                    logs.append(parsed)
        
        except Exception as e:
            print(f"[ERROR] Failed to parse logs: {e}")
        
        return logs
    
    def _parse_log_line(self, line: str) -> Optional[Dict]:
        """Parse single log line"""
        try:
            # Extract IP
            ip_match = line.split()[0]
            
            # Extract timestamp (between [ and ])
            ts_start = line.find('[')
            ts_end = line.find(']')
            timestamp = line[ts_start+1:ts_end] if ts_start >= 0 and ts_end > ts_start else ""
            
            # Extract request (between quotes)
            req_start = line.find('"')
            req_end = line.find('"', req_start + 1)
            request_str = line[req_start+1:req_end] if req_start >= 0 and req_end > req_start else ""
            
            # Parse request: METHOD URI HTTP/VERSION
            parts = request_str.split()
            method = parts[0] if len(parts) > 0 else "GET"
            uri = parts[1] if len(parts) > 1 else "/"
            
            # Extract status code (after request)
            after_req = line[req_end+1:].split()
            status = int(after_req[0]) if after_req and after_req[0].isdigit() else 200
            
            # Extract user agent (last quoted string)
            ua_start = line.rfind('"')
            ua_prev_end = line.rfind('"', 0, ua_start)
            user_agent = line[ua_prev_end+1:ua_start] if ua_prev_end >= 0 else "Unknown"
            
            # Extract payload (from URI query string)
            payload = uri.split('?')[1] if '?' in uri else ""
            
            return {
                'ip': ip_match,
                'timestamp': timestamp,
                'method': method,
                'uri': uri,
                'status': status,
                'user_agent': user_agent,
                'payload': payload,
                'full_line': line.strip()
            }
        
        except Exception as e:
            return None
    
    def _analyze_threats_with_cot(self, logs: List[Dict]) -> List[Dict]:
        """
        Analyze logs using Chain-of-Thought reasoning
        Agent: Security Analyst Agent
        
        Returns: List of threat analyses with CoT reasoning
        """
        
        analysis_results = []
        
        for log_entry in logs:
            # Apply CoT reasoning to each log entry
            cot_result = self.cot_analyzer.analyze_request(log_entry)
            analysis_results.append(cot_result)
        
        return analysis_results
    
    def _generate_defense_rules(self, threat_analysis: List[Dict], logs: List[Dict]) -> Dict:
        """
        Generate WAF and firewall rules
        Agent: Incident Responder Agent
        
        Returns: Dict containing ModSecurity, Nginx, iptables rules
        """
        
        rules = {
            'modsecurity': [],
            'nginx': [],
            'iptables': [],
            'recommendations': []
        }
        
        # Track IPs to block
        ips_to_block = set()
        
        for analysis in threat_analysis:
            if analysis.get('attack_type') == 'None':
                continue
            
            severity = analysis.get('severity')
            ip = analysis.get('ip')
            
            # Generate ModSecurity rule
            mod_rule = self.waf_generator.generate_modsecurity_rule(analysis)
            if mod_rule and mod_rule not in rules['modsecurity']:
                rules['modsecurity'].append(mod_rule)
            
            # Generate Nginx rule
            nginx_rule = self.waf_generator.generate_nginx_rule(analysis, ip)
            if nginx_rule and nginx_rule not in rules['nginx']:
                rules['nginx'].append(nginx_rule)
            
            # Track IP for blocking
            if severity in ['High', 'Critical']:
                ips_to_block.add(ip)
        
        # Generate iptables rules for blocked IPs
        for ip in ips_to_block:
            ipt_rule = self.waf_generator.generate_iptables_rule(ip, 'Critical')
            if ipt_rule:
                rules['iptables'].append(ipt_rule)
        
        # Generate recommendations
        if ips_to_block:
            rules['recommendations'].append(f"Block the following {len(ips_to_block)} IPs: {', '.join(sorted(ips_to_block))}")
        
        return rules
    
    def _create_json_report(self, threat_analysis: List[Dict]) -> Dict:
        """Create JSON format report"""
        
        return {
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'total_requests': len(threat_analysis),
                'threats_detected': len([t for t in threat_analysis if t['attack_type'] != 'None']),
                'critical_threats': len([t for t in threat_analysis if t['severity'] == 'Critical']),
                'high_threats': len([t for t in threat_analysis if t['severity'] == 'High']),
            },
            'threats': threat_analysis
        }
    
    def _save_report(self, report: str, output_dir: str, report_type: str = "technical") -> str:
        """Save markdown report"""
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        
        if report_type == "executive":
            report_path = f"{output_dir}/REPORT-EXECUTIVE-{timestamp}.md"
        else:
            report_path = f"{output_dir}/REPORT-TECHNICAL-{timestamp}.md"
        
        with open(report_path, 'w') as f:
            f.write(report)
        
        return report_path
    
    def _save_json_report(self, json_report: Dict, output_dir: str) -> str:
        """Save JSON report"""
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        json_path = f"{output_dir}/ANALYSIS-{timestamp}.json"
        
        with open(json_path, 'w') as f:
            json.dump(json_report, f, indent=2)
        
        return json_path
    
    def _save_rules(self, rules: Dict, output_dir: str) -> str:
        """Save WAF/firewall rules"""
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        rules_path = f"{output_dir}/DEFENSE-RULES-{timestamp}.txt"
        
        content = ""
        content += "# ModSecurity WAF Rules\n"
        content += "\n".join(rules['modsecurity']) + "\n\n"
        
        content += "# Nginx Deny Rules\n"
        content += "\n".join(rules['nginx']) + "\n\n"
        
        content += "# iptables Firewall Rules\n"
        content += "\n".join(rules['iptables']) + "\n\n"
        
        content += "# Recommendations\n"
        content += "\n".join(f"- {r}" for r in rules['recommendations'])
        
        with open(rules_path, 'w') as f:
            f.write(content)
        
        return rules_path
    
    def _save_memory_log(self, output_dir: str) -> str:
        """Save agent memory preservation log"""
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        memory_path = f"{output_dir}/MEMORY-LOG-{timestamp}.txt"
        
        with open(memory_path, 'w') as f:
            f.write(self.get_memory_log())
        
        return memory_path
