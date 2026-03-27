"""
Full Orchestrator - Phase 1 + Phase 2 + Phase 3

Phase 1: Reconnaissance (Active + Passive)
  - Port scanning
  - Service enumeration
  - OS fingerprinting
  - Public info gathering

Phase 2: Vulnerability Assessment
  - Log analysis
  - Threat detection
  - Risk scoring

Phase 3: Reporting
  - Executive summary
  - Technical report
  - WAF rules
  - Recommendations
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
import os

from src.agents_v2 import SecurityAnalysisAgents
from src.tools_v2 import CoTThreatAnalyzer, WAFRuleGenerator, ReportFormatter
from src.recon_tools import ActiveReconnaissanceTools, PassiveReconnaissanceTools, ReconnaissanceAnalyzer


class Phase1Phase2Phase3Orchestrator:
    """
    Complete orchestrator for Pentest 3-phase workflow:
    Phase 1 → Phase 2 → Phase 3
    """
    
    def __init__(self, target: str = "localhost", verbose=True):
        self.target = target
        self.agents = SecurityAnalysisAgents()
        self.cot_analyzer = CoTThreatAnalyzer()
        self.waf_generator = WAFRuleGenerator()
        self.report_formatter = ReportFormatter()
        self.verbose = verbose
        self.memory_log = []  # Track context through phases
        self.results = {}
    
    def _log_memory(self, phase: str, agent: str, data_summary: Dict):
        """Log memory at each phase for context preservation"""
        entry = {
            'phase': phase,
            'agent': agent,
            'timestamp': datetime.now().isoformat(),
            'data': data_summary
        }
        self.memory_log.append(entry)
    
    def get_memory_log(self) -> str:
        """Get formatted memory preservation log"""
        output = "\n" + "="*70 + "\n"
        output += "MULTI-PHASE MEMORY PRESERVATION LOG\n"
        output += "="*70 + "\n\n"
        
        for entry in self.memory_log:
            output += f"[{entry['phase']}] {entry['agent']}\n"
            output += f"  Timestamp: {entry['timestamp']}\n"
            output += f"  Data: {entry['data']}\n"
            output += "\n"
        
        output += "="*70 + "\n"
        return output
    
    def run_full_pentest(self, log_file: str = None, output_dir: str = 'reports') -> Dict:
        """
        Run complete 3-phase pentest workflow
        
        Flow: Phase 1 → Phase 2 → Phase 3
        """
        
        os.makedirs(output_dir, exist_ok=True)
        
        # ============== PHASE 1: RECONNAISSANCE ==============
        print("\n[PHASE 1] Reconnaissance (Active + Passive)")
        print("-" * 70)
        
        print("[...] Step 1: Active reconnaissance (port scanning)...")
        recon_active = self._phase1_active_recon()
        
        print("[...] Step 2: Passive reconnaissance...")
        recon_passive = self._phase1_passive_recon()
        
        print("[...] Step 3: Analyzing reconnaissance findings...")
        recon_analysis = self._phase1_analyze()
        
        # Store Phase 1
        self.results['phase_1'] = {
            'active': recon_active,
            'passive': recon_passive,
            'analysis': recon_analysis,
            'timestamp': datetime.now().isoformat()
        }
        
        # Log Phase 1 Memory
        self._log_memory("Phase 1", "Reconnaissance Agent", {
            "target": self.target,
            "ports_scanned": len(recon_active.get('open_ports', [])),
            "services_found": len(recon_active.get('open_ports', [])),
            "dns_resolved": recon_passive.get('dns_lookup', {}).get('status'),
            "vulnerabilities_identified": len(recon_analysis)
        })
        
        # ============== PHASE 2: VULNERABILITY ASSESSMENT ==============
        print("\n[PHASE 2] Vulnerability Assessment (Log Analysis)")
        print("-" * 70)
        
        print("[...] Step 1: Parsing logs...")
        parsed_logs = self._parse_logs(log_file) if log_file else []
        
        print("[...] Step 2: Applying Chain-of-Thought analysis...")
        threat_analysis = self._phase2_analyze_threats(parsed_logs)
        
        # Store Phase 2
        self.results['phase_2'] = {
            'logs_parsed': len(parsed_logs),
            'threats_detected': len([t for t in threat_analysis if t['attack_type'] != 'None']),
            'threat_analysis': threat_analysis,
            'timestamp': datetime.now().isoformat()
        }
        
        # Log Phase 2 Memory (inherits from Phase 1)
        self._log_memory("Phase 2", "Security Analyst Agent", {
            "inherited_from": "Phase 1 (reconnaissance_data)",
            "logs_analyzed": len(parsed_logs),
            "threats_detected": len([t for t in threat_analysis if t['attack_type'] != 'None']),
            "critical_threats": len([t for t in threat_analysis if t.get('severity') == 'Critical'])
        })
        
        # ============== PHASE 3: REPORTING ==============
        print("\n[PHASE 3] Reporting & Defense Recommendations")
        print("-" * 70)
        
        print("[...] Step 1: Generating Phase 1 (Reconnaissance) report...")
        phase1_report = self._generate_phase1_report(recon_active, recon_passive, recon_analysis)
        
        print("[...] Step 2: Generating Phase 2 (Vulnerability) report...")
        phase2_technical_report = self.report_formatter.generate_markdown_report(threat_analysis)
        phase2_executive_report = self.report_formatter.generate_executive_report(threat_analysis)
        
        print("[...] Step 3: Generating WAF/iptables rules...")
        rules = self._generate_defense_rules(threat_analysis, parsed_logs)
        
        print("[...] Step 4: Creating JSON exports...")
        json_report = self._create_json_report(
            recon_active, 
            recon_passive, 
            recon_analysis, 
            threat_analysis
        )
        
        # Store Phase 3
        self.results['phase_3'] = {
            'phase1_report': phase1_report,
            'phase2_technical': phase2_technical_report,
            'phase2_executive': phase2_executive_report,
            'rules': rules,
            'json_report': json_report,
            'timestamp': datetime.now().isoformat()
        }
        
        # Log Phase 3 Memory (inherits from Phase 1 + 2)
        self._log_memory("Phase 3", "Incident Responder Agent", {
            "inherited_from": "Phase 1 + Phase 2 (recon_data + threat_analysis)",
            "phase1_report": "generated",
            "phase2_reports": "technical + executive",
            "rules_generated": {
                "modsecurity": len(rules['modsecurity']),
                "nginx": len(rules['nginx']),
                "iptables": len(rules['iptables'])
            }
        })
        
        # Save all outputs
        print("\n[...] Saving outputs...")
        phase1_report_path = self._save_report(phase1_report, output_dir, "PHASE1-RECON")
        phase2_technical_path = self._save_report(phase2_technical_report, output_dir, "PHASE2-TECHNICAL")
        phase2_executive_path = self._save_report(phase2_executive_report, output_dir, "PHASE2-EXECUTIVE")
        json_path = self._save_json_report(json_report, output_dir)
        rules_path = self._save_rules(rules, output_dir)
        memory_path = self._save_memory_log(output_dir)
        
        print(f"\n[OK] All outputs generated in: {output_dir}/")
        print(f"     Phase 1 Recon:       {phase1_report_path}")
        print(f"     Phase 2 Technical:   {phase2_technical_path}")
        print(f"     Phase 2 Executive:   {phase2_executive_path}")
        print(f"     JSON Export:         {json_path}")
        print(f"     Defense Rules:       {rules_path}")
        print(f"     Memory Log:          {memory_path}")
        
        print("\n" + "="*70)
        print("[OK] Complete 3-Phase Pentest Analysis!")
        print("="*70 + "\n")
        
        return {
            'phase1_recon': phase1_report_path,
            'phase2_technical': phase2_technical_path,
            'phase2_executive': phase2_executive_path,
            'json_path': json_path,
            'rules_path': rules_path,
            'memory_log': memory_path,
            'analysis_results': {
                'phase1_findings': len(recon_analysis),
                'phase2_threats': len([t for t in threat_analysis if t['attack_type'] != 'None'])
            }
        }
    
    def _phase1_active_recon(self) -> Dict:
        """Phase 1: Active reconnaissance"""
        active = ActiveReconnaissanceTools(target=self.target, ports="top20")
        return active.scan_ports()
    
    def _phase1_passive_recon(self) -> Dict:
        """Phase 1: Passive reconnaissance"""
        passive = PassiveReconnaissanceTools(target=self.target)
        return {
            'dns_lookup': passive.dns_lookup(),
            'whois': passive.whois_lookup(),
            'public_info': passive.public_info()
        }
    
    def _phase1_analyze(self) -> List[Dict]:
        """Phase 1: Analyze reconnaissance findings"""
        active_results = self._phase1_active_recon()
        analyzer = ReconnaissanceAnalyzer()
        return analyzer.analyze_ports(active_results)
    
    def _generate_phase1_report(self, active: Dict, passive: Dict, analysis: List[Dict]) -> str:
        """Generate Phase 1 reconnaissance report"""
        
        report = f"""# Phase 1: Reconnaissance Report
Target: {self.target}
Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Executive Summary

This reconnaissance phase identified the attack surface of the target system.

### Discovery Results

**Active Reconnaissance (Port Scan):**
- Status: {active.get('status', 'unknown')}
- Ports Scanned: {active.get('scan_time', 'N/A')} seconds
- Open Ports Found: {len(active.get('open_ports', []))}

**Passive Reconnaissance:**
- DNS Resolution: {passive.get('dns_lookup', {}).get('status', 'unknown')}
- IP Address: {passive.get('dns_lookup', {}).get('ip_address', 'unknown')}
- Registrant: {passive.get('whois', {}).get('registrant', 'unknown')}

## Open Services

"""
        
        for port_info in active.get('open_ports', []):
            report += f"\n### Port {port_info['port']}/{port_info.get('service', 'unknown')}\n"
            report += f"- Service: {port_info.get('service', 'Unknown')}\n"
            report += f"- Product: {port_info.get('product', 'Unknown')}\n"
            report += f"- Version: {port_info.get('version', 'Unknown')}\n"
            report += f"- Extra Info: {port_info.get('extrainfo', 'None')}\n"
        
        report += "\n## Vulnerability Assessment\n\n"
        
        critical_count = len([a for a in analysis if a.get('risk_level') == 'Critical'])
        high_count = len([a for a in analysis if a.get('risk_level') == 'High'])
        medium_count = len([a for a in analysis if a.get('risk_level') == 'Medium'])
        
        report += f"- CRITICAL Findings: {critical_count}\n"
        report += f"- HIGH Findings: {high_count}\n"
        report += f"- MEDIUM Findings: {medium_count}\n\n"
        
        for finding in analysis:
            report += f"\n### {finding['risk_level']}: {finding['service']} on Port {finding['port']}\n"
            report += f"- Description: {finding['description']}\n"
            report += f"- Recommendation: {finding['recommendation']}\n"
        
        return report
    
    def _parse_logs(self, log_file: str) -> List[Dict]:
        """Parse log file (Phase 2)"""
        logs = []
        try:
            with open(log_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            for line in lines:
                if not line.strip():
                    continue
                parsed = self._parse_log_line(line)
                if parsed:
                    logs.append(parsed)
        except:
            pass
        
        return logs
    
    def _parse_log_line(self, line: str) -> Optional[Dict]:
        """Parse single log line"""
        try:
            parts = line.split()
            if len(parts) < 2:
                return None
            
            ip = parts[0]
            
            # Extract other fields (simplified)
            return {
                'ip': ip,
                'timestamp': datetime.now().isoformat(),
                'uri': line[80:150] if len(line) > 80 else 'unknown',
                'payload': line[150:] if len(line) > 150 else '',
                'method': 'GET',
                'status': 200
            }
        except:
            return None
    
    def _phase2_analyze_threats(self, logs: List[Dict]) -> List[Dict]:
        """Phase 2: Analyze threats from logs"""
        results = []
        for log in logs:
            result = self.cot_analyzer.analyze_request(log)
            results.append(result)
        return results
    
    def _generate_defense_rules(self, threat_analysis: List[Dict], logs: List[Dict]) -> Dict:
        """Generate defense rules"""
        rules = {
            'modsecurity': [],
            'nginx': [],
            'iptables': [],
            'recommendations': []
        }
        
        ips_to_block = set()
        for analysis in threat_analysis:
            if analysis.get('attack_type') != 'None':
                ip = analysis.get('ip')
                if ip:
                    ips_to_block.add(ip)
        
        for ip in list(ips_to_block)[:10]:  # Top 10 IPs
            rules['iptables'].append(f"iptables -A INPUT -s {ip} -j DROP")
            rules['nginx'].append(f"deny {ip};")
        
        return rules
    
    def _create_json_report(self, active, passive, analysis, threat_analysis) -> Dict:
        """Create JSON summary"""
        return {
            'phase1_recon': {
                'target': self.target,
                'open_ports': len(active.get('open_ports', [])),
                'vulnerabilities': len([a for a in analysis if a.get('risk_level') in ['Critical', 'High']])
            },
            'phase2_threats': {
                'total_logs': len(threat_analysis),
                'threats_detected': len([t for t in threat_analysis if t.get('attack_type') != 'None']),
                'critical': len([t for t in threat_analysis if t.get('severity') == 'Critical'])
            },
            'timestamp': datetime.now().isoformat()
        }
    
    def _save_report(self, report: str, output_dir: str, report_type: str) -> str:
        """Save report"""
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        path = f"{output_dir}/{report_type}-{timestamp}.md"
        with open(path, 'w') as f:
            f.write(report)
        return path
    
    def _save_json_report(self, json_report: Dict, output_dir: str) -> str:
        """Save JSON"""
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        path = f"{output_dir}/ANALYSIS-3PHASE-{timestamp}.json"
        with open(path, 'w') as f:
            json.dump(json_report, f, indent=2)
        return path
    
    def _save_rules(self, rules: Dict, output_dir: str) -> str:
        """Save rules"""
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        path = f"{output_dir}/DEFENSE-3PHASE-{timestamp}.txt"
        with open(path, 'w') as f:
            f.write("# iptables Rules\n")
            f.write("\n".join(rules['iptables']))
        return path
    
    def _save_memory_log(self, output_dir: str) -> str:
        """Save memory log"""
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        path = f"{output_dir}/MEMORY-3PHASE-{timestamp}.txt"
        with open(path, 'w') as f:
            f.write(self.get_memory_log())
        return path
