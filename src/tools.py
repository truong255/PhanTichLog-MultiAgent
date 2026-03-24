"""
Custom Tools Implementation for Multi-Agent Log Analysis System
Includes Log Parser, Data Validator, Pattern Matcher, Threat Detector, etc.
"""

import re
import json
from datetime import datetime
from typing import Dict, List, Tuple
from collections import Counter
import statistics

class LogParser:
    """Parse Apache, Nginx, IIS log formats"""
    
    FORMATS = {
        'apache': r'(?P<ip>[\d.]+) (?P<ident>\S+) (?P<user>\S+) \[(?P<timestamp>.*?)\] "(?P<request>.*?)" (?P<status>\d+) (?P<size>[\d-]+)(?:\s+"(?P<referer>.*?)")?\s+"(?P<user_agent>.*?)"',
        'nginx': r'(?P<ip>[\d.]+) - (?P<user>\S+) \[(?P<timestamp>.*?)\] "(?P<request>.*?)" (?P<status>\d+) (?P<size>\d+)',
    }
    
    def parse(self, log_line: str, format_type: str = 'apache') -> Dict:
        """Parse single log line"""
        try:
            pattern = self.FORMATS.get(format_type, self.FORMATS['apache'])
            match = re.match(pattern, log_line)
            
            if not match:
                return None
            
            groups = match.groupdict()
            
            # Parse HTTP request line
            request_parts = groups.get('request', '').split()
            if len(request_parts) >= 3:
                method = request_parts[0]
                uri = request_parts[1]
            else:
                method = 'UNKNOWN'
                uri = 'UNKNOWN'
            
            # Parse timestamp
            timestamp = self._parse_timestamp(groups.get('timestamp', ''))
            
            return {
                'timestamp': timestamp,
                'ip': groups.get('ip', ''),
                'method': method,
                'uri': uri,
                'status': int(groups.get('status', 0)),
                'size': int(groups.get('size', -1)) if groups.get('size', '').isdigit() else 0,
                'user_agent': groups.get('user_agent', ''),
                'referer': groups.get('referer', ''),
            }
        except Exception as e:
            return None
    
    def _parse_timestamp(self, ts_str: str) -> str:
        """Convert timestamp to ISO 8601"""
        try:
            # Expected format: 24/Mar/2024:09:15:30 +0000
            dt = datetime.strptime(ts_str.split('+')[0].strip(), '%d/%b/%Y:%H:%M:%S')
            return dt.isoformat() + 'Z'
        except:
            return ts_str
    
    def parse_batch(self, log_lines: List[str], format_type: str = 'apache') -> Dict:
        """Parse batch of log lines"""
        parsed = []
        errors = []
        
        for i, line in enumerate(log_lines):
            if line.strip():
                entry = self.parse(line, format_type)
                if entry:
                    parsed.append(entry)
                else:
                    errors.append({'line_num': i, 'line': line, 'error': 'Parse failed'})
        
        return {
            'entries': parsed,
            'total': len(log_lines),
            'parsed': len(parsed),
            'errors': errors,
            'quality_score': len(parsed) / len(log_lines) if log_lines else 0
        }


class DataValidator:
    """Validate and clean parsed log data"""
    
    def validate_entry(self, entry: Dict) -> Tuple[bool, List[str]]:
        """Validate single entry"""
        errors = []
        
        # Validate IP
        if not re.match(r'^[\d.]+$', entry.get('ip', '')):
            errors.append(f"Invalid IP: {entry.get('ip')}")
        
        # Validate method
        valid_methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH']
        if entry.get('method') not in valid_methods:
            errors.append(f"Invalid method: {entry.get('method')}")
        
        # Validate status
        try:
            status = int(entry.get('status', 0))
            if not (100 <= status <= 599):
                errors.append(f"Invalid status: {status}")
        except:
            errors.append(f"Invalid status: {entry.get('status')}")
        
        # Validate size
        if entry.get('size', 0) < 0:
            errors.append(f"Invalid size: {entry.get('size')}")
        
        return len(errors) == 0, errors
    
    def clean_batch(self, entries: List[Dict]) -> Dict:
        """Clean and validate batch"""
        valid = []
        invalid = []
        
        for entry in entries:
            is_valid, errors = self.validate_entry(entry)
            if is_valid:
                valid.append(entry)
            else:
                invalid.append({'entry': entry, 'errors': errors})
        
        return {
            'valid_entries': valid,
            'invalid_entries': invalid,
            'valid_count': len(valid),
            'invalid_count': len(invalid),
            'quality_score': len(valid) / len(entries) if entries else 0
        }


class ThreatSignatureChecker:
    """Check logs against threat signatures"""
    
    THREAT_SIGNATURES = {
        'sql_injection': {
            'patterns': [' OR 1=1', 'UNION SELECT', 'DROP TABLE', '; DELETE', 'exec(', 'execute('],
            'cvss_base': 7.5,
            'cwe': 'CWE-89'
        },
        'xss': {
            'patterns': ['<script', 'onclick=', 'onerror=', 'javascript:', 'onload='],
            'cvss_base': 6.1,
            'cwe': 'CWE-79'
        },
        'command_injection': {
            'patterns': ['; ls', ' && ', ' | cat', '`whoami`', '$('],
            'cvss_base': 8.0,
            'cwe': 'CWE-78'
        },
        'path_traversal': {
            'patterns': ['../', '..\\', '%2e%2e', '..../', '...\\'],
            'cvss_base': 7.5,
            'cwe': 'CWE-22'
        },
        'scanner_detection': {
            'patterns': ['Nikto', 'Nessus', 'Burp', 'sqlmap', 'nmap'],
            'cvss_base': 5.0,
            'cwe': 'CWE-200'
        }
    }
    
    def check_log_entry(self, entry: Dict) -> List[Dict]:
        """Check single entry for threats"""
        threats = []
        uri_lower = entry.get('uri', '').lower()
        user_agent_lower = entry.get('user_agent', '').lower()
        
        for threat_type, sig_data in self.THREAT_SIGNATURES.items():
            for pattern in sig_data.get('patterns', []):
                if pattern.lower() in uri_lower or pattern.lower() in user_agent_lower:
                    threats.append({
                        'type': threat_type,
                        'pattern': pattern,
                        'cvss_base': sig_data['cvss_base'],
                        'cwe': sig_data['cwe'],
                        'location': 'uri' if pattern.lower() in uri_lower else 'user_agent'
                    })
                    break
        
        return threats
    
    def check_brute_force(self, entries: List[Dict], threshold: int = 10) -> List[Dict]:
        """Detect brute force attempts"""
        ip_failures = Counter()
        brute_force_ips = []
        
        for entry in entries:
            if entry.get('status') == 401:  # Failed login
                ip_failures[entry.get('ip')] += 1
        
        for ip, count in ip_failures.items():
            if count >= threshold:
                brute_force_ips.append({
                    'type': 'brute_force',
                    'source_ip': ip,
                    'attempt_count': count,
                    'cvss_base': 9.8,
                    'cwe': 'CWE-307'
                })
        
        return brute_force_ips
    
    def detect_ddos(self, entries: List[Dict], threshold: int = 50) -> List[Dict]:
        """Detect DDoS patterns"""
        ip_requests = Counter()
        ddos_patterns = []
        
        for entry in entries:
            ip_requests[entry.get('ip')] += 1
        
        for ip, count in ip_requests.items():
            if count >= threshold:
                ddos_patterns.append({
                    'type': 'ddos_pattern',
                    'source_ip': ip,
                    'request_count': count,
                    'cvss_base': 7.5,
                    'cwe': 'CWE-400'
                })
        
        return ddos_patterns


class PatternMatcher:
    """Detect behavioral anomalies"""
    
    def establish_baseline(self, entries: List[Dict]) -> Dict:
        """Build baseline from normal traffic"""
        if not entries:
            return {}
        
        sizes = [e.get('size', 0) for e in entries if e.get('size', 0) > 0]
        statuses = [e.get('status') for e in entries]
        methods = [e.get('method') for e in entries]
        uris = [e.get('uri') for e in entries]
        
        baseline = {
            'total_entries': len(entries),
            'avg_response_size': statistics.mean(sizes) if sizes else 0,
            'median_response_size': statistics.median(sizes) if sizes else 0,
            'max_response_size': max(sizes) if sizes else 0,
            'common_methods': Counter(methods).most_common(5),
            'common_uris': Counter(uris).most_common(10),
            'status_distribution': dict(Counter(statuses)),
            'unique_ips': len(set(e.get('ip') for e in entries))
        }
        
        return baseline
    
    def detect_anomalies(self, entry: Dict, baseline: Dict) -> List[str]:
        """Detect anomalies"""
        anomalies = []
        
        # Check unusual response size (>10x average)
        if baseline.get('avg_response_size', 0) > 0:
            if entry.get('size', 0) > baseline['avg_response_size'] * 10:
                anomalies.append('Unusually large response size')
        
        # Check unusual status code distribution
        status_dist = baseline.get('status_distribution', {})
        if status_dist and str(entry.get('status')) not in status_dist:
            if entry.get('status') not in [200, 301, 302, 404]:  # Common expected statuses
                anomalies.append(f"Unusual HTTP status: {entry.get('status')}")
        
        return anomalies


class StatisticalAnalyzer:
    """Statistical analysis of log patterns"""
    
    def analyze_traffic(self, entries: List[Dict]) -> Dict:
        """Generate traffic statistics"""
        return {
            'total_entries': len(entries),
            'unique_ips': len(set(e['ip'] for e in entries)),
            'unique_uris': len(set(e['uri'] for e in entries)),
            'methods_distribution': dict(Counter(e['method'] for e in entries)),
            'status_distribution': dict(Counter(e['status'] for e in entries)),
            'top_ips': Counter(e['ip'] for e in entries).most_common(10),
            'top_uris': Counter(e['uri'] for e in entries).most_common(10),
        }
    
    def calculate_risk_score(self, threats: List[Dict]) -> Dict:
        """Calculate overall risk score"""
        cvss_total = sum(t.get('cvss_base', 0) for t in threats)
        critical_count = len([t for t in threats if t.get('cvss_base', 0) > 9])
        high_count = len([t for t in threats if 7 <= t.get('cvss_base', 0) <= 9])
        
        overall_risk = (critical_count * 10 + high_count * 5 + len(threats) * 2) / max(1, len(threats))
        
        return {
            'overall_risk_score': min(10, overall_risk),
            'threat_count': len(threats),
            'critical_count': critical_count,
            'high_count': high_count,
            'avg_cvss': cvss_total / len(threats) if threats else 0,
        }


class CVSSCalculator:
    """CVSS v3.1 Score Calculation"""
    
    @staticmethod
    def calculate_score(threat_type: str) -> float:
        """Calculate CVSS score based on threat type"""
        scores = {
            'sql_injection': 7.5,
            'xss': 6.1,
            'command_injection': 8.0,
            'path_traversal': 7.5,
            'brute_force': 9.8,
            'ddos_pattern': 7.5,
            'scanner_detection': 5.0,
        }
        return scores.get(threat_type, 5.0)
    
    @staticmethod
    def get_severity(score: float) -> str:
        """Get severity level from score"""
        if score == 0:
            return "None"
        elif score < 4:
            return "Low"
        elif score < 7:
            return "Medium"
        elif score < 9:
            return "High"
        else:
            return "Critical"


class ReportFormatter:
    """Format analysis results"""
    
    @staticmethod
    def format_json_report(findings: Dict) -> str:
        """Format as JSON"""
        return json.dumps(findings, indent=2, default=str)
    
    @staticmethod
    def format_text_report(findings: Dict) -> str:
        """Format as plain text"""
        report = "=" * 60 + "\n"
        report += "SECURITY ANALYSIS REPORT\n"
        report += "=" * 60 + "\n\n"
        
        report += f"Total Logs Analyzed: {findings.get('total_logs', 0)}\n"
        report += f"Threats Detected: {findings.get('threat_count', 0)}\n"
        report += f"Overall Risk Score: {findings.get('overall_risk_score', 0):.1f}/10\n\n"
        
        report += "THREATS FOUND:\n"
        report += "-" * 40 + "\n"
        for threat in findings.get('threats', []):
            report += f"• {threat['type']}: {threat['count']} occurrences\n"
        
        return report

    @staticmethod
    def format_markdown_report(findings: Dict) -> str:
        """Format as Markdown with full details - handles nested JSON structure"""
        timestamp = findings.get('timestamp', 'Unknown')
        exec_summary = findings.get('executive_summary', '')
        
        report = f"""# Security Analysis Report
**Generated:** {timestamp}

## Executive Summary

{exec_summary}

---

## Reconnaissance Phase

"""
        
        # Reconnaissance data
        recon = findings.get('findings', {}).get('reconnaissance', {})
        report += f"""| Metric | Value |
|--------|-------|
| Total Logs Analyzed | {recon.get('total_logs_analyzed', 0)} |
| Unique Sources | {recon.get('unique_sources', 0)} |
| Unique Endpoints | {recon.get('unique_endpoints', 0)} |
| Anomalies Detected | {recon.get('anomalies_detected', 0)} |

### Server Information

"""
        server = recon.get('server_info', {})
        report += f"""- **Web Server**: {server.get('web_server', 'Unknown')}
- **PHP Version**: {server.get('php_version', 'Unknown')}
- **CMS Detected**: {server.get('cms_detected', 'Unknown')}
- **SSL Enabled**: {'✅ Yes' if server.get('ssl_enabled') else '❌ No'}
- **Technologies**: {', '.join(server.get('technologies', []))}

#### Detected Endpoints

"""
        for endpoint in server.get('detected_endpoints', []):
            report += f"- {endpoint}\n"
        
        report += f"""
---

## Vulnerability Assessment Phase

"""
        
        # Vulnerabilities
        vulns = findings.get('findings', {}).get('vulnerabilities', {})
        severity_counts = vulns.get('by_severity', {})
        
        report += f"""### Vulnerability Summary

| Severity | Count |
|----------|-------|
| Critical | {severity_counts.get('Critical', 0)} |
| High | {severity_counts.get('High', 0)} |
| Medium | {severity_counts.get('Medium', 0)} |
| Low | {severity_counts.get('Low', 0)} |
| **Total** | **{vulns.get('total_vulnerabilities', 0)}** |

### Critical Vulnerabilities

"""
        
        for vuln in vulns.get('critical_findings', []):
            report += f"""
#### {vuln.get('id', 'UNKNOWN')} - {vuln.get('type', 'Unknown').upper()}
- **CVSS Score**: {vuln.get('cvss_score', 0)} ({vuln.get('severity', 'Unknown')})
- **CWE**: {vuln.get('cwe', 'N/A')}
- **Source IP**: {vuln.get('evidence', {}).get('source_ip', 'Unknown')}
- **Attack Pattern**: {vuln.get('evidence', {}).get('pattern', 'N/A')}

"""
        
        report += f"""### High-Level Vulnerabilities

"""
        
        for vuln in vulns.get('high_findings', [])[:20]:
            report += f"- **{vuln.get('id')}**: {vuln.get('type').upper()} (CVSS {vuln.get('cvss_score')}) from {vuln.get('evidence', {}).get('source_ip', 'Unknown')}\n"
        
        report += f"""
---

## Risk Assessment & Recommendations

"""
        
        # Risk assessment
        risk = findings.get('findings', {}).get('risk_assessment', {})
        report += f"""**Overall Risk Score**: {risk.get('overall_risk_score', 0):.1f}/10

### Recommendations

"""
        
        for idx, rec in enumerate(risk.get('recommendations', [])[:10], 1):
            report += f"{idx}. {rec}\n"
        
        report += f"""
---

## Generated Alerts

"""
        
        alerts = findings.get('alerts', [])
        report += f"**Total Alerts**: {len(alerts)}\n\n"
        
        for idx, alert in enumerate(alerts[:25], 1):
            report += f"""### Alert {idx}
- **Type**: {alert.get('alert_type', 'Unknown')}
- **Severity**: {alert.get('severity', 'Unknown')}
- **Count**: {alert.get('count', 1)}
- **Description**: {alert.get('description', 'N/A')}

"""
        
        report += f"""---

## Analysis Details

- **Report ID**: {findings.get('report_id', 'Unknown')}
- **Analysis Period**: {findings.get('analysis_period', {}).get('start', 'Unknown')} to {findings.get('analysis_period', {}).get('end', 'Unknown')}
- **Analysis Engine**: Multi-Agent Threat Detection System v1.0
- **Detection Methods**: Pattern Matching + Statistical Analysis + Signature-Based Detection

---

**End of Report**
Generated by Multi-Agent Threat Detection System
"""
        
        return report


# Example usage
if __name__ == "__main__":
    # Test log parsing
    parser = LogParser()
    test_log = '192.168.1.100 - - [24/Mar/2024:09:15:30 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"'
    parsed = parser.parse(test_log)
    print("Parsed entry:", json.dumps(parsed, indent=2))
    
    # Test threat detection
    checker = ThreatSignatureChecker()
    test_entry = {'uri': '/api/users?id=1 OR 1=1', 'user_agent': 'Mozilla/5.0'}
    threats = checker.check_log_entry(test_entry)
    print("\nDetected threats:", json.dumps(threats, indent=2))
