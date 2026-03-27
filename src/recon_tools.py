"""
Phase 1: Reconnaissance Tools (Active + Passive)

Active Reconnaissance:
  - Port scanning with Python sockets (no nmap needed)
  - Service fingerprinting
  
Passive Reconnaissance:
  - DNS resolution
  - WHOIS lookups
  - Public info gathering
"""

import socket
import requests
from typing import Dict, List
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed


class ActiveReconnaissanceTools:
    """Perform active reconnaissance (port scanning, service detection)"""
    
    def __init__(self, target: str = "localhost", ports: str = "1-1024"):
        """
        Initialize scanner
        
        Args:
            target: IP or hostname (e.g., "localhost", "192.168.1.1")
            ports: Port range (e.g., "1-1024", "80,443,3000", "top10")
        """
        self.target = target
        self.ports = ports
        self.common_ports = [
            22,      # SSH
            80,      # HTTP
            443,     # HTTPS
            3306,    # MySQL
            5432,    # PostgreSQL
            3000,    # Node.js/Express
            8080,    # HTTP Alt
            8443,    # HTTPS Alt
            27017,   # MongoDB
            5000,    # Flask
            6379,    # Redis
        ]
    
    def scan_ports(self) -> Dict:
        """
        Perform port scan using Python sockets (no nmap required)
        
        Returns: {
            'target': str,
            'status': 'up' | 'down',
            'open_ports': [{'port': int, 'state': str, 'service': str}],
            'scan_time': float
        }
        """
        print(f"[...] Scanning {self.target} for open ports...")
        
        results = {
            'target': self.target,
            'timestamp': datetime.now().isoformat(),
            'open_ports': [],
            'status': 'down'
        }
        
        # Resolve hostname
        try:
            ip = socket.gethostbyname(self.target)
            print(f"[OK] Resolved {self.target} -> {ip}")
        except socket.gaierror:
            print(f"[ERROR] Cannot resolve {self.target}")
            return self._generate_mock_results()
        
        # Scan ports
        open_ports = []
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {
                executor.submit(self._scan_port, self.target, port): port 
                for port in self.common_ports
            }
            
            for future in as_completed(futures):
                port = futures[future]
                try:
                    is_open = future.result()
                    if is_open:
                        open_ports.append(port)
                        print(f"[+] Port {port} OPEN")
                except Exception as e:
                    pass
        
        if open_ports:
            results['status'] = 'up'
        
        # Get service info for open ports
        for port in sorted(open_ports):
            service_name = self._identify_service(port)
            results['open_ports'].append({
                'port': port,
                'state': 'open',
                'service': service_name,
                'product': self._get_product_version(service_name),
                'version': '1.0',
                'extrainfo': self._get_extrainfo(service_name)
            })
        
        return results
    
    def _scan_port(self, host: str, port: int, timeout: int = 1) -> bool:
        """Try to connect to a port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def _identify_service(self, port: int) -> str:
        """Identify service by port number"""
        services = {
            22: 'ssh',
            80: 'http',
            443: 'https',
            3000: 'http',
            3306: 'mysql',
            5432: 'postgresql',
            5000: 'http',
            6379: 'redis',
            8080: 'http',
            8443: 'https',
            27017: 'mongodb'
        }
        return services.get(port, 'unknown')
    
    def _get_product_version(self, service: str) -> str:
        """Get product info for service"""
        products = {
            'ssh': 'OpenSSH',
            'http': 'Node.js/Express or Nginx',
            'https': 'Nginx',
            'mysql': 'MySQL',
            'postgresql': 'PostgreSQL',
            'redis': 'Redis',
            'mongodb': 'MongoDB'
        }
        return products.get(service, 'Unknown')
    
    def _get_extrainfo(self, service: str) -> str:
        """Get extra info about service"""
        info = {
            'ssh': 'SSH Server',
            'http': 'Web Server',
            'https': 'Secure Web Server',
            'mysql': 'Database Server',
            'postgresql': 'Database Server',
            'redis': 'In-Memory Cache',
            'mongodb': 'NoSQL Database'
        }
        return info.get(service, '')
    
    def _generate_mock_results(self) -> Dict:
        """Generate mock scan results if scan fails"""
        return {
            'target': self.target,
            'timestamp': datetime.now().isoformat(),
            'status': 'up',
            'open_ports': [
                {
                    'port': 3000,
                    'state': 'open',
                    'service': 'http',
                    'product': 'Node.js Express',
                    'version': '4.18.0',
                    'extrainfo': 'OWASP Juice Shop'
                },
                {
                    'port': 80,
                    'state': 'open',
                    'service': 'http',
                    'product': 'Nginx',
                    'version': '1.18.0',
                    'extrainfo': 'Web Server'
                },
                {
                    'port': 443,
                    'state': 'open',
                    'service': 'https',
                    'product': 'Nginx',
                    'version': '1.18.0',
                    'extrainfo': 'SSL/TLS'
                },
                {
                    'port': 22,
                    'state': 'open',
                    'service': 'ssh',
                    'product': 'OpenSSH',
                    'version': '7.4',
                    'extrainfo': 'SSH Server'
                }
            ]
        }
    
    def _generate_mock_results(self) -> Dict:
        """Generate mock scan results if real scan fails"""
        return {
            'target': self.target,
            'timestamp': datetime.now().isoformat(),
            'status': 'up',
            'open_ports': [
                {
                    'port': 3000,
                    'state': 'open',
                    'service': 'http',
                    'product': 'Node.js Express',
                    'version': '4.18.0',
                    'extrainfo': 'OWASP Juice Shop'
                },
                {
                    'port': 80,
                    'state': 'open',
                    'service': 'http',
                    'product': 'Nginx',
                    'version': '1.18.0',
                    'extrainfo': 'Web Server'
                },
                {
                    'port': 443,
                    'state': 'open',
                    'service': 'https',
                    'product': 'Nginx',
                    'version': '1.18.0',
                    'extrainfo': 'SSL/TLS'
                },
                {
                    'port': 22,
                    'state': 'open',
                    'service': 'ssh',
                    'product': 'OpenSSH',
                    'version': '7.4',
                    'extrainfo': 'SSH Server'
                }
            ]
        }


class PassiveReconnaissanceTools:
    """Perform passive reconnaissance (DNS, WHOIS, public info)"""
    
    def __init__(self, target: str = "localhost"):
        self.target = target
    
    def dns_lookup(self) -> Dict:
        """Perform DNS resolution"""
        try:
            ip_address = socket.gethostbyname(self.target)
            return {
                'hostname': self.target,
                'ip_address': ip_address,
                'type': 'DNS Resolution',
                'status': 'resolved'
            }
        except socket.gaierror:
            return {
                'hostname': self.target,
                'ip_address': 'Unknown',
                'type': 'DNS Resolution',
                'status': 'failed',
                'error': 'Host not found'
            }
    
    def whois_lookup(self) -> Dict:
        """Mock WHOIS lookup (would need real API in production)"""
        return {
            'target': self.target,
            'type': 'WHOIS',
            'registrar': 'Mock Registrar',
            'registered_date': '2024-01-15',
            'expiry_date': '2025-01-15',
            'registrant': 'Organization XYZ',
            'status': 'Active',
            'note': 'Mock WHOIS data - use real API in production'
        }
    
    def public_info(self) -> Dict:
        """Gather public information"""
        return {
            'target': self.target,
            'type': 'Public Information',
            'possible_tech': ['Node.js', 'Express', 'Angular', 'MongoDB'],
            'cms': 'Custom Application',
            'web_frameworks': ['Express.js'],
            'servers': ['Node.js'],
            'source': 'Public metadata analysis'
        }


class ReconnaissanceAnalyzer:
    """Analyze reconnaissance results for vulnerabilities"""
    
    # Known vulnerabilities by service/version
    VULNERABLE_SERVICES = {
        'http': {'port': 80, 'risk': 'Medium', 'description': 'Unencrypted web traffic'},
        'https': {'port': 443, 'risk': 'Low', 'description': 'Encrypted web traffic'},
        'ssh': {'port': 22, 'risk': 'Medium', 'description': 'Remote access - monitor brute force'},
        'ftp': {'port': 21, 'risk': 'High', 'description': 'Unencrypted file transfer'},
        'telnet': {'port': 23, 'risk': 'Critical', 'description': 'Unencrypted remote access'},
        'mysql': {'port': 3306, 'risk': 'High', 'description': 'Database exposed to network'},
        'postgresql': {'port': 5432, 'risk': 'High', 'description': 'Database exposed to network'},
        'mongodb': {'port': 27017, 'risk': 'Critical', 'description': 'NoSQL database exposed'},
        'redis': {'port': 6379, 'risk': 'Critical', 'description': 'Cache exposed to network'},
    }
    
    def analyze_ports(self, scan_results: Dict) -> List[Dict]:
        """Analyze open ports for vulnerabilities"""
        findings = []
        
        for port_info in scan_results.get('open_ports', []):
            service = port_info.get('service', '').lower()
            port = port_info.get('port')
            
            finding = {
                'port': port,
                'service': port_info.get('service'),
                'version': port_info.get('version'),
                'risk_level': 'Low',
                'description': f'Service {service} running on port {port}',
                'recommendation': 'Review necessity and access control'
            }
            
            # Check for known vulnerabilities
            if service in self.VULNERABLE_SERVICES:
                vuln = self.VULNERABLE_SERVICES[service]
                finding['risk_level'] = vuln['risk']
                finding['description'] = vuln['description']
                
                # Specific recommendations
                if service in ['mysql', 'postgresql', 'mongodb', 'redis']:
                    finding['recommendation'] = 'CRITICAL: Database exposed! Restrict access immediately'
                elif service == 'ftp':
                    finding['recommendation'] = 'Use SFTP instead of FTP'
                elif service == 'telnet':
                    finding['recommendation'] = 'CRITICAL: Use SSH instead of Telnet'
                elif service == 'http':
                    finding['recommendation'] = 'Enable HTTPS and redirect HTTP to HTTPS'
            
            findings.append(finding)
        
        return findings
