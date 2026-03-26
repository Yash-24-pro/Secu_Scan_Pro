import asyncio
import aiohttp
from typing import Dict, List
import logging
from datetime import datetime
from backend.scanner.modules import (
    sql_injection, xss_scanner, security_headers,
    ssl_validator, directory_scanner, port_scanner,
    cve_checker, subdomain_scanner, sensitive_data_scanner
)
from backend.database.models import Scan, Vulnerability
from backend.scanner.utils.request_handler import RequestHandler

logger = logging.getLogger(__name__)

class ScannerEngine:
    def __init__(self, scan_id: int, url: str):
        self.scan_id = scan_id
        self.url = url
        self.request_handler = RequestHandler()
        self.vulnerabilities = []
        self.scan_progress = 0
        self.modules = [
            sql_injection.SQLInjectionScanner(),
            xss_scanner.XSSScanner(),
            security_headers.SecurityHeadersChecker(),
            ssl_validator.SSLValidator(),
            directory_scanner.DirectoryScanner(),
            port_scanner.PortScanner(),
            cve_checker.CVEChecker(),
            subdomain_scanner.SubdomainScanner(),
            sensitive_data_scanner.SensitiveDataScanner()
        ]
    
    async def run_scan(self) -> Dict:
        """Execute full security scan"""
        logger.info(f"Starting scan for {self.url}")
        
        results = {
            'scan_id': self.scan_id,
            'url': self.url,
            'start_time': datetime.utcnow(),
            'modules': {},
            'total_vulnerabilities': 0,
            'severity_summary': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0
            }
        }
        
        for i, module in enumerate(self.modules):
            self.scan_progress = (i / len(self.modules)) * 100
            try:
                module_results = await module.scan(self.url, self.request_handler)
                results['modules'][module.__class__.__name__] = module_results
                
                # Collect vulnerabilities
                if 'vulnerabilities' in module_results:
                    self.vulnerabilities.extend(module_results['vulnerabilities'])
                    
            except Exception as e:
                logger.error(f"Module {module.__class__.__name__} failed: {e}")
                results['modules'][module.__class__.__name__] = {'error': str(e)}
        
        # Update severity summary
        for vuln in self.vulnerabilities:
            severity = vuln.get('severity', 'low').lower()
            results['severity_summary'][severity] += 1
        
        results['total_vulnerabilities'] = len(self.vulnerabilities)
        results['end_time'] = datetime.utcnow()
        results['scan_progress'] = 100
        
        # Save results to database
        await self._save_results(results)
        
        logger.info(f"Scan completed for {self.url}. Found {len(self.vulnerabilities)} vulnerabilities")
        return results
    
    async def _save_results(self, results: Dict):
        """Save scan results to database"""
        # Database saving logic here
        pass
    
    def get_progress(self) -> int:
        return self.scan_progress