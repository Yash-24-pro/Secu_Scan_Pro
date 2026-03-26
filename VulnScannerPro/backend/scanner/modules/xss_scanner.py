import re
from typing import Dict, List
from bs4 import BeautifulSoup

class XSSScanner:
    """Cross-Site Scripting (XSS) detection module"""
    
    def __init__(self):
        self.payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "'><script>alert('XSS')</script>",
            "\"><script>alert('XSS')</script>",
            "<body onload=alert('XSS')>",
            "<input type='text' value='XSS' onfocus=alert('XSS')>",
            "'';!--\"<XSS>=&{()}",
            "<IMG SRC=javascript:alert('XSS')>",
            "<IFRAME SRC=javascript:alert('XSS')>"
        ]
        
    async def scan(self, url: str, request_handler) -> Dict:
        """Scan for XSS vulnerabilities"""
        results = {
            'vulnerable': False,
            'vulnerabilities': [],
            'tested_payloads': 0,
            'reflected_xss': [],
            'stored_xss': []
        }
        
        # Get initial page
        try:
            response = await request_handler.get(url)
            forms = self._extract_forms(response.text)
            
            # Test forms for XSS
            for form in forms:
                for payload in self.payloads:
                    test_result = await self._test_form_xss(url, form, payload, request_handler)
                    results['tested_payloads'] += 1
                    
                    if test_result['vulnerable']:
                        results['vulnerable'] = True
                        results['reflected_xss'].append(test_result)
                        results['vulnerabilities'].append({
                            'type': 'Reflected XSS',
                            'severity': 'high',
                            'payload': payload,
                            'form': form,
                            'description': "Reflected XSS vulnerability detected",
                            'remediation': "Implement output encoding, use Content Security Policy, and sanitize user input"
                        })
            
            # Test URL parameters for reflected XSS
            url_params = self._extract_url_params(url)
            for param in url_params:
                for payload in self.payloads:
                    test_url = self._inject_url_payload(url, param, payload)
                    test_response = await request_handler.get(test_url)
                    
                    if self._check_payload_in_response(test_response.text, payload):
                        results['vulnerable'] = True
                        results['vulnerabilities'].append({
                            'type': 'Reflected XSS (URL Parameter)',
                            'severity': 'high',
                            'parameter': param,
                            'payload': payload,
                            'location': test_url,
                            'description': "XSS vulnerability in URL parameter",
                            'remediation': "Validate and sanitize all URL parameters"
                        })
                        
        except Exception as e:
            results['error'] = str(e)
            
        return results
    
    def _extract_forms(self, html: str) -> List[Dict]:
        """Extract forms from HTML"""
        soup = BeautifulSoup(html, 'html.parser')
        forms = []
        
        for form in soup.find_all('form'):
            form_data = {
                'action': form.get('action', ''),
                'method': form.get('method', 'get').lower(),
                'inputs': []
            }
            
            for input_tag in form.find_all('input'):
                form_data['inputs'].append({
                    'name': input_tag.get('name', ''),
                    'type': input_tag.get('type', 'text'),
                    'value': input_tag.get('value', '')
                })
            
            forms.append(form_data)
            
        return forms
    
    async def _test_form_xss(self, url: str, form: Dict, payload: str, request_handler) -> Dict:
        """Test a form for XSS vulnerability"""
        result = {'vulnerable': False, 'payload': payload, 'form': form}
        
        # Prepare form data with payload
        form_data = {}
        for input_field in form['inputs']:
            if input_field['type'] not in ['submit', 'button', 'reset']:
                form_data[input_field['name']] = payload
            else:
                form_data[input_field['name']] = input_field['value']
        
        # Submit form
        action_url = self._resolve_url(url, form['action'])
        
        try:
            if form['method'] == 'post':
                response = await request_handler.post(action_url, data=form_data)
            else:
                response = await request_handler.get(action_url, params=form_data)
                
            if self._check_payload_in_response(response.text, payload):
                result['vulnerable'] = True
                
        except Exception as e:
            pass
            
        return result
    
    def _check_payload_in_response(self, response_text: str, payload: str) -> bool:
        """Check if payload is reflected in response"""
        # Remove HTML tags for better matching
        clean_text = re.sub(r'<[^>]+>', '', response_text)
        
        # Check for payload in response
        if payload in clean_text:
            return True
            
        # Check for JavaScript execution indicators
        js_indicators = ['alert', 'XSS', 'onerror', 'onload']
        for indicator in js_indicators:
            if indicator in payload and indicator in clean_text:
                return True
                
        return False
    
    def _extract_url_params(self, url: str) -> List[str]:
        """Extract parameters from URL"""
        params = []
        if '?' in url:
            query = url.split('?')[1]
            for param in query.split('&'):
                params.append(param.split('=')[0])
        return params
    
    def _inject_url_payload(self, url: str, param: str, payload: str) -> str:
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
    
    def _resolve_url(self, base_url: str, relative_url: str) -> str:
        """Resolve relative URL to absolute URL"""
        if relative_url.startswith('http'):
            return relative_url
        elif relative_url.startswith('/'):
            base_parts = base_url.split('/')
            return f"{base_parts[0]}//{base_parts[2]}{relative_url}"
        else:
            if base_url.endswith('/'):
                return base_url + relative_url
            else:
                return base_url + '/' + relative_url