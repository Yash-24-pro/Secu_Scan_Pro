# app.py - Advanced Website Security & Quality Scanner
from flask import Flask, render_template, request, jsonify
import requests
import ssl
import socket
import datetime
from urllib.parse import urlparse, urljoin
import json
import time
import re
import dns.resolver
from bs4 import BeautifulSoup
import whois

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'

# Store scan history
scan_history = []

def check_ssl_security(hostname):
    """SSL/TLS security check"""
    results = {
        'valid': False,
        'details': [],
        'issues': []
    }
    
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                
                # Check expiry
                expiry = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                days_left = (expiry - datetime.datetime.now()).days
                
                if days_left < 0:
                    results['issues'].append('Certificate expired')
                    results['details'].append({'check': 'Certificate Status', 'value': 'Expired', 'status': 'Critical'})
                elif days_left < 30:
                    results['issues'].append(f'Certificate expires in {days_left} days')
                    results['details'].append({'check': 'Certificate Status', 'value': f'{days_left} days left', 'status': 'Warning'})
                else:
                    results['details'].append({'check': 'Certificate Status', 'value': f'{days_left} days left', 'status': 'Good'})
                
                # Check protocol
                protocol = ssock.version()
                if 'TLSv1.2' in protocol or 'TLSv1.3' in protocol:
                    results['details'].append({'check': 'TLS Version', 'value': protocol, 'status': 'Good'})
                else:
                    results['details'].append({'check': 'TLS Version', 'value': protocol, 'status': 'Warning'})
                    results['issues'].append(f'Using outdated protocol: {protocol}')
                
                results['valid'] = True
                
    except Exception as e:
        results['issues'].append(f'SSL error: {str(e)}')
        results['details'].append({'check': 'SSL Connection', 'value': 'Failed', 'status': 'Critical'})
    
    return results

def check_security_headers(headers):
    """Security headers analysis"""
    checks = {
        'Strict-Transport-Security': 'HSTS - Forces HTTPS',
        'Content-Security-Policy': 'CSP - Prevents XSS',
        'X-Frame-Options': 'Clickjacking Protection',
        'X-Content-Type-Options': 'MIME Sniffing Protection',
        'X-XSS-Protection': 'XSS Protection'
    }
    
    results = []
    for header, desc in checks.items():
        if header in headers:
            results.append({'check': desc, 'status': 'Present', 'value': headers[header][:50], 'severity': 'Good'})
        else:
            results.append({'check': desc, 'status': 'Missing', 'value': 'Not configured', 'severity': 'Warning'})
    
    return results

def check_traffic_and_seo(url):
    """Check traffic metrics and SEO factors"""
    results = {
        'traffic_indicators': [],
        'seo_factors': [],
        'score': 100
    }
    
    try:
        response = requests.get(url, timeout=10, verify=False)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Check for analytics (traffic measurement)
        analytics_found = []
        analytics_scripts = ['google-analytics', 'gtag', 'facebook-pixel', 'hotjar', 'mixpanel', 'segment']
        for script in analytics_scripts:
            if script in response.text.lower():
                analytics_found.append(script)
        
        if analytics_found:
            results['traffic_indicators'].append({'type': 'Analytics Tools', 'value': ', '.join(analytics_found), 'status': 'Good'})
        else:
            results['traffic_indicators'].append({'type': 'Analytics Tools', 'value': 'None detected', 'status': 'Warning'})
            results['score'] -= 15
        
        # Check for meta tags
        meta_description = soup.find('meta', {'name': 'description'})
        if meta_description:
            results['seo_factors'].append({'check': 'Meta Description', 'value': 'Present', 'status': 'Good'})
        else:
            results['seo_factors'].append({'check': 'Meta Description', 'value': 'Missing', 'status': 'Warning'})
            results['score'] -= 10
        
        # Check for viewport (mobile friendly)
        viewport = soup.find('meta', {'name': 'viewport'})
        if viewport:
            results['seo_factors'].append({'check': 'Mobile Friendly', 'value': 'Configured', 'status': 'Good'})
        else:
            results['seo_factors'].append({'check': 'Mobile Friendly', 'value': 'Not configured', 'status': 'Warning'})
            results['score'] -= 10
        
        # Check for robots.txt
        robots_url = url.rstrip('/') + '/robots.txt'
        try:
            robots_resp = requests.get(robots_url, timeout=5)
            if robots_resp.status_code == 200:
                results['seo_factors'].append({'check': 'Robots.txt', 'value': 'Present', 'status': 'Good'})
            else:
                results['seo_factors'].append({'check': 'Robots.txt', 'value': 'Missing', 'status': 'Warning'})
                results['score'] -= 5
        except:
            results['seo_factors'].append({'check': 'Robots.txt', 'value': 'Not accessible', 'status': 'Warning'})
        
        # Check for sitemap
        sitemap_url = url.rstrip('/') + '/sitemap.xml'
        try:
            sitemap_resp = requests.get(sitemap_url, timeout=5)
            if sitemap_resp.status_code == 200:
                results['seo_factors'].append({'check': 'Sitemap', 'value': 'Present', 'status': 'Good'})
            else:
                results['seo_factors'].append({'check': 'Sitemap', 'value': 'Missing', 'status': 'Info'})
        except:
            pass
        
        # Check page load time
        start_time = time.time()
        requests.get(url, timeout=10, verify=False)
        load_time = (time.time() - start_time) * 1000
        if load_time < 1000:
            results['seo_factors'].append({'check': 'Page Load Time', 'value': f'{load_time:.0f}ms', 'status': 'Good'})
        elif load_time < 3000:
            results['seo_factors'].append({'check': 'Page Load Time', 'value': f'{load_time:.0f}ms', 'status': 'Warning'})
            results['score'] -= 10
        else:
            results['seo_factors'].append({'check': 'Page Load Time', 'value': f'{load_time:.0f}ms', 'status': 'Critical'})
            results['score'] -= 20
        
    except Exception as e:
        results['traffic_indicators'].append({'type': 'Analysis Error', 'value': str(e), 'status': 'Error'})
    
    return results

def check_financial_involvement(url, response_text):
    """Detect if website handles financial transactions"""
    financial_indicators = {
        'payment': ['paypal', 'stripe', 'square', 'razorpay', 'payment', 'checkout', 'cart', 'shopify', 'woocommerce'],
        'banking': ['bank', 'credit card', 'debit card', 'net banking', 'upi', 'transfer', 'transaction'],
        'security': ['ssl', 'secure', 'encrypted', 'pci', 'compliance', 'verified by visa', 'mastercard secure']
    }
    
    results = {
        'has_financial': False,
        'indicators': [],
        'security_level': 'Unknown',
        'recommendations': []
    }
    
    text_lower = response_text.lower()
    
    for category, keywords in financial_indicators.items():
        found = [kw for kw in keywords if kw in text_lower]
        if found:
            results['has_financial'] = True
            results['indicators'].append({'category': category, 'found': found})
    
    if results['has_financial']:
        # Check for payment security indicators
        if 'https' in url and 'secure' in text_lower:
            results['security_level'] = 'Good'
            results['recommendations'].append('✓ Payment gateway detected with SSL')
        else:
            results['security_level'] = 'Warning'
            results['recommendations'].append('⚠️ Financial transactions detected but security measures need verification')
        
        results['recommendations'].append('✓ Ensure PCI DSS compliance for payment processing')
        results['recommendations'].append('✓ Use trusted payment gateways')
        results['recommendations'].append('✓ Implement 3D Secure for card payments')
    else:
        results['security_level'] = 'Not Applicable'
        results['recommendations'].append('No financial transactions detected')
    
    return results

def check_website_quality(url, response_text, soup):
    """Check overall website quality metrics"""
    results = {
        'score': 100,
        'factors': [],
        'issues': []
    }
    
    # Check for SSL (already done)
    
    # Check for mobile responsiveness indicators
    viewport = soup.find('meta', {'name': 'viewport'})
    if viewport:
        results['factors'].append({'check': 'Mobile Responsive', 'value': 'Yes', 'status': 'Good'})
    else:
        results['factors'].append({'check': 'Mobile Responsive', 'value': 'No', 'status': 'Warning'})
        results['score'] -= 15
        results['issues'].append('Not mobile-friendly - add viewport meta tag')
    
    # Check for favicon
    favicon = soup.find('link', {'rel': 'icon'}) or soup.find('link', {'rel': 'shortcut icon'})
    if favicon:
        results['factors'].append({'check': 'Favicon', 'value': 'Present', 'status': 'Good'})
    else:
        results['factors'].append({'check': 'Favicon', 'value': 'Missing', 'status': 'Info'})
    
    # Check for title
    title = soup.find('title')
    if title and len(title.text.strip()) > 0:
        title_len = len(title.text.strip())
        if 30 <= title_len <= 60:
            results['factors'].append({'check': 'Title Tag', 'value': f'{title_len} chars (Good length)', 'status': 'Good'})
        else:
            results['factors'].append({'check': 'Title Tag', 'value': f'{title_len} chars (Not optimal)', 'status': 'Warning'})
            results['score'] -= 5
    else:
        results['factors'].append({'check': 'Title Tag', 'value': 'Missing', 'status': 'Critical'})
        results['score'] -= 20
    
    # Check for heading structure
    h1_tags = soup.find_all('h1')
    if len(h1_tags) == 1:
        results['factors'].append({'check': 'H1 Tag', 'value': 'Single H1 (Good)', 'status': 'Good'})
    elif len(h1_tags) > 1:
        results['factors'].append({'check': 'H1 Tag', 'value': f'{len(h1_tags)} H1 tags found', 'status': 'Warning'})
        results['score'] -= 5
        results['issues'].append('Multiple H1 tags - use only one H1 per page')
    else:
        results['factors'].append({'check': 'H1 Tag', 'value': 'Missing', 'status': 'Warning'})
        results['score'] -= 10
    
    # Check for images with alt text
    images = soup.find_all('img')
    images_with_alt = [img for img in images if img.get('alt')]
    if images:
        alt_percentage = (len(images_with_alt) / len(images)) * 100
        if alt_percentage >= 90:
            results['factors'].append({'check': 'Image Alt Text', 'value': f'{alt_percentage:.0f}% coverage', 'status': 'Good'})
        elif alt_percentage >= 50:
            results['factors'].append({'check': 'Image Alt Text', 'value': f'{alt_percentage:.0f}% coverage', 'status': 'Warning'})
            results['score'] -= 10
        else:
            results['factors'].append({'check': 'Image Alt Text', 'value': f'{alt_percentage:.0f}% coverage', 'status': 'Critical'})
            results['score'] -= 20
    
    # Check for broken links (sample of links)
    links = soup.find_all('a', href=True)[:10]  # Check first 10 links
    broken_links = 0
    for link in links:
        href = link['href']
        if href.startswith('http'):
            try:
                resp = requests.head(href, timeout=3, allow_redirects=True)
                if resp.status_code >= 400:
                    broken_links += 1
            except:
                broken_links += 1
    
    if broken_links == 0:
        results['factors'].append({'check': 'Broken Links', 'value': 'None found', 'status': 'Good'})
    elif broken_links <= 2:
        results['factors'].append({'check': 'Broken Links', 'value': f'{broken_links} broken links', 'status': 'Warning'})
        results['score'] -= 10
    else:
        results['factors'].append({'check': 'Broken Links', 'value': f'{broken_links} broken links', 'status': 'Critical'})
        results['score'] -= 20
    
    # Check for social media presence
    social_platforms = ['facebook.com', 'twitter.com', 'instagram.com', 'linkedin.com', 'youtube.com']
    social_found = [platform for platform in social_platforms if platform in response_text.lower()]
    if social_found:
        results['factors'].append({'check': 'Social Media', 'value': f'{len(social_found)} platforms', 'status': 'Good'})
    else:
        results['factors'].append({'check': 'Social Media', 'value': 'None detected', 'status': 'Info'})
    
    return results

def scan_website_comprehensive(url, progress_callback=None):
    """Complete website security and quality scan with progress tracking"""
    
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    results = {
        'url': url,
        'scan_time': datetime.datetime.now().isoformat(),
        'vulnerabilities': [],
        'security_score': 100,
        'categories': {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        },
        'detailed_checks': {},
        'seo_metrics': {},
        'traffic_metrics': {},
        'financial_info': {},
        'quality_metrics': {},
        'recommendations': []
    }
    
    hostname = url.replace('https://', '').replace('http://', '').split('/')[0]
    domain = hostname.split(':')[0]
    
    # 1. SSL/TLS Security (10%)
    if progress_callback:
        progress_callback(10, "🔒 Checking SSL/TLS Security... (10%)")
    
    ssl_results = check_ssl_security(domain)
    results['detailed_checks']['SSL/TLS Security'] = ssl_results['details']
    for issue in ssl_results['issues']:
        results['vulnerabilities'].append({'type': issue, 'severity': 'high'})
        results['security_score'] -= 15
        results['categories']['high'] += 1
    
    # 2. Get website content
    if progress_callback:
        progress_callback(20, "🌐 Fetching website content... (20%)")
    
    try:
        response = requests.get(url, timeout=15, verify=False)
        headers = response.headers
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # 3. Security Headers (30%)
        if progress_callback:
            progress_callback(30, "🛡️ Analyzing Security Headers... (30%)")
        
        header_results = check_security_headers(headers)
        results['detailed_checks']['Security Headers'] = header_results
        for header in header_results:
            if header['status'] == 'Missing':
                results['vulnerabilities'].append({'type': header['check'], 'severity': 'medium'})
                results['security_score'] -= 8
                results['categories']['medium'] += 1
                results['recommendations'].append(f"Add {header['check']} header")
        
        # 4. Traffic & Analytics (40%)
        if progress_callback:
            progress_callback(40, "📊 Analyzing Traffic & Analytics... (40%)")
        
        traffic_results = check_traffic_and_seo(url)
        results['traffic_metrics'] = traffic_results
        results['security_score'] += traffic_results['score'] - 100  # Adjust score
        for indicator in traffic_results.get('traffic_indicators', []):
            if indicator['status'] == 'Warning':
                results['recommendations'].append(f"Add analytics tools to track traffic: {indicator['type']}")
        
        # 5. Financial Involvement Detection (50%)
        if progress_callback:
            progress_callback(50, "💰 Checking for Financial Transactions... (50%)")
        
        financial_results = check_financial_involvement(url, response.text)
        results['financial_info'] = financial_results
        if financial_results['has_financial']:
            results['recommendations'].extend(financial_results['recommendations'])
        
        # 6. DNS Configuration (60%)
        if progress_callback:
            progress_callback(60, "🌍 Checking DNS Configuration... (60%)")
        
        try:
            dns_records = []
            for record_type in ['A', 'MX', 'TXT']:
                try:
                    answers = dns.resolver.resolve(domain, record_type)
                    dns_records.append({'type': record_type, 'value': str(answers[0])})
                except:
                    pass
            results['detailed_checks']['DNS Configuration'] = dns_records
        except:
            pass
        
        # 7. Security Vulnerabilities (70%)
        if progress_callback:
            progress_callback(70, "💉 Testing for Common Vulnerabilities... (70%)")
        
        # SQL Injection test
        test_payloads = ["'", "' OR '1'='1", "admin'--"]
        for payload in test_payloads:
            test_url = f"{url}?id={payload}"
            try:
                resp = requests.get(test_url, timeout=5)
                sql_errors = ['sql', 'mysql', 'syntax', 'unclosed']
                if any(error in resp.text.lower() for error in sql_errors):
                    results['vulnerabilities'].append({'type': 'SQL Injection Vulnerability', 'severity': 'critical'})
                    results['security_score'] -= 40
                    results['categories']['critical'] += 1
                    results['recommendations'].append("Fix SQL injection vulnerabilities - use parameterized queries")
                    break
            except:
                pass
        
        # XSS test
        xss_payload = "<script>alert('XSS')</script>"
        test_url = f"{url}?search={xss_payload}"
        try:
            resp = requests.get(test_url, timeout=5)
            if xss_payload in resp.text:
                results['vulnerabilities'].append({'type': 'XSS Vulnerability', 'severity': 'high'})
                results['security_score'] -= 30
                results['categories']['high'] += 1
                results['recommendations'].append("Fix XSS vulnerabilities - implement output encoding and CSP")
        except:
            pass
        
        # 8. Website Quality Metrics (80%)
        if progress_callback:
            progress_callback(80, "📈 Evaluating Website Quality... (80%)")
        
        quality_results = check_website_quality(url, response.text, soup)
        results['quality_metrics'] = quality_results
        results['security_score'] = (results['security_score'] + quality_results['score']) / 2
        results['recommendations'].extend(quality_results['issues'])
        
        # 9. Server & Performance (90%)
        if progress_callback:
            progress_callback(90, "⚡ Checking Server & Performance... (90%)")
        
        server_info = headers.get('Server', 'Not disclosed')
        results['detailed_checks']['Server Info'] = server_info
        
        # Check for CDN
        cdn_headers = ['cf-ray', 'x-cache', 'x-amz-cf', 'x-akamai']
        cdn_detected = [h for h in cdn_headers if h in headers]
        if cdn_detected:
            results['detailed_checks']['CDN'] = "CDN Detected (Good for performance)"
        
        # 10. Final Analysis (100%)
        if progress_callback:
            progress_callback(100, "✅ Generating Final Report... (100%)")
        
        # Calculate final score
        results['security_score'] = max(0, min(100, results['security_score']))
        
        # Add summary recommendations
        if results['security_score'] >= 80:
            results['recommendations'].insert(0, "✓ Overall: Website is secure! Maintain regular security updates.")
        elif results['security_score'] >= 60:
            results['recommendations'].insert(0, "⚠️ Overall: Some security issues found. Review recommendations.")
        else:
            results['recommendations'].insert(0, "🔴 Overall: Critical security issues detected. Immediate action required!")
        
        # Calculate percentages
        total_vulns = sum(results['categories'].values())
        if total_vulns > 0:
            for key in results['categories']:
                results['categories'][key] = round((results['categories'][key] / total_vulns) * 100)
        
    except Exception as e:
        results['vulnerabilities'].append({'type': f'Connection Error: {str(e)}', 'severity': 'critical'})
        results['security_score'] = 0
    
    return results

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    data = request.get_json()
    url = data.get('url', '')
    
    if not url:
        return jsonify({'error': 'No URL provided'}), 400
    
    results = scan_website_comprehensive(url)
    
    scan_history.append({
        'url': url,
        'timestamp': datetime.datetime.now().isoformat(),
        'score': results['security_score'],
        'vulnerabilities': len(results['vulnerabilities'])
    })
    
    return jsonify(results)

@app.route('/history')
def history():
    return jsonify(scan_history)

@app.route('/stats')
def stats():
    if not scan_history:
        return jsonify({'total_scans': 0, 'average_score': 0})
    
    total_score = sum(scan['score'] for scan in scan_history)
    avg_score = total_score / len(scan_history)
    
    return jsonify({
        'total_scans': len(scan_history),
        'average_score': round(avg_score, 2),
        'latest_scan': scan_history[-1] if scan_history else None
    })

if __name__ == '__main__':
    print("=" * 60)
    print("🚀 Advanced Website Security & Quality Scanner")
    print("=" * 60)
    print("\n📊 Features:")
    print("   • SSL/TLS Security Analysis")
    print("   • Traffic & Analytics Detection")
    print("   • Financial Transaction Detection")
    print("   • Website Quality Metrics")
    print("   • SEO Optimization Check")
    print("   • Security Headers Analysis")
    print("   • Performance Evaluation")
    print("   • Real-time Progress with Percentages")
    print("\n🌐 Open browser: http://localhost:5000")
    print("=" * 60)
    app.run(debug=True, port=5000)