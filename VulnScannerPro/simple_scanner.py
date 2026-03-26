# simple_scanner.py - One Click Vulnerability Scanner
import requests
import ssl
import socket
import datetime
from urllib.parse import urlparse
import json
import time

print("=" * 60)
print("     VULNERABILITY SCANNER - Simple Version")
print("=" * 60)

# Get URL from user
url = input("\n🔗 Enter website URL to scan (e.g., https://example.com): ").strip()

if not url.startswith(('http://', 'https://')):
    url = 'https://' + url

print(f"\n📡 Scanning: {url}")
print("⏳ Please wait...\n")
time.sleep(1)

results = {
    'url': url,
    'vulnerabilities': [],
    'security_score': 100
}

# 1. CHECK SSL CERTIFICATE
print("🔒 Checking SSL Certificate...")
try:
    hostname = url.replace('https://', '').replace('http://', '').split('/')[0]
    ctx = ssl.create_default_context()
    with socket.create_connection((hostname, 443), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert = ssock.getpeercert()
            expiry = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            
            if expiry < datetime.datetime.now():
                results['vulnerabilities'].append({'type': 'Expired SSL Certificate', 'severity': 'CRITICAL'})
                results['security_score'] -= 30
                print("   ❌ CRITICAL: SSL Certificate EXPIRED!")
            elif (expiry - datetime.datetime.now()).days < 30:
                results['vulnerabilities'].append({'type': 'SSL Certificate Expiring Soon', 'severity': 'HIGH'})
                results['security_score'] -= 15
                print(f"   ⚠️  WARNING: SSL expires in {(expiry - datetime.datetime.now()).days} days")
            else:
                print("   ✅ Valid SSL Certificate")
except:
    results['vulnerabilities'].append({'type': 'No SSL/HTTPS', 'severity': 'CRITICAL'})
    results['security_score'] -= 50
    print("   ❌ CRITICAL: No HTTPS/SSL detected!")

# 2. CHECK SECURITY HEADERS
print("\n🛡️  Checking Security Headers...")
try:
    response = requests.get(url, timeout=10, verify=False)
    headers = response.headers
    
    security_headers = {
        'Strict-Transport-Security': 'HSTS (Prevents SSL stripping)',
        'Content-Security-Policy': 'CSP (Prevents XSS)',
        'X-Frame-Options': 'Clickjacking Protection',
        'X-Content-Type-Options': 'MIME Sniffing Protection',
        'X-XSS-Protection': 'XSS Protection'
    }
    
    missing_headers = []
    for header, description in security_headers.items():
        if header not in headers:
            missing_headers.append(description)
    
    if missing_headers:
        results['security_score'] -= len(missing_headers) * 5
        print(f"   ⚠️  Missing {len(missing_headers)} security headers:")
        for missing in missing_headers[:3]:
            print(f"      - {missing}")
    else:
        print("   ✅ All security headers present!")
        
except:
    print("   ⚠️  Could not check headers")
    results['security_score'] -= 10

# 3. CHECK FOR SQL INJECTION VULNERABILITY
print("\n💉 Testing for SQL Injection...")
test_payloads = ["'", "' OR '1'='1", "admin'--", "' UNION SELECT NULL--"]
vulnerable = False

try:
    for payload in test_payloads:
        test_url = f"{url}?id={payload}"
        try:
            resp = requests.get(test_url, timeout=5)
            if any(error in resp.text.lower() for error in ['sql', 'mysql', 'syntax', 'unclosed']):
                vulnerable = True
                break
        except:
            pass
    
    if vulnerable:
        results['vulnerabilities'].append({'type': 'SQL Injection Possible', 'severity': 'CRITICAL'})
        results['security_score'] -= 40
        print("   ❌ CRITICAL: Possible SQL Injection vulnerability!")
    else:
        print("   ✅ No obvious SQL injection detected")
except:
    print("   ⚠️  Could not test SQL injection")

# 4. CHECK FOR XSS VULNERABILITY
print("\n🌐 Testing for XSS (Cross-Site Scripting)...")
xss_payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"]
xss_found = False

try:
    for payload in xss_payloads:
        test_url = f"{url}?search={payload}"
        try:
            resp = requests.get(test_url, timeout=5)
            if payload in resp.text:
                xss_found = True
                break
        except:
            pass
    
    if xss_found:
        results['vulnerabilities'].append({'type': 'XSS Vulnerability', 'severity': 'HIGH'})
        results['security_score'] -= 30
        print("   ❌ HIGH: Possible XSS vulnerability detected!")
    else:
        print("   ✅ No obvious XSS detected")
except:
    print("   ⚠️  Could not test XSS")

# 5. CHECK OPEN PORTS (Common dangerous ports)
print("\n🔌 Checking for dangerous open ports...")
dangerous_ports = {
    21: "FTP (Insecure)",
    23: "Telnet (Insecure)",
    3389: "RDP (Remote Desktop)",
    3306: "MySQL Database",
    5432: "PostgreSQL Database"
}

open_dangerous = []
for port, service in dangerous_ports.items():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((hostname, port))
        if result == 0:
            open_dangerous.append(f"{port} ({service})")
        sock.close()
    except:
        pass

if open_dangerous:
    results['security_score'] -= len(open_dangerous) * 10
    print(f"   ⚠️  WARNING: Dangerous ports open: {', '.join(open_dangerous)}")
else:
    print("   ✅ No dangerous open ports detected")

# 6. CHECK DIRECTORY LISTING
print("\n📁 Checking for sensitive directories...")
sensitive_dirs = ['/admin', '/backup', '/config', '/.git', '/wp-admin', '/phpmyadmin']
exposed = []

for directory in sensitive_dirs:
    try:
        test_url = url.rstrip('/') + directory
        resp = requests.get(test_url, timeout=5)
        if resp.status_code == 200:
            exposed.append(directory)
    except:
        pass

if exposed:
    results['security_score'] -= len(exposed) * 5
    print(f"   ⚠️  Sensitive directories accessible: {', '.join(exposed)}")
else:
    print("   ✅ No sensitive directories exposed")

# 7. CHECK SERVER INFORMATION LEAKAGE
print("\nℹ️  Checking for information leakage...")
try:
    response = requests.get(url, timeout=10, verify=False)
    server = response.headers.get('Server', '')
    if server:
        print(f"   ℹ️  Server info exposed: {server}")
        results['vulnerabilities'].append({'type': 'Server Information Leakage', 'severity': 'LOW'})
        results['security_score'] -= 5
    else:
        print("   ✅ Server info hidden")
except:
    pass

# FINAL REPORT
print("\n" + "=" * 60)
print("                    SCAN REPORT")
print("=" * 60)

print(f"\n📊 SECURITY SCORE: {results['security_score']}/100")

# Rating
if results['security_score'] >= 80:
    rating = "A+ (Excellent)"
    color = "🟢"
elif results['security_score'] >= 60:
    rating = "B (Good - Some issues)"
    color = "🟡"
elif results['security_score'] >= 40:
    rating = "C (Average - Needs improvement)"
    color = "🟠"
elif results['security_score'] >= 20:
    rating = "D (Poor - High risk)"
    color = "🔴"
else:
    rating = "F (Critical - Immediate action required)"
    color = "💀"

print(f"{color}  RATING: {rating}")

# Vulnerabilities Found
if results['vulnerabilities']:
    print(f"\n⚠️  VULNERABILITIES FOUND ({len(results['vulnerabilities'])}):")
    for vuln in results['vulnerabilities']:
        severity_icon = "💀" if vuln['severity'] == 'CRITICAL' else "🔴" if vuln['severity'] == 'HIGH' else "🟡" if vuln['severity'] == 'MEDIUM' else "🔵"
        print(f"   {severity_icon} [{vuln['severity']}] {vuln['type']}")
else:
    print("\n✅ NO VULNERABILITIES DETECTED!")
    print("   The website looks secure!")

# Recommendations
print("\n📋 RECOMMENDATIONS:")
if results['security_score'] < 100:
    print("   • Enable HTTPS/SSL if not already")
    print("   • Add security headers (HSTS, CSP, X-Frame-Options)")
    print("   • Implement input validation to prevent SQL injection/XSS")
    print("   • Close unnecessary open ports")
    print("   • Hide server information from headers")
    print("   • Restrict access to sensitive directories")
else:
    print("   • Keep security measures updated")
    print("   • Regular security audits recommended")

print("\n" + "=" * 60)
print("✅ Scan completed!")
print("=" * 60)

# Option to save report
save = input("\n💾 Save report to file? (y/n): ").lower()
if save == 'y':
    filename = f"scan_report_{hostname}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(filename, 'w') as f:
        f.write(f"Vulnerability Scan Report for {url}\n")
        f.write("=" * 50 + "\n\n")
        f.write(f"Security Score: {results['security_score']}/100\n")
        f.write(f"Rating: {rating}\n\n")
        f.write(f"Vulnerabilities Found: {len(results['vulnerabilities'])}\n")
        for vuln in results['vulnerabilities']:
            f.write(f"- [{vuln['severity']}] {vuln['type']}\n")
    print(f"✅ Report saved to: {filename}")

print("\n🎉 Done! Press Enter to exit...")
input()