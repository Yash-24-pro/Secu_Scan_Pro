# test_scan.py
import requests
import time
import json

def test_scan():
    """Test the scanner API"""
    base_url = "http://localhost:8000"
    
    print("=" * 50)
    print("Testing VulnScanner Pro API")
    print("=" * 50)
    
    # Test 1: Check if server is running
    print("\n1. Checking server status...")
    try:
        response = requests.get(f"{base_url}/")
        if response.status_code == 200:
            print("   ✓ Server is running")
            print(f"   Response: {response.json()}")
        else:
            print(f"   ✗ Server returned status: {response.status_code}")
            return
    except Exception as e:
        print(f"   ✗ Cannot connect to server: {e}")
        print("   Make sure the server is running: python run.py")
        return
    
    # Test 2: Start a scan
    print("\n2. Starting a scan...")
    test_url = input("   Enter URL to scan (default: https://example.com): ").strip()
    if not test_url:
        test_url = "https://example.com"
    
    scan_data = {
        "url": test_url,
        "scheduled": False
    }
    
    try:
        response = requests.post(
            f"{base_url}/api/scan",
            json=scan_data,
            headers={"Content-Type": "application/json"}
        )
        
        if response.status_code == 200:
            result = response.json()
            print(f"   ✓ Scan started successfully!")
            print(f"   Scan ID: {result['scan_id']}")
            print(f"   Message: {result['message']}")
            scan_id = result['scan_id']
        else:
            print(f"   ✗ Failed to start scan: {response.text}")
            return
            
    except Exception as e:
        print(f"   ✗ Error starting scan: {e}")
        return
    
    # Test 3: Monitor scan progress
    print("\n3. Monitoring scan progress...")
    print("   Press Ctrl+C to stop monitoring")
    
    try:
        while True:
            response = requests.get(f"{base_url}/api/scan/{scan_id}/status")
            if response.status_code == 200:
                status = response.json()
                progress = status.get('progress', 0)
                scan_status = status.get('status', 'unknown')
                
                # Create progress bar
                bar_length = 30
                filled = int(bar_length * progress / 100)
                bar = '█' * filled + '░' * (bar_length - filled)
                
                print(f"\r   Progress: [{bar}] {progress}% - Status: {scan_status}", end='')
                
                if scan_status in ['completed', 'failed']:
                    print("\n")
                    if scan_status == 'completed':
                        print("   ✓ Scan completed successfully!")
                    else:
                        print(f"   ✗ Scan failed: {status.get('error', 'Unknown error')}")
                    break
                    
                time.sleep(1)
            else:
                print(f"\n   ✗ Error getting status: {response.status_code}")
                break
                
    except KeyboardInterrupt:
        print("\n   Monitoring stopped by user")
    
    # Test 4: List all scans
    print("\n4. Listing all scans...")
    response = requests.get(f"{base_url}/api/scans")
    if response.status_code == 200:
        scans = response.json()
        print(f"   Total scans: {scans['total']}")
        for scan in scans['scans'][:5]:
            print(f"   - {scan['id']}: {scan['url']} ({scan['status']})")
    
    print("\n" + "=" * 50)
    print("Testing completed!")
    print("=" * 50)

if __name__ == "__main__":
    test_scan()