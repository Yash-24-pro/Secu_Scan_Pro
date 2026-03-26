#!/usr/bin/env python3
"""
VulnScanner Pro Installation Script
Handles dependency installation gracefully
"""

import subprocess
import sys
import platform
import os

def run_command(cmd):
    """Run a command and print output"""
    print(f"Running: {cmd}")
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Error: {result.stderr}")
        return False
    print(result.stdout)
    return True

def install_package(package, version=None):
    """Install a package with pip"""
    if version:
        package_spec = f"{package}=={version}"
    else:
        package_spec = package
    
    return run_command(f"{sys.executable} -m pip install {package_spec}")

def main():
    print("=" * 50)
    print("VulnScanner Pro Installation")
    print("=" * 50)
    
    # Check Python version
    if sys.version_info < (3, 8):
        print("Error: Python 3.8 or higher is required")
        sys.exit(1)
    
    # Create virtual environment (optional)
    create_venv = input("Create virtual environment? (y/n): ").lower()
    if create_venv == 'y':
        run_command(f"{sys.executable} -m venv venv")
        if platform.system() == 'Windows':
            python_path = os.path.join('venv', 'Scripts', 'python')
            pip_path = os.path.join('venv', 'Scripts', 'pip')
        else:
            python_path = os.path.join('venv', 'bin', 'python')
            pip_path = os.path.join('venv', 'bin', 'pip')
        
        # Update to use virtual environment
        sys.executable = python_path
        print(f"Using virtual environment: {sys.executable}")
    
    # Upgrade pip
    print("\nUpgrading pip...")
    run_command(f"{sys.executable} -m pip install --upgrade pip")
    
    # Core packages (must have)
    print("\nInstalling core packages...")
    core_packages = [
        "fastapi==0.104.1",
        "uvicorn[standard]==0.24.0",
        "websockets==12.0",
        "pydantic==2.5.0",
        "sqlalchemy==2.0.23",
        "requests==2.31.0",
        "aiohttp==3.9.0",
        "beautifulsoup4==4.12.2",
        "python-dotenv==1.0.0",
        "cryptography==41.0.7",
        "jinja2==3.1.2",
        "psutil==5.9.6"
    ]
    
    for package in core_packages:
        if not install_package(package.split('==')[0], package.split('==')[1] if '==' in package else None):
            print(f"Failed to install {package}")
            if input("Continue anyway? (y/n): ").lower() != 'y':
                sys.exit(1)
    
    # Optional packages
    print("\nInstalling optional packages...")
    optional_packages = [
        "python-nmap==0.7.1",
        "dnspython==2.4.2",
        "whois==0.9.4",
        "celery==5.3.4",
        "redis==5.0.1",
        "reportlab==4.0.7",
        "markdown==3.5.1",
        "selenium==4.15.2"
    ]
    
    for package in optional_packages:
        print(f"\nInstall {package}? (y/n): ", end='')
        if input().lower() == 'y':
            install_package(package.split('==')[0], package.split('==')[1] if '==' in package else None)
    
    # Windows-specific packages
    if platform.system() == 'Windows':
        print("\nInstalling Windows-specific packages...")
        install_package("pywin32", "306")
    
    # Create necessary directories
    print("\nCreating directories...")
    directories = ['reports', 'logs', 'uploads', 'reports/pdf', 'reports/html']
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
    
    print("\n" + "=" * 50)
    print("Installation completed successfully!")
    print("\nTo start the application:")
    print("1. Activate virtual environment (if created)")
    print("2. Run: python main.py")
    print("3. Open browser at http://localhost:8000")
    print("=" * 50)

if __name__ == "__main__":
    main()