# init_db.py
import asyncio
import os
import sys

# Add the current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from backend.database.database import init_db, engine
from backend.database.models import Base

async def main():
    """Initialize database tables"""
    print("=" * 50)
    print("VulnScanner Pro - Database Initialization")
    print("=" * 50)
    
    try:
        # Create tables
        print("\nCreating database tables...")
        Base.metadata.create_all(bind=engine)
        
        print("\n✓ Database initialized successfully!")
        print("  Database file: vulnscanner.db")
        print("\nTables created:")
        print("  - scans (store scan results)")
        print("  - vulnerabilities (store found vulnerabilities)")
        print("  - scheduled_scans (store scheduled scans)")
        
    except Exception as e:
        print(f"\n✗ Error initializing database: {e}")
        sys.exit(1)
    
    print("\n" + "=" * 50)

if __name__ == "__main__":
    asyncio.run(main())