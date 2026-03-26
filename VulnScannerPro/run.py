# run.py
import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import uuid
import asyncio
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title="VulnScanner Pro",
    version="2.0.0",
    description="Advanced Web Vulnerability Scanner"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Models
class ScanRequest(BaseModel):
    url: str
    email: Optional[str] = None
    scheduled: bool = False
    schedule_time: Optional[str] = None

class ScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str

# In-memory storage for active scans (for testing)
active_scans = {}

# Routes
@app.get("/")
async def root():
    return {
        "message": "VulnScanner Pro API",
        "status": "running",
        "version": "2.0.0",
        "endpoints": [
            "/api/scan - Start a new scan",
            "/api/scan/{scan_id}/status - Get scan status",
            "/api/scans - List recent scans",
            "/docs - API Documentation"
        ]
    }

@app.post("/api/scan", response_model=ScanResponse)
async def start_scan(request: ScanRequest):
    """Start a new security scan"""
    try:
        scan_id = str(uuid.uuid4())[:8]
        
        # Validate URL
        if not request.url.startswith(('http://', 'https://')):
            request.url = 'https://' + request.url
        
        # Store scan info
        active_scans[scan_id] = {
            'id': scan_id,
            'url': request.url,
            'status': 'running',
            'progress': 0,
            'started_at': asyncio.get_event_loop().time()
        }
        
        # Start scan in background
        asyncio.create_task(run_scan_background(scan_id, request.url))
        
        logger.info(f"Scan started: {scan_id} for {request.url}")
        
        return ScanResponse(
            scan_id=scan_id,
            status="started",
            message=f"Scan started for {request.url}"
        )
        
    except Exception as e:
        logger.error(f"Error starting scan: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/scan/{scan_id}/status")
async def get_scan_status(scan_id: str):
    """Get scan status"""
    if scan_id in active_scans:
        return active_scans[scan_id]
    return {"status": "not_found", "scan_id": scan_id}

@app.get("/api/scans")
async def list_scans(limit: int = 10):
    """List recent scans"""
    scans = list(active_scans.values())
    return {"scans": scans[:limit], "total": len(scans)}

@app.get("/api/stats")
async def get_stats():
    """Get system statistics"""
    return {
        "totalScans": len(active_scans),
        "vulnerabilities": 0,
        "criticalVulns": 0,
        "highVulns": 0,
        "mediumVulns": 0,
        "lowVulns": 0,
        "averageScore": 100
    }

async def run_scan_background(scan_id: str, url: str):
    """Background task to run the scan"""
    try:
        # Simulate scan progress
        for progress in range(0, 101, 10):
            await asyncio.sleep(1)
            if scan_id in active_scans:
                active_scans[scan_id]['progress'] = progress
                logger.info(f"Scan {scan_id} progress: {progress}%")
        
        # Update status
        if scan_id in active_scans:
            active_scans[scan_id]['status'] = 'completed'
            active_scans[scan_id]['progress'] = 100
            
        logger.info(f"Scan {scan_id} completed for {url}")
        
    except Exception as e:
        logger.error(f"Scan {scan_id} failed: {e}")
        if scan_id in active_scans:
            active_scans[scan_id]['status'] = 'failed'
            active_scans[scan_id]['error'] = str(e)

if __name__ == "__main__":
    print("=" * 50)
    print("VulnScanner Pro Server")
    print("=" * 50)
    print("\nStarting server...")
    print("API Documentation: http://localhost:8000/docs")
    print("Health Check: http://localhost:8000/")
    print("\nPress Ctrl+C to stop the server")
    print("=" * 50)
    
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )