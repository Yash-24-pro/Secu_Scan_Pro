# main.py
from run import app
import uvicorn

if __name__ == "__main__":
    uvicorn.run(
        "run:app",  # This enables reload to work properly
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )