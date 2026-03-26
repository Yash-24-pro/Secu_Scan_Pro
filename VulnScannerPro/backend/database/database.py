# backend/database/database.py
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.ext.declarative import declarative_base
import os
from typing import Generator
import logging

logger = logging.getLogger(__name__)

# Use SQLite for initial testing (no Redis/PostgreSQL required)
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./vulnscanner.db")

# Create engine
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {}
)

# Create SessionLocal
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Create Base
Base = declarative_base()

def get_db() -> Generator[Session, None, None]:
    """Get database session"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

async def init_db():
    """Initialize database - create all tables"""
    try:
        # Import all models here to ensure they are registered
        from backend.database import models
        
        # Create tables
        Base.metadata.create_all(bind=engine)
        logger.info("Database initialized successfully!")
        print("✓ Database tables created successfully")
        
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        print(f"✗ Database initialization failed: {e}")
        raise