from sqlalchemy import Column, Integer, String, DateTime, JSON, Boolean, Text
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime

Base = declarative_base()

class Scan(Base):
    __tablename__ = 'scans'
    
    id = Column(Integer, primary_key=True)
    url = Column(String(500), nullable=False)
    status = Column(String(50), default='pending')
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime)
    vulnerabilities = Column(JSON, default=list)
    summary = Column(JSON, default=dict)
    user_email = Column(String(200))
    report_path = Column(String(500))

class Vulnerability(Base):
    __tablename__ = 'vulnerabilities'
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer)
    name = Column(String(200))
    severity = Column(String(50))  # Critical, High, Medium, Low
    description = Column(Text)
    remediation = Column(Text)
    discovered_at = Column(DateTime, default=datetime.utcnow)
    location = Column(String(500))

class ScheduledScan(Base):
    __tablename__ = 'scheduled_scans'
    
    id = Column(Integer, primary_key=True)
    url = Column(String(500))
    schedule_time = Column(DateTime)
    frequency = Column(String(50))  # daily, weekly, monthly
    last_run = Column(DateTime)
    next_run = Column(DateTime)
    active = Column(Boolean, default=True)

    # backend/database/models.py
from sqlalchemy import Column, Integer, String, DateTime, JSON, Boolean, Text
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime

Base = declarative_base()

class Scan(Base):
    __tablename__ = 'scans'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String(100), unique=True, nullable=False)
    url = Column(String(500), nullable=False)
    status = Column(String(50), default='pending')
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    vulnerabilities = Column(JSON, default=list)
    summary = Column(JSON, default=dict)
    user_email = Column(String(200), nullable=True)
    report_path = Column(String(500), nullable=True)
    progress = Column(Integer, default=0)

class Vulnerability(Base):
    __tablename__ = 'vulnerabilities'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, nullable=False)
    name = Column(String(200))
    severity = Column(String(50))  # Critical, High, Medium, Low
    description = Column(Text)
    remediation = Column(Text)
    discovered_at = Column(DateTime, default=datetime.utcnow)
    location = Column(String(500))
    details = Column(JSON, default=dict)

class ScheduledScan(Base):
    __tablename__ = 'scheduled_scans'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    url = Column(String(500))
    schedule_time = Column(DateTime)
    frequency = Column(String(50))  # daily, weekly, monthly
    last_run = Column(DateTime, nullable=True)
    next_run = Column(DateTime)
    active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)