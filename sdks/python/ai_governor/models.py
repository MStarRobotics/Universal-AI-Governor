"""
Universal AI Governor Python SDK Models

Data models for the AI Governor API.
"""

from pydantic import BaseModel
from typing import Optional, Dict, Any, List
from datetime import datetime


class Policy(BaseModel):
    """AI Governance Policy model"""
    id: Optional[str] = None
    name: str
    description: str
    rules: Dict[str, Any]
    enabled: bool = True
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class User(BaseModel):
    """User model"""
    id: Optional[str] = None
    username: str
    email: str
    roles: List[str] = []
    created_at: Optional[datetime] = None
    last_login: Optional[datetime] = None


class AuditLog(BaseModel):
    """Audit log entry model"""
    id: Optional[str] = None
    user_id: str
    action: str
    resource: str
    details: Dict[str, Any] = {}
    timestamp: datetime
    ip_address: Optional[str] = None
