"""
Universal AI Governor Python SDK Models

Pydantic models for API data structures.
"""

from datetime import datetime
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field


class Policy(BaseModel):
    """AI Governance Policy model"""
    
    id: Optional[str] = None
    name: str = Field(..., description="Policy name")
    description: str = Field(..., description="Policy description")
    enabled: bool = Field(default=True, description="Whether the policy is enabled")
    rules: Dict[str, Any] = Field(default_factory=dict, description="Policy rules")
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class User(BaseModel):
    """System User model"""
    
    id: Optional[str] = None
    username: str = Field(..., description="Username")
    email: str = Field(..., description="User email address")
    roles: List[str] = Field(default_factory=list, description="User roles")
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class AuditLog(BaseModel):
    """Audit Log Entry model"""
    
    id: Optional[str] = None
    user_id: str = Field(..., description="ID of the user who performed the action")
    action: str = Field(..., description="Action that was performed")
    resource: str = Field(..., description="Resource that was acted upon")
    details: Dict[str, Any] = Field(default_factory=dict, description="Additional details")
    timestamp: Optional[datetime] = None
    ip_address: Optional[str] = Field(None, description="IP address of the user")
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class HealthStatus(BaseModel):
    """Health Check Response model"""
    
    status: str = Field(..., description="Service status")
    service: str = Field(..., description="Service name")
    version: str = Field(..., description="Service version")
    timestamp: datetime = Field(..., description="Response timestamp")
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class APIError(BaseModel):
    """API Error Response model"""
    
    error: str = Field(..., description="Error message")
    code: Optional[str] = Field(None, description="Error code")
    details: Optional[Dict[str, Any]] = Field(None, description="Additional error details")


class PolicyRule(BaseModel):
    """Individual Policy Rule model"""
    
    name: str = Field(..., description="Rule name")
    type: str = Field(..., description="Rule type")
    value: Any = Field(..., description="Rule value")
    description: Optional[str] = Field(None, description="Rule description")
    enabled: bool = Field(default=True, description="Whether the rule is enabled")


class UserRole(BaseModel):
    """User Role model"""
    
    name: str = Field(..., description="Role name")
    description: Optional[str] = Field(None, description="Role description")
    permissions: List[str] = Field(default_factory=list, description="Role permissions")


class AuditLogFilter(BaseModel):
    """Audit Log Filter model for search queries"""
    
    user_id: Optional[str] = Field(None, description="Filter by user ID")
    action: Optional[str] = Field(None, description="Filter by action")
    resource: Optional[str] = Field(None, description="Filter by resource")
    start_time: Optional[datetime] = Field(None, description="Filter by start time")
    end_time: Optional[datetime] = Field(None, description="Filter by end time")
    limit: Optional[int] = Field(None, description="Limit number of results")
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }
