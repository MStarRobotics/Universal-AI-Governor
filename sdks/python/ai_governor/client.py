"""
Universal AI Governor Python Client

Main client class for interacting with the AI Governor API.
"""

import httpx
from typing import Optional, Dict, Any, List
from .models import Policy, User, AuditLog


class GovernorClient:
    """Client for Universal AI Governor API"""
    
    def __init__(self, base_url: str, api_key: Optional[str] = None):
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.client = httpx.AsyncClient()
        
    async def get_policies(self) -> List[Policy]:
        """Get all policies"""
        response = await self.client.get(f"{self.base_url}/api/v1/policies")
        response.raise_for_status()
        return [Policy(**policy) for policy in response.json()]
        
    async def create_policy(self, policy: Policy) -> Policy:
        """Create a new policy"""
        response = await self.client.post(
            f"{self.base_url}/api/v1/policies",
            json=policy.dict()
        )
        response.raise_for_status()
        return Policy(**response.json())
        
    async def get_audit_logs(self) -> List[AuditLog]:
        """Get audit logs"""
        response = await self.client.get(f"{self.base_url}/api/v1/audit")
        response.raise_for_status()
        return [AuditLog(**log) for log in response.json()]
