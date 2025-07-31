"""
Universal AI Governor Python Client

Provides async HTTP client for interacting with the Universal AI Governor API.
"""

import asyncio
from typing import List, Optional, Dict, Any
import httpx
from .models import Policy, User, AuditLog


class GovernorClient:
    """Async client for Universal AI Governor API"""
    
    def __init__(self, base_url: str, api_key: Optional[str] = None):
        """
        Initialize the client
        
        Args:
            base_url: Base URL of the Universal AI Governor API
            api_key: Optional API key for authentication
        """
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
            
        self.client = httpx.AsyncClient(
            base_url=self.base_url,
            headers=headers,
            timeout=30.0
        )
    
    async def __aenter__(self):
        """Async context manager entry"""
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.client.aclose()
    
    async def close(self):
        """Close the HTTP client"""
        await self.client.aclose()
    
    async def health_check(self) -> Dict[str, Any]:
        """Check the health of the API service"""
        response = await self.client.get("/health")
        response.raise_for_status()
        return response.json()
    
    async def get_policies(self) -> List[Policy]:
        """Get all policies"""
        response = await self.client.get("/api/v1/policies")
        response.raise_for_status()
        data = response.json()
        return [Policy(**item) for item in data]
    
    async def create_policy(self, policy: Policy) -> Policy:
        """Create a new policy"""
        response = await self.client.post(
            "/api/v1/policies",
            json=policy.dict(exclude={'id'})
        )
        response.raise_for_status()
        data = response.json()
        return Policy(**data)
    
    async def get_policy(self, policy_id: str) -> Policy:
        """Get a specific policy by ID"""
        response = await self.client.get(f"/api/v1/policies/{policy_id}")
        response.raise_for_status()
        data = response.json()
        return Policy(**data)
    
    async def update_policy(self, policy_id: str, policy: Policy) -> Policy:
        """Update an existing policy"""
        response = await self.client.put(
            f"/api/v1/policies/{policy_id}",
            json=policy.dict(exclude={'id'})
        )
        response.raise_for_status()
        data = response.json()
        return Policy(**data)
    
    async def delete_policy(self, policy_id: str) -> bool:
        """Delete a policy"""
        response = await self.client.delete(f"/api/v1/policies/{policy_id}")
        response.raise_for_status()
        return response.status_code == 204
    
    async def get_users(self) -> List[User]:
        """Get all users"""
        response = await self.client.get("/api/v1/users")
        response.raise_for_status()
        data = response.json()
        return [User(**item) for item in data]
    
    async def get_user(self, user_id: str) -> User:
        """Get a specific user by ID"""
        response = await self.client.get(f"/api/v1/users/{user_id}")
        response.raise_for_status()
        data = response.json()
        return User(**data)
    
    async def create_user(self, user: User) -> User:
        """Create a new user"""
        response = await self.client.post(
            "/api/v1/users",
            json=user.dict(exclude={'id'})
        )
        response.raise_for_status()
        data = response.json()
        return User(**data)
    
    async def get_audit_logs(self, limit: Optional[int] = None) -> List[AuditLog]:
        """Get audit logs"""
        params = {}
        if limit:
            params['limit'] = limit
            
        response = await self.client.get("/api/v1/audit", params=params)
        response.raise_for_status()
        data = response.json()
        return [AuditLog(**item) for item in data]
    
    async def search_audit_logs(
        self, 
        user_id: Optional[str] = None,
        action: Optional[str] = None,
        resource: Optional[str] = None,
        limit: Optional[int] = None
    ) -> List[AuditLog]:
        """Search audit logs with filters"""
        params = {}
        if user_id:
            params['user_id'] = user_id
        if action:
            params['action'] = action
        if resource:
            params['resource'] = resource
        if limit:
            params['limit'] = limit
            
        response = await self.client.get("/api/v1/audit/search", params=params)
        response.raise_for_status()
        data = response.json()
        return [AuditLog(**item) for item in data]
