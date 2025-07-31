"""Tests for the Universal AI Governor Python client"""

import pytest
from unittest.mock import AsyncMock, patch
from ai_governor.client import GovernorClient
from ai_governor.models import Policy, User, AuditLog


@pytest.mark.asyncio
async def test_client_initialization():
    """Test client initialization"""
    client = GovernorClient("http://localhost:8080", "test-api-key")
    assert client.base_url == "http://localhost:8080"
    assert client.api_key == "test-api-key"


@pytest.mark.asyncio
async def test_get_policies():
    """Test getting policies"""
    client = GovernorClient("http://localhost:8080")
    
    with patch.object(client.client, 'get') as mock_get:
        mock_response = AsyncMock()
        mock_response.json.return_value = [
            {
                "id": "1",
                "name": "Test Policy",
                "description": "A test policy",
                "rules": {},
                "enabled": True
            }
        ]
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response
        
        policies = await client.get_policies()
        assert len(policies) == 1
        assert policies[0].name == "Test Policy"


@pytest.mark.asyncio
async def test_create_policy():
    """Test creating a policy"""
    client = GovernorClient("http://localhost:8080")
    
    policy = Policy(
        name="New Policy",
        description="A new policy",
        rules={},
        enabled=True
    )
    
    with patch.object(client.client, 'post') as mock_post:
        mock_response = AsyncMock()
        mock_response.json.return_value = {
            "id": "2",
            "name": "New Policy",
            "description": "A new policy",
            "rules": {},
            "enabled": True
        }
        mock_response.raise_for_status.return_value = None
        mock_post.return_value = mock_response
        
        created_policy = await client.create_policy(policy)
        assert created_policy.id == "2"
        assert created_policy.name == "New Policy"


@pytest.mark.asyncio
async def test_get_audit_logs():
    """Test getting audit logs"""
    client = GovernorClient("http://localhost:8080")
    
    with patch.object(client.client, 'get') as mock_get:
        mock_response = AsyncMock()
        mock_response.json.return_value = [
            {
                "id": "1",
                "user_id": "user1",
                "action": "login",
                "resource": "system",
                "details": {},
                "timestamp": "2024-01-01T00:00:00Z"
            }
        ]
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response
        
        logs = await client.get_audit_logs()
        assert len(logs) == 1
        assert logs[0].action == "login"
