"""Tests for the Universal AI Governor Python models"""

import pytest
from datetime import datetime
from ai_governor.models import Policy, User, AuditLog


def test_policy_model():
    """Test Policy model"""
    policy = Policy(
        id="1",
        name="Test Policy",
        description="A test policy",
        rules={"max_tokens": 1000},
        enabled=True
    )
    
    assert policy.id == "1"
    assert policy.name == "Test Policy"
    assert policy.description == "A test policy"
    assert policy.rules["max_tokens"] == 1000
    assert policy.enabled is True


def test_user_model():
    """Test User model"""
    user = User(
        id="1",
        username="testuser",
        email="test@example.com",
        roles=["admin", "user"]
    )
    
    assert user.id == "1"
    assert user.username == "testuser"
    assert user.email == "test@example.com"
    assert "admin" in user.roles
    assert "user" in user.roles


def test_audit_log_model():
    """Test AuditLog model"""
    timestamp = datetime.now()
    log = AuditLog(
        id="1",
        user_id="user1",
        action="login",
        resource="system",
        details={"ip": "127.0.0.1"},
        timestamp=timestamp,
        ip_address="127.0.0.1"
    )
    
    assert log.id == "1"
    assert log.user_id == "user1"
    assert log.action == "login"
    assert log.resource == "system"
    assert log.details["ip"] == "127.0.0.1"
    assert log.timestamp == timestamp
    assert log.ip_address == "127.0.0.1"


def test_policy_serialization():
    """Test Policy model serialization"""
    policy = Policy(
        name="Test Policy",
        description="A test policy",
        rules={"max_tokens": 1000},
        enabled=True
    )
    
    data = policy.dict()
    assert data["name"] == "Test Policy"
    assert data["rules"]["max_tokens"] == 1000
    assert data["enabled"] is True
