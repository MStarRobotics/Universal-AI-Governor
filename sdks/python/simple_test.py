#!/usr/bin/env python3
"""
Simple test runner for Universal AI Governor Python SDK
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from ai_governor.models import Policy, User, AuditLog
from datetime import datetime

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
    print("✓ Policy model test passed")

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
    print("✓ User model test passed")

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
    print("✓ AuditLog model test passed")

def main():
    """Run all tests"""
    print("Running Universal AI Governor Python SDK tests...")
    
    try:
        test_policy_model()
        test_user_model()
        test_audit_log_model()
        print("\n✅ All tests passed!")
        return 0
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
