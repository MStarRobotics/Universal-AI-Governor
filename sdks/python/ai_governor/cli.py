"""
Command Line Interface for Universal AI Governor Python SDK
"""

import asyncio
import argparse
import json
from .client import GovernorClient


async def list_policies(client):
    """List all policies"""
    policies = await client.get_policies()
    for policy in policies:
        print(f"ID: {policy.id}, Name: {policy.name}, Enabled: {policy.enabled}")


async def list_users(client):
    """List all users"""
    users = await client.get_users()
    for user in users:
        print(f"ID: {user.id}, Username: {user.username}, Email: {user.email}")


async def list_audit_logs(client):
    """List audit logs"""
    logs = await client.get_audit_logs()
    for log in logs:
        print(f"ID: {log.id}, User: {log.user_id}, Action: {log.action}, Time: {log.timestamp}")


async def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(description="Universal AI Governor CLI")
    parser.add_argument("--url", default="http://localhost:8080", help="API base URL")
    parser.add_argument("--api-key", help="API key for authentication")
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Policies command
    subparsers.add_parser("policies", help="List policies")
    
    # Users command
    subparsers.add_parser("users", help="List users")
    
    # Audit logs command
    subparsers.add_parser("audit", help="List audit logs")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    client = GovernorClient(args.url, args.api_key)
    
    try:
        if args.command == "policies":
            await list_policies(client)
        elif args.command == "users":
            await list_users(client)
        elif args.command == "audit":
            await list_audit_logs(client)
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    asyncio.run(main())
