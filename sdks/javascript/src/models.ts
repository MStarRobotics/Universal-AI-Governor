/**
 * Universal AI Governor JavaScript SDK Models
 * 
 * Data models for the AI Governor API.
 */

export interface Policy {
    id?: string;
    name: string;
    description: string;
    rules: Record<string, any>;
    enabled: boolean;
    created_at?: string;
    updated_at?: string;
}

export interface User {
    id?: string;
    username: string;
    email: string;
    roles: string[];
    created_at?: string;
    last_login?: string;
}

export interface AuditLog {
    id?: string;
    user_id: string;
    action: string;
    resource: string;
    details: Record<string, any>;
    timestamp: string;
    ip_address?: string;
}
