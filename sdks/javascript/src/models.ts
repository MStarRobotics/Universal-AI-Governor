/**
 * Universal AI Governor JavaScript SDK Models
 * 
 * TypeScript interfaces and types for API data structures
 */

export interface Policy {
    id: string;
    name: string;
    description: string;
    enabled: boolean;
    rules: Record<string, any>;
    created_at?: string;
    updated_at?: string;
}

export interface User {
    id: string;
    username: string;
    email: string;
    roles: string[];
    created_at?: string;
    updated_at?: string;
}

export interface AuditLog {
    id: string;
    user_id: string;
    action: string;
    resource: string;
    details: Record<string, any>;
    timestamp: string;
    ip_address?: string;
}

export interface HealthStatus {
    status: string;
    service: string;
    version: string;
    timestamp: string;
}

export interface APIError {
    error: string;
    code?: string;
    details?: Record<string, any>;
}

export interface PolicyRule {
    name: string;
    type: string;
    value: any;
    description?: string;
    enabled: boolean;
}

export interface UserRole {
    name: string;
    description?: string;
    permissions: string[];
}

export interface AuditLogFilter {
    user_id?: string;
    action?: string;
    resource?: string;
    start_time?: string;
    end_time?: string;
    limit?: number;
}
