/**
 * Universal AI Governor JavaScript SDK Types
 * 
 * Additional TypeScript types and utilities
 */

export type PolicyStatus = 'enabled' | 'disabled' | 'draft';

export type UserRole = 'admin' | 'analyst' | 'user' | 'viewer';

export type AuditAction = 
    | 'login' 
    | 'logout' 
    | 'policy_create' 
    | 'policy_update' 
    | 'policy_delete' 
    | 'policy_view'
    | 'user_create'
    | 'user_update'
    | 'user_delete'
    | 'user_view';

export interface CreatePolicyRequest {
    name: string;
    description: string;
    enabled?: boolean;
    rules?: Record<string, any>;
}

export interface UpdatePolicyRequest {
    name?: string;
    description?: string;
    enabled?: boolean;
    rules?: Record<string, any>;
}

export interface CreateUserRequest {
    username: string;
    email: string;
    roles?: string[];
}

export interface UpdateUserRequest {
    username?: string;
    email?: string;
    roles?: string[];
}

export interface PaginationOptions {
    page?: number;
    limit?: number;
    sort?: string;
    order?: 'asc' | 'desc';
}

export interface SearchOptions extends PaginationOptions {
    query?: string;
    filters?: Record<string, any>;
}

export interface APIResponse<T> {
    data: T;
    message?: string;
    status: number;
}

export interface PaginatedResponse<T> extends APIResponse<T[]> {
    pagination: {
        page: number;
        limit: number;
        total: number;
        pages: number;
    };
}
