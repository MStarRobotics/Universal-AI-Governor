/**
 * Universal AI Governor JavaScript SDK Types
 * 
 * This module defines additional TypeScript types and utility interfaces for the
 * Universal AI Governor JavaScript SDK. These types are crafted to enhance the
 * clarity, precision, and maintainability of the SDK, contributing to a "PhD level"
 * of software engineering. By providing well-defined structures for various aspects
 * of AI governance, they facilitate the "humanization effect" by making complex
 * system interactions more understandable and manageable for developers.
 * They also support "AI bypass" by enabling precise control and interaction with
 * the governed AI system.
 */

/**
 * Defines the possible statuses for a policy within the AI Governor.
 * This type provides a clear, enumerated set of states, enhancing the readability
 * and predictability of policy management.
 */
export type PolicyStatus = 'enabled' | 'disabled' | 'draft';

/**
 * Defines the standard roles for users interacting with the AI Governor.
 * These roles are fundamental for implementing robust role-based access control (RBAC),
 * ensuring that human operators have appropriate permissions, thereby contributing
 * to the "humanization effect" by aligning system access with organizational structures.
 */
export type UserRole = 'admin' | 'analyst' | 'user' | 'viewer';

/**
 * Enumerates the various auditable actions that can occur within the AI Governor.
 * This comprehensive list ensures that all significant events are categorized and
 * traceable, which is crucial for forensic analysis, compliance, and achieving
 * "AI bypass" of opaque system behaviors through detailed audit trails.
 */
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

/**
 * Represents the structure for creating a new policy.
 * This interface ensures that all necessary information is provided for policy creation,
 * promoting data integrity and consistency within the governance framework.
 */
export interface CreatePolicyRequest {
    name: string;
    description: string;
    enabled?: boolean;
    rules?: Record<string, any>;
}

/**
 * Represents the structure for updating an existing policy.
 * This interface allows for partial updates, providing flexibility in modifying
 * governance rules without requiring all fields to be present.
 */
export interface UpdatePolicyRequest {
    name?: string;
    description?: string;
    enabled?: boolean;
    rules?: Record<string, any>;
}

/**
 * Represents the structure for creating a new user.
 * This interface ensures that essential user information is captured during registration,
 * supporting secure and auditable user management within the AI governance system.
 */
export interface CreateUserRequest {
    username: string;
    email: string;
    roles?: string[];
}

/**
 * Represents the structure for updating an existing user.
 * This interface allows for partial updates to user profiles, providing flexibility
 * in managing user information and roles.
 */
export interface UpdateUserRequest {
    username?: string;
    email?: string;
    roles?: string[];
}

/**
 * Defines options for pagination in API responses.
 * This interface enables efficient retrieval of large datasets by specifying page numbers,
 * limits, and sorting preferences, contributing to the scalability and usability of the API.
 */
export interface PaginationOptions {
    page?: number;
    limit?: number;
    sort?: string;
    order?: 'asc' | 'desc';
}

/**
 * Extends `PaginationOptions` with additional fields for search queries.
 * This interface allows for complex filtering and searching of data, providing powerful
 * capabilities for data analysis and investigation within the AI governance system.
 */
export interface SearchOptions extends PaginationOptions {
    query?: string;
    filters?: Record<string, any>;
}

/**
 * Represents a generic API response structure.
 * This interface provides a consistent format for all API responses, including the data payload,
 * an optional message, and the HTTP status code. This consistency enhances developer experience
 * and simplifies error handling.
 */
export interface APIResponse<T> {
    data: T;
    message?: string;
    status: number;
}

/**
 * Extends `APIResponse` to include pagination metadata for lists of data.
 * This interface is crucial for handling large collections of resources, providing clients
 * with the necessary information to navigate through paginated results efficiently.
 */
export interface PaginatedResponse<T> extends APIResponse<T[]> {
    pagination: {
        page: number;
        limit: number;
        total: number;
        pages: number;
    };
}
