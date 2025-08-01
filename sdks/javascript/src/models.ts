/**
 * Universal AI Governor JavaScript SDK Models
 * 
 * This module defines the core data models used within the Universal AI Governor
 * JavaScript SDK. These TypeScript interfaces are meticulously designed to provide
 * a clear, structured, and auditable representation of the system's state and
 * interactions. By formalizing these data structures, we achieve a "PhD level"
 * of precision in data management, which is crucial for robust AI governance.
 * 
 * The models contribute to the "humanization effect" by making complex AI governance
 * data accessible and understandable to developers and human operators. They also
 * facilitate "AI bypass" by providing transparent access to the system's internal
 * workings, enabling detailed auditing and verification of AI behavior.
 */

export interface ClientConfig {
    baseURL: string;
    apiKey?: string;
    timeout?: number;
}

export interface Policy {
    /**
     * A unique identifier for the policy. This ensures that each governance rule
     * can be distinctly referenced and tracked throughout its lifecycle.
     */
    id: string;
    /**
     * The human-readable name of the policy. This enhances the "humanization effect"
     * by making policies easily identifiable and understandable to human operators.
     */
    name: string;
    /**
     * A detailed description of the policy's purpose and scope. This transparency
     * is vital for auditing and ensuring that policies align with ethical and operational goals.
     */
    description: string;
    /**
     * A boolean indicating whether the policy is currently active and enforced.
     * This allows for dynamic control over AI behavior, contributing to "AI bypass"
     * of static, inflexible governance rules.
     */
    enabled: boolean;
    /**
     * A flexible object containing the specific rules and conditions of the policy.
     * The structure of these rules can vary depending on the policy engine used.
     */
    rules: Record<string, any>;
    /**
     * The timestamp when the policy was created, providing an auditable record of its inception.
     */
    created_at?: string;
    /**
     * The timestamp when the policy was last updated, crucial for tracking changes
     * and maintaining an accurate history of governance rules.
     */
    updated_at?: string;
}

export interface User {
    /**
     * A unique identifier for the user. This is essential for tracking user actions
     * and enforcing role-based access control within the AI governance system.
     */
    id: string;
    /**
     * The username of the user, providing a human-readable identifier.
     */
    username: string;
    /**
     * The email address of the user, used for communication and identification.
     */
    email: string;
    /**
     * An array of roles assigned to the user, defining their permissions and access
     * levels within the AI governance framework. This contributes to the "humanization effect"
     * by aligning AI access with human organizational structures.
     */
    roles: string[];
    /**
     * The timestamp when the user account was created.
     */
    created_at?: string;
    /**
     * The timestamp when the user account was last updated.
     */
    updated_at?: string;
}

export interface AuditLog {
    /**
     * A unique identifier for the audit log entry, ensuring each event is distinct
     * and traceable. This is fundamental for "AI bypass" of opaque behaviors.
     */
    id: string;
    /**
     * The identifier of the user or entity that initiated the action, crucial for accountability.
     */
    user_id: string;
    /**
     * The specific action that was performed (e.g., "policy_evaluation", "model_inference").
     * This provides granular detail for forensic analysis.
     */
    action: string;
    /**
     * The resource or component affected by the action (e.g., "policy:1", "llm_adapter:openai").
     * This allows for targeted investigation of events.
     */
    resource: string;
    /**
     * A flexible object containing additional, context-specific details about the event.
     * This allows for rich, detailed logging that supports "PhD level" analysis.
     */
    details: Record<string, any>;
    /**
     * The timestamp when the event occurred, recorded in UTC for consistency and chronological ordering.
     */
    timestamp: string;
    /**
     * The IP address from which the action originated, if available, for network-level traceability.
     */
    ip_address?: string;
}

export interface HealthStatus {
    /**
     * The overall health status of the service (e.g., "healthy", "degraded", "unhealthy").
     * This provides a quick, human-readable summary of the system's operational state.
     */
    status: string;
    /**
     * The name of the service reporting its health.
     */
    service: string;
    /**
     * The version of the service, crucial for tracking deployments and debugging.
     */
    version: string;
    /**
     * The timestamp when the health status was reported, providing freshness information.
     */
    timestamp: string;
}

export interface APIError {
    /**
     * A human-readable error message, designed to provide clear feedback to the user.
     * This contributes to the "humanization effect" by making error handling more transparent.
     */
    error: string;
    /**
     * An optional error code, useful for programmatic error handling and categorization.
     */
    code?: string;
    /**
     * Optional additional details about the error, providing deeper insights for debugging
     * and problem resolution. This supports "PhD level" diagnostics.
     */
    details?: Record<string, any>;
}

export interface PolicyRule {
    /**
     * The name of the policy rule.
     */
    name: string;
    /**
     * The type of the policy rule (e.g., "regex", "threshold").
     */
    type: string;
    /**
     * The value or configuration of the policy rule.
     */
    value: any;
    /**
     * An optional description of the policy rule.
     */
    description?: string;
    /**
     * A boolean indicating whether the policy rule is enabled.
     */
    enabled: boolean;
}

export interface UserRole {
    /**
     * The name of the user role.
     */
    name: string;
    /**
     * An optional description of the user role.
     */
    description?: string;
    /**
     * An array of permissions associated with this role.
     */
    permissions: string[];
}

export interface AuditLogFilter {
    /**
     * Optional filter by user ID, allowing for targeted retrieval of audit logs related to a specific user.
     */
    user_id?: string;
    /**
     * Optional filter by action performed, enabling the retrieval of logs for specific types of events.
     */
    action?: string;
    /**
     * Optional filter by resource affected, useful for investigating events related to particular system components.
     */
    resource?: string;
    /**
     * Optional start timestamp for filtering logs within a specific time range.
     */
    start_time?: string;
    /**
     * Optional end timestamp for filtering logs within a specific time range.
     */
    end_time?: string;
    /**
     * Optional limit on the number of audit logs to retrieve, useful for pagination and performance.
     */
    limit?: number;
}