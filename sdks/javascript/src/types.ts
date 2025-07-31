/**
 * Universal AI Governor JavaScript SDK Types
 * 
 * Type definitions for the AI Governor API.
 */

export interface ApiResponse<T> {
    data: T;
    success: boolean;
    message?: string;
}

export interface PaginatedResponse<T> {
    data: T[];
    total: number;
    page: number;
    per_page: number;
}

export interface ErrorResponse {
    error: string;
    code: number;
    details?: Record<string, any>;
}
