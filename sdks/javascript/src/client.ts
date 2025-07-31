/**
 * Universal AI Governor JavaScript Client
 * 
 * HTTP client for interacting with the Universal AI Governor API
 */

import axios, { AxiosInstance, AxiosRequestConfig, InternalAxiosRequestConfig } from 'axios';
import { Policy, User, AuditLog, HealthStatus } from './models';

export interface ClientConfig {
    baseURL: string;
    apiKey?: string;
    timeout?: number;
}

export class GovernorClient {
    private client: AxiosInstance;

    constructor(baseURL: string, apiKey?: string, config?: Partial<ClientConfig>) {
        const headers: Record<string, string> = {
            'Content-Type': 'application/json',
        };

        if (apiKey) {
            headers['Authorization'] = `Bearer ${apiKey}`;
        }

        this.client = axios.create({
            baseURL: baseURL.replace(/\/$/, ''),
            headers,
            timeout: config?.timeout || 30000,
        });
    }

    /**
     * Check the health of the API service
     */
    async healthCheck(): Promise<HealthStatus> {
        const response = await this.client.get<HealthStatus>('/health');
        return response.data;
    }

    /**
     * Get all policies
     */
    async getPolicies(): Promise<Policy[]> {
        const response = await this.client.get<Policy[]>('/api/v1/policies');
        return response.data;
    }

    /**
     * Create a new policy
     */
    async createPolicy(policy: Omit<Policy, 'id'>): Promise<Policy> {
        const response = await this.client.post<Policy>('/api/v1/policies', policy);
        return response.data;
    }

    /**
     * Get a specific policy by ID
     */
    async getPolicy(policyId: string): Promise<Policy> {
        const response = await this.client.get<Policy>(`/api/v1/policies/${policyId}`);
        return response.data;
    }

    /**
     * Update an existing policy
     */
    async updatePolicy(policyId: string, policy: Partial<Policy>): Promise<Policy> {
        const response = await this.client.put<Policy>(`/api/v1/policies/${policyId}`, policy);
        return response.data;
    }

    /**
     * Delete a policy
     */
    async deletePolicy(policyId: string): Promise<boolean> {
        const response = await this.client.delete(`/api/v1/policies/${policyId}`);
        return response.status === 204;
    }

    /**
     * Get all users
     */
    async getUsers(): Promise<User[]> {
        const response = await this.client.get<User[]>('/api/v1/users');
        return response.data;
    }

    /**
     * Get a specific user by ID
     */
    async getUser(userId: string): Promise<User> {
        const response = await this.client.get<User>(`/api/v1/users/${userId}`);
        return response.data;
    }

    /**
     * Create a new user
     */
    async createUser(user: Omit<User, 'id'>): Promise<User> {
        const response = await this.client.post<User>('/api/v1/users', user);
        return response.data;
    }

    /**
     * Get audit logs
     */
    async getAuditLogs(limit?: number): Promise<AuditLog[]> {
        const params: Record<string, any> = {};
        if (limit) {
            params.limit = limit;
        }

        const response = await this.client.get<AuditLog[]>('/api/v1/audit', { params });
        return response.data;
    }

    /**
     * Search audit logs with filters
     */
    async searchAuditLogs(filters: {
        userId?: string;
        action?: string;
        resource?: string;
        limit?: number;
    }): Promise<AuditLog[]> {
        const params: Record<string, any> = {};
        
        if (filters.userId) params.user_id = filters.userId;
        if (filters.action) params.action = filters.action;
        if (filters.resource) params.resource = filters.resource;
        if (filters.limit) params.limit = filters.limit;

        const response = await this.client.get<AuditLog[]>('/api/v1/audit/search', { params });
        return response.data;
    }

    /**
     * Add request interceptor
     */
    addRequestInterceptor(
        onFulfilled?: (value: InternalAxiosRequestConfig) => InternalAxiosRequestConfig | Promise<InternalAxiosRequestConfig>,
        onRejected?: (error: any) => any
    ): number {
        return this.client.interceptors.request.use(onFulfilled, onRejected);
    }

    /**
     * Add response interceptor
     */
    addResponseInterceptor(
        onFulfilled?: (value: any) => any | Promise<any>,
        onRejected?: (error: any) => any
    ): number {
        return this.client.interceptors.response.use(onFulfilled, onRejected);
    }
}
