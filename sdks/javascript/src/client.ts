/**
 * Universal AI Governor JavaScript Client
 * 
 * Main client class for interacting with the AI Governor API.
 */

import axios, { AxiosInstance } from 'axios';
import { Policy, User, AuditLog } from './models';

export class GovernorClient {
    private client: AxiosInstance;

    constructor(baseUrl: string, apiKey?: string) {
        this.client = axios.create({
            baseURL: baseUrl.replace(/\/$/, ''),
            headers: apiKey ? { 'Authorization': `Bearer ${apiKey}` } : {}
        });
    }

    async getPolicies(): Promise<Policy[]> {
        const response = await this.client.get('/api/v1/policies');
        return response.data;
    }

    async createPolicy(policy: Omit<Policy, 'id' | 'created_at' | 'updated_at'>): Promise<Policy> {
        const response = await this.client.post('/api/v1/policies', policy);
        return response.data;
    }

    async getAuditLogs(): Promise<AuditLog[]> {
        const response = await this.client.get('/api/v1/audit');
        return response.data;
    }

    async getUsers(): Promise<User[]> {
        const response = await this.client.get('/api/v1/users');
        return response.data;
    }
}
