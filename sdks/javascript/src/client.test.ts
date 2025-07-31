/**
 * Tests for Universal AI Governor JavaScript Client
 */

import { GovernorClient } from './client';
import { Policy, User, AuditLog } from './models';
import axios from 'axios';

// Mock axios
jest.mock('axios');
const mockedAxios = axios as jest.Mocked<typeof axios>;

describe('GovernorClient', () => {
    let client: GovernorClient;
    let mockAxiosInstance: any;

    beforeEach(() => {
        mockAxiosInstance = {
            get: jest.fn(),
            post: jest.fn(),
        };
        mockedAxios.create.mockReturnValue(mockAxiosInstance);
        client = new GovernorClient('http://localhost:8080', 'test-api-key');
    });

    afterEach(() => {
        jest.clearAllMocks();
    });

    test('should initialize client correctly', () => {
        expect(mockedAxios.create).toHaveBeenCalledWith({
            baseURL: 'http://localhost:8080',
            headers: { 
                'Authorization': 'Bearer test-api-key',
                'Content-Type': 'application/json'
            },
            timeout: 30000
        });
    });

    test('should get policies', async () => {
        const mockPolicies: Policy[] = [
            {
                id: '1',
                name: 'Test Policy',
                description: 'A test policy',
                rules: { max_tokens: 1000 },
                enabled: true
            }
        ];

        mockAxiosInstance.get.mockResolvedValue({ data: mockPolicies });

        const policies = await client.getPolicies();

        expect(mockAxiosInstance.get).toHaveBeenCalledWith('/api/v1/policies');
        expect(policies).toEqual(mockPolicies);
    });

    test('should create policy', async () => {
        const newPolicy = {
            name: 'New Policy',
            description: 'A new policy',
            rules: { max_tokens: 2000 },
            enabled: true
        };

        const createdPolicy: Policy = {
            id: '2',
            ...newPolicy
        };

        mockAxiosInstance.post.mockResolvedValue({ data: createdPolicy });

        const result = await client.createPolicy(newPolicy);

        expect(mockAxiosInstance.post).toHaveBeenCalledWith('/api/v1/policies', newPolicy);
        expect(result).toEqual(createdPolicy);
    });

    test('should get audit logs', async () => {
        const mockLogs: AuditLog[] = [
            {
                id: '1',
                user_id: 'user1',
                action: 'login',
                resource: 'system',
                details: {},
                timestamp: '2024-01-01T00:00:00Z'
            }
        ];

        mockAxiosInstance.get.mockResolvedValue({ data: mockLogs });

        const logs = await client.getAuditLogs();

        expect(mockAxiosInstance.get).toHaveBeenCalledWith('/api/v1/audit', { params: {} });
        expect(logs).toEqual(mockLogs);
    });

    test('should get users', async () => {
        const mockUsers: User[] = [
            {
                id: '1',
                username: 'testuser',
                email: 'test@example.com',
                roles: ['admin']
            }
        ];

        mockAxiosInstance.get.mockResolvedValue({ data: mockUsers });

        const users = await client.getUsers();

        expect(mockAxiosInstance.get).toHaveBeenCalledWith('/api/v1/users');
        expect(users).toEqual(mockUsers);
    });
});
