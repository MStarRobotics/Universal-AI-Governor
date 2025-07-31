/**
 * Universal AI Governor JavaScript/TypeScript Client
 * 
 * Main client class for interacting with the Universal AI Governor service.
 * Supports both browser and Node.js environments.
 */

import axios, { AxiosInstance, AxiosRequestConfig, AxiosResponse } from 'axios';
import {
  GovernanceRequest,
  GovernanceResponse,
  HealthStatus,
  MetricsSnapshot,
  PolicyDocument,
  AuditLogEntry,
  BatchProcessRequest,
  BatchProcessResponse,
  ValidationRequest,
  ValidationResponse,
} from './types';
import { ClientConfig, defaultConfig } from './config';
import {
  GovernorError,
  ConnectionError,
  AuthenticationError,
  RateLimitError,
  ValidationError,
  TimeoutError,
} from './errors';
import { validateRequest, generateRequestId } from './utils';

/**
 * Main client class for the Universal AI Governor service
 */
export class GovernorClient {
  private readonly config: ClientConfig;
  private readonly httpClient: AxiosInstance;

  /**
   * Create a new Governor client instance
   * 
   * @param config - Client configuration options
   */
  constructor(config: Partial<ClientConfig> = {}) {
    this.config = { ...defaultConfig, ...config };
    
    // Create axios instance with default configuration
    this.httpClient = axios.create({
      baseURL: this.config.baseUrl,
      timeout: this.config.timeout,
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': `ai-governor-js-sdk/${this.config.version}`,
      },
    });

    // Add authentication if provided
    if (this.config.apiKey) {
      this.httpClient.defaults.headers.common['Authorization'] = `Bearer ${this.config.apiKey}`;
    } else if (this.config.authToken) {
      this.httpClient.defaults.headers.common['Authorization'] = `Token ${this.config.authToken}`;
    }

    // Add request interceptor for retry logic
    this.setupInterceptors();
  }

  /**
   * Process a governance request
   * 
   * @param request - The governance request to process
   * @returns Promise resolving to the governance response
   */
  async processRequest(request: GovernanceRequest): Promise<GovernanceResponse> {
    // Validate request
    const validationError = validateRequest(request);
    if (validationError) {
      throw new ValidationError(validationError);
    }

    // Generate request ID if not provided
    if (!request.requestId) {
      request.requestId = generateRequestId();
    }

    try {
      const response = await this.httpClient.post<GovernanceResponse>(
        '/api/v1/governance/process',
        request
      );
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Validate input without processing through LLM
   * 
   * @param request - The validation request
   * @returns Promise resolving to validation results
   */
  async validateInput(request: ValidationRequest): Promise<ValidationResponse> {
    if (!request.prompt) {
      throw new ValidationError('Prompt cannot be empty');
    }
    if (!request.userId) {
      throw new ValidationError('User ID cannot be empty');
    }

    try {
      const response = await this.httpClient.post<ValidationResponse>(
        '/api/v1/governance/validate',
        request
      );
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Process multiple governance requests in a batch
   * 
   * @param request - The batch process request
   * @returns Promise resolving to batch process response
   */
  async batchProcess(request: BatchProcessRequest): Promise<BatchProcessResponse> {
    if (!request.requests || request.requests.length === 0) {
      throw new ValidationError('Requests array cannot be empty');
    }
    if (request.requests.length > this.config.maxBatchSize) {
      throw new ValidationError(`Batch size exceeds maximum of ${this.config.maxBatchSize}`);
    }

    // Validate each request in the batch
    for (const req of request.requests) {
      const validationError = validateRequest(req);
      if (validationError) {
        throw new ValidationError(`Invalid request in batch: ${validationError}`);
      }
      
      // Generate request ID if not provided
      if (!req.requestId) {
        req.requestId = generateRequestId();
      }
    }

    try {
      const response = await this.httpClient.post<BatchProcessResponse>(
        '/api/v1/governance/batch',
        request
      );
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Get service health status
   * 
   * @param detailed - Whether to return detailed health information
   * @returns Promise resolving to health status
   */
  async getHealth(detailed: boolean = false): Promise<HealthStatus> {
    try {
      const response = await this.httpClient.get<HealthStatus>(
        '/api/v1/system/health',
        { params: { detailed: detailed.toString() } }
      );
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Get service metrics
   * 
   * @returns Promise resolving to metrics snapshot
   */
  async getMetrics(): Promise<MetricsSnapshot> {
    try {
      const response = await this.httpClient.get<MetricsSnapshot>('/api/v1/system/metrics');
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Get list of available LLM adapters
   * 
   * @returns Promise resolving to list of adapter names
   */
  async getLLMAdapters(): Promise<string[]> {
    try {
      const response = await this.httpClient.get<{ adapters: string[] }>('/api/v1/llm/adapters');
      return response.data.adapters;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Get list of active policies
   * 
   * @returns Promise resolving to list of policies
   */
  async getPolicies(): Promise<PolicyDocument[]> {
    try {
      const response = await this.httpClient.get<{ policies: PolicyDocument[] }>('/api/v1/policies');
      return response.data.policies;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Create a new policy
   * 
   * @param policy - The policy document to create
   * @returns Promise resolving to creation result
   */
  async createPolicy(policy: Omit<PolicyDocument, 'id' | 'createdAt' | 'updatedAt'>): Promise<{ message: string; policyId: string }> {
    if (!policy.name) {
      throw new ValidationError('Policy name is required');
    }

    try {
      const response = await this.httpClient.post<{ message: string; policy_id: string }>(
        '/api/v1/policies',
        policy
      );
      return {
        message: response.data.message,
        policyId: response.data.policy_id,
      };
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Update an existing policy
   * 
   * @param policyId - ID of the policy to update
   * @param policy - Updated policy document
   * @returns Promise resolving to update result
   */
  async updatePolicy(
    policyId: string,
    policy: Partial<Omit<PolicyDocument, 'id' | 'createdAt' | 'updatedAt'>>
  ): Promise<{ message: string; policyId: string }> {
    if (!policyId) {
      throw new ValidationError('Policy ID is required');
    }

    try {
      const response = await this.httpClient.put<{ message: string; policy_id: string }>(
        `/api/v1/policies/${policyId}`,
        policy
      );
      return {
        message: response.data.message,
        policyId: response.data.policy_id,
      };
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Delete a policy
   * 
   * @param policyId - ID of the policy to delete
   * @returns Promise resolving to deletion result
   */
  async deletePolicy(policyId: string): Promise<{ message: string; policyId: string }> {
    if (!policyId) {
      throw new ValidationError('Policy ID is required');
    }

    try {
      const response = await this.httpClient.delete<{ message: string; policy_id: string }>(
        `/api/v1/policies/${policyId}`
      );
      return {
        message: response.data.message,
        policyId: response.data.policy_id,
      };
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Get audit logs with pagination
   * 
   * @param options - Query options for audit logs
   * @returns Promise resolving to paginated audit logs
   */
  async getAuditLogs(options: {
    page?: number;
    limit?: number;
    userId?: string;
    status?: string;
  } = {}): Promise<{
    logs: AuditLogEntry[];
    page: number;
    limit: number;
    total: number;
    hasMore: boolean;
  }> {
    const params: Record<string, string> = {
      page: (options.page || 1).toString(),
      limit: (options.limit || 50).toString(),
    };

    if (options.userId) {
      params.user_id = options.userId;
    }
    if (options.status) {
      params.status = options.status;
    }

    try {
      const response = await this.httpClient.get<{
        logs: AuditLogEntry[];
        page: number;
        limit: number;
        total: number;
        has_more: boolean;
      }>('/api/v1/audit/logs', { params });

      return {
        logs: response.data.logs,
        page: response.data.page,
        limit: response.data.limit,
        total: response.data.total,
        hasMore: response.data.has_more,
      };
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Update service configuration at runtime
   * 
   * @param configUpdate - Configuration updates to apply
   * @returns Promise resolving to update result
   */
  async updateConfiguration(configUpdate: Record<string, any>): Promise<{ message: string; status: string }> {
    try {
      const response = await this.httpClient.put<{ message: string; status: string }>(
        '/api/v1/system/config',
        configUpdate
      );
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Get service version information
   * 
   * @returns Promise resolving to version info
   */
  async getVersion(): Promise<{
    version: string;
    buildTime: string;
    gitCommit: string;
    goVersion: string;
  }> {
    try {
      const response = await this.httpClient.get<{
        version: string;
        build_time: string;
        git_commit: string;
        go_version: string;
      }>('/api/v1/system/version');

      return {
        version: response.data.version,
        buildTime: response.data.build_time,
        gitCommit: response.data.git_commit,
        goVersion: response.data.go_version,
      };
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Setup axios interceptors for error handling and retries
   */
  private setupInterceptors(): void {
    // Request interceptor
    this.httpClient.interceptors.request.use(
      (config) => {
        // Add timestamp to requests
        config.metadata = { startTime: Date.now() };
        return config;
      },
      (error) => Promise.reject(error)
    );

    // Response interceptor
    this.httpClient.interceptors.response.use(
      (response) => {
        // Log response time if debugging is enabled
        if (this.config.debug) {
          const duration = Date.now() - (response.config.metadata?.startTime || 0);
          console.debug(`Request to ${response.config.url} took ${duration}ms`);
        }
        return response;
      },
      async (error) => {
        const originalRequest = error.config;

        // Retry logic for certain errors
        if (
          this.config.retryAttempts > 0 &&
          !originalRequest._retry &&
          this.shouldRetry(error)
        ) {
          originalRequest._retry = true;
          originalRequest._retryCount = (originalRequest._retryCount || 0) + 1;

          if (originalRequest._retryCount <= this.config.retryAttempts) {
            // Wait before retrying
            await this.delay(this.config.retryDelay * originalRequest._retryCount);
            return this.httpClient(originalRequest);
          }
        }

        return Promise.reject(error);
      }
    );
  }

  /**
   * Determine if a request should be retried
   */
  private shouldRetry(error: any): boolean {
    if (!error.response) {
      // Network errors should be retried
      return true;
    }

    const status = error.response.status;
    // Retry on server errors and rate limits
    return status >= 500 || status === 429;
  }

  /**
   * Delay execution for the specified number of milliseconds
   */
  private delay(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  /**
   * Handle and transform axios errors into appropriate GovernorError types
   */
  private handleError(error: any): GovernorError {
    if (axios.isAxiosError(error)) {
      if (!error.response) {
        // Network error
        return new ConnectionError('Network error: Unable to connect to the service');
      }

      const { status, data } = error.response;

      switch (status) {
        case 401:
          return new AuthenticationError('Authentication failed');
        case 403:
          // For governance endpoints, 403 might be a valid blocked response
          if (error.config?.url?.includes('/governance/')) {
            return new GovernorError('Request was blocked by governance policies', status, data);
          }
          return new AuthenticationError('Access forbidden');
        case 429:
          return new RateLimitError('Rate limit exceeded');
        case 408:
          return new TimeoutError('Request timed out');
        case 422:
          return new ValidationError(data?.message || 'Validation failed');
        default:
          if (status >= 500) {
            return new ConnectionError(`Server error: ${status}`);
          }
          return new GovernorError(
            data?.message || `Request failed with status ${status}`,
            status,
            data
          );
      }
    }

    // Non-axios error
    return new GovernorError(error.message || 'Unknown error occurred');
  }
}
