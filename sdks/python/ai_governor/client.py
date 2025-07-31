"""
Universal AI Governor Python Client

Provides both synchronous and asynchronous clients for interacting with the
Universal AI Governor service.
"""

import json
import time
import uuid
from typing import Dict, List, Optional, Union, Any
from urllib.parse import urljoin

import requests
import aiohttp
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .types import (
    GovernanceRequest,
    GovernanceResponse,
    ResponseStatus,
    HealthStatus,
    MetricsSnapshot,
)
from .config import ClientConfig
from .exceptions import (
    GovernorException,
    ConnectionError,
    AuthenticationError,
    RateLimitError,
    ValidationError,
    TimeoutError,
)


class GovernorClient:
    """
    Synchronous client for the Universal AI Governor service.
    
    This client provides a simple interface for sending governance requests,
    checking health status, retrieving metrics, and managing policies.
    """
    
    def __init__(self, config: Optional[ClientConfig] = None):
        """
        Initialize the Governor client.
        
        Args:
            config: Client configuration. If None, uses default configuration.
        """
        self.config = config or ClientConfig()
        self.session = requests.Session()
        
        # Configure retries
        retry_strategy = Retry(
            total=self.config.max_retries,
            backoff_factor=self.config.retry_backoff,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Set default headers
        self.session.headers.update({
            "Content-Type": "application/json",
            "User-Agent": f"ai-governor-python-sdk/{self.config.version}",
        })
        
        # Set authentication if provided
        if self.config.api_key:
            self.session.headers["Authorization"] = f"Bearer {self.config.api_key}"
        elif self.config.auth_token:
            self.session.headers["Authorization"] = f"Token {self.config.auth_token}"
    
    def process_request(
        self,
        prompt: str,
        user_id: str,
        context: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        llm_adapter: Optional[str] = None,
        llm_options: Optional[Dict[str, Any]] = None,
        request_id: Optional[str] = None,
    ) -> GovernanceResponse:
        """
        Process a governance request.
        
        Args:
            prompt: The input prompt to process
            user_id: ID of the user making the request
            context: Additional context for the request
            metadata: Request metadata
            llm_adapter: Name of the LLM adapter to use
            llm_options: Options for the LLM adapter
            request_id: Optional request ID (generated if not provided)
            
        Returns:
            GovernanceResponse: The governance response
            
        Raises:
            ValidationError: If request validation fails
            ConnectionError: If connection to service fails
            AuthenticationError: If authentication fails
            RateLimitError: If rate limit is exceeded
            TimeoutError: If request times out
            GovernorException: For other service errors
        """
        if not prompt:
            raise ValidationError("Prompt cannot be empty")
        if not user_id:
            raise ValidationError("User ID cannot be empty")
        
        request = GovernanceRequest(
            request_id=request_id or str(uuid.uuid4()),
            prompt=prompt,
            user_id=user_id,
            context=context or {},
            metadata=metadata or {},
            llm_adapter=llm_adapter,
            llm_options=llm_options or {},
        )
        
        return self._make_request("POST", "/api/v1/governance/process", request.dict())
    
    def validate_input(
        self,
        prompt: str,
        user_id: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Validate input without processing through LLM.
        
        Args:
            prompt: The input prompt to validate
            user_id: ID of the user making the request
            context: Additional context for validation
            
        Returns:
            Dict containing validation results
        """
        if not prompt:
            raise ValidationError("Prompt cannot be empty")
        if not user_id:
            raise ValidationError("User ID cannot be empty")
        
        data = {
            "prompt": prompt,
            "user_id": user_id,
            "context": context or {},
        }
        
        return self._make_request("POST", "/api/v1/governance/validate", data)
    
    def batch_process(
        self,
        requests: List[GovernanceRequest],
    ) -> List[GovernanceResponse]:
        """
        Process multiple governance requests in a single call.
        
        Args:
            requests: List of governance requests to process
            
        Returns:
            List of governance responses
        """
        if not requests:
            raise ValidationError("Requests list cannot be empty")
        if len(requests) > self.config.max_batch_size:
            raise ValidationError(f"Batch size exceeds maximum of {self.config.max_batch_size}")
        
        data = {
            "requests": [req.dict() for req in requests]
        }
        
        response = self._make_request("POST", "/api/v1/governance/batch", data)
        return [GovernanceResponse(**resp) for resp in response["responses"]]
    
    def get_health(self, detailed: bool = False) -> HealthStatus:
        """
        Get service health status.
        
        Args:
            detailed: Whether to return detailed health information
            
        Returns:
            HealthStatus: Current health status
        """
        params = {"detailed": "true"} if detailed else {}
        response = self._make_request("GET", "/api/v1/system/health", params=params)
        return HealthStatus(**response)
    
    def get_metrics(self) -> MetricsSnapshot:
        """
        Get service metrics.
        
        Returns:
            MetricsSnapshot: Current metrics snapshot
        """
        response = self._make_request("GET", "/api/v1/system/metrics")
        return MetricsSnapshot(**response)
    
    def get_llm_adapters(self) -> List[str]:
        """
        Get list of available LLM adapters.
        
        Returns:
            List of adapter names
        """
        response = self._make_request("GET", "/api/v1/llm/adapters")
        return response["adapters"]
    
    def get_policies(self) -> List[Dict[str, Any]]:
        """
        Get list of active policies.
        
        Returns:
            List of policy documents
        """
        response = self._make_request("GET", "/api/v1/policies")
        return response["policies"]
    
    def create_policy(self, policy: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create a new policy.
        
        Args:
            policy: Policy document
            
        Returns:
            Created policy information
        """
        return self._make_request("POST", "/api/v1/policies", policy)
    
    def update_policy(self, policy_id: str, policy: Dict[str, Any]) -> Dict[str, Any]:
        """
        Update an existing policy.
        
        Args:
            policy_id: ID of the policy to update
            policy: Updated policy document
            
        Returns:
            Updated policy information
        """
        return self._make_request("PUT", f"/api/v1/policies/{policy_id}", policy)
    
    def delete_policy(self, policy_id: str) -> Dict[str, Any]:
        """
        Delete a policy.
        
        Args:
            policy_id: ID of the policy to delete
            
        Returns:
            Deletion confirmation
        """
        return self._make_request("DELETE", f"/api/v1/policies/{policy_id}")
    
    def get_audit_logs(
        self,
        page: int = 1,
        limit: int = 50,
        user_id: Optional[str] = None,
        status: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Get audit logs with pagination.
        
        Args:
            page: Page number (1-based)
            limit: Number of logs per page
            user_id: Filter by user ID
            status: Filter by status
            
        Returns:
            Paginated audit logs
        """
        params = {"page": page, "limit": limit}
        if user_id:
            params["user_id"] = user_id
        if status:
            params["status"] = status
        
        return self._make_request("GET", "/api/v1/audit/logs", params=params)
    
    def _make_request(
        self,
        method: str,
        endpoint: str,
        data: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> Any:
        """
        Make an HTTP request to the Governor service.
        
        Args:
            method: HTTP method
            endpoint: API endpoint
            data: Request body data
            params: Query parameters
            
        Returns:
            Response data
            
        Raises:
            Various GovernorException subclasses based on error type
        """
        url = urljoin(self.config.base_url, endpoint)
        
        try:
            response = self.session.request(
                method=method,
                url=url,
                json=data,
                params=params,
                timeout=self.config.timeout,
                verify=self.config.verify_ssl,
            )
            
            # Handle different response status codes
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 401:
                raise AuthenticationError("Authentication failed")
            elif response.status_code == 403:
                # For governance requests, 403 means blocked
                if "governance" in endpoint:
                    return response.json()
                else:
                    raise AuthenticationError("Access forbidden")
            elif response.status_code == 429:
                raise RateLimitError("Rate limit exceeded")
            elif response.status_code >= 500:
                raise ConnectionError(f"Server error: {response.status_code}")
            else:
                error_data = response.json() if response.content else {}
                raise GovernorException(
                    f"Request failed with status {response.status_code}",
                    status_code=response.status_code,
                    error_data=error_data,
                )
                
        except requests.exceptions.Timeout:
            raise TimeoutError("Request timed out")
        except requests.exceptions.ConnectionError as e:
            raise ConnectionError(f"Connection failed: {e}")
        except requests.exceptions.RequestException as e:
            raise GovernorException(f"Request failed: {e}")
    
    def close(self):
        """Close the client session."""
        self.session.close()
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()


class AsyncGovernorClient:
    """
    Asynchronous client for the Universal AI Governor service.
    
    This client provides an async interface for sending governance requests,
    checking health status, retrieving metrics, and managing policies.
    """
    
    def __init__(self, config: Optional[ClientConfig] = None):
        """
        Initialize the async Governor client.
        
        Args:
            config: Client configuration. If None, uses default configuration.
        """
        self.config = config or ClientConfig()
        self.session: Optional[aiohttp.ClientSession] = None
    
    async def __aenter__(self):
        """Async context manager entry."""
        await self._ensure_session()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()
    
    async def _ensure_session(self):
        """Ensure the aiohttp session is created."""
        if self.session is None:
            headers = {
                "Content-Type": "application/json",
                "User-Agent": f"ai-governor-python-sdk/{self.config.version}",
            }
            
            if self.config.api_key:
                headers["Authorization"] = f"Bearer {self.config.api_key}"
            elif self.config.auth_token:
                headers["Authorization"] = f"Token {self.config.auth_token}"
            
            timeout = aiohttp.ClientTimeout(total=self.config.timeout)
            connector = aiohttp.TCPConnector(verify_ssl=self.config.verify_ssl)
            
            self.session = aiohttp.ClientSession(
                headers=headers,
                timeout=timeout,
                connector=connector,
            )
    
    async def process_request(
        self,
        prompt: str,
        user_id: str,
        context: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        llm_adapter: Optional[str] = None,
        llm_options: Optional[Dict[str, Any]] = None,
        request_id: Optional[str] = None,
    ) -> GovernanceResponse:
        """
        Process a governance request asynchronously.
        
        Args:
            prompt: The input prompt to process
            user_id: ID of the user making the request
            context: Additional context for the request
            metadata: Request metadata
            llm_adapter: Name of the LLM adapter to use
            llm_options: Options for the LLM adapter
            request_id: Optional request ID (generated if not provided)
            
        Returns:
            GovernanceResponse: The governance response
        """
        if not prompt:
            raise ValidationError("Prompt cannot be empty")
        if not user_id:
            raise ValidationError("User ID cannot be empty")
        
        request = GovernanceRequest(
            request_id=request_id or str(uuid.uuid4()),
            prompt=prompt,
            user_id=user_id,
            context=context or {},
            metadata=metadata or {},
            llm_adapter=llm_adapter,
            llm_options=llm_options or {},
        )
        
        response = await self._make_request("POST", "/api/v1/governance/process", request.dict())
        return GovernanceResponse(**response)
    
    async def validate_input(
        self,
        prompt: str,
        user_id: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Validate input without processing through LLM asynchronously.
        
        Args:
            prompt: The input prompt to validate
            user_id: ID of the user making the request
            context: Additional context for validation
            
        Returns:
            Dict containing validation results
        """
        if not prompt:
            raise ValidationError("Prompt cannot be empty")
        if not user_id:
            raise ValidationError("User ID cannot be empty")
        
        data = {
            "prompt": prompt,
            "user_id": user_id,
            "context": context or {},
        }
        
        return await self._make_request("POST", "/api/v1/governance/validate", data)
    
    async def batch_process(
        self,
        requests: List[GovernanceRequest],
    ) -> List[GovernanceResponse]:
        """
        Process multiple governance requests in a single call asynchronously.
        
        Args:
            requests: List of governance requests to process
            
        Returns:
            List of governance responses
        """
        if not requests:
            raise ValidationError("Requests list cannot be empty")
        if len(requests) > self.config.max_batch_size:
            raise ValidationError(f"Batch size exceeds maximum of {self.config.max_batch_size}")
        
        data = {
            "requests": [req.dict() for req in requests]
        }
        
        response = await self._make_request("POST", "/api/v1/governance/batch", data)
        return [GovernanceResponse(**resp) for resp in response["responses"]]
    
    async def get_health(self, detailed: bool = False) -> HealthStatus:
        """
        Get service health status asynchronously.
        
        Args:
            detailed: Whether to return detailed health information
            
        Returns:
            HealthStatus: Current health status
        """
        params = {"detailed": "true"} if detailed else {}
        response = await self._make_request("GET", "/api/v1/system/health", params=params)
        return HealthStatus(**response)
    
    async def get_metrics(self) -> MetricsSnapshot:
        """
        Get service metrics asynchronously.
        
        Returns:
            MetricsSnapshot: Current metrics snapshot
        """
        response = await self._make_request("GET", "/api/v1/system/metrics")
        return MetricsSnapshot(**response)
    
    async def get_llm_adapters(self) -> List[str]:
        """
        Get list of available LLM adapters asynchronously.
        
        Returns:
            List of adapter names
        """
        response = await self._make_request("GET", "/api/v1/llm/adapters")
        return response["adapters"]
    
    async def _make_request(
        self,
        method: str,
        endpoint: str,
        data: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> Any:
        """
        Make an async HTTP request to the Governor service.
        
        Args:
            method: HTTP method
            endpoint: API endpoint
            data: Request body data
            params: Query parameters
            
        Returns:
            Response data
        """
        await self._ensure_session()
        url = urljoin(self.config.base_url, endpoint)
        
        try:
            async with self.session.request(
                method=method,
                url=url,
                json=data,
                params=params,
            ) as response:
                
                # Handle different response status codes
                if response.status == 200:
                    return await response.json()
                elif response.status == 401:
                    raise AuthenticationError("Authentication failed")
                elif response.status == 403:
                    # For governance requests, 403 means blocked
                    if "governance" in endpoint:
                        return await response.json()
                    else:
                        raise AuthenticationError("Access forbidden")
                elif response.status == 429:
                    raise RateLimitError("Rate limit exceeded")
                elif response.status >= 500:
                    raise ConnectionError(f"Server error: {response.status}")
                else:
                    try:
                        error_data = await response.json()
                    except:
                        error_data = {}
                    raise GovernorException(
                        f"Request failed with status {response.status}",
                        status_code=response.status,
                        error_data=error_data,
                    )
                    
        except aiohttp.ClientTimeout:
            raise TimeoutError("Request timed out")
        except aiohttp.ClientError as e:
            raise ConnectionError(f"Connection failed: {e}")
    
    async def close(self):
        """Close the async client session."""
        if self.session:
            await self.session.close()
            self.session = None
