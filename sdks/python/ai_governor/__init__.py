"""
Universal AI Governor Python SDK

A comprehensive Python SDK for interacting with the Universal AI Governor service.
Supports all major Python versions and provides both synchronous and asynchronous APIs.
"""

__version__ = "1.0.0"
__author__ = "Universal AI Governor Team"
__email__ = "team@example.com"

from .client import GovernorClient, AsyncGovernorClient
from .types import (
    GovernanceRequest,
    GovernanceResponse,
    ResponseStatus,
    LLMRequest,
    LLMResponse,
    ModerationResult,
    PolicyResult,
    GuardrailResult,
    HealthStatus,
    MetricsSnapshot,
    GovernanceError,
    ValidationError,
)
from .config import ClientConfig
from .exceptions import (
    GovernorException,
    ConnectionError,
    AuthenticationError,
    RateLimitError,
    ValidationError as SDKValidationError,
    TimeoutError,
)

__all__ = [
    # Main client classes
    "GovernorClient",
    "AsyncGovernorClient",
    
    # Data types
    "GovernanceRequest",
    "GovernanceResponse",
    "ResponseStatus",
    "LLMRequest", 
    "LLMResponse",
    "ModerationResult",
    "PolicyResult",
    "GuardrailResult",
    "HealthStatus",
    "MetricsSnapshot",
    "GovernanceError",
    "ValidationError",
    
    # Configuration
    "ClientConfig",
    
    # Exceptions
    "GovernorException",
    "ConnectionError",
    "AuthenticationError", 
    "RateLimitError",
    "SDKValidationError",
    "TimeoutError",
]

# Version info
VERSION_INFO = tuple(map(int, __version__.split('.')))

def get_version():
    """Return the version string."""
    return __version__

def get_version_info():
    """Return the version info tuple."""
    return VERSION_INFO
