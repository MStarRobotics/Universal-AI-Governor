# Universal AI Governor Python SDK

Python client library for the Universal AI Governor platform.

## Installation

```bash
pip install universal-ai-governor
```

## Usage

```python
from ai_governor import GovernorClient

# Initialize client
client = GovernorClient("http://localhost:8080", api_key="your-api-key")

# Get policies
policies = await client.get_policies()

# Create a new policy
policy = Policy(
    name="My Policy",
    description="A custom policy",
    rules={"max_tokens": 1000},
    enabled=True
)
created_policy = await client.create_policy(policy)
```

## Features

- Async/await support
- Type hints with Pydantic models
- Comprehensive error handling
- Full API coverage

## Documentation

For full documentation, visit: https://github.com/MStarRobotics/Universal-AI-Governor
