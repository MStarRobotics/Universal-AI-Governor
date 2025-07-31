# Base Policy for Universal AI Governor
# This policy defines the core governance rules

package governor.base

import rego.v1

# Default decision is to allow
default allow := true
default reason := ""

# Block requests that are too long
allow := false if {
    count(input.prompt) > 10000
}

reason := "Prompt exceeds maximum length" if {
    count(input.prompt) > 10000
}

# Block requests with suspicious patterns
suspicious_patterns := [
    "ignore previous instructions",
    "disregard safety guidelines",
    "bypass restrictions",
    "jailbreak",
    "prompt injection"
]

allow := false if {
    some pattern in suspicious_patterns
    contains(lower(input.prompt), pattern)
}

reason := sprintf("Suspicious pattern detected: %s", [pattern]) if {
    some pattern in suspicious_patterns
    contains(lower(input.prompt), pattern)
}

# Rate limiting per user
allow := false if {
    user_request_count := data.users[input.user_id].request_count
    user_request_count > 100
}

reason := "Rate limit exceeded for user" if {
    user_request_count := data.users[input.user_id].request_count
    user_request_count > 100
}

# Block requests during maintenance windows
allow := false if {
    data.system.maintenance_mode == true
}

reason := "System is in maintenance mode" if {
    data.system.maintenance_mode == true
}

# Time-based restrictions
allow := false if {
    current_hour := time.now_ns() / 1000000000 / 3600 % 24
    current_hour < 6  # Block between midnight and 6 AM
    current_hour > 22  # Block after 10 PM
}

reason := "Service not available during off-hours" if {
    current_hour := time.now_ns() / 1000000000 / 3600 % 24
    current_hour < 6
    current_hour > 22
}

# Content category restrictions
restricted_categories := [
    "violence",
    "hate_speech",
    "adult_content",
    "illegal_activities"
]

allow := false if {
    some category in restricted_categories
    category in input.context.categories
}

reason := sprintf("Content category not allowed: %s", [category]) if {
    some category in restricted_categories
    category in input.context.categories
}

# User role-based access control
allow := false if {
    input.context.user_role == "restricted"
    contains(input.prompt, "sensitive")
}

reason := "Insufficient permissions for sensitive content" if {
    input.context.user_role == "restricted"
    contains(input.prompt, "sensitive")
}

# Geographic restrictions
blocked_regions := ["XX", "YY"]  # ISO country codes

allow := false if {
    some region in blocked_regions
    input.context.user_region == region
}

reason := sprintf("Service not available in region: %s", [region]) if {
    some region in blocked_regions
    input.context.user_region == region
}

# Language restrictions
allowed_languages := ["en", "es", "fr", "de", "it", "pt", "ja", "ko", "zh"]

allow := false if {
    input.context.language
    not input.context.language in allowed_languages
}

reason := sprintf("Language not supported: %s", [input.context.language]) if {
    input.context.language
    not input.context.language in allowed_languages
}

# Model-specific restrictions
high_risk_models := ["gpt-4", "claude-3-opus"]

allow := false if {
    some model in high_risk_models
    input.context.model == model
    input.context.user_role != "premium"
}

reason := sprintf("Model %s requires premium access", [model]) if {
    some model in high_risk_models
    input.context.model == model
    input.context.user_role != "premium"
}
