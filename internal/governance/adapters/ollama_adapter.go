package adapters

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/universal-ai-governor/internal/config"
	"github.com/universal-ai-governor/internal/logging"
	"github.com/universal-ai-governor/internal/types"
)

// OllamaAdapter implements the LLMAdapter interface for interacting with Ollama local models.
// This adapter is a crucial component in enabling the "humanization effect" by allowing
// the Universal AI Governor to integrate with locally hosted, customizable LLMs.
// This provides greater control over data privacy and model behavior, fostering trust
// and reducing reliance on external, potentially opaque, AI services. It also contributes
// to "AI bypass" by offering an alternative to commercial APIs, allowing for more
// transparent and auditable AI interactions within a controlled environment.
type OllamaAdapter struct {
	*BaseAdapter // Embeds common adapter functionalities
	baseURL    string        // Base URL of the Ollama API endpoint
	model      string        // Default model to use for generation
	timeout    time.Duration // Timeout for HTTP requests to Ollama
	httpClient *http.Client  // HTTP client for making requests
}

// OllamaRequest represents the structure of a request sent to the Ollama API.
type OllamaRequest struct {
	Model   string                 `json:"model"`             // The name of the model to use
	Prompt  string                 `json:"prompt"`            // The input prompt for generation
	Stream  bool                   `json:"stream"`            // Whether to stream the response (false for single response)
	Options map[string]interface{} `json:"options,omitempty"` // Additional model-specific options
}

// OllamaResponse represents the structure of a response received from the Ollama API.
type OllamaResponse struct {
	Model     string `json:"model"`             // The model that generated the response
	Response  string `json:"response"`          // The generated text content
	Done      bool   `json:"done"`              // Indicates if the generation is complete
	Context   []int  `json:"context,omitempty"` // Context for continued generation (if streaming)
	TotalTime int64  `json:"total_duration,omitempty"` // Total time taken for generation in nanoseconds
}

// NewOllamaAdapter creates a new instance of the OllamaAdapter.
// It initializes the adapter with configuration, logger, and sets up the HTTP client.
func NewOllamaAdapter(config config.LLMAdapterConfig, logger logging.Logger) (*OllamaAdapter, error) {
	base := NewBaseAdapter(config, logger) // Initialize the common base adapter
	
	// Retrieve and set the base URL for the Ollama API, with a default fallback.
	baseURL := base.getStringConfig("base_url")
	if baseURL == "" {
		baseURL = "http://localhost:11434" // Default Ollama local endpoint
	}
	
	// Retrieve and set the default model name, with a fallback.
	model := base.getStringConfig("default_model")
	if model == "" {
		model = "llama2" // Default model if not specified
	}
	
	// Retrieve and set the request timeout duration.
	timeout := base.getDurationConfig("timeout")
	
	// Construct the OllamaAdapter instance.
	adapter := &OllamaAdapter{
		BaseAdapter: base,
		baseURL:     baseURL,
		model:       model,
		timeout:     timeout,
		httpClient: &http.Client{
			Timeout: timeout, // Apply the configured timeout to the HTTP client
		},
	}
	
	// Log successful initialization for observability.
	logger.Info("Ollama adapter initialized", 
		"name", config.Name,
		"base_url", baseURL,
		"model", model)
	
	return adapter, nil
}

// Generate sends a request to the Ollama API to generate text.
// It handles request validation, marshaling, HTTP communication, and response parsing.
func (oa *OllamaAdapter) Generate(ctx context.Context, req *types.LLMRequest) (*types.LLMResponse, error) {
	// Validate the incoming request to ensure it meets basic requirements.
	if err := oa.validateRequest(req); err != nil {
		return nil, fmt.Errorf("request validation failed: %w", err)
	}
	
	// Determine the model to use, prioritizing the request-specific option over the default.
	model := oa.model
	if modelOption, ok := req.Options["model"].(string); ok && modelOption != "" {
		model = modelOption
	}
	
	// Construct the Ollama API request payload.
	ollamaReq := OllamaRequest{
		Model:  model,
		Prompt: req.Prompt,
		Stream: false, // Currently, we don't support streaming responses.
	}
	
	// Include any additional options provided in the request.
	if len(req.Options) > 0 {
		ollamaReq.Options = make(map[string]interface{})
		for key, value := range req.Options {
			if key != "model" { // The model field is handled separately.
				ollamaReq.Options[key] = value
			}
		}
	}
	
	// Marshal the request payload to JSON format.
	reqBody, err := json.Marshal(ollamaReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}
	
	// Create the HTTP request object with context for cancellation/timeout.
	httpReq, err := http.NewRequestWithContext(ctx, "POST", oa.baseURL+"/api/generate", bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	
	httpReq.Header.Set("Content-Type", "application/json")
	
	// Send the HTTP request to the Ollama API.
	startTime := time.Now()
	resp, err := oa.httpClient.Do(httpReq)
	if err != nil {
		// Log network or connectivity errors.
		oa.logger.Error("Ollama request failed", "error", err, "model", model)
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close() // Ensure the response body is closed.
	
	// Check the HTTP response status code for API-level errors.
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body) // Read response body for error details.
		oa.logger.Error("Ollama API error", "status", resp.StatusCode, "body", string(body))
		return nil, fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(body))
	}
	
	// Parse the JSON response from the Ollama API.
	var ollamaResp OllamaResponse
	if err := json.NewDecoder(resp.Body).Decode(&ollamaResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	
	// Estimate token usage (a rough approximation for now).
	tokensUsed := len(req.Prompt)/4 + len(ollamaResp.Response)/4
	
	// Determine the reason for the generation finishing.
	finishReason := "stop"
	if !ollamaResp.Done {
		finishReason = "length" // If not done, it means the generation was truncated.
	}
	
	duration := time.Since(startTime)
	oa.logger.Debug("Ollama generation completed",
		"model", model,
		"tokens", tokensUsed,
		"duration", duration,
		"finish_reason", finishReason)
	
	// Return a standardized LLMResponse.
	return oa.createResponse(ollamaResp.Response, model, tokensUsed, finishReason), nil
}

// Health returns the current operational status of the Ollama adapter.
// It performs a basic check by attempting to query the Ollama API's tags endpoint.
func (oa *OllamaAdapter) Health() types.ComponentHealth {
	// Set a short timeout for the health check to avoid blocking.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel() // Ensure the context is cancelled to release resources.
	
	// Attempt to create an HTTP request to the Ollama /api/tags endpoint.
	req, err := http.NewRequestWithContext(ctx, "GET", oa.baseURL+"/api/tags", nil)
	if err != nil {
		return types.ComponentHealth{
			Status:    types.HealthStatusUnhealthy,
			Message:   fmt.Sprintf("Failed to create health check request: %v", err),
			Timestamp: time.Now(),
		}
	}
	
	// Execute the HTTP request.
	resp, err := oa.httpClient.Do(req)
	if err != nil {
		// Report unhealthy if the service is unreachable.
		return types.ComponentHealth{
			Status:    types.HealthStatusUnhealthy,
			Message:   fmt.Sprintf("Ollama service unreachable: %v", err),
			Timestamp: time.Now(),
		}
	}
	defer resp.Body.Close() // Ensure the response body is closed.
	
	// Check if the response status code indicates success.
	if resp.StatusCode != http.StatusOK {
		// Report unhealthy if the API returns an error status.
		return types.ComponentHealth{
			Status:    types.HealthStatusUnhealthy,
			Message:   fmt.Sprintf("Ollama service returned status %d", resp.StatusCode),
			Timestamp: time.Now(),
		}
	}
	
	// If all checks pass, the Ollama adapter is considered healthy.
	return types.ComponentHealth{
		Status:    types.HealthStatusHealthy,
		Message:   "Ollama service operational",
		Timestamp: time.Now(),
		Metadata: map[string]interface{}{
			"base_url": oa.baseURL,
			"model":    oa.model,
		},
	}
}

// Close gracefully shuts down the Ollama adapter.
// For HTTP clients, explicit closing is often not strictly necessary as they
// manage their own connections, but this method is part of the interface.
func (oa *OllamaAdapter) Close() error {
	oa.logger.Info("Closing Ollama adapter", "name", oa.name)
	// No specific resources to close for a simple HTTP client.
	return nil
}

// validateRequest validates the LLM request for the Ollama adapter.
// This is a specific implementation of the validation logic for Ollama.
func (oa *OllamaAdapter) validateRequest(req *types.LLMRequest) error {
	if req == nil {
		return fmt.Errorf("request cannot be nil")
	}
	if req.ID == "" {
		return fmt.Errorf("request ID cannot be empty")
	}
	// TODO: Add more specific validation for Ollama requests if needed.
	return nil
}

// createResponse constructs a standardized LLMResponse from an Ollama API response.
// This ensures consistency in the output format across different LLM integrations.
func (oa *OllamaAdapter) createResponse(content, model string, tokensUsed int, finishReason string) *types.LLMResponse {
	return &types.LLMResponse{
		ID:           fmt.Sprintf("ollama-%d", time.Now().UnixNano()), // Generate a unique ID for the response.
		Content:      content,
		Model:        model,
		TokensUsed:   tokensUsed,
		FinishReason: finishReason,
		Usage: types.Usage{
			TotalTokens: tokensUsed, // Populate total tokens from the estimated usage.
		},
		Metadata: map[string]interface{}{
			"provider": "ollama", // Indicate the source provider.
			"model":    model,
		},
	}
}

// Name returns the human-readable name of this Ollama adapter instance.
func (oa *OllamaAdapter) Name() string {
	return "Ollama Adapter" // A descriptive name for the adapter.
}

// Type returns the programmatic type identifier for this Ollama adapter.
func (oa *OllamaAdapter) Type() string {
	return string(types.LLMAdapterTypeOllama) // Returns the constant string representation of the adapter type.
}