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

// OllamaAdapter implements LLM adapter for Ollama local models
type OllamaAdapter struct {
	*BaseAdapter
	baseURL    string
	model      string
	timeout    time.Duration
	httpClient *http.Client
}

// OllamaRequest represents a request to Ollama API
type OllamaRequest struct {
	Model   string                 `json:"model"`
	Prompt  string                 `json:"prompt"`
	Stream  bool                   `json:"stream"`
	Options map[string]interface{} `json:"options,omitempty"`
}

// OllamaResponse represents a response from Ollama API
type OllamaResponse struct {
	Model     string `json:"model"`
	Response  string `json:"response"`
	Done      bool   `json:"done"`
	Context   []int  `json:"context,omitempty"`
	TotalTime int64  `json:"total_duration,omitempty"`
}

// NewOllamaAdapter creates a new Ollama adapter
func NewOllamaAdapter(config config.LLMAdapterConfig, logger logging.Logger) (*OllamaAdapter, error) {
	base := NewBaseAdapter(config, logger)
	
	baseURL := base.getStringConfig("base_url")
	if baseURL == "" {
		baseURL = "http://localhost:11434"
	}
	
	model := base.getStringConfig("default_model")
	if model == "" {
		model = "llama2"
	}
	
	timeout := base.getDurationConfig("timeout")
	
	adapter := &OllamaAdapter{
		BaseAdapter: base,
		baseURL:     baseURL,
		model:       model,
		timeout:     timeout,
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}
	
	logger.Info("Ollama adapter initialized", 
		"name", config.Name,
		"base_url", baseURL,
		"model", model)
	
	return adapter, nil
}

// Generate generates text using Ollama
func (oa *OllamaAdapter) Generate(ctx context.Context, req *types.LLMRequest) (*types.LLMResponse, error) {
	if err := oa.validateRequest(req); err != nil {
		return nil, fmt.Errorf("request validation failed: %w", err)
	}
	
	// Prepare Ollama request
	model := oa.model
	if modelOption, ok := req.Options["model"].(string); ok && modelOption != "" {
		model = modelOption
	}
	
	ollamaReq := OllamaRequest{
		Model:  model,
		Prompt: req.Prompt,
		Stream: false,
	}
	
	// Add options if provided
	if len(req.Options) > 0 {
		ollamaReq.Options = make(map[string]interface{})
		for key, value := range req.Options {
			if key != "model" { // model is handled separately
				ollamaReq.Options[key] = value
			}
		}
	}
	
	// Marshal request
	reqBody, err := json.Marshal(ollamaReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}
	
	// Create HTTP request
	httpReq, err := http.NewRequestWithContext(ctx, "POST", oa.baseURL+"/api/generate", bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	
	httpReq.Header.Set("Content-Type", "application/json")
	
	// Send request
	startTime := time.Now()
	resp, err := oa.httpClient.Do(httpReq)
	if err != nil {
		oa.logger.Error("Ollama request failed", "error", err, "model", model)
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()
	
	// Check response status
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		oa.logger.Error("Ollama API error", "status", resp.StatusCode, "body", string(body))
		return nil, fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(body))
	}
	
	// Parse response
	var ollamaResp OllamaResponse
	if err := json.NewDecoder(resp.Body).Decode(&ollamaResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	
	// Calculate approximate token usage (rough estimation)
	tokensUsed := len(req.Prompt)/4 + len(ollamaResp.Response)/4
	
	// Determine finish reason
	finishReason := "stop"
	if !ollamaResp.Done {
		finishReason = "length"
	}
	
	duration := time.Since(startTime)
	oa.logger.Debug("Ollama generation completed",
		"model", model,
		"tokens", tokensUsed,
		"duration", duration,
		"finish_reason", finishReason)
	
	return oa.createResponse(ollamaResp.Response, model, tokensUsed, finishReason), nil
}

// Health returns the health status of the Ollama adapter
func (oa *OllamaAdapter) Health() types.ComponentHealth {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	// Try to get model list to check if Ollama is running
	req, err := http.NewRequestWithContext(ctx, "GET", oa.baseURL+"/api/tags", nil)
	if err != nil {
		return types.ComponentHealth{
			Status:    types.HealthStatusUnhealthy,
			Message:   fmt.Sprintf("Failed to create health check request: %v", err),
			Timestamp: time.Now(),
		}
	}
	
	resp, err := oa.httpClient.Do(req)
	if err != nil {
		return types.ComponentHealth{
			Status:    types.HealthStatusUnhealthy,
			Message:   fmt.Sprintf("Ollama service unreachable: %v", err),
			Timestamp: time.Now(),
		}
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return types.ComponentHealth{
			Status:    types.HealthStatusUnhealthy,
			Message:   fmt.Sprintf("Ollama service returned status %d", resp.StatusCode),
			Timestamp: time.Now(),
		}
	}
	
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

// Close closes the Ollama adapter
func (oa *OllamaAdapter) Close() error {
	oa.logger.Info("Closing Ollama adapter", "name", oa.name)
	// HTTP client doesn't need explicit closing
	return nil
}
