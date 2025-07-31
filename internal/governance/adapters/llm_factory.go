package adapters

import (
	"context"
	"fmt"
	"time"

	"github.com/universal-ai-governor/internal/config"
	"github.com/universal-ai-governor/internal/logging"
	"github.com/universal-ai-governor/internal/types"
)

// LLMAdapter interface defines the contract for LLM integrations
type LLMAdapter interface {
	Generate(ctx context.Context, req *types.LLMRequest) (*types.LLMResponse, error)
	Health() types.ComponentHealth
	Close() error
	Name() string
	Type() string
}

// NewLLMAdapter creates an LLM adapter based on configuration
func NewLLMAdapter(config config.LLMAdapterConfig, logger logging.Logger) (LLMAdapter, error) {
	switch config.Type {
	case types.LLMAdapterTypeOpenAI:
		return NewOpenAIAdapter(config, logger)
	case types.LLMAdapterTypeAnthropic:
		return NewAnthropicAdapter(config, logger)
	case types.LLMAdapterTypeLocal:
		return NewLocalAdapter(config, logger)
	case types.LLMAdapterTypeOllama:
		return NewOllamaAdapter(config, logger)
	case types.LLMAdapterTypeHuggingFace:
		return NewHuggingFaceAdapter(config, logger)
	default:
		return nil, fmt.Errorf("unsupported LLM adapter type: %s", config.Type)
	}
}

// BaseAdapter provides common functionality for all LLM adapters
type BaseAdapter struct {
	name   string
	config config.LLMAdapterConfig
	logger logging.Logger
}

// NewBaseAdapter creates a new base adapter
func NewBaseAdapter(config config.LLMAdapterConfig, logger logging.Logger) *BaseAdapter {
	return &BaseAdapter{
		name:   config.Name,
		config: config,
		logger: logger,
	}
}

// Name returns the adapter name
func (ba *BaseAdapter) Name() string {
	return ba.name
}

// Type returns the adapter type
func (ba *BaseAdapter) Type() string {
	return ba.config.Type
}

// validateRequest performs common request validation
func (ba *BaseAdapter) validateRequest(req *types.LLMRequest) error {
	if req.Prompt == "" {
		return fmt.Errorf("prompt cannot be empty")
	}
	
	if len(req.Prompt) > 100000 { // 100KB limit
		return fmt.Errorf("prompt too large: %d characters", len(req.Prompt))
	}
	
	return nil
}

// createResponse creates a standardized LLM response
func (ba *BaseAdapter) createResponse(content, model string, tokensUsed int, finishReason string) *types.LLMResponse {
	return &types.LLMResponse{
		Content:      content,
		Model:        model,
		TokensUsed:   tokensUsed,
		FinishReason: finishReason,
		Metadata: map[string]interface{}{
			"adapter":   ba.name,
			"timestamp": time.Now(),
		},
	}
}

// getStringConfig retrieves a string configuration value
func (ba *BaseAdapter) getStringConfig(key string) string {
	if val, ok := ba.config.Config[key].(string); ok {
		return val
	}
	return ""
}

// getIntConfig retrieves an integer configuration value
func (ba *BaseAdapter) getIntConfig(key string) int {
	if val, ok := ba.config.Config[key].(int); ok {
		return val
	}
	return 0
}

// getBoolConfig retrieves a boolean configuration value
func (ba *BaseAdapter) getBoolConfig(key string) bool {
	if val, ok := ba.config.Config[key].(bool); ok {
		return val
	}
	return false
}

// getDurationConfig retrieves a duration configuration value
func (ba *BaseAdapter) getDurationConfig(key string) time.Duration {
	if val, ok := ba.config.Config[key].(string); ok {
		if duration, err := time.ParseDuration(val); err == nil {
			return duration
		}
	}
	return 30 * time.Second // default timeout
}
