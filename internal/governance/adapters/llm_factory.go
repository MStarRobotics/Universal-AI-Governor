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
	return nil, fmt.Errorf("LLM adapters are currently disabled")
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
	return nil
}

// createResponse creates a standardized LLM response
func (ba *BaseAdapter) createResponse(content, model string, tokensUsed int, finishReason string) *types.LLMResponse {
	return nil
}

// getStringConfig retrieves a string configuration value
func (ba *BaseAdapter) getStringConfig(key string) string {
	return ""
}

// getIntConfig retrieves an integer configuration value
func (ba *BaseAdapter) getIntConfig(key string) int {
	return 0
}

// getBoolConfig retrieves a boolean configuration value
func (ba *BaseAdapter) getBoolConfig(key string) bool {
	return false
}

// getDurationConfig retrieves a duration configuration value
func (ba *BaseAdapter) getDurationConfig(key string) time.Duration {
	return 0
}
