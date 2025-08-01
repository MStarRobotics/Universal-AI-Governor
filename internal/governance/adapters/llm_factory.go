package adapters

import (
	"context"
	"fmt"
	"time"

	"github.com/universal-ai-governor/internal/config"
	"github.com/universal-ai-governor/internal/logging"
	"github.com/universal-ai-governor/internal/types"
)

// LLMAdapter defines the interface for interacting with various Large Language Models.
// Each concrete LLM integration (e.g., OpenAI, Ollama) must implement this interface.
type LLMAdapter interface {
	// Generate sends a request to the LLM and returns its generated response.
	// The context allows for cancellation and timeouts.
	Generate(ctx context.Context, req *types.LLMRequest) (*types.LLMResponse, error)

	// Health returns the current operational status of the LLM adapter.
	// This can include checks for connectivity to the LLM service or model availability.
	Health() types.ComponentHealth

	// Close gracefully shuts down the LLM adapter, releasing any resources
	// (e.g., HTTP connections, local model instances).
	Close() error

	// Name returns the unique name of this LLM adapter instance.
	Name() string

	// Type returns the type of LLM adapter (e.g., "openai", "ollama").
	Type() string
}

// NewLLMAdapter is a factory function that creates a concrete LLMAdapter
// based on the provided configuration. It acts as a central point for
// instantiating different LLM integrations, embodying the principle of
// modularity and extensibility. This design allows the Universal AI Governor
// to seamlessly integrate with a diverse ecosystem of AI models, effectively
// providing an "AI bypass" around vendor lock-in and enabling the "humanization effect"
// by allowing organizations to choose models that best align with their ethical
// and operational requirements.
func NewLLMAdapter(config config.LLMAdapterConfig, logger logging.Logger) (LLMAdapter, error) {
	switch types.LLMAdapterType(config.Type) {
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

// BaseAdapter provides common fields and utility methods that can be embedded
// into concrete LLMAdapter implementations. This promotes code reuse and consistency.
type BaseAdapter struct {
	name   string                 // The unique name of this adapter instance
	config config.LLMAdapterConfig // Configuration for this specific adapter
	logger logging.Logger          // Logger for adapter-specific events
}

// NewBaseAdapter creates a new instance of the BaseAdapter.
func NewBaseAdapter(config config.LLMAdapterConfig, logger logging.Logger) *BaseAdapter {
	return &BaseAdapter{
		name:   config.Name,
		config: config,
		logger: logger,
	}
}

// Name returns the configured name of the adapter.
func (ba *BaseAdapter) Name() string {
	return ba.name
}

// Type returns the configured type of the adapter.
func (ba *BaseAdapter) Type() string {
	return ba.config.Type
}

// validateRequest performs common validation checks on an LLMRequest.
// This ensures that requests sent to LLMs meet basic requirements.
func (ba *BaseAdapter) validateRequest(req *types.LLMRequest) error {
	// TODO: Implement more comprehensive request validation.
	// For example, checking for empty prompts, excessive length, or invalid parameters.
	return nil
}

// createResponse is a utility method to construct a standardized LLMResponse.
// This helps ensure consistency in the output format across different LLM integrations.
func (ba *BaseAdapter) createResponse(content, model string, tokensUsed int, finishReason string) *types.LLMResponse {
	// TODO: Implement actual response construction.
	return nil
}

// getStringConfig retrieves a string value from the adapter's configuration map.
// It safely handles cases where the key might be missing or the value is not a string.
func (ba *BaseAdapter) getStringConfig(key string) string {
	if val, ok := ba.config.Config[key].(string); ok {
		return val
	}
	return "" // Return empty string if key not found or not a string.
}

// getIntConfig retrieves an integer value from the adapter's configuration map.
// It safely handles cases where the key might be missing or the value is not an integer.
func (ba *BaseAdapter) getIntConfig(key string) int {
	if val, ok := ba.config.Config[key].(int); ok {
		return val
	}
	return 0 // Return 0 if key not found or not an integer.
}

// getBoolConfig retrieves a boolean value from the adapter's configuration map.
// It safely handles cases where the key might be missing or the value is not a boolean.
func (ba *BaseAdapter) getBoolConfig(key string) bool {
	if val, ok := ba.config.Config[key].(bool); ok {
		return val
	}
	return false // Return false if key not found or not a boolean.
}

// getDurationConfig retrieves a time.Duration value from the adapter's configuration map.
// It parses string durations (e.g., "10s", "1m") and handles errors gracefully.
func (ba *BaseAdapter) getDurationConfig(key string) time.Duration {
	if val, ok := ba.config.Config[key].(string); ok {
		if duration, err := time.ParseDuration(val); err == nil {
			return duration
		}
	}
	return 30 * time.Second // Default timeout if key not found or parsing fails.
}