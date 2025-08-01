package adapters

import (
	"context"
	"fmt"

	"github.com/universal-ai-governor/internal/config"
	"github.com/universal-ai-governor/internal/logging"
	"github.com/universal-ai-governor/internal/types"
)

// NewAnthropicAdapter creates a new Anthropic adapter (stub)
func NewAnthropicAdapter(config config.LLMAdapterConfig, logger logging.Logger) (LLMAdapter, error) {
	return &StubAdapter{name: "Anthropic", adapterType: string(types.LLMAdapterTypeAnthropic)}, nil
}

// NewLocalAdapter creates a new Local adapter (stub)
func NewLocalAdapter(config config.LLMAdapterConfig, logger logging.Logger) (LLMAdapter, error) {
	return &StubAdapter{name: "Local", adapterType: string(types.LLMAdapterTypeLocal)}, nil
}

// NewHuggingFaceAdapter creates a new HuggingFace adapter (stub)
func NewHuggingFaceAdapter(config config.LLMAdapterConfig, logger logging.Logger) (LLMAdapter, error) {
	return &StubAdapter{name: "HuggingFace", adapterType: string(types.LLMAdapterTypeHuggingFace)}, nil
}

// StubAdapter is a placeholder adapter for unimplemented adapters
type StubAdapter struct {
	name        string
	adapterType string
}

func (s *StubAdapter) Generate(ctx context.Context, req *types.LLMRequest) (*types.LLMResponse, error) {
	return nil, fmt.Errorf("Generate not implemented")
}

func (s *StubAdapter) Health() types.ComponentHealth {
	return types.ComponentHealth{}
}

func (s *StubAdapter) Close() error {
	return nil
}

func (s *StubAdapter) Name() string {
	return s.name + " Adapter"
}

func (s *StubAdapter) Type() string {
	return s.adapterType
}
