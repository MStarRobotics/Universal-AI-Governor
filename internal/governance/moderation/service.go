package moderation

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/universal-ai-governor/internal/config"
	"github.com/universal-ai-governor/internal/logging"
	"github.com/universal-ai-governor/internal/types"
)

// Service interface for content moderation
type Service interface {
	ModerateInput(ctx context.Context, content string, userID string) (*types.ModerationResult, error)
	ModerateOutput(ctx context.Context, content string, userID string) (*types.ModerationResult, error)
	Health() types.ComponentHealth
	Close() error
}

// Provider interface for moderation providers
type Provider interface {
	Moderate(ctx context.Context, content string, userID string) (*types.ModerationResult, error)
	Name() string
	Priority() int
	Health() types.ComponentHealth
	Close() error
}

// ModerationService implements the moderation service
type ModerationService struct {
	config    config.ModerationConfig
	logger    logging.Logger
	providers []Provider
}

// NewService creates a new moderation service
func NewService(config config.ModerationConfig, logger logging.Logger) (*ModerationService, error) {
	service := &ModerationService{
		config:    config,
		logger:    logger,
		providers: make([]Provider, 0),
	}

	// Initialize providers
	for _, providerConfig := range config.Providers {
		if !providerConfig.Enabled {
			continue
		}

		provider, err := NewProvider(providerConfig, logger)
		if err != nil {
			logger.Error("Failed to initialize moderation provider",
				"provider", providerConfig.Name,
				"error", err)
			continue
		}

		service.providers = append(service.providers, provider)
		logger.Info("Initialized moderation provider",
			"provider", providerConfig.Name,
			"type", providerConfig.Type,
			"priority", providerConfig.Priority)
	}

	// Sort providers by priority (lower number = higher priority)
	sort.Slice(service.providers, func(i, j int) bool {
		return service.providers[i].Priority() < service.providers[j].Priority()
	})

	logger.Info("Moderation service initialized",
		"providers", len(service.providers),
		"enabled", config.Enabled)

	return service, nil
}

// ModerateInput moderates input content
func (s *ModerationService) ModerateInput(ctx context.Context, content string, userID string) (*types.ModerationResult, error) {
	if !s.config.Enabled {
		return &types.ModerationResult{
			Blocked:    false,
			Confidence: 1.0,
			Metadata: map[string]interface{}{
				"moderation_disabled": true,
			},
		}, nil
	}

	return s.moderate(ctx, content, userID, "input")
}

// ModerateOutput moderates output content
func (s *ModerationService) ModerateOutput(ctx context.Context, content string, userID string) (*types.ModerationResult, error) {
	if !s.config.Enabled {
		return &types.ModerationResult{
			Blocked:    false,
			Confidence: 1.0,
			Metadata: map[string]interface{}{
				"moderation_disabled": true,
			},
		}, nil
	}

	return s.moderate(ctx, content, userID, "output")
}

// moderate performs the actual moderation using available providers
func (s *ModerationService) moderate(ctx context.Context, content string, userID string, contentType string) (*types.ModerationResult, error) {
	if len(s.providers) == 0 {
		s.logger.Warn("No moderation providers available")
		return s.getFallbackResult(), nil
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(ctx, s.config.Timeout)
	defer cancel()

	var lastError error
	var results []*types.ModerationResult

	// Try each provider in priority order
	for _, provider := range s.providers {
		s.logger.Debug("Attempting moderation",
			"provider", provider.Name(),
			"content_type", contentType,
			"user_id", userID)

		result, err := provider.Moderate(ctx, content, userID)
		if err != nil {
			s.logger.Error("Moderation provider failed",
				"provider", provider.Name(),
				"error", err,
				"user_id", userID)
			lastError = err
			continue
		}

		// Add provider metadata
		if result.Metadata == nil {
			result.Metadata = make(map[string]interface{})
		}
		result.Metadata["provider"] = provider.Name()
		result.Metadata["content_type"] = contentType
		result.Metadata["timestamp"] = time.Now()

		results = append(results, result)

		// If content is blocked by any provider, return immediately
		if result.Blocked {
			s.logger.Info("Content blocked by moderation",
				"provider", provider.Name(),
				"reason", result.Reason,
				"confidence", result.Confidence,
				"user_id", userID)
			return result, nil
		}
	}

	// If we have results but none blocked, return the highest confidence result
	if len(results) > 0 {
		// Sort by confidence (highest first)
		sort.Slice(results, func(i, j int) bool {
			return results[i].Confidence > results[j].Confidence
		})

		bestResult := results[0]
		bestResult.Metadata["all_results"] = results
		return bestResult, nil
	}

	// All providers failed, use fallback
	s.logger.Error("All moderation providers failed", "last_error", lastError)
	
	fallbackResult := s.getFallbackResult()
	fallbackResult.Metadata = map[string]interface{}{
		"fallback_used": true,
		"last_error":    lastError.Error(),
	}

	return fallbackResult, nil
}

// getFallbackResult returns the fallback moderation result
func (s *ModerationService) getFallbackResult() *types.ModerationResult {
	switch s.config.Fallback {
	case "block":
		return &types.ModerationResult{
			Blocked:    true,
			Reason:     "Moderation service unavailable - blocking as fallback",
			Confidence: 0.5,
			Categories: []string{"service_unavailable"},
		}
	case "allow":
		fallthrough
	default:
		return &types.ModerationResult{
			Blocked:    false,
			Reason:     "Moderation service unavailable - allowing as fallback",
			Confidence: 0.5,
			Categories: []string{"service_unavailable"},
		}
	}
}

// Health returns the health status of the moderation service
func (s *ModerationService) Health() types.ComponentHealth {
	if !s.config.Enabled {
		return types.ComponentHealth{
			Status:    types.HealthStatusHealthy,
			Message:   "Moderation disabled",
			Timestamp: time.Now(),
		}
	}

	if len(s.providers) == 0 {
		return types.ComponentHealth{
			Status:    types.HealthStatusUnhealthy,
			Message:   "No moderation providers available",
			Timestamp: time.Now(),
		}
	}

	healthyProviders := 0
	providerHealth := make(map[string]types.ComponentHealth)

	for _, provider := range s.providers {
		health := provider.Health()
		providerHealth[provider.Name()] = health
		
		if health.Status == types.HealthStatusHealthy {
			healthyProviders++
		}
	}

	var status string
	var message string

	if healthyProviders == 0 {
		status = types.HealthStatusUnhealthy
		message = "No healthy moderation providers"
	} else if healthyProviders < len(s.providers) {
		status = types.HealthStatusDegraded
		message = fmt.Sprintf("%d of %d providers healthy", healthyProviders, len(s.providers))
	} else {
		status = types.HealthStatusHealthy
		message = "All moderation providers healthy"
	}

	return types.ComponentHealth{
		Status:    status,
		Message:   message,
		Timestamp: time.Now(),
		Metadata: map[string]interface{}{
			"total_providers":   len(s.providers),
			"healthy_providers": healthyProviders,
			"provider_health":   providerHealth,
		},
	}
}

// Close gracefully shuts down the moderation service
func (s *ModerationService) Close() error {
	s.logger.Info("Shutting down moderation service")

	var errors []error
	for _, provider := range s.providers {
		if err := provider.Close(); err != nil {
			errors = append(errors, fmt.Errorf("failed to close provider %s: %w", provider.Name(), err))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("errors during moderation service shutdown: %v", errors)
	}

	return nil
}

// NewProvider creates a new moderation provider based on configuration
func NewProvider(config config.ModerationProvider, logger logging.Logger) (Provider, error) {
	switch config.Type {
	case types.ModerationProviderOpenAI:
		return NewOpenAIProvider(config, logger)
	case types.ModerationProviderCohere:
		return NewCohereProvider(config, logger)
	case types.ModerationProviderHuggingFace:
		return NewHuggingFaceProvider(config, logger)
	case types.ModerationProviderLocal:
		return NewLocalProvider(config, logger)
	case types.ModerationProviderCustom:
		return NewCustomProvider(config, logger)
	default:
		return nil, fmt.Errorf("unsupported moderation provider type: %s", config.Type)
	}
}
