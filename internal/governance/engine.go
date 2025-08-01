package governance

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/universal-ai-governor/internal/config"
	"github.com/universal-ai-governor/internal/governance/adapters"
	"github.com/universal-ai-governor/internal/governance/audit"
	"github.com/universal-ai-governor/internal/governance/guardrails"
	"github.com/universal-ai-governor/internal/governance/moderation"
	"github.com/universal-ai-governor/internal/governance/policy"
	"github.com/universal-ai-governor/internal/logging"
	"github.com/universal-ai-governor/internal/types"
)

// Engine represents the main governance engine
type Engine struct {
	config         config.GovernanceConfig
	logger         logging.Logger
	policyEngine   policy.Engine
	moderationSvc  moderation.Service
	guardrailsSvc  guardrails.Service
	auditSvc       audit.Service
	llmAdapters    map[string]adapters.LLMAdapter
	mu             sync.RWMutex
	metrics        *Metrics
	closed         bool
}

// NewEngine creates a new governance engine instance
func NewEngine(cfg config.GovernanceConfig, logger logging.Logger) (*Engine, error) {
	engine := &Engine{
		config:      cfg,
		logger:      logger,
		llmAdapters: make(map[string]adapters.LLMAdapter),
		metrics:     NewMetrics(),
	}

	// Initialize policy engine
	policyEngine, err := policy.NewOPAEngine(cfg.PolicyEngine, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize policy engine: %w", err)
	}
	engine.policyEngine = policyEngine

	// Initialize moderation service
	moderationSvc, err := moderation.NewService(cfg.Moderation, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize moderation service: %w", err)
	}
	engine.moderationSvc = moderationSvc

	// Initialize guardrails service
	guardrailsSvc, err := guardrails.NewService(cfg.Guardrails, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize guardrails service: %w", err)
	}
	engine.guardrailsSvc = guardrailsSvc

	// Initialize audit service
	auditSvc, err := audit.NewService(cfg.AuditSettings, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize audit service: %w", err)
	}
	engine.auditSvc = auditSvc

	// Initialize LLM adapters
	for _, adapterCfg := range cfg.LLMAdapters {
		if !adapterCfg.Enabled {
			continue
		}

		adapter, err := adapters.NewLLMAdapter(adapterCfg, logger)
		if err != nil {
			logger.Error("Failed to initialize LLM adapter", "name", adapterCfg.Name, "error", err)
			continue
		}

		engine.llmAdapters[adapterCfg.Name] = adapter
		logger.Info("Initialized LLM adapter", "name", adapterCfg.Name, "type", adapterCfg.Type)
	}

	logger.Info("Governance engine initialized successfully")
	return engine, nil
}

// ProcessRequest processes a governance request through the complete pipeline
func (e *Engine) ProcessRequest(ctx context.Context, req *types.GovernanceRequest) (*types.GovernanceResponse, error) {
	if e.closed {
		return nil, fmt.Errorf("governance engine is closed")
	}

	startTime := time.Now()
	requestID := req.ID
	if requestID == "" {
		requestID = generateRequestID()
		req.ID = requestID
	}

	e.logger.Info("Processing governance request", "request_id", requestID, "user_id", req.UserID)

	// Create audit entry
	auditEntry := &types.AuditEntry{
		RequestID:   requestID,
		UserID:      req.UserID,
		Timestamp:   startTime,
		InputPrompt: req.Prompt,
		Metadata:    req.Metadata,
		Steps:       make([]types.AuditStep, 0),
	}

	response := &types.GovernanceResponse{
		RequestID: requestID,
		Status:    types.StatusProcessing,
		Metadata:  make(map[string]interface{}),
	}

	// Step 1: Input Moderation
	if e.config.Moderation.Enabled {
		moderationResult, err := e.moderationSvc.ModerateInput(ctx, req.Prompt, req.UserID)
		if err != nil {
			e.logger.Error("Input moderation failed", "request_id", requestID, "error", err)
			response.Status = types.StatusError
			response.Error = "Input moderation failed"
			e.metrics.IncrementErrors("input_moderation")
			return response, err
		}

		auditEntry.Steps = append(auditEntry.Steps, types.AuditStep{
			Step:      "input_moderation",
			Timestamp: time.Now(),
			Result:    moderationResult,
		})

		if moderationResult.Blocked {
			response.Status = types.StatusBlocked
			response.Reason = moderationResult.Reason
			response.Metadata["moderation"] = moderationResult
			e.auditSvc.LogEntry(auditEntry)
			e.metrics.IncrementBlocked("input_moderation")
			return response, nil
		}
	}

	// Step 2: Policy Evaluation
	policyResult, err := e.policyEngine.Evaluate(ctx, &policy.EvaluationRequest{
		Input:     req.Prompt,
		UserID:    req.UserID,
		Context:   req.Context,
		Metadata:  req.Metadata,
	})
	if err != nil {
		return nil, fmt.Errorf("policy evaluation failed: %w", err)
	}

	auditEntry.Steps = append(auditEntry.Steps, types.AuditStep{
		Step:      "policy_evaluation",
		Timestamp: time.Now(),
		Result:    policyResult,
	})

	if !policyResult.Allowed {
		response.Status = types.StatusBlocked
		response.Reason = policyResult.Reason
		response.Metadata["policy"] = policyResult
		e.auditSvc.LogEntry(auditEntry)
		e.metrics.IncrementBlocked("policy_evaluation")
		return response, nil
	}

	// Step 3: Input Guardrails
	if e.config.Guardrails.Enabled {
		guardrailResult, err := e.guardrailsSvc.ValidateInput(ctx, req.Prompt, req.Context)
		if err != nil {
			e.logger.Error("Input guardrails failed", "request_id", requestID, "error", err)
			response.Status = types.StatusError
			response.Error = "Input guardrails failed"
			e.metrics.IncrementErrors("input_guardrails")
			return response, err
		}

		auditEntry.Steps = append(auditEntry.Steps, types.AuditStep{
			Step:      "input_guardrails",
			Timestamp: time.Now(),
			Result:    guardrailResult,
		})

		if !guardrailResult.Valid {
			response.Status = types.StatusBlocked
			response.Reason = guardrailResult.Reason
			response.Metadata["guardrails"] = guardrailResult
			e.auditSvc.LogEntry(auditEntry)
			e.metrics.IncrementBlocked("input_guardrails")
			return response, nil
		}

		// Apply any transformations
		if guardrailResult.TransformedInput != "" {
			req.Prompt = guardrailResult.TransformedInput
		}
	}

	// Step 4: LLM Processing
	var llmResponse *types.LLMResponse
	if req.LLMAdapter != "" {
		adapter, exists := e.llmAdapters[req.LLMAdapter]
		if !exists {
			response.Status = types.StatusError
			response.Error = fmt.Sprintf("LLM adapter '%s' not found", req.LLMAdapter)
			e.metrics.IncrementErrors("llm_adapter_not_found")
			return response, fmt.Errorf("LLM adapter '%s' not found", req.LLMAdapter)
		}

		llmResponse, err = adapter.Generate(ctx, &types.LLMRequest{
			Prompt:    req.Prompt,
			Options:   req.LLMOptions,
		})
		if err != nil {
			e.logger.Error("LLM generation failed", "request_id", requestID, "adapter", req.LLMAdapter, "error", err)
			response.Status = types.StatusError
			response.Error = "LLM generation failed"
			e.metrics.IncrementErrors("llm_generation")
			return response, err
		}

		auditEntry.Steps = append(auditEntry.Steps, types.AuditStep{
			Step:      "llm_generation",
			Timestamp: time.Now(),
			Result:    llmResponse,
		})

		response.LLMResponse = llmResponse.Content
		response.Metadata["llm"] = map[string]interface{}{
			"adapter":      req.LLMAdapter,
			"model":        llmResponse.Model,
			"tokens_used":  llmResponse.TokensUsed,
			"finish_reason": llmResponse.FinishReason,
		}
	}

	// Step 5: Output Guardrails
	if e.config.Guardrails.Enabled && llmResponse != nil {
		outputGuardrailResult, err := e.guardrailsSvc.ValidateOutput(ctx, llmResponse.Content, req.Context)
		if err != nil {
			e.logger.Error("Output guardrails failed", "request_id", requestID, "error", err)
			response.Status = types.StatusError
			response.Error = "Output guardrails failed"
			e.metrics.IncrementErrors("output_guardrails")
			return response, err
		}

		auditEntry.Steps = append(auditEntry.Steps, types.AuditStep{
			Step:      "output_guardrails",
			Timestamp: time.Now(),
			Result:    outputGuardrailResult,
		})

		if !outputGuardrailResult.Valid {
			response.Status = types.StatusBlocked
			response.Reason = outputGuardrailResult.Reason
			response.Metadata["guardrails"] = outputGuardrailResult
			e.auditSvc.LogEntry(auditEntry)
			e.metrics.IncrementBlocked("output_guardrails")
			return response, nil
		}

		// Apply any transformations
		if outputGuardrailResult.TransformedOutput != "" {
			response.LLMResponse = outputGuardrailResult.TransformedOutput
		}
	}

	// Step 6: Output Moderation
	if e.config.Moderation.Enabled && llmResponse != nil {
		outputModerationResult, err := e.moderationSvc.ModerateOutput(ctx, response.LLMResponse, req.UserID)
		if err != nil {
			e.logger.Error("Output moderation failed", "request_id", requestID, "error", err)
			response.Status = types.StatusError
			response.Error = "Output moderation failed"
			e.metrics.IncrementErrors("output_moderation")
			return response, err
		}

		auditEntry.Steps = append(auditEntry.Steps, types.AuditStep{
			Step:      "output_moderation",
			Timestamp: time.Now(),
			Result:    outputModerationResult,
		})

		if outputModerationResult.Blocked {
			response.Status = types.StatusBlocked
			response.Reason = outputModerationResult.Reason
			response.Metadata["output_moderation"] = outputModerationResult
			e.auditSvc.LogEntry(auditEntry)
			e.metrics.IncrementBlocked("output_moderation")
			return response, nil
		}
	}

	// Success
	response.Status = types.StatusAllowed
	processingTime := time.Since(startTime)
	response.Metadata["processing_time_ms"] = processingTime.Milliseconds()

	// Complete audit entry
	auditEntry.OutputResponse = response.LLMResponse
	auditEntry.Status = string(response.Status)
	auditEntry.ProcessingTime = processingTime

	// Log audit entry
	e.auditSvc.LogEntry(auditEntry)

	// Update metrics
	e.metrics.IncrementProcessed()
	e.metrics.RecordProcessingTime(processingTime)

	e.logger.Info("Governance request processed successfully", 
		"request_id", requestID, 
		"status", response.Status,
		"processing_time_ms", processingTime.Milliseconds())

	return response, nil
}

// GetLLMAdapters returns the list of available LLM adapters
func (e *Engine) GetLLMAdapters() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()

	adapters := make([]string, 0, len(e.llmAdapters))
	for name := range e.llmAdapters {
		adapters = append(adapters, name)
	}
	return adapters
}

// GetMetrics returns the current metrics
func (e *Engine) GetMetrics() *Metrics {
	return e.metrics
}

// Health returns the health status of the governance engine
func (e *Engine) Health() types.ComponentHealth {
	status := types.ComponentHealth{
		Status:    types.HealthStatusHealthy,
		Timestamp: time.Now(),
		Components: make(map[string]types.ComponentHealth),
	}

	// Check policy engine health
	policyHealth := e.policyEngine.Health()
	if policyHealth.Status != types.HealthStatusHealthy {
		status.Status = types.HealthStatusDegraded
	}
	status.Components["policy_engine"] = policyHealth

	// Check moderation service health
	moderationHealth := e.moderationSvc.Health()
	if moderationHealth.Status != types.HealthStatusHealthy {
		status.Status = types.HealthStatusDegraded
	}
	status.Components["moderation"] = moderationHealth

	// Check guardrails service health
	guardrailsHealth := e.guardrailsSvc.Health()
	if guardrailsHealth.Status != types.HealthStatusHealthy {
		status.Status = types.HealthStatusDegraded
	}
	status.Components["guardrails"] = guardrailsHealth

	// Check audit service health
	auditHealth := e.auditSvc.Health()
	if auditHealth.Status != types.HealthStatusHealthy {
		status.Status = types.HealthStatusDegraded
	}
	status.Components["audit"] = auditHealth

	// Check LLM adapters health
	for name, adapter := range e.llmAdapters {
		adapterHealth := adapter.Health()
		if adapterHealth.Status != types.HealthStatusHealthy {
			status.Status = types.HealthStatusDegraded
		}
		status.Components["llm_"+name] = adapterHealth
	}

	return status
}

// Close gracefully shuts down the governance engine
func (e *Engine) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.closed {
		return nil
	}

	e.logger.Info("Shutting down governance engine")

	// Close all components
	var errors []error

	if err := e.policyEngine.Close(); err != nil {
		errors = append(errors, fmt.Errorf("policy engine close error: %w", err))
	}

	if err := e.moderationSvc.Close(); err != nil {
		errors = append(errors, fmt.Errorf("moderation service close error: %w", err))
	}

	if err := e.guardrailsSvc.Close(); err != nil {
		errors = append(errors, fmt.Errorf("guardrails service close error: %w", err))
	}

	if err := e.auditSvc.Close(); err != nil {
		errors = append(errors, fmt.Errorf("audit service close error: %w", err))
	}

	for name, adapter := range e.llmAdapters {
		if err := adapter.Close(); err != nil {
			errors = append(errors, fmt.Errorf("LLM adapter %s close error: %w", name, err))
		}
	}

	e.closed = true

	if len(errors) > 0 {
		return fmt.Errorf("errors during shutdown: %v", errors)
	}

	e.logger.Info("Governance engine shut down successfully")
	return nil
}

// generateRequestID generates a unique request ID
func generateRequestID() string {
	return fmt.Sprintf("req_%d", time.Now().UnixNano())
}


// GetLLMAdapters returns the list of available LLM adapters
func (e *Engine) GetLLMAdapters() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()

	adapters := make([]string, 0, len(e.llmAdapters))
	for name := range e.llmAdapters {
		adapters = append(adapters, name)
	}
	return adapters
}

// GetMetrics returns the current metrics
func (e *Engine) GetMetrics() *Metrics {
	return e.metrics
}

// Health returns the health status of the governance engine
func (e *Engine) Health() types.ComponentHealth {
	status := types.ComponentHealth{
		Status:    types.HealthStatusHealthy,
		Timestamp: time.Now(),
		Components: make(map[string]types.ComponentHealth),
	}

	// Check policy engine health
	policyHealth := e.policyEngine.Health()
	if policyHealth.Status != types.HealthStatusHealthy {
		status.Status = types.HealthStatusDegraded
	}
	status.Components["policy_engine"] = policyHealth

	// Check moderation service health
	moderationHealth := e.moderationSvc.Health()
	if moderationHealth.Status != types.HealthStatusHealthy {
		status.Status = types.HealthStatusDegraded
	}
	status.Components["moderation"] = moderationHealth

	// Check guardrails service health
	guardrailsHealth := e.guardrailsSvc.Health()
	if guardrailsHealth.Status != types.HealthStatusHealthy {
		status.Status = types.HealthStatusDegraded
	}
	status.Components["guardrails"] = guardrailsHealth

	// Check audit service health
	auditHealth := e.auditSvc.Health()
	if auditHealth.Status != types.HealthStatusHealthy {
		status.Status = types.HealthStatusDegraded
	}
	status.Components["audit"] = auditHealth

	// Check LLM adapters health
	for name, adapter := range e.llmAdapters {
		adapterHealth := adapter.Health()
		if adapterHealth.Status != types.HealthStatusHealthy {
			status.Status = types.HealthStatusDegraded
		}
		status.Components["llm_"+name] = adapterHealth
	}

	return status
}

// Close gracefully shuts down the governance engine
func (e *Engine) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.closed {
		return nil
	}

	e.logger.Info("Shutting down governance engine")

	// Close all components
	var errors []error

	if err := e.policyEngine.Close(); err != nil {
		errors = append(errors, fmt.Errorf("policy engine close error: %w", err))
	}

	if err := e.moderationSvc.Close(); err != nil {
		errors = append(errors, fmt.Errorf("moderation service close error: %w", err))
	}

	if err := e.guardrailsSvc.Close(); err != nil {
		errors = append(errors, fmt.Errorf("guardrails service close error: %w", err))
	}

	if err := e.auditSvc.Close(); err != nil {
		errors = append(errors, fmt.Errorf("audit service close error: %w", err))
	}

	for name, adapter := range e.llmAdapters {
		if err := adapter.Close(); err != nil {
			errors = append(errors, fmt.Errorf("LLM adapter %s close error: %w", name, err))
		}
	}

	e.closed = true

	if len(errors) > 0 {
		return fmt.Errorf("errors during shutdown: %v", errors)
	}

	e.logger.Info("Governance engine shut down successfully")
	return nil
}

// generateRequestID generates a unique request ID
func generateRequestID() string {
	return fmt.Sprintf("req_%d", time.Now().UnixNano())
}
