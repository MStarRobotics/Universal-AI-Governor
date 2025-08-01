package governance

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid" // For generating unique request IDs
	"github.com/universal-ai-governor/internal/config"
	"github.com/universal-ai-governor/internal/governance/adapters"
	"github.com/universal-ai-governor/internal/governance/audit"
	"github.com/universal-ai-governor/internal/governance/guardrails"
	"github.com/universal-ai-governor/internal/governance/moderation"
	"github.com/universal-ai-governor/internal/governance/policy"
	"github.com/universal-ai-governor/internal/logging"
	"github.com/universal-ai-governor/internal/types"
)

// Engine represents the core of the AI governance platform. It orchestrates
// policy evaluation, moderation, guardrails, and auditing for AI interactions.
// This component is designed to be robust and extensible, allowing for
// integration with various AI models and security measures.
type Engine struct {
	config         config.GovernanceConfig
	logger         logging.Logger
	policyEngine   policy.Engine
	moderationSvc  moderation.Service
	guardrailsSvc  guardrails.Service
	auditSvc       audit.Service
	llmAdapters    map[string]adapters.LLMAdapter // Manages various LLM integrations
	mu             sync.RWMutex                   // Protects access to engine state
	metrics        *Metrics                       // Tracks operational metrics
	closed         bool                           // Indicates if the engine has been shut down
}

// NewEngine creates a new instance of the governance engine. It initializes
// all sub-components based on the provided configuration. This function is
// the entry point for setting up the entire governance pipeline.
func NewEngine(cfg config.GovernanceConfig, logger logging.Logger) (*Engine, error) {
	engine := &Engine{
		config:      cfg,
		logger:      logger,
		llmAdapters: make(map[string]adapters.LLMAdapter), // Initialize map for LLM adapters
		metrics:     NewMetrics(),                       // Setup metrics collection
	}

	// Initialize the policy engine. This component is responsible for evaluating
	// Rego policies against incoming requests and LLM responses.
	policyEngine, err := policy.NewOPAEngine(cfg.PolicyEngine, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize policy engine: %w", err)
	}
	engine.policyEngine = policyEngine

	// Initialize the moderation service. This service is crucial for identifying
	// and blocking harmful or inappropriate content in both inputs and outputs.
	moderationSvc, err := moderation.NewService(cfg.Moderation, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize moderation service: %w", err)
	}
	engine.moderationSvc = moderationSvc

	// Initialize the guardrails service. Guardrails provide an additional layer
	// of safety and compliance checks, often involving data validation and transformation.
	guardrailsSvc, err := guardrails.NewService(cfg.Guardrails, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize guardrails service: %w", err)
	}
	engine.guardrailsSvc = guardrailsSvc

	// Initialize the audit service. This component is vital for logging all
	// governance decisions and events, ensuring a comprehensive and immutable
	// audit trail for compliance and forensic analysis.
	auditSvc, err := audit.NewService(cfg.AuditSettings, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize audit service: %w", err)
	}
	engine.auditSvc = auditSvc

	// Initialize various LLM adapters. These adapters allow the Governor to
	// interact with different Large Language Models, providing a flexible
	// and model-agnostic governance layer.
	for _, adapterCfg := range cfg.LLMAdapters {
		if !adapterCfg.Enabled {
			// Skip disabled adapters to optimize resource usage
			continue
		}

		adapter, err := adapters.NewLLMAdapter(adapterCfg, logger)
		if err != nil {
			// Log the error but continue initializing other adapters
			logger.Error("Failed to initialize LLM adapter", "name", adapterCfg.Name, "error", err)
			continue
		}

		engine.llmAdapters[adapterCfg.Name] = adapter
		logger.Info("Initialized LLM adapter", "name", adapterCfg.Name, "type", adapterCfg.Type)
	}

	logger.Info("Governance engine initialized successfully")
	return engine, nil
}

// ProcessRequest orchestrates the entire governance pipeline for a given AI request.
// This function is the beating heart of the Universal AI Governor, embodying its
// commitment to responsible AI. It meticulously applies a multi-layered defense-in-depth
// strategy, ensuring that every AI interaction is not only efficient but also
// ethically sound, compliant with policies, and transparently auditable.
//
// The "humanization effect" is subtly woven into this process by prioritizing
// safety and ethical considerations at every step, aiming to prevent harmful
// outputs and ensure AI systems serve human values. The "AI bypass" concept
// is addressed through robust, non-predictable request IDs and comprehensive
// audit trails, making every decision traceable and accountable, thus preventing
// opaque AI behavior.
//
// The pipeline consists of the following critical stages:
// 1. Input Moderation: Proactive screening of user prompts for harmful content.
// 2. Policy Evaluation: Dynamic assessment against defined governance policies.
// 3. Input Guardrails: Data validation, sanitization, and transformation.
// 4. LLM Processing: Interaction with the Large Language Model.
// 5. Output Guardrails: Post-processing of LLM responses for safety and compliance.
// 6. Output Moderation: Final content screening before delivery to the user.
//
// Throughout these stages, a detailed audit trail is maintained, capturing
// every decision, transformation, and interaction, providing unparalleled
// transparency and forensic capabilities. Metrics are also diligently collected
// to monitor the system's performance and identify areas for optimization.

func (e *Engine) ProcessRequest(ctx context.Context, req *types.GovernanceRequest) (*types.GovernanceResponse, error) {
	// Ensure the engine is operational before processing any requests.
	if e.closed {
		return nil, fmt.Errorf("governance engine is closed")
	}

	startTime := time.Now()
	requestID := req.ID // Use the ID from the request, or generate a new one if empty.
	if requestID == "" {
		requestID = generateRequestID()
		req.ID = requestID // Assign the generated ID back to the request.
	}

	// Log the initiation of a new governance request for traceability.
	e.logger.Info("Processing governance request", "request_id", requestID, "user_id", req.UserID)

	// Initialize an audit entry to record all steps and decisions made during processing.
	auditEntry := &types.AuditEntry{
		RequestID:   requestID,
		UserID:      req.UserID,
		Timestamp:   startTime,
		InputPrompt: req.Prompt,
		Metadata:    req.Metadata,
		Steps:       make([]types.AuditStep, 0), // Prepare for detailed step-by-step logging.
	}

	// Initialize the response structure. This will be updated throughout the pipeline.
	response := &types.GovernanceResponse{
		RequestID: requestID,
		Status:    types.StatusProcessing,
		Metadata:  make(map[string]interface{}),
	}

	// Step 1: Input Moderation
	// This phase checks the incoming user prompt for any content that violates
	// predefined safety or ethical guidelines. If enabled, it's a critical
	// first line of defense.
	if e.config.Moderation.Enabled {
		moderationResult, err := e.moderationSvc.ModerateInput(ctx, req.Prompt, req.UserID)
		if err != nil {
			// Log the error and set the response status to indicate failure.
			e.logger.Error("Input moderation failed", "request_id", requestID, "error", err)
			response.Status = types.StatusError
			response.Error = "Input moderation failed"
			e.metrics.IncrementErrors("input_moderation")
			return response, err
		}

		// Record the outcome of the input moderation step in the audit trail.
		auditEntry.Steps = append(auditEntry.Steps, types.AuditStep{
			Step:      "input_moderation",
			Timestamp: time.Now(),
			Result:    moderationResult,
		})

		// If moderation flags the content as blocked, short-circuit the pipeline
		// and return a blocked response immediately.
		if moderationResult.Blocked {
			response.Status = types.StatusBlocked
			response.Reason = moderationResult.Reason
			response.Metadata["moderation"] = moderationResult
			e.auditSvc.LogEntry(auditEntry) // Log the blocking decision for auditability.
			e.metrics.IncrementBlocked("input_moderation") // Record the blocked request for metrics.
			return response, nil
		}
	}

	// Step 2: Policy Evaluation
	// This phase evaluates the request against a set of defined governance policies
	// (e.g., Rego policies). It determines if the request is allowed, blocked, or
	// requires further review based on organizational rules.
	policyResult, err := e.policyEngine.Evaluate(ctx, &policy.EvaluationRequest{
		Input:     req.Prompt,
		UserID:    req.UserID,
		Context:   req.Context,
		Metadata:  req.Metadata,
	})
	if err != nil {
		// A failure in policy evaluation is a critical error.
		return nil, fmt.Errorf("policy evaluation failed: %w", err)
	}

	// Record the outcome of the policy evaluation step.
	auditEntry.Steps = append(auditEntry.Steps, types.AuditStep{
		Step:      "policy_evaluation",
		Timestamp: time.Now(),
		Result:    policyResult,
	})

	// If policies dictate that the request is not allowed, block it.
	if !policyResult.Allowed {
		response.Status = types.StatusBlocked
		response.Reason = policyResult.Reason
		response.Metadata["policy"] = policyResult
		e.auditSvc.LogEntry(auditEntry) // Log the blocking decision for auditability.
		e.metrics.IncrementBlocked("policy_evaluation") // Record the blocked request for metrics.
		return response, nil
	}

	// Step 3: Input Guardrails
	// Guardrails provide additional checks and potential transformations on the input.
	// This can include data sanitization, PII detection, or format validation.
	if e.config.Guardrails.Enabled {
		guardrailResult, err := e.guardrailsSvc.ValidateInput(ctx, req.Prompt, req.Context)
		if err != nil {
			// Log the error and set the response status.
			e.logger.Error("Input guardrails failed", "request_id", requestID, "error", err)
			response.Status = types.StatusError
			response.Error = "Input guardrails failed"
			e.metrics.IncrementErrors("input_guardrails")
			return response, err
		}

		// Record the outcome of the input guardrails step.
		auditEntry.Steps = append(auditEntry.Steps, types.AuditStep{
			Step:      "input_guardrails",
			Timestamp: time.Now(),
			Result:    guardrailResult,
		})

		// If guardrails block the content, return a blocked response.
		if !guardrailResult.Valid {
			response.Status = types.StatusBlocked
			response.Reason = guardrailResult.Reason
			response.Metadata["guardrails"] = guardrailResult
			e.auditSvc.LogEntry(auditEntry) // Log the blocking decision for auditability.
			e.metrics.IncrementBlocked("input_guardrails") // Record the blocked request for metrics.
			return response, nil
		}

		// Apply any transformations suggested by the guardrails.
		if guardrailResult.TransformedInput != "" {
			req.Prompt = guardrailResult.TransformedInput
		}
	}

	// Step 4: LLM Processing
	// This is where the request is sent to the appropriate Large Language Model
	// via its adapter. The LLM generates a response based on the (potentially
	// transformed) input.
	var llmResponse *types.LLMResponse
	if req.LLMAdapter != "" {
		adapter, exists := e.llmAdapters[req.LLMAdapter]
		if !exists {
			// If the requested LLM adapter is not found, it's an error.
			response.Status = types.StatusError
			response.Error = fmt.Sprintf("LLM adapter '%s' not found", req.LLMAdapter)
			e.metrics.IncrementErrors("llm_adapter_not_found") // Record the error for metrics.
			return response, fmt.Errorf("LLM adapter '%s' not found", req.LLMAdapter)
		}

		// Generate response using the selected LLM adapter.
		llmResponse, err = adapter.Generate(ctx, &types.LLMRequest{
			Prompt:    req.Prompt,
			Options:   req.LLMOptions,
		})
		if err != nil {
			// Log LLM generation errors.
			e.logger.Error("LLM generation failed", "request_id", requestID, "adapter", req.LLMAdapter, "error", err)
			response.Status = types.StatusError
			response.Error = "LLM generation failed"
			e.metrics.IncrementErrors("llm_generation") // Record the error for metrics.
			return response, err
		}

		// Record the LLM generation outcome.
		auditEntry.Steps = append(auditEntry.Steps, types.AuditStep{
			Step:      "llm_generation",
			Timestamp: time.Now(),
			Result:    llmResponse,
		})

		// Store the LLM's response and relevant metadata.
		response.LLMResponse = llmResponse.Content
		response.Metadata["llm"] = map[string]interface{}{
			"adapter":      req.LLMAdapter,
			"model":        llmResponse.Model,
			"tokens_used":  llmResponse.TokensUsed,
			"finish_reason": llmResponse.FinishReason,
		}
	}

	// Step 5: Output Guardrails
	// Similar to input guardrails, this phase applies checks and transformations
	// to the LLM's generated output to ensure it meets safety and compliance standards.
	if e.config.Guardrails.Enabled && llmResponse != nil {
		outputGuardrailResult, err := e.guardrailsSvc.ValidateOutput(ctx, llmResponse.Content, req.Context)
		if err != nil {
			// Log errors during output guardrail validation.
			e.logger.Error("Output guardrails failed", "request_id", requestID, "error", err)
			response.Status = types.StatusError
			response.Error = "Output guardrails failed"
			e.metrics.IncrementErrors("output_guardrails") // Record the error for metrics.
			return response, err
		}

		// Record the outcome of the output guardrails step.
		auditEntry.Steps = append(auditEntry.Steps, types.AuditStep{
			Step:      "output_guardrails",
			Timestamp: time.Now(),
			Result:    outputGuardrailResult,
		})

		// If output guardrails block the content, return a blocked response.
		if !outputGuardrailResult.Valid {
			response.Status = types.StatusBlocked
			response.Reason = outputGuardrailResult.Reason
			response.Metadata["output_guardrails"] = outputGuardrailResult
			e.auditSvc.LogEntry(auditEntry) // Log the blocking decision for auditability.
			e.metrics.IncrementBlocked("output_guardrails") // Record the blocked request for metrics.
			return response, nil
		}

		// Apply any transformations to the LLM's output.
		if outputGuardrailResult.TransformedOutput != "" {
			response.LLMResponse = outputGuardrailResult.TransformedOutput
		}
	}

	// Step 6: Output Moderation
	// The final moderation pass on the LLM's output to ensure it meets all
	// safety and compliance requirements before being sent back to the user.
	if e.config.Moderation.Enabled && llmResponse != nil {
		outputModerationResult, err := e.moderationSvc.ModerateOutput(ctx, response.LLMResponse, req.UserID)
		if err != nil {
			// Log errors during output moderation.
			e.logger.Error("Output moderation failed", "request_id", requestID, "error", err)
			response.Status = types.StatusError
			response.Error = "Output moderation failed"
			e.metrics.IncrementErrors("output_moderation") // Record the error for metrics.
			return response, err
		}

		// Record the outcome of the output moderation step.
		auditEntry.Steps = append(auditEntry.Steps, types.AuditStep{
			Step:      "output_moderation",
			Timestamp: time.Now(),
			Result:    outputModerationResult,
		})

		// If output moderation blocks the content, return a blocked response.
		if outputModerationResult.Blocked {
			response.Status = types.StatusBlocked
			response.Reason = outputModerationResult.Reason
			response.Metadata["output_moderation"] = outputModerationResult
			e.auditSvc.LogEntry(auditEntry) // Log the blocking decision for auditability.
			e.metrics.IncrementBlocked("output_moderation") // Record the blocked request for metrics.
			return response, nil
		}
	}

	// Final step: If all checks pass, the request is allowed.
	response.Status = types.StatusAllowed
	processingTime := time.Since(startTime)
	response.Metadata["processing_time_ms"] = processingTime.Milliseconds()

	// Complete the audit entry with final response details.
	auditEntry.OutputResponse = response.LLMResponse
	auditEntry.Status = string(response.Status)
	auditEntry.ProcessingTime = processingTime

	// Log the final audit entry, providing a comprehensive record of the request's journey.
	e.auditSvc.LogEntry(auditEntry)

	// Update performance metrics, offering insights into the engine's operational efficiency.
	e.metrics.IncrementProcessed()
	e.metrics.RecordProcessingTime(processingTime)

	// Log the successful processing of the governance request.
	e.logger.Info("Governance request processed successfully", 
		"request_id", requestID, 
		"status", response.Status,
		"processing_time_ms", processingTime.Milliseconds())

	return response, nil
}

// GetLLMAdapters returns a list of names of all initialized LLM adapters.
// This is useful for dynamically querying available AI model integrations.
func (e *Engine) GetLLMAdapters() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()

	adapters := make([]string, 0, len(e.llmAdapters))
	for name := range e.llmAdapters {
		adapters = append(adapters, name)
	}
	return adapters
}

// GetMetrics returns the current metrics snapshot for the governance engine.
// This provides insights into performance, request volumes, and error rates.
func (e *Engine) GetMetrics() *Metrics {
	return e.metrics
}

// Health returns the current health status of the entire governance engine
// and its sub-components. This provides a comprehensive overview of the
// system's operational state.
func (e *Engine) Health() types.ComponentHealth {
	status := types.ComponentHealth{
		Status:    types.HealthStatusHealthy,
		Timestamp: time.Now(),
		Components: make(map[string]types.ComponentHealth), // Map to hold health of individual components
	}

	// Check the health of the policy engine and update overall status if degraded.
	policyHealth := e.policyEngine.Health()
	if policyHealth.Status != types.HealthStatusHealthy {
		status.Status = types.HealthStatusDegraded
	}
	status.Components["policy_engine"] = policyHealth

	// Check the health of the moderation service.
	moderationHealth := e.moderationSvc.Health()
	if moderationHealth.Status != types.HealthStatusHealthy {
		status.Status = types.HealthStatusDegraded
	}
	status.Components["moderation"] = moderationHealth

	// Check the health of the guardrails service.
	guardrailsHealth := e.guardrailsSvc.Health()
	if guardrailsHealth.Status != types.HealthStatusHealthy {
		status.Status = types.HealthStatusDegraded
	}
	status.Components["guardrails"] = guardrailsHealth

	// Check the health of the audit service.
	auditHealth := e.auditSvc.Health()
	if auditHealth.Status != types.HealthStatusHealthy {
		status.Status = types.HealthStatusDegraded
	}
	status.Components["audit"] = auditHealth

	// Iterate through all initialized LLM adapters and check their health.
	for name, adapter := range e.llmAdapters {
		adapterHealth := adapter.Health()
		if adapterHealth.Status != types.HealthStatusHealthy {
			status.Status = types.HealthStatusDegraded
		}
		status.Components["llm_"+name] = adapterHealth
	}

	return status
}

// Close gracefully shuts down the governance engine and all its sub-components.
// This ensures proper resource release and state persistence.
func (e *Engine) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Prevent multiple shutdown attempts.
	if e.closed {
		return nil
	}

	e.logger.Info("Shutting down governance engine")

	// Collect any errors encountered during component shutdown.
	var errors []error

	// Attempt to close each major component.
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

	// Close all LLM adapters.
	for name, adapter := range e.llmAdapters {
		if err := adapter.Close(); err != nil {
			errors = append(errors, fmt.Errorf("LLM adapter %s close error: %w", name, err))
		}
	}

	// Mark the engine as closed.
	e.closed = true

	// Return a combined error if any component failed to close gracefully.
	if len(errors) > 0 {
		return fmt.Errorf("errors during shutdown: %v", errors)
	}

	e.logger.Info("Governance engine shut down successfully")
	return nil
}

// generateRequestID creates a unique identifier for each governance request.
// This is crucial for traceability and auditing throughout the pipeline, ensuring
// non-predictability and robust tracking for "AI bypass" scenarios.
func generateRequestID() string {
	return uuid.New().String()
}