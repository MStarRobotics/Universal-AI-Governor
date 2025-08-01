package policy

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/storage/inmem"
	"github.com/universal-ai-governor/internal/config"
	"github.com/universal-ai-governor/internal/logging"
	"github.com/universal-ai-governor/internal/types"
)

// Engine defines the interface for a policy evaluation engine.
// This component is responsible for interpreting and enforcing governance rules.
type Engine interface {
	// Evaluate assesses a given request against the loaded policies.
	// It returns a PolicyResult indicating whether the request is allowed,
	// blocked, or requires further action, along with reasons and metadata.
	Evaluate(ctx context.Context, req *EvaluationRequest) (*types.PolicyResult, error)

	// LoadPolicies loads or reloads all policy definitions from their source.
	// This allows for dynamic updates to governance rules without restarting the engine.
	LoadPolicies() error

	// Health returns the current operational status of the policy engine.
	// It indicates whether the engine is functioning correctly and its readiness
	// to evaluate policies.
	Health() types.ComponentHealth

	// Close gracefully shuts down the policy engine, releasing any allocated resources.
	Close() error
}

// EvaluationRequest encapsulates all information needed by the policy engine
// to make a governance decision. This includes the input prompt, user context,
// and any relevant metadata.
type EvaluationRequest struct {
	Input    string                 `json:"input"`    // The primary content to be evaluated (e.g., LLM prompt)
	UserID   string                 `json:"user_id"`  // Identifier for the user initiating the request
	Context  map[string]interface{} `json:"context"`  // Additional contextual data for policy evaluation
	Metadata map[string]interface{} `json:"metadata"` // Arbitrary metadata for policy decisions
}

// OPAEngine implements the Engine interface using Open Policy Agent (OPA).
// OPA provides a powerful and declarative language (Rego) for defining policies,
// making it suitable for complex governance rules.
type OPAEngine struct {
	config  config.PolicyEngineConfig      // Configuration specific to the OPA engine
	logger  logging.Logger                 // Logger for engine-specific events
	store   storage.Store                  // OPA's in-memory data store for policies and data
	queries map[string]*rego.PreparedEvalQuery // Cache for prepared OPA queries for efficiency
}

// NewOPAEngine creates a new instance of the OPA-based policy engine.
// It initializes the OPA store and attempts to load policies and data
// from the configured directories.
func NewOPAEngine(config config.PolicyEngineConfig, logger logging.Logger) (*OPAEngine, error) {
	engine := &OPAEngine{
		config:  config,
		logger:  logger,
		store:   inmem.New(), // Using an in-memory store for simplicity; can be replaced with persistent storage
		queries: make(map[string]*rego.PreparedEvalQuery), // Initialize query cache
	}

	// Attempt to load policies from the specified directory. This is a crucial step
	// as the engine cannot function without its governance rules.
	if err := engine.LoadPolicies(); err != nil {
		return nil, fmt.Errorf("failed to load policies: %w", err)
	}

	// Load any external data required for policy evaluation (e.g., user roles, external threat intelligence).
	if err := engine.loadData(); err != nil {
		return nil, fmt.Errorf("failed to load data: %w", err)
	}

	logger.Info("OPA policy engine initialized successfully")
	return engine, nil
}

// Evaluate assesses a given request against the loaded policies.
// This function is the intellectual core of the policy engine, where abstract
// governance rules are transformed into concrete, auditable decisions. It plays
// a pivotal role in achieving the "humanization effect" by ensuring that AI
// behavior aligns with predefined ethical, legal, and operational boundaries.
// By providing clear reasons for decisions (allow/block), it contributes to
// the "AI bypass" of opaque black-box decision-making, offering transparency
// and accountability.
//
// The evaluation process involves:
// 1. Constructing a comprehensive input for the OPA engine, including the prompt,
//    user context, and relevant metadata.
// 2. Executing a pre-compiled Rego query against the OPA's in-memory store,
//    which contains all loaded policies and data.
// 3. Interpreting the OPA's decision, extracting the 'allow' status and the
//    'reason' for the decision, which are crucial for auditability and user feedback.
// 4. Identifying the specific policies that were applied during the evaluation,
//    providing a detailed lineage for each governance decision.
//
// This meticulous process ensures that every AI interaction is not just processed,
// but *governed* with precision and foresight.
func (e *OPAEngine) Evaluate(ctx context.Context, req *EvaluationRequest) (*types.PolicyResult, error) {
	// Prepare the input data structure that OPA expects.
	input := map[string]interface{}{
		"prompt":   req.Input,
		"user_id":  req.UserID,
		"context":  req.Context,
		"metadata": req.Metadata,
	}

	// Retrieve a prepared query from the cache, or create it if it doesn't exist.
	// Prepared queries are more efficient for repeated evaluations.
	query, exists := e.queries["main"]
	if !exists {
		var err error
		// Define the main policy query that determines allowance and reason.
		query, err = e.prepareQuery("data.governor.base.allow", "data.governor.base.reason")
		if err != nil {
			return nil, fmt.Errorf("failed to prepare query: %w", err)
		}
		e.queries["main"] = query // Cache the prepared query for future use.
	}

	// Execute the OPA query with the prepared input.
	results, err := query.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		// Log OPA evaluation errors for debugging and auditing.
		e.logger.Error("Policy evaluation failed", "error", err, "user_id", req.UserID)
		return &types.PolicyResult{
			Allowed: false,
			Reason:  "Policy evaluation error",
			Metadata: map[string]interface{}{
				"error": err.Error(),
			},
		}, nil
	}

	// Handle cases where no results are returned by OPA (e.g., no matching policy).
	if len(results) == 0 {
		return &types.PolicyResult{
			Allowed: false,
			Reason:  "No policy results",
		}, nil
	}

	result := results[0] // Assuming a single result for simplicity in this example.
	
	// Extract the 'allow' decision from OPA's evaluation result.
	allowed := false
	if allowValue, ok := result.Bindings["allow"]; ok {
		if allowBool, ok := allowValue.(bool); ok {
			allowed = allowBool
		}
	}

	// Extract the 'reason' for the decision from OPA's evaluation result.
	reason := ""
	if reasonValue, ok := result.Bindings["reason"]; ok {
		if reasonStr, ok := reasonValue.(string); ok {
			reason = reasonStr
		}
	}

	// Determine which policies were applied during the evaluation.
	policies := e.getAppliedPolicies(result)

	// Construct the final PolicyResult to be returned.
	policyResult := &types.PolicyResult{
		Allowed:  allowed,
		Reason:   reason,
		Policies: policies,
		Metadata: map[string]interface{}{
			"evaluation_time": time.Now(),
			"input_hash":      e.hashInput(input), // Hash input for traceability and caching.
		},
	}

	// Log the outcome of the policy evaluation for monitoring and debugging.
	e.logger.Debug("Policy evaluation completed",
		"user_id", req.UserID,
		"allowed", allowed,
		"reason", reason,
		"policies", policies,
	)

	return policyResult, nil
}

// LoadPolicies loads all policy files from the configured directory into the OPA store.
// This function is a cornerstone of the engine's adaptability and resilience.
// It enables dynamic updates to governance rules without requiring a service restart,
// embodying the principle of continuous governance. By allowing policies to be
// updated on the fly, it ensures that the AI system can rapidly adapt to evolving
// ethical considerations, regulatory changes, and emerging threats, thereby
// enhancing its "humanization effect" by staying aligned with human values and
// preventing "AI bypass" through outdated rules.
//
// The process involves:
// 1. Recursively traversing the specified policy directory.
// 2. Reading and parsing each Rego policy file.
// 3. Atomically updating the OPA's in-memory policy store within a transaction,
//    guaranteeing consistency and integrity.
// 4. Clearing any cached prepared queries to ensure that subsequent evaluations
//    utilize the newly loaded policies.
//
// This mechanism ensures that the governance framework remains agile and responsive
// to the dynamic landscape of AI ethics and regulation.
func (e *OPAEngine) LoadPolicies() error {
	e.logger.Info("Loading policies from directory", "policy_dir", e.config.PolicyDir)

	// Walk through the policy directory, processing each Rego file.
	err := filepath.WalkDir(e.config.PolicyDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err // Propagate errors encountered during directory traversal.
		}

		// Skip directories and only process files with the .rego extension.
		if d.IsDir() || !strings.HasSuffix(path, ".rego") {
			return nil
		}

		// Read the content of the Rego policy file.
		content, err := os.ReadFile(path)
		if err != nil {
			e.logger.Error("Failed to read policy file", "path", path, "error", err)
			return err
		}

		// Derive a unique module name for the policy from its file path.
		relPath, _ := filepath.Rel(e.config.PolicyDir, path)
		moduleName := strings.TrimSuffix(relPath, ".rego")
		moduleName = strings.ReplaceAll(moduleName, "/", ".") // Convert path separators to dots for OPA module naming.

		// Begin a new transaction to safely update the OPA policy store.
		txn, err := e.store.NewTransaction(context.Background(), storage.WriteParams)
		if err != nil {
			return fmt.Errorf("failed to create transaction: %w", err)
		}

		// Insert or update the policy in the OPA store.
		if err := e.store.UpsertPolicy(context.Background(), txn, moduleName, content); err != nil {
			e.store.Abort(context.Background(), txn) // Rollback transaction on error.
			return fmt.Errorf("failed to upsert policy: %w", err)
		}

		// Commit the transaction to make the policy changes permanent.
		if err := e.store.Commit(context.Background(), txn); err != nil {
			return fmt.Errorf("failed to commit transaction: %w", err)
		}

		e.logger.Info("Loaded policy", "module", moduleName, "path", path)
		return nil
	})

	if err != nil {
		return fmt.Errorf("failed to load policies: %w", err)
	}

	// Clear any previously cached prepared queries, as policies have changed.
	e.queries = make(map[string]*rego.PreparedEvalQuery)

	e.logger.Info("Successfully loaded all policies")
	return nil
}

// loadData loads external data files (e.g., JSON) into the OPA store.
// This function is crucial for providing context to policies, enabling them
// to make informed decisions based on dynamic external information. It supports
// the "humanization effect" by allowing policies to adapt to real-world data,
// such as user roles, threat intelligence feeds, or compliance registries.
// By integrating external data, the policy engine can achieve a more nuanced
// and context-aware governance, preventing "AI bypass" through data-driven
// policy enforcement.
//
// The process involves:
// 1. Iterating through the configured data directory.
// 2. Parsing JSON files into Go data structures.
// 3. Storing this data in the OPA's in-memory store, making it accessible
//    to Rego policies during evaluation.
func (e *OPAEngine) loadData() error {
	// If no data directory is configured, there's nothing to load.
	if e.config.DataDir == "" {
		return nil
	}

	e.logger.Info("Loading data from directory", "data_dir", e.config.DataDir)

	// Walk through the data directory, processing each JSON file.
	err := filepath.WalkDir(e.config.DataDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err // Propagate errors encountered during directory traversal.
		}

		// Skip directories and only process files with the .json extension.
		if d.IsDir() || !strings.HasSuffix(path, ".json") {
			return nil
		}

		// Read the content of the JSON data file.
		content, err := os.ReadFile(path)
		if err != nil {
			e.logger.Error("Failed to read data file", "path", path, "error", err)
			return err
		}

		// Parse the JSON content into a generic interface.
		var data interface{}
		if err := json.Unmarshal(content, &data); err != nil {
			e.logger.Error("Failed to parse data file", "path", path, "error", err)
			return err
		}

		// Derive a data path for OPA from the file path.
		relPath, _ := filepath.Rel(e.config.DataDir, path)
		dataPath := strings.TrimSuffix(relPath, ".json")
		dataPath = strings.ReplaceAll(dataPath, "/", ".") // Convert path separators to dots for OPA data path.

		// Begin a new transaction to safely update the OPA data store.
		txn, err := e.store.NewTransaction(context.Background(), storage.WriteParams)
		if err != nil {
			return fmt.Errorf("failed to create transaction: %w", err)
		}

		// Write the data into the OPA store at the derived path.
		storagePath := storage.MustParsePath("/" + strings.ReplaceAll(dataPath, ".", "/"))
		if err := e.store.Write(context.Background(), txn, storage.AddOp, storagePath, data); err != nil {
			e.store.Abort(context.Background(), txn) // Rollback transaction on error.
			return fmt.Errorf("failed to write data: %w", err)
		}

		// Commit the transaction to make the data changes permanent.
		if err := e.store.Commit(context.Background(), txn); err != nil {
			return fmt.Errorf("failed to commit transaction: %w", err)
		}

		e.logger.Info("Loaded data", "path", dataPath, "file", path)
		return nil
	})

	if err != nil {
		return fmt.Errorf("failed to load data: %w", err)
	}

	e.logger.Info("Successfully loaded all data")
	return nil
}

// prepareQuery creates a prepared OPA evaluation query from a set of Rego expressions.
// Prepared queries are optimized for repeated execution.
func (e *OPAEngine) prepareQuery(expressions ...string) (*rego.PreparedEvalQuery, error) {
	// Construct the Rego query object.
	r := rego.New(
		rego.Query(strings.Join(expressions, "; ")), // Combine multiple expressions into a single query.
		rego.Store(e.store), // Associate the query with the OPA data store.
	)

	// Prepare the query for evaluation. This step performs parsing and compilation.
	query, err := r.PrepareForEval(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to prepare query: %w", err)
	}

	return &query, nil
}

// getAppliedPolicies extracts the names of policies that were evaluated and contributed
// to the decision from an OPA evaluation result. This is a simplified example;
// a more sophisticated implementation might parse OPA's trace or decision explanation.
func (e *OPAEngine) getAppliedPolicies(result rego.Result) []string {
	// TODO: Implement more sophisticated policy tracking based on OPA evaluation results.
	// For now, we return a hardcoded value.
	policies := []string{"base"}
	
	return policies
}

// hashInput generates a SHA256 hash of the input request.
// This hash can be used for caching, deduplication, or integrity checking.
func (e *OPAEngine) hashInput(input map[string]interface{}) string {
	// Marshal the input map to JSON bytes for consistent hashing.
	data, _ := json.Marshal(input)
	// Compute SHA256 hash and return its hexadecimal representation (truncated for brevity).
	return fmt.Sprintf("%x", sha256.Sum256(data))[:16]
}

// Health returns the current health status of the OPA policy engine.
// It checks the accessibility of the OPA store and whether policies are loaded.
func (e *OPAEngine) Health() types.ComponentHealth {
	// Use a context with a timeout to prevent indefinite blocking during health checks.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Attempt to create a transaction to verify store accessibility.
	txn, err := e.store.NewTransaction(ctx, storage.TransactionParams{})
	if err != nil {
		return types.ComponentHealth{
			Status:    types.HealthStatusUnhealthy,
			Message:   fmt.Sprintf("Failed to create OPA store transaction: %v", err),
			Timestamp: time.Now(),
		}
	}
	e.store.Abort(ctx, txn) // Abort the transaction as it was only for a health check.

	// Check if any policies have been successfully loaded into the engine.
	if len(e.queries) == 0 {
		return types.ComponentHealth{
			Status:    types.HealthStatusDegraded,
			Message:   "No policies loaded in OPA engine",
			Timestamp: time.Now(),
		}
	}

	// If both checks pass, the policy engine is considered healthy.
	return types.ComponentHealth{
		Status:    types.HealthStatusHealthy,
		Message:   "OPA policy engine operational",
		Timestamp: time.Now(),
		Metadata: map[string]interface{}{
			"loaded_queries": len(e.queries),
		},
	}
}

// Close gracefully shuts down the OPA policy engine.
// It clears any cached queries and logs the shutdown event.
func (e *OPAEngine) Close() error {
	e.logger.Info("Shutting down OPA policy engine")
	
	// Clear the query cache to release resources.
	e.queries = make(map[string]*rego.PreparedEvalQuery)
	
	// Note: For in-memory OPA stores, explicit closing is often not required,
	// but for persistent stores, this would involve closing database connections.
	return nil
}