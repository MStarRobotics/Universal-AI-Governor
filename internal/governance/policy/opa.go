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

// Engine interface for policy evaluation
type Engine interface {
	Evaluate(ctx context.Context, req *EvaluationRequest) (*types.PolicyResult, error)
	LoadPolicies() error
	Health() types.ComponentHealth
	Close() error
}

// EvaluationRequest represents a policy evaluation request
type EvaluationRequest struct {
	Input    string                 `json:"input"`
	UserID   string                 `json:"user_id"`
	Context  map[string]interface{} `json:"context"`
	Metadata map[string]interface{} `json:"metadata"`
}

// OPAEngine implements the policy engine using Open Policy Agent
type OPAEngine struct {
	config  config.PolicyEngineConfig
	logger  logging.Logger
	store   storage.Store
	queries map[string]*rego.PreparedEvalQuery
}

// NewOPAEngine creates a new OPA-based policy engine
func NewOPAEngine(config config.PolicyEngineConfig, logger logging.Logger) (*OPAEngine, error) {
	engine := &OPAEngine{
		config:  config,
		logger:  logger,
		store:   inmem.New(),
		queries: make(map[string]*rego.PreparedEvalQuery),
	}

	// Load policies
	if err := engine.LoadPolicies(); err != nil {
		return nil, fmt.Errorf("failed to load policies: %w", err)
	}

	// Load data
	if err := engine.loadData(); err != nil {
		return nil, fmt.Errorf("failed to load data: %w", err)
	}

	logger.Info("OPA policy engine initialized successfully")
	return engine, nil
}

// Evaluate evaluates a request against loaded policies
func (e *OPAEngine) Evaluate(ctx context.Context, req *EvaluationRequest) (*types.PolicyResult, error) {
	// Prepare input for OPA
	input := map[string]interface{}{
		"prompt":   req.Input,
		"user_id":  req.UserID,
		"context":  req.Context,
		"metadata": req.Metadata,
	}

	// Get or create prepared query for the main policy
	query, exists := e.queries["main"]
	if !exists {
		var err error
		query, err = e.prepareQuery("data.governor.base.allow", "data.governor.base.reason")
		if err != nil {
			return nil, fmt.Errorf("failed to prepare query: %w", err)
		}
		e.queries["main"] = query
	}

	// Execute query
	results, err := query.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		e.logger.Error("Policy evaluation failed", "error", err, "user_id", req.UserID)
		return &types.PolicyResult{
			Allowed: false,
			Reason:  "Policy evaluation error",
			Metadata: map[string]interface{}{
				"error": err.Error(),
			},
		}, nil
	}

	// Process results
	if len(results) == 0 {
		return &types.PolicyResult{
			Allowed: false,
			Reason:  "No policy results",
		}, nil
	}

	result := results[0]
	
	// Extract allow decision
	allowed := false
	if allowValue, ok := result.Bindings["allow"]; ok {
		if allowBool, ok := allowValue.(bool); ok {
			allowed = allowBool
		}
	}

	// Extract reason
	reason := ""
	if reasonValue, ok := result.Bindings["reason"]; ok {
		if reasonStr, ok := reasonValue.(string); ok {
			reason = reasonStr
		}
	}

	// Get applied policies
	policies := e.getAppliedPolicies(result)

	policyResult := &types.PolicyResult{
		Allowed:  allowed,
		Reason:   reason,
		Policies: policies,
		Metadata: map[string]interface{}{
			"evaluation_time": time.Now(),
			"input_hash":      e.hashInput(input),
		},
	}

	e.logger.Debug("Policy evaluation completed",
		"user_id", req.UserID,
		"allowed", allowed,
		"reason", reason,
		"policies", policies,
	)

	return policyResult, nil
}

// LoadPolicies loads all policy files from the configured directory
func (e *OPAEngine) LoadPolicies() error {
	e.logger.Info("Loading policies from directory", "policy_dir", e.config.PolicyDir)

	// Walk through policy directory
	err := filepath.WalkDir(e.config.PolicyDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// Skip directories and non-rego files
		if d.IsDir() || !strings.HasSuffix(path, ".rego") {
			return nil
		}

		// Read policy file
		content, err := os.ReadFile(path)
		if err != nil {
			e.logger.Error("Failed to read policy file", "path", path, "error", err)
			return err
		}

		// Create module name from file path
		relPath, _ := filepath.Rel(e.config.PolicyDir, path)
		moduleName := strings.TrimSuffix(relPath, ".rego")
		moduleName = strings.ReplaceAll(moduleName, "/", ".")

		// Store policy in OPA store
		txn, err := e.store.NewTransaction(context.Background(), storage.WriteParams)
		if err != nil {
			return fmt.Errorf("failed to create transaction: %w", err)
		}

		if err := e.store.UpsertPolicy(context.Background(), txn, moduleName, content); err != nil {
			e.store.Abort(context.Background(), txn)
			return fmt.Errorf("failed to upsert policy: %w", err)
		}

		if err := e.store.Commit(context.Background(), txn); err != nil {
			return fmt.Errorf("failed to commit transaction: %w", err)
		}

		e.logger.Info("Loaded policy", "module", moduleName, "path", path)
		return nil
	})

	if err != nil {
		return fmt.Errorf("failed to load policies: %w", err)
	}

	// Clear cached queries since policies changed
	e.queries = make(map[string]*rego.PreparedEvalQuery)

	e.logger.Info("Successfully loaded all policies")
	return nil
}

// loadData loads data files for policy evaluation
func (e *OPAEngine) loadData() error {
	if e.config.DataDir == "" {
		return nil
	}

	e.logger.Info("Loading data from directory", "data_dir", e.config.DataDir)

	err := filepath.WalkDir(e.config.DataDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// Skip directories and non-JSON files
		if d.IsDir() || !strings.HasSuffix(path, ".json") {
			return nil
		}

		// Read data file
		content, err := os.ReadFile(path)
		if err != nil {
			e.logger.Error("Failed to read data file", "path", path, "error", err)
			return err
		}

		// Parse JSON
		var data interface{}
		if err := json.Unmarshal(content, &data); err != nil {
			e.logger.Error("Failed to parse data file", "path", path, "error", err)
			return err
		}

		// Create data path from file path
		relPath, _ := filepath.Rel(e.config.DataDir, path)
		dataPath := strings.TrimSuffix(relPath, ".json")
		dataPath = strings.ReplaceAll(dataPath, "/", ".")

		// Store data in OPA store
		txn, err := e.store.NewTransaction(context.Background(), storage.WriteParams)
		if err != nil {
			return fmt.Errorf("failed to create transaction: %w", err)
		}

		storagePath := storage.MustParsePath("/" + strings.ReplaceAll(dataPath, ".", "/"))
		if err := e.store.Write(context.Background(), txn, storage.AddOp, storagePath, data); err != nil {
			e.store.Abort(context.Background(), txn)
			return fmt.Errorf("failed to write data: %w", err)
		}

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

// prepareQuery creates a prepared query for the given expressions
func (e *OPAEngine) prepareQuery(expressions ...string) (*rego.PreparedEvalQuery, error) {
	// Create rego query
	r := rego.New(
		rego.Query(strings.Join(expressions, "; ")),
		rego.Store(e.store),
	)

	// Prepare query
	query, err := r.PrepareForEval(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to prepare query: %w", err)
	}

	return &query, nil
}

// getAppliedPolicies extracts the list of applied policies from evaluation results
func (e *OPAEngine) getAppliedPolicies(result rego.Result) []string {
	// This is a simplified implementation
	// In a real scenario, you might want to track which policies were evaluated
	policies := []string{"base"}
	
	// Add more sophisticated policy tracking here
	return policies
}

// hashInput creates a hash of the input for caching/tracking purposes
func (e *OPAEngine) hashInput(input map[string]interface{}) string {
	// Simple hash implementation
	data, _ := json.Marshal(input)
	return fmt.Sprintf("%x", sha256.Sum256(data))[:16]
}

// Health returns the health status of the policy engine
func (e *OPAEngine) Health() types.ComponentHealth {
	// Check if store is accessible
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	txn, err := e.store.NewTransaction(ctx, storage.TransactionParams{})
	if err != nil {
		return types.ComponentHealth{
			Status:    types.HealthStatusUnhealthy,
			Message:   fmt.Sprintf("Failed to create transaction: %v", err),
			Timestamp: time.Now(),
		}
	}
	e.store.Abort(ctx, txn)

	// Check if policies are loaded
	if len(e.queries) == 0 {
		return types.ComponentHealth{
			Status:    types.HealthStatusDegraded,
			Message:   "No policies loaded",
			Timestamp: time.Now(),
		}
	}

	return types.ComponentHealth{
		Status:    types.HealthStatusHealthy,
		Message:   "Policy engine operational",
		Timestamp: time.Now(),
		Metadata: map[string]interface{}{
			"loaded_queries": len(e.queries),
		},
	}
}

// Close gracefully shuts down the policy engine
func (e *OPAEngine) Close() error {
	e.logger.Info("Shutting down OPA policy engine")
	
	// Clear queries
	e.queries = make(map[string]*rego.PreparedEvalQuery)
	
	// Note: inmem store doesn't need explicit closing
	return nil
}
