package security

import (
	"regexp"
	"sync"
	"time"
)

// ThreatSignatureDB manages threat signatures for pattern-based detection
type ThreatSignatureDB struct {
	signatures map[string]*ThreatSignature
	categories map[string][]*ThreatSignature
	mutex      sync.RWMutex
}

// AnomalyDetector implements statistical anomaly detection algorithms
type AnomalyDetector struct {
	models map[string]*StatisticalModel
	mutex  sync.RWMutex
}

// RiskCalculator computes risk scores based on multiple factors
type RiskCalculator struct {
	weights map[string]float64
	mutex   sync.RWMutex
}

// StatisticalModel represents a statistical model for anomaly detection
type StatisticalModel struct {
	Mean       float64   `json:"mean"`
	StdDev     float64   `json:"std_dev"`
	Samples    []float64 `json:"samples"`
	LastUpdate time.Time `json:"last_update"`
}

// NewThreatSignatureDB creates a new threat signature database
func NewThreatSignatureDB() *ThreatSignatureDB {
	db := &ThreatSignatureDB{
		signatures: make(map[string]*ThreatSignature),
		categories: make(map[string][]*ThreatSignature),
	}
	
	// Initialize with default signatures
	db.loadDefaultSignatures()
	
	return db
}

// loadDefaultSignatures loads built-in threat signatures
func (db *ThreatSignatureDB) loadDefaultSignatures() {
	defaultSignatures := []*ThreatSignature{
		{
			ID:                "SQL_INJECTION_001",
			Name:              "SQL Injection - UNION Attack",
			Category:          "injection",
			Severity:          5,
			PatternString:     `(?i)(union\s+select|union\s+all\s+select)`,
			Description:       "Detects SQL injection attempts using UNION statements",
			Indicators:        []string{"union", "select", "sql"},
			FalsePositiveRate: 0.02,
			LastUpdated:       time.Now(),
			Active:            true,
		},
		{
			ID:                "XSS_001",
			Name:              "Cross-Site Scripting - Script Tag",
			Category:          "xss",
			Severity:          4,
			PatternString:     `(?i)<script[^>]*>.*?</script>`,
			Description:       "Detects XSS attempts using script tags",
			Indicators:        []string{"script", "javascript", "xss"},
			FalsePositiveRate: 0.01,
			LastUpdated:       time.Now(),
			Active:            true,
		},
		{
			ID:                "CMD_INJECTION_001",
			Name:              "Command Injection - Shell Commands",
			Category:          "injection",
			Severity:          5,
			PatternString:     `(?i)(;|\||&|` + "`" + `)\s*(ls|cat|wget|curl|nc|bash|sh|cmd|powershell)`,
			Description:       "Detects command injection attempts",
			Indicators:        []string{"command", "shell", "injection"},
			FalsePositiveRate: 0.03,
			LastUpdated:       time.Now(),
			Active:            true,
		},
		{
			ID:                "PATH_TRAVERSAL_001",
			Name:              "Path Traversal Attack",
			Category:          "traversal",
			Severity:          4,
			PatternString:     `(\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e%5c){2,}`,
			Description:       "Detects directory traversal attempts",
			Indicators:        []string{"traversal", "directory", "path"},
			FalsePositiveRate: 0.01,
			LastUpdated:       time.Now(),
			Active:            true,
		},
		{
			ID:                "PROMPT_INJECTION_001",
			Name:              "AI Prompt Injection",
			Category:          "ai_attack",
			Severity:          3,
			PatternString:     `(?i)(ignore\s+previous\s+instructions|disregard\s+safety|bypass\s+restrictions)`,
			Description:       "Detects AI prompt injection attempts",
			Indicators:        []string{"prompt", "injection", "ai"},
			FalsePositiveRate: 0.05,
			LastUpdated:       time.Now(),
			Active:            true,
		},
	}
	
	for _, sig := range defaultSignatures {
		sig.Pattern = regexp.MustCompile(sig.PatternString)
		db.signatures[sig.ID] = sig
		db.categories[sig.Category] = append(db.categories[sig.Category], sig)
	}
}

// GetActiveSignatures returns all active threat signatures
func (db *ThreatSignatureDB) GetActiveSignatures() []*ThreatSignature {
	db.mutex.RLock()
	defer db.mutex.RUnlock()
	
	active := make([]*ThreatSignature, 0)
	for _, sig := range db.signatures {
		if sig.Active {
			active = append(active, sig)
		}
	}
	
	return active
}

// AddSignature adds a new threat signature
func (db *ThreatSignatureDB) AddSignature(sig *ThreatSignature) error {
	pattern, err := regexp.Compile(sig.PatternString)
	if err != nil {
		return err
	}
	
	sig.Pattern = pattern
	sig.LastUpdated = time.Now()
	
	db.mutex.Lock()
	defer db.mutex.Unlock()
	
	db.signatures[sig.ID] = sig
	db.categories[sig.Category] = append(db.categories[sig.Category], sig)
	
	return nil
}

// UpdateSignature updates an existing signature
func (db *ThreatSignatureDB) UpdateSignature(id string, updates map[string]interface{}) error {
	db.mutex.Lock()
	defer db.mutex.Unlock()
	
	sig, exists := db.signatures[id]
	if !exists {
		return nil
	}
	
	// Apply updates
	if pattern, ok := updates["pattern"].(string); ok {
		compiled, err := regexp.Compile(pattern)
		if err != nil {
			return err
		}
		sig.PatternString = pattern
		sig.Pattern = compiled
	}
	
	if active, ok := updates["active"].(bool); ok {
		sig.Active = active
	}
	
	if severity, ok := updates["severity"].(int); ok {
		sig.Severity = severity
	}
	
	sig.LastUpdated = time.Now()
	
	return nil
}

// NewAnomalyDetector creates a new anomaly detector
func NewAnomalyDetector() *AnomalyDetector {
	return &AnomalyDetector{
		models: make(map[string]*StatisticalModel),
	}
}

// UpdateModel updates a statistical model with new data
func (ad *AnomalyDetector) UpdateModel(modelName string, value float64) {
	ad.mutex.Lock()
	defer ad.mutex.Unlock()
	
	model, exists := ad.models[modelName]
	if !exists {
		model = &StatisticalModel{
			Samples: make([]float64, 0),
		}
		ad.models[modelName] = model
	}
	
	model.Samples = append(model.Samples, value)
	
	// Keep only recent samples (sliding window)
	if len(model.Samples) > 1000 {
		model.Samples = model.Samples[1:]
	}
	
	// Recalculate statistics
	ad.recalculateStats(model)
	model.LastUpdate = time.Now()
}

// DetectAnomaly detects if a value is anomalous for a given model
func (ad *AnomalyDetector) DetectAnomaly(modelName string, value float64, threshold float64) bool {
	ad.mutex.RLock()
	defer ad.mutex.RUnlock()
	
	model, exists := ad.models[modelName]
	if !exists || len(model.Samples) < 10 {
		return false // Not enough data
	}
	
	// Calculate z-score
	if model.StdDev == 0 {
		return false
	}
	
	zScore := (value - model.Mean) / model.StdDev
	return zScore > threshold || zScore < -threshold
}

// recalculateStats recalculates mean and standard deviation
func (ad *AnomalyDetector) recalculateStats(model *StatisticalModel) {
	if len(model.Samples) == 0 {
		return
	}
	
	// Calculate mean
	sum := 0.0
	for _, sample := range model.Samples {
		sum += sample
	}
	model.Mean = sum / float64(len(model.Samples))
	
	// Calculate standard deviation
	variance := 0.0
	for _, sample := range model.Samples {
		diff := sample - model.Mean
		variance += diff * diff
	}
	variance /= float64(len(model.Samples))
	model.StdDev = variance
}

// NewRiskCalculator creates a new risk calculator
func NewRiskCalculator() *RiskCalculator {
	return &RiskCalculator{
		weights: map[string]float64{
			"signature_match":     0.8,
			"behavioral_anomaly":  0.6,
			"geographic_anomaly":  0.4,
			"temporal_anomaly":    0.3,
			"frequency_anomaly":   0.5,
			"content_entropy":     0.2,
			"user_trust_score":    -0.3, // Negative weight (higher trust = lower risk)
		},
	}
}

// CalculateRisk calculates overall risk score from multiple factors
func (rc *RiskCalculator) CalculateRisk(factors map[string]float64) float64 {
	rc.mutex.RLock()
	defer rc.mutex.RUnlock()
	
	totalRisk := 0.0
	totalWeight := 0.0
	
	for factor, value := range factors {
		if weight, exists := rc.weights[factor]; exists {
			totalRisk += value * weight
			totalWeight += weight
		}
	}
	
	if totalWeight == 0 {
		return 0.0
	}
	
	// Normalize risk score to 0-1 range
	normalizedRisk := totalRisk / totalWeight
	if normalizedRisk < 0 {
		return 0.0
	}
	if normalizedRisk > 1 {
		return 1.0
	}
	
	return normalizedRisk
}

// UpdateWeights updates risk calculation weights
func (rc *RiskCalculator) UpdateWeights(newWeights map[string]float64) {
	rc.mutex.Lock()
	defer rc.mutex.Unlock()
	
	for factor, weight := range newWeights {
		rc.weights[factor] = weight
	}
}
