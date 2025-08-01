package security

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ThreatDetectionEngine implements advanced behavioral analysis and anomaly detection
// using machine learning algorithms and statistical analysis for real-time threat identification
type ThreatDetectionEngine struct {
	behaviorProfiles    map[string]*UserBehaviorProfile
	anomalyDetector     *AnomalyDetector
	signatureDatabase   *ThreatSignatureDB
	riskCalculator      *RiskCalculator
	mutex               sync.RWMutex
	alertThreshold      float64
	learningEnabled     bool
	adaptiveThreshold   bool
}

// UserBehaviorProfile maintains statistical models of normal user behavior patterns
type UserBehaviorProfile struct {
	UserID              string                 `json:"user_id"`
	RequestFrequency    *FrequencyAnalyzer     `json:"request_frequency"`
	ContentPatterns     *PatternAnalyzer       `json:"content_patterns"`
	GeographicProfile   *GeographicAnalyzer    `json:"geographic_profile"`
	TemporalProfile     *TemporalAnalyzer      `json:"temporal_profile"`
	DeviceFingerprints  map[string]int         `json:"device_fingerprints"`
	TypicalIPRanges     []string               `json:"typical_ip_ranges"`
	LastUpdated         time.Time              `json:"last_updated"`
	TrustScore          float64                `json:"trust_score"`
	RiskFactors         []string               `json:"risk_factors"`
}

// ThreatSignature represents a known attack pattern or malicious behavior indicator
type ThreatSignature struct {
	ID                  string                 `json:"id"`
	Name                string                 `json:"name"`
	Category            string                 `json:"category"`
	Severity            int                    `json:"severity"`
	Pattern             *regexp.Regexp         `json:"-"`
	PatternString       string                 `json:"pattern"`
	Description         string                 `json:"description"`
	Indicators          []string               `json:"indicators"`
	FalsePositiveRate   float64                `json:"false_positive_rate"`
	LastUpdated         time.Time              `json:"last_updated"`
	Active              bool                   `json:"active"`
}

// ThreatAlert represents a detected security threat with contextual information
type ThreatAlert struct {
	ID                  string                 `json:"id"`
	Timestamp           time.Time              `json:"timestamp"`
	UserID              string                 `json:"user_id"`
	ThreatType          string                 `json:"threat_type"`
	Severity            int                    `json:"severity"`
	RiskScore           float64                `json:"risk_score"`
	Description         string                 `json:"description"`
	Evidence            map[string]interface{} `json:"evidence"`
	RecommendedAction   string                 `json:"recommended_action"`
	IPAddress           string                 `json:"ip_address"`
	UserAgent           string                 `json:"user_agent"`
	RequestContent      string                 `json:"request_content"`
	GeolocationData     map[string]interface{} `json:"geolocation_data"`
	DeviceFingerprint   string                 `json:"device_fingerprint"`
	SessionID           string                 `json:"session_id"`
	Mitigated           bool                   `json:"mitigated"`
	MitigationActions   []string               `json:"mitigation_actions"`
}

// NewThreatDetectionEngine initializes the threat detection system with
// machine learning models and signature databases
func NewThreatDetectionEngine() *ThreatDetectionEngine {
	return &ThreatDetectionEngine{
		behaviorProfiles:    make(map[string]*UserBehaviorProfile),
		anomalyDetector:     NewAnomalyDetector(),
		signatureDatabase:   NewThreatSignatureDB(),
		riskCalculator:      NewRiskCalculator(),
		alertThreshold:      0.7,
		learningEnabled:     true,
		adaptiveThreshold:   true,
	}
}

// AnalyzeThreat performs comprehensive threat analysis on incoming requests
// using multiple detection techniques and behavioral analysis
func (tde *ThreatDetectionEngine) AnalyzeThreat(ctx context.Context, request *SecurityContext) (*ThreatAlert, error) {
	tde.mutex.RLock()
	profile := tde.behaviorProfiles[request.UserID]
	tde.mutex.RUnlock()

	// Initialize user profile if not exists
	if profile == nil {
		profile = tde.initializeUserProfile(request.UserID)
		tde.mutex.Lock()
		tde.behaviorProfiles[request.UserID] = profile
		tde.mutex.Unlock()
	}

	// Perform multi-layered threat analysis
	threatScore := 0.0
	evidence := make(map[string]interface{})
	detectedThreats := []string{}

	// 1. Signature-based detection
	signatureThreats, sigEvidence := tde.detectSignatureThreats(request)
	if len(signatureThreats) > 0 {
		threatScore += 0.8
		evidence["signature_threats"] = signatureThreats
		evidence["signature_evidence"] = sigEvidence
		detectedThreats = append(detectedThreats, signatureThreats...)
	}

	// 2. Behavioral anomaly detection
	behaviorScore, behaviorEvidence := tde.analyzeBehavioralAnomalies(request, profile)
	threatScore += behaviorScore * 0.6
	if behaviorScore > 0.3 {
		evidence["behavioral_anomalies"] = behaviorEvidence
		detectedThreats = append(detectedThreats, "behavioral_anomaly")
	}

	// 3. Geographic anomaly detection
	geoScore, geoEvidence := tde.analyzeGeographicAnomalies(request, profile)
	threatScore += geoScore * 0.4
	if geoScore > 0.5 {
		evidence["geographic_anomalies"] = geoEvidence
		detectedThreats = append(detectedThreats, "geographic_anomaly")
	}

	// 4. Temporal pattern analysis
	temporalScore, temporalEvidence := tde.analyzeTemporalAnomalies(request, profile)
	threatScore += temporalScore * 0.3
	if temporalScore > 0.4 {
		evidence["temporal_anomalies"] = temporalEvidence
		detectedThreats = append(detectedThreats, "temporal_anomaly")
	}

	// 5. Content analysis for injection attacks
	contentScore, contentEvidence := tde.analyzeContentThreats(request)
	threatScore += contentScore * 0.9
	if contentScore > 0.2 {
		evidence["content_threats"] = contentEvidence
		detectedThreats = append(detectedThreats, "content_threat")
	}

	// 6. Rate limiting and abuse detection
	rateScore, rateEvidence := tde.analyzeRateAnomalies(request, profile)
	threatScore += rateScore * 0.5
	if rateScore > 0.6 {
		evidence["rate_anomalies"] = rateEvidence
		detectedThreats = append(detectedThreats, "rate_abuse")
	}

	// Normalize threat score
	threatScore = math.Min(threatScore, 1.0)

	// Update user profile with new data
	if tde.learningEnabled {
		tde.updateUserProfile(profile, request, threatScore)
	}

	// Generate alert if threshold exceeded
	if threatScore >= tde.alertThreshold {
		alert := &ThreatAlert{
			ID:                generateAlertID(),
			Timestamp:         time.Now(),
			UserID:            request.UserID,
			ThreatType:        strings.Join(detectedThreats, ","),
			Severity:          tde.calculateSeverity(threatScore),
			RiskScore:         threatScore,
			Description:       tde.generateThreatDescription(detectedThreats, threatScore),
			Evidence:          evidence,
			RecommendedAction: tde.recommendAction(threatScore, detectedThreats),
			IPAddress:         request.IPAddress,
			UserAgent:         request.UserAgent,
			RequestContent:    request.RequestContent,
			GeolocationData:   request.GeolocationData,
			DeviceFingerprint: request.DeviceFingerprint,
			SessionID:         request.SessionID,
			Mitigated:         false,
		}

		return alert, nil
	}

	return nil, nil
}

// detectSignatureThreats checks request content against known threat signatures
func (tde *ThreatDetectionEngine) detectSignatureThreats(request *SecurityContext) ([]string, map[string]interface{}) {
	threats := []string{}
	evidence := make(map[string]interface{})

	signatures := tde.signatureDatabase.GetActiveSignatures()
	
	for _, signature := range signatures {
		if signature.Pattern.MatchString(request.RequestContent) {
			threats = append(threats, signature.Name)
			evidence[signature.ID] = map[string]interface{}{
				"pattern":     signature.PatternString,
				"severity":    signature.Severity,
				"category":    signature.Category,
				"description": signature.Description,
			}
		}
	}

	// Check for common injection patterns
	injectionPatterns := []struct {
		name    string
		pattern string
	}{
		{"sql_injection", `(?i)(union|select|insert|update|delete|drop|exec|script)`},
		{"xss_attempt", `(?i)(<script|javascript:|onload=|onerror=)`},
		{"command_injection", `(?i)(;|\||&|`+"`"+`|\$\(|system\(|exec\()`},
		{"path_traversal", `(\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e%5c)`},
		{"ldap_injection", `(?i)(\*|\(|\)|&|\||!|=|<|>|~|;)`},
	}

	for _, pattern := range injectionPatterns {
		if matched, _ := regexp.MatchString(pattern.pattern, request.RequestContent); matched {
			threats = append(threats, pattern.name)
			evidence[pattern.name] = map[string]interface{}{
				"pattern": pattern.pattern,
				"type":    "injection_attempt",
			}
		}
	}

	return threats, evidence
}

// analyzeBehavioralAnomalies detects deviations from normal user behavior patterns
func (tde *ThreatDetectionEngine) analyzeBehavioralAnomalies(request *SecurityContext, profile *UserBehaviorProfile) (float64, map[string]interface{}) {
	evidence := make(map[string]interface{})
	anomalyScore := 0.0

	// Analyze request frequency patterns
	freqScore := profile.RequestFrequency.AnalyzeAnomaly(time.Now())
	if freqScore > 0.5 {
		anomalyScore += freqScore * 0.4
		evidence["frequency_anomaly"] = freqScore
	}

	// Analyze content patterns
	contentScore := profile.ContentPatterns.AnalyzeContent(request.RequestContent)
	if contentScore > 0.6 {
		anomalyScore += contentScore * 0.3
		evidence["content_pattern_anomaly"] = contentScore
	}

	// Check device fingerprint consistency
	if _, exists := profile.DeviceFingerprints[request.DeviceFingerprint]; !exists {
		anomalyScore += 0.3
		evidence["new_device"] = request.DeviceFingerprint
	}

	// Analyze IP address patterns
	ipScore := tde.analyzeIPAnomaly(request.IPAddress, profile.TypicalIPRanges)
	if ipScore > 0.4 {
		anomalyScore += ipScore * 0.2
		evidence["ip_anomaly"] = ipScore
	}

	return math.Min(anomalyScore, 1.0), evidence
}

// analyzeGeographicAnomalies detects unusual geographic access patterns
func (tde *ThreatDetectionEngine) analyzeGeographicAnomalies(request *SecurityContext, profile *UserBehaviorProfile) (float64, map[string]interface{}) {
	evidence := make(map[string]interface{})
	
	if profile.GeographicProfile == nil {
		return 0.0, evidence
	}

	geoScore := profile.GeographicProfile.AnalyzeLocation(request.GeolocationData)
	
	if geoScore > 0.5 {
		evidence["geographic_distance"] = geoScore
		evidence["current_location"] = request.GeolocationData
		evidence["typical_locations"] = profile.GeographicProfile.GetTypicalLocations()
	}

	return geoScore, evidence
}

// analyzeTemporalAnomalies detects unusual timing patterns in requests
func (tde *ThreatDetectionEngine) analyzeTemporalAnomalies(request *SecurityContext, profile *UserBehaviorProfile) (float64, map[string]interface{}) {
	evidence := make(map[string]interface{})
	
	if profile.TemporalProfile == nil {
		return 0.0, evidence
	}

	temporalScore := profile.TemporalProfile.AnalyzeTimestamp(time.Now())
	
	if temporalScore > 0.4 {
		evidence["temporal_anomaly"] = temporalScore
		evidence["current_time"] = time.Now()
		evidence["typical_hours"] = profile.TemporalProfile.GetTypicalHours()
	}

	return temporalScore, evidence
}

// analyzeContentThreats performs deep content analysis for malicious patterns
func (tde *ThreatDetectionEngine) analyzeContentThreats(request *SecurityContext) (float64, map[string]interface{}) {
	evidence := make(map[string]interface{})
	threatScore := 0.0

	content := strings.ToLower(request.RequestContent)

	// Check for prompt injection attempts
	promptInjectionPatterns := []string{
		"ignore previous instructions",
		"disregard safety guidelines",
		"bypass restrictions",
		"jailbreak",
		"prompt injection",
		"system prompt",
		"override security",
	}

	for _, pattern := range promptInjectionPatterns {
		if strings.Contains(content, pattern) {
			threatScore += 0.3
			evidence["prompt_injection"] = pattern
		}
	}

	// Check for data exfiltration attempts
	exfiltrationPatterns := []string{
		"show me all users",
		"dump database",
		"list all files",
		"show configuration",
		"reveal secrets",
	}

	for _, pattern := range exfiltrationPatterns {
		if strings.Contains(content, pattern) {
			threatScore += 0.4
			evidence["data_exfiltration"] = pattern
		}
	}

	// Analyze entropy for encoded payloads
	entropy := calculateEntropy(request.RequestContent)
	if entropy > 4.5 {
		threatScore += 0.2
		evidence["high_entropy"] = entropy
	}

	return math.Min(threatScore, 1.0), evidence
}

// analyzeRateAnomalies detects rate-based attacks and abuse patterns
func (tde *ThreatDetectionEngine) analyzeRateAnomalies(request *SecurityContext, profile *UserBehaviorProfile) (float64, map[string]interface{}) {
	evidence := make(map[string]interface{})
	
	if profile.RequestFrequency == nil {
		return 0.0, evidence
	}

	rateScore := profile.RequestFrequency.AnalyzeCurrentRate()
	
	if rateScore > 0.6 {
		evidence["rate_anomaly"] = rateScore
		evidence["current_rate"] = profile.RequestFrequency.GetCurrentRate()
		evidence["normal_rate"] = profile.RequestFrequency.GetNormalRate()
	}

	return rateScore, evidence
}

// Helper functions and structures

func (tde *ThreatDetectionEngine) initializeUserProfile(userID string) *UserBehaviorProfile {
	return &UserBehaviorProfile{
		UserID:             userID,
		RequestFrequency:   NewFrequencyAnalyzer(),
		ContentPatterns:    NewPatternAnalyzer(),
		GeographicProfile:  NewGeographicAnalyzer(),
		TemporalProfile:    NewTemporalAnalyzer(),
		DeviceFingerprints: make(map[string]int),
		TypicalIPRanges:    []string{},
		LastUpdated:        time.Now(),
		TrustScore:         0.5,
		RiskFactors:        []string{},
	}
}

func (tde *ThreatDetectionEngine) updateUserProfile(profile *UserBehaviorProfile, request *SecurityContext, threatScore float64) {
	profile.RequestFrequency.Update(time.Now())
	profile.ContentPatterns.Update(request.RequestContent)
	profile.GeographicProfile.Update(request.GeolocationData)
	profile.TemporalProfile.Update(time.Now())
	
	// Update device fingerprints
	profile.DeviceFingerprints[request.DeviceFingerprint]++
	
	// Update trust score based on threat score
	if threatScore < 0.3 {
		profile.TrustScore = math.Min(profile.TrustScore+0.01, 1.0)
	} else {
		profile.TrustScore = math.Max(profile.TrustScore-0.05, 0.0)
	}
	
	profile.LastUpdated = time.Now()
}

func (tde *ThreatDetectionEngine) analyzeIPAnomaly(ipAddress string, typicalRanges []string) float64 {
	ip := net.ParseIP(ipAddress)
	if ip == nil {
		return 0.8 // Invalid IP is suspicious
	}

	for _, rangeStr := range typicalRanges {
		_, network, err := net.ParseCIDR(rangeStr)
		if err == nil && network.Contains(ip) {
			return 0.0 // IP is in typical range
		}
	}

	return 0.6 // IP is outside typical ranges
}

func calculateEntropy(data string) float64 {
	if len(data) == 0 {
		return 0
	}

	frequency := make(map[rune]int)
	for _, char := range data {
		frequency[char]++
	}

	entropy := 0.0
	length := float64(len(data))

	for _, count := range frequency {
		probability := float64(count) / length
		entropy -= probability * math.Log2(probability)
	}

	return entropy
}

func generateAlertID() string {
	hash := sha256.Sum256([]byte(fmt.Sprintf("%d", time.Now().UnixNano())))
	return hex.EncodeToString(hash[:8])
}

func (tde *ThreatDetectionEngine) calculateSeverity(threatScore float64) int {
	switch {
	case threatScore >= 0.9:
		return 5 // Critical
	case threatScore >= 0.7:
		return 4 // High
	case threatScore >= 0.5:
		return 3 // Medium
	case threatScore >= 0.3:
		return 2 // Low
	default:
		return 1 // Info
	}
}

func (tde *ThreatDetectionEngine) generateThreatDescription(threats []string, score float64) string {
	if len(threats) == 0 {
		return "No specific threats detected"
	}
	
	return fmt.Sprintf("Detected threats: %s (Risk Score: %.2f)", strings.Join(threats, ", "), score)
}

func (tde *ThreatDetectionEngine) recommendAction(score float64, threats []string) string {
	switch {
	case score >= 0.9:
		return "BLOCK_IMMEDIATELY"
	case score >= 0.7:
		return "REQUIRE_ADDITIONAL_VERIFICATION"
	case score >= 0.5:
		return "INCREASE_MONITORING"
	default:
		return "LOG_AND_MONITOR"
	}
}
