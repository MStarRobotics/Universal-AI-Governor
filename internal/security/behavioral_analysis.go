package security

import (
	"math"
	"sync"
	"time"
)

// FrequencyAnalyzer tracks request frequency patterns for anomaly detection
type FrequencyAnalyzer struct {
	requestTimes    []time.Time
	windowSize      time.Duration
	normalRate      float64
	deviationThresh float64
	mutex           sync.RWMutex
}

// PatternAnalyzer analyzes content patterns for behavioral profiling
type PatternAnalyzer struct {
	contentHashes   map[string]int
	patterns        map[string]float64
	totalRequests   int
	mutex           sync.RWMutex
}

// GeographicAnalyzer tracks geographic access patterns
type GeographicAnalyzer struct {
	locations       []GeographicPoint
	typicalRegions  map[string]float64
	maxDistance     float64
	mutex           sync.RWMutex
}

// TemporalAnalyzer analyzes temporal access patterns
type TemporalAnalyzer struct {
	hourlyActivity  [24]int
	weeklyActivity  [7]int
	totalRequests   int
	mutex           sync.RWMutex
}

// GeographicPoint represents a geographic location
type GeographicPoint struct {
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
	Timestamp time.Time `json:"timestamp"`
}

// NewFrequencyAnalyzer creates a new frequency analyzer
func NewFrequencyAnalyzer() *FrequencyAnalyzer {
	return &FrequencyAnalyzer{
		requestTimes:    make([]time.Time, 0),
		windowSize:      time.Hour,
		normalRate:      10.0, // requests per hour
		deviationThresh: 3.0,  // standard deviations
	}
}

// Update adds a new request timestamp
func (fa *FrequencyAnalyzer) Update(timestamp time.Time) {
	fa.mutex.Lock()
	defer fa.mutex.Unlock()
	
	fa.requestTimes = append(fa.requestTimes, timestamp)
	
	// Clean old entries
	cutoff := timestamp.Add(-fa.windowSize)
	filtered := make([]time.Time, 0)
	for _, t := range fa.requestTimes {
		if t.After(cutoff) {
			filtered = append(filtered, t)
		}
	}
	fa.requestTimes = filtered
}

// AnalyzeAnomaly returns anomaly score based on current frequency
func (fa *FrequencyAnalyzer) AnalyzeAnomaly(currentTime time.Time) float64 {
	fa.mutex.RLock()
	defer fa.mutex.RUnlock()
	
	cutoff := currentTime.Add(-fa.windowSize)
	recentCount := 0
	
	for _, t := range fa.requestTimes {
		if t.After(cutoff) {
			recentCount++
		}
	}
	
	currentRate := float64(recentCount)
	deviation := math.Abs(currentRate - fa.normalRate)
	
	if deviation > fa.deviationThresh*math.Sqrt(fa.normalRate) {
		return math.Min(deviation/fa.normalRate, 1.0)
	}
	
	return 0.0
}

// AnalyzeCurrentRate returns current rate anomaly score
func (fa *FrequencyAnalyzer) AnalyzeCurrentRate() float64 {
	return fa.AnalyzeAnomaly(time.Now())
}

// GetCurrentRate returns current request rate
func (fa *FrequencyAnalyzer) GetCurrentRate() float64 {
	fa.mutex.RLock()
	defer fa.mutex.RUnlock()
	
	cutoff := time.Now().Add(-fa.windowSize)
	count := 0
	
	for _, t := range fa.requestTimes {
		if t.After(cutoff) {
			count++
		}
	}
	
	return float64(count)
}

// GetNormalRate returns the normal request rate
func (fa *FrequencyAnalyzer) GetNormalRate() float64 {
	return fa.normalRate
}

// NewPatternAnalyzer creates a new pattern analyzer
func NewPatternAnalyzer() *PatternAnalyzer {
	return &PatternAnalyzer{
		contentHashes: make(map[string]int),
		patterns:      make(map[string]float64),
		totalRequests: 0,
	}
}

// Update adds new content for pattern analysis
func (pa *PatternAnalyzer) Update(content string) {
	pa.mutex.Lock()
	defer pa.mutex.Unlock()
	
	hash := calculateContentHash(content)
	pa.contentHashes[hash]++
	pa.totalRequests++
	
	// Update pattern frequencies
	patterns := extractPatterns(content)
	for _, pattern := range patterns {
		pa.patterns[pattern] = pa.patterns[pattern] + 1.0/float64(pa.totalRequests)
	}
}

// AnalyzeContent returns anomaly score for given content
func (pa *PatternAnalyzer) AnalyzeContent(content string) float64 {
	pa.mutex.RLock()
	defer pa.mutex.RUnlock()
	
	patterns := extractPatterns(content)
	anomalyScore := 0.0
	
	for _, pattern := range patterns {
		frequency := pa.patterns[pattern]
		if frequency < 0.01 { // Very rare pattern
			anomalyScore += 0.3
		}
	}
	
	return math.Min(anomalyScore, 1.0)
}

// NewGeographicAnalyzer creates a new geographic analyzer
func NewGeographicAnalyzer() *GeographicAnalyzer {
	return &GeographicAnalyzer{
		locations:      make([]GeographicPoint, 0),
		typicalRegions: make(map[string]float64),
		maxDistance:    1000.0, // km
	}
}

// Update adds a new geographic location
func (ga *GeographicAnalyzer) Update(locationData map[string]interface{}) {
	ga.mutex.Lock()
	defer ga.mutex.Unlock()
	
	lat, latOk := locationData["latitude"].(float64)
	lon, lonOk := locationData["longitude"].(float64)
	
	if latOk && lonOk {
		point := GeographicPoint{
			Latitude:  lat,
			Longitude: lon,
			Timestamp: time.Now(),
		}
		ga.locations = append(ga.locations, point)
		
		// Keep only recent locations
		if len(ga.locations) > 100 {
			ga.locations = ga.locations[1:]
		}
	}
}

// AnalyzeLocation returns anomaly score for given location
func (ga *GeographicAnalyzer) AnalyzeLocation(locationData map[string]interface{}) float64 {
	ga.mutex.RLock()
	defer ga.mutex.RUnlock()
	
	lat, latOk := locationData["latitude"].(float64)
	lon, lonOk := locationData["longitude"].(float64)
	
	if !latOk || !lonOk || len(ga.locations) == 0 {
		return 0.0
	}
	
	currentPoint := GeographicPoint{Latitude: lat, Longitude: lon}
	minDistance := math.MaxFloat64
	
	for _, point := range ga.locations {
		distance := calculateDistance(currentPoint, point)
		if distance < minDistance {
			minDistance = distance
		}
	}
	
	if minDistance > ga.maxDistance {
		return math.Min(minDistance/ga.maxDistance, 1.0)
	}
	
	return 0.0
}

// GetTypicalLocations returns typical access locations
func (ga *GeographicAnalyzer) GetTypicalLocations() []GeographicPoint {
	ga.mutex.RLock()
	defer ga.mutex.RUnlock()
	
	return ga.locations
}

// NewTemporalAnalyzer creates a new temporal analyzer
func NewTemporalAnalyzer() *TemporalAnalyzer {
	return &TemporalAnalyzer{
		hourlyActivity:  [24]int{},
		weeklyActivity:  [7]int{},
		totalRequests:   0,
	}
}

// Update adds a new timestamp for temporal analysis
func (ta *TemporalAnalyzer) Update(timestamp time.Time) {
	ta.mutex.Lock()
	defer ta.mutex.Unlock()
	
	hour := timestamp.Hour()
	weekday := int(timestamp.Weekday())
	
	ta.hourlyActivity[hour]++
	ta.weeklyActivity[weekday]++
	ta.totalRequests++
}

// AnalyzeTimestamp returns anomaly score for given timestamp
func (ta *TemporalAnalyzer) AnalyzeTimestamp(timestamp time.Time) float64 {
	ta.mutex.RLock()
	defer ta.mutex.RUnlock()
	
	if ta.totalRequests == 0 {
		return 0.0
	}
	
	hour := timestamp.Hour()
	weekday := int(timestamp.Weekday())
	
	hourlyFreq := float64(ta.hourlyActivity[hour]) / float64(ta.totalRequests)
	weeklyFreq := float64(ta.weeklyActivity[weekday]) / float64(ta.totalRequests)
	
	// Low frequency indicates anomaly
	anomalyScore := 0.0
	if hourlyFreq < 0.02 { // Less than 2% of requests
		anomalyScore += 0.5
	}
	if weeklyFreq < 0.1 { // Less than 10% of requests
		anomalyScore += 0.3
	}
	
	return math.Min(anomalyScore, 1.0)
}

// GetTypicalHours returns typical access hours
func (ta *TemporalAnalyzer) GetTypicalHours() []int {
	ta.mutex.RLock()
	defer ta.mutex.RUnlock()
	
	typical := make([]int, 0)
	avgActivity := float64(ta.totalRequests) / 24.0
	
	for hour, activity := range ta.hourlyActivity {
		if float64(activity) > avgActivity*0.5 {
			typical = append(typical, hour)
		}
	}
	
	return typical
}

// Helper functions

func calculateContentHash(content string) string {
	// Simplified hash calculation
	hash := 0
	for _, char := range content {
		hash = hash*31 + int(char)
	}
	return string(rune(hash % 1000000))
}

func extractPatterns(content string) []string {
	// Simplified pattern extraction
	patterns := make([]string, 0)
	
	// Length pattern
	if len(content) < 10 {
		patterns = append(patterns, "short")
	} else if len(content) > 1000 {
		patterns = append(patterns, "long")
	} else {
		patterns = append(patterns, "medium")
	}
	
	// Character patterns
	if containsNumbers(content) {
		patterns = append(patterns, "numeric")
	}
	if containsSpecialChars(content) {
		patterns = append(patterns, "special")
	}
	
	return patterns
}

func containsNumbers(s string) bool {
	for _, char := range s {
		if char >= '0' && char <= '9' {
			return true
		}
	}
	return false
}

func containsSpecialChars(s string) bool {
	specialChars := "!@#$%^&*()_+-=[]{}|;:,.<>?"
	for _, char := range s {
		for _, special := range specialChars {
			if char == special {
				return true
			}
		}
	}
	return false
}

func calculateDistance(p1, p2 GeographicPoint) float64 {
	// Haversine formula for distance calculation
	const earthRadius = 6371.0 // km
	
	lat1Rad := p1.Latitude * math.Pi / 180
	lat2Rad := p2.Latitude * math.Pi / 180
	deltaLat := (p2.Latitude - p1.Latitude) * math.Pi / 180
	deltaLon := (p2.Longitude - p1.Longitude) * math.Pi / 180
	
	a := math.Sin(deltaLat/2)*math.Sin(deltaLat/2) +
		math.Cos(lat1Rad)*math.Cos(lat2Rad)*
			math.Sin(deltaLon/2)*math.Sin(deltaLon/2)
	
	c := 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))
	
	return earthRadius * c
}
