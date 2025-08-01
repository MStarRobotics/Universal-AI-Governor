package governance

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/universal-ai-governor/internal/types"
)

// Metrics tracks key performance indicators and operational statistics
// for the governance engine. This component is vital for understanding the
// real-world impact and performance of the AI governance system. By providing
// clear, quantifiable insights into system behavior, it contributes to the
// "humanization effect" by making complex AI operations transparent and
// understandable to human stakeholders. It also enables the "AI bypass"
// of potential issues by providing early warning signals and data-driven
// insights for continuous improvement and responsible deployment.
type Metrics struct {
	// Request counters: These are atomic to ensure thread-safe updates
	// across concurrent request processing.
	totalRequests   int64 // Total number of requests processed
	allowedRequests int64 // Number of requests that passed all governance checks
	blockedRequests int64 // Number of requests blocked by governance policies/rules
	errorRequests   int64 // Number of requests that resulted in an internal error

	// Component-specific counters: Tracks blocks and errors attributed to
	// individual governance components (e.g., policy engine, moderation service).
	blockedByComponent map[string]int64 // Counts blocks per component
	errorsByComponent  map[string]int64 // Counts errors per component
	componentMutex     sync.RWMutex     // Protects access to component-specific maps

	// Timing metrics: Stores recent processing times to calculate averages and percentiles.
	processingTimes []time.Duration // Stores individual request processing durations
	timingMutex     sync.RWMutex    // Protects access to the processingTimes slice

	// Rate tracking: Used for calculating requests per second.
	requestsPerSecond  float64 // Current estimated requests per second
	lastSecond         int64   // Unix timestamp of the last second for RPS calculation
	currentSecondCount int64   // Counter for requests within the current second

	// Start time for uptime calculation.
	startTime time.Time // Timestamp when the metrics instance was created
}

// NewMetrics creates and initializes a new Metrics instance.
// It sets up the necessary maps and initializes counters to zero.
func NewMetrics() *Metrics {
	return &Metrics{
		blockedByComponent: make(map[string]int64),
		errorsByComponent:  make(map[string]int64),
		processingTimes:    make([]time.Duration, 0, 1000), // Pre-allocate capacity for efficiency
		startTime:          time.Now(),
	}
}

// IncrementProcessed increments the counter for successfully processed requests.
// It also contributes to the overall requests per second calculation.
func (m *Metrics) IncrementProcessed() {
	atomic.AddInt64(&m.totalRequests, 1)
	atomic.AddInt64(&m.allowedRequests, 1)
	m.updateRequestsPerSecond()
}

// IncrementBlocked increments the counter for requests blocked by a specific component.
// It also updates the total requests and contributes to RPS calculation.
func (m *Metrics) IncrementBlocked(component string) {
	atomic.AddInt64(&m.totalRequests, 1)
	atomic.AddInt64(&m.blockedRequests, 1)
	
	m.componentMutex.Lock() // Protect map access
	m.blockedByComponent[component]++
	m.componentMutex.Unlock()
	
	m.updateRequestsPerSecond()
}

// IncrementErrors increments the counter for requests that resulted in an error
// within a specific component. It also updates total requests and contributes to RPS.
func (m *Metrics) IncrementErrors(component string) {
	atomic.AddInt64(&m.totalRequests, 1)
	atomic.AddInt64(&m.errorRequests, 1)
	
	m.componentMutex.Lock() // Protect map access
	m.errorsByComponent[component]++
	m.componentMutex.Unlock()
	
	m.updateRequestsPerSecond()
}

// RecordProcessingTime adds a new request processing duration to the collection.
// It maintains a rolling window of the last 1000 processing times to manage memory.
func (m *Metrics) RecordProcessingTime(duration time.Duration) {
	m.timingMutex.Lock() // Protect slice access
	defer m.timingMutex.Unlock()
	
	// If the slice reaches its capacity, remove the oldest entry to make space.
	if len(m.processingTimes) >= 1000 {
		m.processingTimes = m.processingTimes[1:]
	}
	
	m.processingTimes = append(m.processingTimes, duration)
}

// updateRequestsPerSecond calculates and updates the requests per second metric.
// It uses a simple exponential moving average for smoothing.
func (m *Metrics) updateRequestsPerSecond() {
	currentSecond := time.Now().Unix() // Get current Unix timestamp in seconds.
	
	// Check if a new second has started.
	if currentSecond != atomic.LoadInt64(&m.lastSecond) {
		// If it's a new second, update RPS and reset the counter for the new second.
		count := atomic.SwapInt64(&m.currentSecondCount, 1) // Get current count and reset to 1.
		atomic.StoreInt64(&m.lastSecond, currentSecond)     // Update the last second timestamp.
		
		// Apply exponential moving average: newRPS is 10% of current second's rate, 90% of old RPS.
		newRPS := float64(count)
		oldRPS := m.requestsPerSecond
		m.requestsPerSecond = 0.1*newRPS + 0.9*oldRPS
	} else {
		// If still in the same second, just increment the counter.
		atomic.AddInt64(&m.currentSecondCount, 1)
	}
}

// GetSnapshot returns a comprehensive snapshot of the current metrics.
// All counters are converted to uint64 for consistency in the snapshot.
func (m *Metrics) GetSnapshot() *types.MetricsSnapshot {
	m.componentMutex.RLock() // Read-lock component maps
	// Create copies of component-specific maps to avoid race conditions
	// and ensure the snapshot is consistent.
	blockedByComponent := make(map[string]uint64)
	for k, v := range m.blockedByComponent {
		blockedByComponent[k] = uint64(v)
	}
	
	errorsByComponent := make(map[string]uint64)
	for k, v := range m.errorsByComponent {
		errorsByComponent[k] = uint64(v)
	}
	m.componentMutex.RUnlock() // Release read-lock
	
	m.timingMutex.RLock() // Read-lock timing metrics
	avgProcessingTime := m.calculateAverageProcessingTime() // Calculate average processing time.
	m.timingMutex.RUnlock() // Release read-lock
	
	return &types.MetricsSnapshot{
		Timestamp:             time.Now(),
		TotalRequests:         uint64(atomic.LoadInt64(&m.totalRequests)),
		AllowedRequests:       uint64(atomic.LoadInt64(&m.allowedRequests)),
		BlockedRequests:       uint64(atomic.LoadInt64(&m.blockedRequests)),
		ErrorRequests:         uint64(atomic.LoadInt64(&m.errorRequests)),
		AverageProcessingTime: float64(avgProcessingTime.Milliseconds()), // Convert duration to milliseconds for float representation.
		RequestsPerSecond:     m.requestsPerSecond,
		BlockedByComponent:    blockedByComponent,
		ErrorsByComponent:     errorsByComponent,
	}
}

// calculateAverageProcessingTime computes the average processing time from the collected durations.
// It returns 0 if no processing times have been recorded.
func (m *Metrics) calculateAverageProcessingTime() time.Duration {
	if len(m.processingTimes) == 0 {
		return 0
	}
	
	var total time.Duration
	for _, duration := range m.processingTimes {
		total += duration
	}
	
	return total / time.Duration(len(m.processingTimes))
}

// GetPercentiles calculates and returns various percentiles for processing times.
// This provides insights into the distribution of request latencies.
func (m *Metrics) GetPercentiles() map[string]time.Duration {
	m.timingMutex.RLock() // Read-lock timing metrics
	defer m.timingMutex.RUnlock()
	
	if len(m.processingTimes) == 0 {
		return map[string]time.Duration{
			"p50": 0,
			"p90": 0,
			"p95": 0,
			"p99": 0,
		}
	}
	
	// Create a sorted copy of processing times to calculate percentiles.
	times := make([]time.Duration, len(m.processingTimes))
	copy(times, m.processingTimes)
	
	// Simple bubble sort is used here for illustrative purposes. For very large
	// datasets, a more efficient sorting algorithm would be preferred.
	for i := 0; i < len(times); i++ {
		for j := 0; j < len(times)-1-i; j++ {
			if times[j] > times[j+1] {
				times[j], times[j+1] = times[j+1], times[j]
			}
		}
	}
	
	return map[string]time.Duration{
		"p50": times[len(times)*50/100],
		"p90": times[len(times)*90/100],
		"p95": times[len(times)*95/100],
		"p99": times[len(times)*99/100],
	}
}

// GetUptime returns the total uptime of the metrics instance since its creation.
func (m *Metrics) GetUptime() time.Duration {
	return time.Since(m.startTime)
}

// Reset clears all collected metrics, resetting counters and stored times to zero.
// This is useful for starting a new measurement period.
func (m *Metrics) Reset() {
	atomic.StoreInt64(&m.totalRequests, 0)
	atomic.StoreInt64(&m.allowedRequests, 0)
	atomic.StoreInt64(&m.blockedRequests, 0)
	atomic.StoreInt64(&m.errorRequests, 0)
	atomic.StoreInt64(&m.currentSecondCount, 0)
	atomic.StoreInt64(&m.lastSecond, 0)
	
	m.componentMutex.Lock() // Protect map access during reset.
	m.blockedByComponent = make(map[string]int64)
	m.errorsByComponent = make(map[string]int64)
	m.componentMutex.Unlock()
	
	m.timingMutex.Lock() // Protect slice access during reset.
	m.processingTimes = make([]time.Duration, 0, 1000)
	m.timingMutex.Unlock()
	
	m.requestsPerSecond = 0
	m.startTime = time.Now() // Reset start time to current time.
}

// GetTotalRequests returns the total number of requests processed.
func (m *Metrics) GetTotalRequests() int64 {
	return atomic.LoadInt64(&m.totalRequests)
}

// GetAllowedRequests returns the number of requests that were allowed.
func (m *Metrics) GetAllowedRequests() int64 {
	return atomic.LoadInt64(&m.allowedRequests)
}

// GetBlockedRequests returns the number of requests that were blocked.
func (m *Metrics) GetBlockedRequests() int64 {
	return atomic.LoadInt64(&m.blockedRequests)
}

// GetErrorRequests returns the number of requests that resulted in an error.
func (m *Metrics) GetErrorRequests() int64 {
	return atomic.LoadInt64(&m.errorRequests)
}

// GetRequestsPerSecond returns the current estimated requests per second.
func (m *Metrics) GetRequestsPerSecond() float64 {
	return m.requestsPerSecond
}

// GetBlockedByComponent returns a map of blocked requests categorized by component.
func (m *Metrics) GetBlockedByComponent() map[string]int64 {
	m.componentMutex.RLock() // Read-lock for safe map access.
	defer m.componentMutex.RUnlock()
	
	result := make(map[string]int64)
	for k, v := range m.blockedByComponent {
		result[k] = v
	}
	return result
}

// GetErrorsByComponent returns a map of error requests categorized by component.
func (m *Metrics) GetErrorsByComponent() map[string]int64 {
	m.componentMutex.RLock() // Read-lock for safe map access.
	defer m.componentMutex.RUnlock()
	
	result := make(map[string]int64)
	for k, v := range m.errorsByComponent {
		result[k] = v
	}
	return result
}

// GetSuccessRate calculates the percentage of successfully processed requests.
func (m *Metrics) GetSuccessRate() float64 {
	total := atomic.LoadInt64(&m.totalRequests)
	if total == 0 {
		return 100.0 // Avoid division by zero; 100% success if no requests.
	}
	
	allowed := atomic.LoadInt64(&m.allowedRequests)
	return float64(allowed) / float64(total) * 100.0
}

// GetBlockRate calculates the percentage of requests that were blocked.
func (m *Metrics) GetBlockRate() float64 {
	total := atomic.LoadInt64(&m.totalRequests)
	if total == 0 {
		return 0.0 // Avoid division by zero.
	}
	
	blocked := atomic.LoadInt64(&m.blockedRequests)
	return float64(blocked) / float64(total) * 100.0
}

// GetErrorRate calculates the percentage of requests that resulted in an error.
func (m *Metrics) GetErrorRate() float64 {
	total := atomic.LoadInt64(&m.totalRequests)
	if total == 0 {
		return 0.0 // Avoid division by zero.
	}
	
	errors := atomic.LoadInt64(&m.errorRequests)
	return float64(errors) / float64(total) * 100.0
}
