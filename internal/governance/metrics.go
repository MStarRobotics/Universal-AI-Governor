package governance

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/universal-ai-governor/internal/types"
)

// Metrics tracks governance engine performance and statistics
type Metrics struct {
	// Request counters
	totalRequests   int64
	allowedRequests int64
	blockedRequests int64
	errorRequests   int64

	// Component-specific counters
	blockedByComponent map[string]int64
	errorsByComponent  map[string]int64
	componentMutex     sync.RWMutex

	// Timing metrics
	processingTimes []time.Duration
	timingMutex     sync.RWMutex

	// Rate tracking
	requestsPerSecond float64
	lastSecond        int64
	currentSecondCount int64

	// Start time for uptime calculation
	startTime time.Time
}

// NewMetrics creates a new metrics instance
func NewMetrics() *Metrics {
	return &Metrics{
		blockedByComponent: make(map[string]int64),
		errorsByComponent:  make(map[string]int64),
		processingTimes:    make([]time.Duration, 0, 1000), // Keep last 1000 processing times
		startTime:          time.Now(),
	}
}

// IncrementProcessed increments the total processed requests counter
func (m *Metrics) IncrementProcessed() {
	atomic.AddInt64(&m.totalRequests, 1)
	atomic.AddInt64(&m.allowedRequests, 1)
	m.updateRequestsPerSecond()
}

// IncrementBlocked increments the blocked requests counter for a specific component
func (m *Metrics) IncrementBlocked(component string) {
	atomic.AddInt64(&m.totalRequests, 1)
	atomic.AddInt64(&m.blockedRequests, 1)
	
	m.componentMutex.Lock()
	m.blockedByComponent[component]++
	m.componentMutex.Unlock()
	
	m.updateRequestsPerSecond()
}

// IncrementErrors increments the error counter for a specific component
func (m *Metrics) IncrementErrors(component string) {
	atomic.AddInt64(&m.totalRequests, 1)
	atomic.AddInt64(&m.errorRequests, 1)
	
	m.componentMutex.Lock()
	m.errorsByComponent[component]++
	m.componentMutex.Unlock()
	
	m.updateRequestsPerSecond()
}

// RecordProcessingTime records the processing time for a request
func (m *Metrics) RecordProcessingTime(duration time.Duration) {
	m.timingMutex.Lock()
	defer m.timingMutex.Unlock()
	
	// Keep only the last 1000 processing times to avoid memory growth
	if len(m.processingTimes) >= 1000 {
		// Remove the oldest entry
		m.processingTimes = m.processingTimes[1:]
	}
	
	m.processingTimes = append(m.processingTimes, duration)
}

// updateRequestsPerSecond updates the requests per second metric
func (m *Metrics) updateRequestsPerSecond() {
	currentSecond := time.Now().Unix()
	
	if currentSecond != atomic.LoadInt64(&m.lastSecond) {
		// New second, update RPS and reset counter
		count := atomic.SwapInt64(&m.currentSecondCount, 1)
		atomic.StoreInt64(&m.lastSecond, currentSecond)
		
		// Simple exponential moving average
		newRPS := float64(count)
		oldRPS := m.requestsPerSecond
		m.requestsPerSecond = 0.1*newRPS + 0.9*oldRPS
	} else {
		atomic.AddInt64(&m.currentSecondCount, 1)
	}
}

// GetSnapshot returns a snapshot of current metrics
func (m *Metrics) GetSnapshot() *types.MetricsSnapshot {
	m.componentMutex.RLock()
	blockedByComponent := make(map[string]int64)
	for k, v := range m.blockedByComponent {
		blockedByComponent[k] = v
	}
	
	errorsByComponent := make(map[string]int64)
	for k, v := range m.errorsByComponent {
		errorsByComponent[k] = v
	}
	m.componentMutex.RUnlock()
	
	m.timingMutex.RLock()
	avgProcessingTime := m.calculateAverageProcessingTime()
	m.timingMutex.RUnlock()
	
	return &types.MetricsSnapshot{
		Timestamp:             time.Now(),
		TotalRequests:         atomic.LoadInt64(&m.totalRequests),
		AllowedRequests:       atomic.LoadInt64(&m.allowedRequests),
		BlockedRequests:       atomic.LoadInt64(&m.blockedRequests),
		ErrorRequests:         atomic.LoadInt64(&m.errorRequests),
		AverageProcessingTime: avgProcessingTime,
		RequestsPerSecond:     m.requestsPerSecond,
		BlockedByComponent:    blockedByComponent,
		ErrorsByComponent:     errorsByComponent,
	}
}

// calculateAverageProcessingTime calculates the average processing time from recorded times
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

// GetPercentiles returns processing time percentiles
func (m *Metrics) GetPercentiles() map[string]time.Duration {
	m.timingMutex.RLock()
	defer m.timingMutex.RUnlock()
	
	if len(m.processingTimes) == 0 {
		return map[string]time.Duration{
			"p50": 0,
			"p90": 0,
			"p95": 0,
			"p99": 0,
		}
	}
	
	// Create a sorted copy of processing times
	times := make([]time.Duration, len(m.processingTimes))
	copy(times, m.processingTimes)
	
	// Simple bubble sort (good enough for small arrays)
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

// GetUptime returns the uptime of the metrics instance
func (m *Metrics) GetUptime() time.Duration {
	return time.Since(m.startTime)
}

// Reset resets all metrics to zero
func (m *Metrics) Reset() {
	atomic.StoreInt64(&m.totalRequests, 0)
	atomic.StoreInt64(&m.allowedRequests, 0)
	atomic.StoreInt64(&m.blockedRequests, 0)
	atomic.StoreInt64(&m.errorRequests, 0)
	atomic.StoreInt64(&m.currentSecondCount, 0)
	atomic.StoreInt64(&m.lastSecond, 0)
	
	m.componentMutex.Lock()
	m.blockedByComponent = make(map[string]int64)
	m.errorsByComponent = make(map[string]int64)
	m.componentMutex.Unlock()
	
	m.timingMutex.Lock()
	m.processingTimes = make([]time.Duration, 0, 1000)
	m.timingMutex.Unlock()
	
	m.requestsPerSecond = 0
	m.startTime = time.Now()
}

// GetTotalRequests returns the total number of requests processed
func (m *Metrics) GetTotalRequests() int64 {
	return atomic.LoadInt64(&m.totalRequests)
}

// GetAllowedRequests returns the number of allowed requests
func (m *Metrics) GetAllowedRequests() int64 {
	return atomic.LoadInt64(&m.allowedRequests)
}

// GetBlockedRequests returns the number of blocked requests
func (m *Metrics) GetBlockedRequests() int64 {
	return atomic.LoadInt64(&m.blockedRequests)
}

// GetErrorRequests returns the number of error requests
func (m *Metrics) GetErrorRequests() int64 {
	return atomic.LoadInt64(&m.errorRequests)
}

// GetRequestsPerSecond returns the current requests per second rate
func (m *Metrics) GetRequestsPerSecond() float64 {
	return m.requestsPerSecond
}

// GetBlockedByComponent returns blocked requests by component
func (m *Metrics) GetBlockedByComponent() map[string]int64 {
	m.componentMutex.RLock()
	defer m.componentMutex.RUnlock()
	
	result := make(map[string]int64)
	for k, v := range m.blockedByComponent {
		result[k] = v
	}
	return result
}

// GetErrorsByComponent returns error requests by component
func (m *Metrics) GetErrorsByComponent() map[string]int64 {
	m.componentMutex.RLock()
	defer m.componentMutex.RUnlock()
	
	result := make(map[string]int64)
	for k, v := range m.errorsByComponent {
		result[k] = v
	}
	return result
}

// GetSuccessRate returns the success rate as a percentage
func (m *Metrics) GetSuccessRate() float64 {
	total := atomic.LoadInt64(&m.totalRequests)
	if total == 0 {
		return 100.0
	}
	
	allowed := atomic.LoadInt64(&m.allowedRequests)
	return float64(allowed) / float64(total) * 100.0
}

// GetBlockRate returns the block rate as a percentage
func (m *Metrics) GetBlockRate() float64 {
	total := atomic.LoadInt64(&m.totalRequests)
	if total == 0 {
		return 0.0
	}
	
	blocked := atomic.LoadInt64(&m.blockedRequests)
	return float64(blocked) / float64(total) * 100.0
}

// GetErrorRate returns the error rate as a percentage
func (m *Metrics) GetErrorRate() float64 {
	total := atomic.LoadInt64(&m.totalRequests)
	if total == 0 {
		return 0.0
	}
	
	errors := atomic.LoadInt64(&m.errorRequests)
	return float64(errors) / float64(total) * 100.0
}
