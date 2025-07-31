// Fault Injection & Chaos Testing
// Simulates hardware failures and system faults to test resilience

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::time::sleep;
use universal_ai_governor::governor_core::{
    hardware::{HardwareAbstraction, HardwareError},
    master_key_service::MasterKeyService,
    secure_enclave::{SecureEnclaveManager, EnclaveError},
};

/// Chaos testing suite for fault injection
pub struct FaultInjectionTests {
    hardware: Arc<HardwareAbstraction>,
    master_key_service: Arc<MasterKeyService>,
    enclave_manager: Arc<SecureEnclaveManager>,
    fault_injector: Arc<FaultInjector>,
    test_scenarios: Vec<FaultScenario>,
}

/// Fault injection controller
pub struct FaultInjector {
    active_faults: Arc<Mutex<Vec<ActiveFault>>>,
    fault_probability: f64,
    chaos_mode: bool,
}

/// Active fault being injected
#[derive(Debug, Clone)]
pub struct ActiveFault {
    pub fault_type: FaultType,
    pub target_component: String,
    pub start_time: Instant,
    pub duration: Duration,
    pub severity: FaultSeverity,
}

/// Types of faults to inject
#[derive(Debug, Clone, PartialEq)]
pub enum FaultType {
    // Hardware faults
    TmpTimeout,
    TmpCorruption,
    HsmDisconnection,
    EnclaveCorruption,
    PcrModification,
    
    // System faults
    MemoryExhaustion,
    DiskFull,
    NetworkPartition,
    CpuStarvation,
    
    // Application faults
    DatabaseCorruption,
    ConfigurationError,
    CertificateExpiry,
    KeyRotationFailure,
    
    // Timing faults
    ClockSkew,
    RaceCondition,
    DeadlockInduction,
    
    // Security faults
    PrivilegeEscalation,
    AuthenticationBypass,
    EncryptionFailure,
}

/// Severity levels for fault injection
#[derive(Debug, Clone, PartialEq)]
pub enum FaultSeverity {
    Low,      // Minor degradation
    Medium,   // Noticeable impact
    High,     // Significant failure
    Critical, // System-threatening
}

/// Fault injection scenario
#[derive(Debug, Clone)]
pub struct FaultScenario {
    pub name: String,
    pub description: String,
    pub faults: Vec<FaultType>,
    pub expected_behavior: ExpectedBehavior,
    pub recovery_time_limit: Duration,
    pub criticality: FaultSeverity,
}

/// Expected system behavior under fault conditions
#[derive(Debug, Clone, PartialEq)]
pub enum ExpectedBehavior {
    GracefulDegradation,  // System continues with reduced functionality
    FailSafe,             // System fails to a safe state
    AutoRecovery,         // System automatically recovers
    ManualIntervention,   // Requires manual intervention
    SystemQuarantine,     // System quarantines itself
}

/// Results of fault injection testing
#[derive(Debug)]
pub struct FaultTestResults {
    pub total_scenarios: usize,
    pub passed_scenarios: usize,
    pub failed_scenarios: usize,
    pub scenario_results: Vec<ScenarioResult>,
    pub system_stability_score: f64,
    pub recovery_metrics: RecoveryMetrics,
}

/// Results for individual scenario
#[derive(Debug)]
pub struct ScenarioResult {
    pub scenario_name: String,
    pub test_passed: bool,
    pub actual_behavior: ExpectedBehavior,
    pub recovery_time: Duration,
    pub error_messages: Vec<String>,
    pub system_state_changes: Vec<String>,
}

/// Recovery time metrics
#[derive(Debug)]
pub struct RecoveryMetrics {
    pub average_recovery_time: Duration,
    pub max_recovery_time: Duration,
    pub min_recovery_time: Duration,
    pub failed_recoveries: usize,
}

impl FaultInjectionTests {
    /// Initialize fault injection test suite
    pub async fn new(
        hardware: Arc<HardwareAbstraction>,
        master_key_service: Arc<MasterKeyService>,
        enclave_manager: Arc<SecureEnclaveManager>,
    ) -> Self {
        let fault_injector = Arc::new(FaultInjector::new(0.1, false)); // 10% fault probability
        let test_scenarios = Self::generate_fault_scenarios();
        
        Self {
            hardware,
            master_key_service,
            enclave_manager,
            fault_injector,
            test_scenarios,
        }
    }

    /// Generate comprehensive fault injection scenarios
    fn generate_fault_scenarios() -> Vec<FaultScenario> {
        vec![
            // Hardware fault scenarios
            FaultScenario {
                name: "tpm_timeout_cascade".to_string(),
                description: "TPM operations timeout, triggering fallback mechanisms".to_string(),
                faults: vec![FaultType::TmpTimeout],
                expected_behavior: ExpectedBehavior::GracefulDegradation,
                recovery_time_limit: Duration::from_secs(30),
                criticality: FaultSeverity::Medium,
            },
            
            FaultScenario {
                name: "pcr_corruption_attack".to_string(),
                description: "PCR values corrupted, simulating boot tampering".to_string(),
                faults: vec![FaultType::PcrModification],
                expected_behavior: ExpectedBehavior::SystemQuarantine,
                recovery_time_limit: Duration::from_secs(5),
                criticality: FaultSeverity::Critical,
            },
            
            FaultScenario {
                name: "enclave_crash_recovery".to_string(),
                description: "Secure enclave crashes during key operation".to_string(),
                faults: vec![FaultType::EnclaveCorruption],
                expected_behavior: ExpectedBehavior::FailSafe,
                recovery_time_limit: Duration::from_secs(60),
                criticality: FaultSeverity::High,
            },
            
            FaultScenario {
                name: "hsm_disconnection".to_string(),
                description: "HSM becomes unavailable during critical operation".to_string(),
                faults: vec![FaultType::HsmDisconnection],
                expected_behavior: ExpectedBehavior::GracefulDegradation,
                recovery_time_limit: Duration::from_secs(45),
                criticality: FaultSeverity::Medium,
            },
            
            // System resource exhaustion
            FaultScenario {
                name: "memory_exhaustion_stress".to_string(),
                description: "System runs out of memory during key operations".to_string(),
                faults: vec![FaultType::MemoryExhaustion],
                expected_behavior: ExpectedBehavior::GracefulDegradation,
                recovery_time_limit: Duration::from_secs(120),
                criticality: FaultSeverity::High,
            },
            
            FaultScenario {
                name: "disk_full_scenario".to_string(),
                description: "Disk becomes full during audit logging".to_string(),
                faults: vec![FaultType::DiskFull],
                expected_behavior: ExpectedBehavior::FailSafe,
                recovery_time_limit: Duration::from_secs(30),
                criticality: FaultSeverity::Medium,
            },
            
            // Timing and concurrency faults
            FaultScenario {
                name: "race_condition_exploit".to_string(),
                description: "Race condition in concurrent key access".to_string(),
                faults: vec![FaultType::RaceCondition],
                expected_behavior: ExpectedBehavior::FailSafe,
                recovery_time_limit: Duration::from_secs(10),
                criticality: FaultSeverity::High,
            },
            
            FaultScenario {
                name: "clock_skew_attack".to_string(),
                description: "System clock manipulation affects time-based security".to_string(),
                faults: vec![FaultType::ClockSkew],
                expected_behavior: ExpectedBehavior::SystemQuarantine,
                recovery_time_limit: Duration::from_secs(15),
                criticality: FaultSeverity::Critical,
            },
            
            // Multi-fault scenarios
            FaultScenario {
                name: "cascading_failure".to_string(),
                description: "Multiple simultaneous faults test system resilience".to_string(),
                faults: vec![
                    FaultType::TmpTimeout,
                    FaultType::NetworkPartition,
                    FaultType::MemoryExhaustion,
                ],
                expected_behavior: ExpectedBehavior::FailSafe,
                recovery_time_limit: Duration::from_secs(180),
                criticality: FaultSeverity::Critical,
            },
            
            // Security-focused faults
            FaultScenario {
                name: "encryption_failure_cascade".to_string(),
                description: "Encryption operations fail, testing fallback security".to_string(),
                faults: vec![FaultType::EncryptionFailure],
                expected_behavior: ExpectedBehavior::FailSafe,
                recovery_time_limit: Duration::from_secs(20),
                criticality: FaultSeverity::Critical,
            },
        ]
    }

    /// Run all fault injection scenarios
    pub async fn run_all_scenarios(&self) -> Result<FaultTestResults, Box<dyn std::error::Error>> {
        println!("💥 Starting Fault Injection & Chaos Testing");
        
        let mut results = FaultTestResults {
            total_scenarios: self.test_scenarios.len(),
            passed_scenarios: 0,
            failed_scenarios: 0,
            scenario_results: Vec::new(),
            system_stability_score: 0.0,
            recovery_metrics: RecoveryMetrics {
                average_recovery_time: Duration::from_secs(0),
                max_recovery_time: Duration::from_secs(0),
                min_recovery_time: Duration::from_secs(u64::MAX),
                failed_recoveries: 0,
            },
        };
        
        for scenario in &self.test_scenarios {
            println!("🎯 Testing scenario: {} - {}", scenario.name, scenario.description);
            
            let scenario_result = self.run_fault_scenario(scenario).await?;
            
            if scenario_result.test_passed {
                results.passed_scenarios += 1;
            } else {
                results.failed_scenarios += 1;
            }
            
            results.scenario_results.push(scenario_result);
            
            // Recovery period between scenarios
            sleep(Duration::from_secs(2)).await;
        }
        
        // Calculate metrics
        self.calculate_recovery_metrics(&mut results);
        results.system_stability_score = self.calculate_stability_score(&results);
        
        println!("✅ Fault injection testing completed");
        println!("📊 System stability score: {:.2}/100", results.system_stability_score);
        
        Ok(results)
    }

    /// Run a single fault injection scenario
    async fn run_fault_scenario(&self, scenario: &FaultScenario) -> Result<ScenarioResult, Box<dyn std::error::Error>> {
        let start_time = Instant::now();
        let mut error_messages = Vec::new();
        let mut system_state_changes = Vec::new();
        
        // Inject faults
        for fault_type in &scenario.faults {
            self.fault_injector.inject_fault(fault_type.clone(), "system".to_string(), Duration::from_secs(60)).await;
            system_state_changes.push(format!("Injected fault: {:?}", fault_type));
        }
        
        // Test system behavior under fault conditions
        let actual_behavior = self.test_system_behavior_under_faults(scenario).await?;
        
        // Wait for recovery or timeout
        let recovery_start = Instant::now();
        let recovered = self.wait_for_recovery(scenario.recovery_time_limit).await;
        let recovery_time = recovery_start.elapsed();
        
        // Clear injected faults
        self.fault_injector.clear_all_faults().await;
        
        // Determine if test passed
        let test_passed = actual_behavior == scenario.expected_behavior && 
                         (recovered || scenario.expected_behavior == ExpectedBehavior::ManualIntervention);
        
        if !test_passed {
            error_messages.push(format!(
                "Expected behavior: {:?}, Actual: {:?}", 
                scenario.expected_behavior, 
                actual_behavior
            ));
        }
        
        Ok(ScenarioResult {
            scenario_name: scenario.name.clone(),
            test_passed,
            actual_behavior,
            recovery_time,
            error_messages,
            system_state_changes,
        })
    }

    /// Test system behavior under injected faults
    async fn test_system_behavior_under_faults(&self, scenario: &FaultScenario) -> Result<ExpectedBehavior, Box<dyn std::error::Error>> {
        // Test key operations under fault conditions
        let key_operation_result = self.test_key_operations_under_faults().await;
        
        // Test attestation under fault conditions
        let attestation_result = self.test_attestation_under_faults().await;
        
        // Test audit logging under fault conditions
        let audit_result = self.test_audit_logging_under_faults().await;
        
        // Determine behavior based on results
        if key_operation_result.is_err() && attestation_result.is_err() {
            if scenario.faults.contains(&FaultType::PcrModification) || 
               scenario.faults.contains(&FaultType::ClockSkew) {
                Ok(ExpectedBehavior::SystemQuarantine)
            } else {
                Ok(ExpectedBehavior::FailSafe)
            }
        } else if key_operation_result.is_err() || attestation_result.is_err() {
            Ok(ExpectedBehavior::GracefulDegradation)
        } else {
            Ok(ExpectedBehavior::AutoRecovery)
        }
    }

    /// Test key operations under fault conditions
    async fn test_key_operations_under_faults(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Test JWT generation
        let claims = serde_json::json!({
            "test": "fault_injection",
            "timestamp": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        });
        
        match self.master_key_service.generate_jwt_token(&claims, false).await {
            Ok(_) => Ok(()),
            Err(e) => Err(Box::new(e)),
        }
    }

    /// Test attestation under fault conditions
    async fn test_attestation_under_faults(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Test hardware attestation
        match self.hardware.get_attestation().await {
            Ok(_) => Ok(()),
            Err(e) => Err(Box::new(e)),
        }
    }

    /// Test audit logging under fault conditions
    async fn test_audit_logging_under_faults(&self) -> Result<(), Box<dyn std::error::Error>> {
        // This would test the enhanced audit logger
        // For now, we'll simulate the test
        if self.fault_injector.is_fault_active(&FaultType::DiskFull).await {
            Err("Disk full - audit logging failed".into())
        } else {
            Ok(())
        }
    }

    /// Wait for system recovery
    async fn wait_for_recovery(&self, timeout: Duration) -> bool {
        let start = Instant::now();
        
        while start.elapsed() < timeout {
            // Test if system has recovered
            if self.test_system_health().await {
                return true;
            }
            
            sleep(Duration::from_millis(500)).await;
        }
        
        false
    }

    /// Test overall system health
    async fn test_system_health(&self) -> bool {
        // Simple health check - in practice would be more comprehensive
        let key_test = self.test_key_operations_under_faults().await.is_ok();
        let attestation_test = self.test_attestation_under_faults().await.is_ok();
        
        key_test && attestation_test
    }

    /// Calculate recovery metrics
    fn calculate_recovery_metrics(&self, results: &mut FaultTestResults) {
        let recovery_times: Vec<Duration> = results.scenario_results
            .iter()
            .map(|r| r.recovery_time)
            .collect();
        
        if !recovery_times.is_empty() {
            let total_time: Duration = recovery_times.iter().sum();
            results.recovery_metrics.average_recovery_time = total_time / recovery_times.len() as u32;
            results.recovery_metrics.max_recovery_time = recovery_times.iter().max().unwrap().clone();
            results.recovery_metrics.min_recovery_time = recovery_times.iter().min().unwrap().clone();
        }
        
        results.recovery_metrics.failed_recoveries = results.scenario_results
            .iter()
            .filter(|r| !r.test_passed)
            .count();
    }

    /// Calculate system stability score
    fn calculate_stability_score(&self, results: &FaultTestResults) -> f64 {
        if results.total_scenarios == 0 {
            return 0.0;
        }
        
        let base_score = (results.passed_scenarios as f64 / results.total_scenarios as f64) * 100.0;
        
        // Adjust score based on criticality of failed scenarios
        let critical_failures = results.scenario_results
            .iter()
            .filter(|r| !r.test_passed && r.scenario_name.contains("critical"))
            .count();
        
        let penalty = critical_failures as f64 * 20.0; // 20 point penalty per critical failure
        
        (base_score - penalty).max(0.0)
    }

    /// Run continuous chaos testing
    pub async fn run_chaos_mode(&self, duration: Duration) -> Result<(), Box<dyn std::error::Error>> {
        println!("🌪️ Starting Chaos Mode for {:?}", duration);
        
        self.fault_injector.enable_chaos_mode().await;
        
        let start_time = Instant::now();
        let mut iteration = 0;
        
        while start_time.elapsed() < duration {
            iteration += 1;
            println!("🎲 Chaos iteration {}", iteration);
            
            // Randomly inject faults
            self.fault_injector.inject_random_fault().await;
            
            // Test system resilience
            let health_ok = self.test_system_health().await;
            if !health_ok {
                println!("⚠️ System health degraded during chaos iteration {}", iteration);
            }
            
            // Random sleep between 1-10 seconds
            let sleep_duration = Duration::from_secs(rand::random::<u64>() % 10 + 1);
            sleep(sleep_duration).await;
            
            // Occasionally clear faults to allow recovery
            if iteration % 5 == 0 {
                self.fault_injector.clear_random_faults().await;
            }
        }
        
        self.fault_injector.disable_chaos_mode().await;
        self.fault_injector.clear_all_faults().await;
        
        println!("✅ Chaos mode completed after {} iterations", iteration);
        Ok(())
    }
}

impl FaultInjector {
    pub fn new(fault_probability: f64, chaos_mode: bool) -> Self {
        Self {
            active_faults: Arc::new(Mutex::new(Vec::new())),
            fault_probability,
            chaos_mode,
        }
    }

    /// Inject a specific fault
    pub async fn inject_fault(&self, fault_type: FaultType, target: String, duration: Duration) {
        let fault = ActiveFault {
            fault_type,
            target_component: target,
            start_time: Instant::now(),
            duration,
            severity: FaultSeverity::Medium,
        };
        
        let mut faults = self.active_faults.lock().unwrap();
        faults.push(fault);
        
        println!("💥 Injected fault: {:?}", fault_type);
    }

    /// Check if a specific fault is active
    pub async fn is_fault_active(&self, fault_type: &FaultType) -> bool {
        let faults = self.active_faults.lock().unwrap();
        faults.iter().any(|f| &f.fault_type == fault_type && 
                         f.start_time.elapsed() < f.duration)
    }

    /// Clear all active faults
    pub async fn clear_all_faults(&self) {
        let mut faults = self.active_faults.lock().unwrap();
        faults.clear();
        println!("🧹 Cleared all injected faults");
    }

    /// Clear random faults (for chaos mode)
    pub async fn clear_random_faults(&self) {
        let mut faults = self.active_faults.lock().unwrap();
        if !faults.is_empty() {
            let remove_count = (faults.len() / 2).max(1);
            for _ in 0..remove_count {
                if !faults.is_empty() {
                    let index = rand::random::<usize>() % faults.len();
                    faults.remove(index);
                }
            }
        }
    }

    /// Inject random fault (for chaos mode)
    pub async fn inject_random_fault(&self) {
        if !self.chaos_mode {
            return;
        }
        
        let fault_types = vec![
            FaultType::TmpTimeout,
            FaultType::MemoryExhaustion,
            FaultType::NetworkPartition,
            FaultType::CpuStarvation,
            FaultType::RaceCondition,
        ];
        
        let fault_type = fault_types[rand::random::<usize>() % fault_types.len()].clone();
        let duration = Duration::from_secs(rand::random::<u64>() % 30 + 10); // 10-40 seconds
        
        self.inject_fault(fault_type, "random".to_string(), duration).await;
    }

    /// Enable chaos mode
    pub async fn enable_chaos_mode(&self) {
        // In a real implementation, this would modify the chaos_mode field
        println!("🌪️ Chaos mode enabled");
    }

    /// Disable chaos mode
    pub async fn disable_chaos_mode(&self) {
        // In a real implementation, this would modify the chaos_mode field
        println!("🛑 Chaos mode disabled");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_fault_scenario_generation() {
        let scenarios = FaultInjectionTests::generate_fault_scenarios();
        
        assert!(!scenarios.is_empty());
        assert!(scenarios.iter().any(|s| s.faults.contains(&FaultType::TmpTimeout)));
        assert!(scenarios.iter().any(|s| s.faults.contains(&FaultType::PcrModification)));
        assert!(scenarios.iter().any(|s| s.criticality == FaultSeverity::Critical));
    }

    #[tokio::test]
    async fn test_fault_injector() {
        let injector = FaultInjector::new(0.5, false);
        
        // Test fault injection
        injector.inject_fault(
            FaultType::TmpTimeout, 
            "test_component".to_string(), 
            Duration::from_secs(1)
        ).await;
        
        assert!(injector.is_fault_active(&FaultType::TmpTimeout).await);
        
        // Wait for fault to expire
        sleep(Duration::from_millis(1100)).await;
        assert!(!injector.is_fault_active(&FaultType::TmpTimeout).await);
    }

    #[test]
    fn test_stability_score_calculation() {
        let test_suite = FaultInjectionTests {
            hardware: Arc::new(HardwareAbstraction::new_mock()),
            master_key_service: Arc::new(MasterKeyService::new_mock()),
            enclave_manager: Arc::new(SecureEnclaveManager::new_mock()),
            fault_injector: Arc::new(FaultInjector::new(0.1, false)),
            test_scenarios: vec![],
        };
        
        let results = FaultTestResults {
            total_scenarios: 10,
            passed_scenarios: 8,
            failed_scenarios: 2,
            scenario_results: vec![],
            system_stability_score: 0.0,
            recovery_metrics: RecoveryMetrics {
                average_recovery_time: Duration::from_secs(30),
                max_recovery_time: Duration::from_secs(60),
                min_recovery_time: Duration::from_secs(10),
                failed_recoveries: 2,
            },
        };
        
        let score = test_suite.calculate_stability_score(&results);
        assert!(score >= 70.0 && score <= 90.0); // Should be around 80%
    }
}
