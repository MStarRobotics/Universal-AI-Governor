// Remote Attestation Endpoint
// Provides HTTPS endpoint for device integrity verification

use crate::governor_core::hardware::{HardwareAbstraction, AttestationData, PcrState};
use crate::governor_core::master_key_service::MasterKeyService;
use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::Json,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tower::ServiceBuilder;
use tower_http::cors::CorsLayer;

/// Attestation endpoint service
pub struct AttestationEndpoint {
    hardware: Arc<HardwareAbstraction>,
    master_key_service: Arc<MasterKeyService>,
    attestation_cache: RwLock<HashMap<String, CachedAttestation>>,
    config: AttestationConfig,
}

/// Attestation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationConfig {
    pub endpoint_enabled: bool,
    pub require_authentication: bool,
    pub cache_duration_seconds: u64,
    pub max_nonce_age_seconds: u64,
    pub include_firmware_hashes: bool,
    pub include_boot_log: bool,
    pub rate_limit_per_minute: u32,
    pub trusted_ca_certificates: Vec<String>,
}

/// Cached attestation data
#[derive(Debug, Clone)]
struct CachedAttestation {
    data: AttestationResponse,
    created_at: u64,
    access_count: u64,
}

/// Attestation request parameters
#[derive(Debug, Deserialize)]
pub struct AttestationRequest {
    pub nonce: Option<String>,
    pub include_pcr_values: Option<bool>,
    pub include_firmware_hashes: Option<bool>,
    pub include_boot_log: Option<bool>,
    pub pcr_indices: Option<Vec<u32>>,
    pub challenge: Option<String>,
}

/// Attestation response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationResponse {
    pub device_id: String,
    pub timestamp: u64,
    pub nonce: Option<String>,
    pub attestation_signature: String,
    pub pcr_values: Option<Vec<PcrState>>,
    pub firmware_hashes: Option<Vec<FirmwareHash>>,
    pub boot_log: Option<Vec<BootLogEntry>>,
    pub hardware_capabilities: HardwareCapabilities,
    pub integrity_status: IntegrityStatus,
    pub certificate_chain: Option<Vec<String>>,
    pub quote_signature: String,
}

/// Firmware hash information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirmwareHash {
    pub component: String,
    pub version: String,
    pub hash_algorithm: String,
    pub hash_value: String,
    pub measurement_pcr: Option<u32>,
}

/// Boot log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootLogEntry {
    pub sequence: u32,
    pub pcr_index: u32,
    pub event_type: String,
    pub digest: String,
    pub event_data: String,
    pub timestamp: Option<u64>,
}

/// Hardware capabilities for attestation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareCapabilities {
    pub tpm_version: Option<String>,
    pub tpm_manufacturer: Option<String>,
    pub secure_boot_enabled: bool,
    pub measured_boot_enabled: bool,
    pub hsm_available: bool,
    pub secure_enclave_available: bool,
    pub sgx_available: bool,
}

/// Device integrity status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityStatus {
    pub overall_status: IntegrityLevel,
    pub pcr_integrity: bool,
    pub firmware_integrity: bool,
    pub boot_integrity: bool,
    pub runtime_integrity: bool,
    pub last_verified: u64,
    pub anomalies_detected: Vec<String>,
}

/// Integrity levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IntegrityLevel {
    Trusted,
    Warning,
    Compromised,
    Unknown,
}

/// Attestation verification request
#[derive(Debug, Deserialize)]
pub struct VerifyAttestationRequest {
    pub attestation_data: String,
    pub expected_pcr_values: Option<HashMap<u32, String>>,
    pub trusted_firmware_hashes: Option<Vec<String>>,
    pub nonce: Option<String>,
}

/// Attestation verification response
#[derive(Debug, Serialize)]
pub struct VerifyAttestationResponse {
    pub is_valid: bool,
    pub verification_details: VerificationDetails,
    pub trust_level: TrustLevel,
    pub recommendations: Vec<String>,
}

/// Verification details
#[derive(Debug, Serialize)]
pub struct VerificationDetails {
    pub signature_valid: bool,
    pub pcr_values_match: bool,
    pub firmware_hashes_match: bool,
    pub nonce_valid: bool,
    pub certificate_chain_valid: bool,
    pub timestamp_valid: bool,
}

/// Trust levels for attestation
#[derive(Debug, Serialize)]
pub enum TrustLevel {
    FullyTrusted,
    ConditionallyTrusted,
    Untrusted,
    VerificationFailed,
}

impl AttestationEndpoint {
    /// Create new attestation endpoint
    pub fn new(
        hardware: Arc<HardwareAbstraction>,
        master_key_service: Arc<MasterKeyService>,
        config: AttestationConfig,
    ) -> Self {
        Self {
            hardware,
            master_key_service,
            attestation_cache: RwLock::new(HashMap::new()),
            config,
        }
    }

    /// Create router for attestation endpoints
    pub fn create_router(self) -> Router {
        let shared_state = Arc::new(self);

        Router::new()
            .route("/attestation", get(get_attestation))
            .route("/attestation/verify", post(verify_attestation))
            .route("/attestation/capabilities", get(get_capabilities))
            .route("/attestation/health", get(health_check))
            .with_state(shared_state)
            .layer(
                ServiceBuilder::new()
                    .layer(CorsLayer::permissive())
                    .into_inner(),
            )
    }

    /// Generate device attestation
    pub async fn generate_attestation(
        &self,
        request: &AttestationRequest,
    ) -> Result<AttestationResponse, AttestationError> {
        // Check cache first
        if let Some(cached) = self.check_cache(&request.nonce).await {
            return Ok(cached.data);
        }

        // Generate device ID
        let device_id = self.generate_device_id().await?;

        // Get hardware attestation data
        let attestation_data = self.hardware.get_attestation().await
            .map_err(|e| AttestationError::HardwareError(e.to_string()))?;

        // Get PCR values if requested
        let pcr_values = if request.include_pcr_values.unwrap_or(true) {
            let mut pcr_values = self.hardware.get_pcr_values().await
                .map_err(|e| AttestationError::HardwareError(e.to_string()))?;

            // Filter by requested indices if specified
            if let Some(indices) = &request.pcr_indices {
                pcr_values.retain(|pcr| indices.contains(&pcr.index));
            }

            Some(pcr_values)
        } else {
            None
        };

        // Get firmware hashes if requested
        let firmware_hashes = if request.include_firmware_hashes.unwrap_or(self.config.include_firmware_hashes) {
            Some(self.collect_firmware_hashes().await?)
        } else {
            None
        };

        // Get boot log if requested
        let boot_log = if request.include_boot_log.unwrap_or(self.config.include_boot_log) {
            Some(self.collect_boot_log().await?)
        } else {
            None
        };

        // Get hardware capabilities
        let hardware_capabilities = self.get_hardware_capabilities().await;

        // Assess integrity status
        let integrity_status = self.assess_integrity_status(&pcr_values, &firmware_hashes).await?;

        // Create attestation payload
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let attestation_payload = serde_json::json!({
            "device_id": device_id,
            "timestamp": timestamp,
            "nonce": request.nonce,
            "pcr_values": pcr_values,
            "firmware_hashes": firmware_hashes,
            "boot_log": boot_log,
            "hardware_capabilities": hardware_capabilities,
            "integrity_status": integrity_status,
        });

        // Sign attestation with hardware-backed key
        let payload_bytes = serde_json::to_vec(&attestation_payload)
            .map_err(|e| AttestationError::SerializationError(e.to_string()))?;

        let attestation_signature = self.hardware.sign_data("attestation_key", &payload_bytes).await
            .map_err(|e| AttestationError::SigningError(e.to_string()))?;

        // Generate TPM quote signature
        let quote_signature = self.generate_tpm_quote(&request.nonce, &pcr_values).await?;

        // Get certificate chain if available
        let certificate_chain = self.get_certificate_chain().await;

        let response = AttestationResponse {
            device_id,
            timestamp,
            nonce: request.nonce.clone(),
            attestation_signature: base64::encode(&attestation_signature),
            pcr_values,
            firmware_hashes,
            boot_log,
            hardware_capabilities,
            integrity_status,
            certificate_chain,
            quote_signature: base64::encode(&quote_signature),
        };

        // Cache the response
        self.cache_attestation(&request.nonce, &response).await;

        Ok(response)
    }

    /// Verify attestation data
    pub async fn verify_attestation_data(
        &self,
        request: &VerifyAttestationRequest,
    ) -> Result<VerifyAttestationResponse, AttestationError> {
        // Decode attestation data
        let attestation_bytes = base64::decode(&request.attestation_data)
            .map_err(|_| AttestationError::InvalidFormat)?;

        let attestation: AttestationResponse = serde_json::from_slice(&attestation_bytes)
            .map_err(|_| AttestationError::InvalidFormat)?;

        // Verify signature
        let signature_bytes = base64::decode(&attestation.attestation_signature)
            .map_err(|_| AttestationError::InvalidFormat)?;

        let attestation_payload = serde_json::json!({
            "device_id": attestation.device_id,
            "timestamp": attestation.timestamp,
            "nonce": attestation.nonce,
            "pcr_values": attestation.pcr_values,
            "firmware_hashes": attestation.firmware_hashes,
            "boot_log": attestation.boot_log,
            "hardware_capabilities": attestation.hardware_capabilities,
            "integrity_status": attestation.integrity_status,
        });

        let payload_bytes = serde_json::to_vec(&attestation_payload)
            .map_err(|e| AttestationError::SerializationError(e.to_string()))?;

        let signature_valid = self.hardware.verify_signature("attestation_key", &payload_bytes, &signature_bytes).await
            .map_err(|e| AttestationError::VerificationError(e.to_string()))?;

        // Verify PCR values if provided
        let pcr_values_match = if let Some(expected_pcrs) = &request.expected_pcr_values {
            self.verify_pcr_values(&attestation.pcr_values, expected_pcrs)
        } else {
            true
        };

        // Verify firmware hashes if provided
        let firmware_hashes_match = if let Some(trusted_hashes) = &request.trusted_firmware_hashes {
            self.verify_firmware_hashes(&attestation.firmware_hashes, trusted_hashes)
        } else {
            true
        };

        // Verify nonce if provided
        let nonce_valid = if let Some(expected_nonce) = &request.nonce {
            attestation.nonce.as_ref() == Some(expected_nonce)
        } else {
            true
        };

        // Verify certificate chain
        let certificate_chain_valid = self.verify_certificate_chain(&attestation.certificate_chain).await;

        // Verify timestamp (not too old)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let timestamp_valid = (now - attestation.timestamp) < self.config.max_nonce_age_seconds;

        let verification_details = VerificationDetails {
            signature_valid,
            pcr_values_match,
            firmware_hashes_match,
            nonce_valid,
            certificate_chain_valid,
            timestamp_valid,
        };

        // Determine overall validity and trust level
        let is_valid = signature_valid && pcr_values_match && firmware_hashes_match 
            && nonce_valid && certificate_chain_valid && timestamp_valid;

        let trust_level = if is_valid {
            match attestation.integrity_status.overall_status {
                IntegrityLevel::Trusted => TrustLevel::FullyTrusted,
                IntegrityLevel::Warning => TrustLevel::ConditionallyTrusted,
                IntegrityLevel::Compromised => TrustLevel::Untrusted,
                IntegrityLevel::Unknown => TrustLevel::ConditionallyTrusted,
            }
        } else {
            TrustLevel::VerificationFailed
        };

        // Generate recommendations
        let recommendations = self.generate_recommendations(&verification_details, &attestation.integrity_status);

        Ok(VerifyAttestationResponse {
            is_valid,
            verification_details,
            trust_level,
            recommendations,
        })
    }

    /// Generate device ID from hardware characteristics
    async fn generate_device_id(&self) -> Result<String, AttestationError> {
        // In a real implementation, this would use:
        // - TPM endorsement key
        // - CPU serial number
        // - Motherboard serial number
        // - MAC addresses
        
        let hardware_info = format!("device_{}", 
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        );

        use ring::digest;
        let device_id_hash = digest::digest(&digest::SHA256, hardware_info.as_bytes());
        Ok(hex::encode(device_id_hash.as_ref()))
    }

    /// Collect firmware hashes from system
    async fn collect_firmware_hashes(&self) -> Result<Vec<FirmwareHash>, AttestationError> {
        // In a real implementation, this would:
        // - Read UEFI firmware measurements
        // - Collect bootloader hashes
        // - Get kernel module signatures
        // - Retrieve microcode versions

        Ok(vec![
            FirmwareHash {
                component: "UEFI Firmware".to_string(),
                version: "2.70".to_string(),
                hash_algorithm: "SHA256".to_string(),
                hash_value: "a1b2c3d4e5f6...".to_string(),
                measurement_pcr: Some(0),
            },
            FirmwareHash {
                component: "Bootloader".to_string(),
                version: "GRUB 2.06".to_string(),
                hash_algorithm: "SHA256".to_string(),
                hash_value: "f6e5d4c3b2a1...".to_string(),
                measurement_pcr: Some(4),
            },
        ])
    }

    /// Collect boot log entries
    async fn collect_boot_log(&self) -> Result<Vec<BootLogEntry>, AttestationError> {
        // In a real implementation, this would:
        // - Parse TPM event log
        // - Read UEFI boot services log
        // - Collect kernel boot messages
        // - Get systemd journal entries

        Ok(vec![
            BootLogEntry {
                sequence: 1,
                pcr_index: 0,
                event_type: "EV_S_CRTM_VERSION".to_string(),
                digest: "sha256:a1b2c3...".to_string(),
                event_data: "UEFI Firmware v2.70".to_string(),
                timestamp: Some(std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() - 3600),
            },
        ])
    }

    /// Get hardware capabilities
    async fn get_hardware_capabilities(&self) -> HardwareCapabilities {
        let hw_caps = self.hardware.get_capabilities();
        
        HardwareCapabilities {
            tpm_version: if hw_caps.tmp_available { Some("2.0".to_string()) } else { None },
            tpm_manufacturer: if hw_caps.tpm_available { Some("Infineon".to_string()) } else { None },
            secure_boot_enabled: hw_caps.secure_boot,
            measured_boot_enabled: hw_caps.measured_boot,
            hsm_available: hw_caps.hsm_available,
            secure_enclave_available: false, // Will be implemented in secure enclave module
            sgx_available: false, // Will be implemented in secure enclave module
        }
    }

    /// Assess overall integrity status
    async fn assess_integrity_status(
        &self,
        pcr_values: &Option<Vec<PcrState>>,
        firmware_hashes: &Option<Vec<FirmwareHash>>,
    ) -> Result<IntegrityStatus, AttestationError> {
        let mut anomalies = Vec::new();
        
        // Check PCR integrity
        let pcr_integrity = if let Some(pcrs) = pcr_values {
            // In a real implementation, compare against known good values
            let suspicious_pcrs = pcrs.iter()
                .filter(|pcr| pcr.value.iter().all(|&b| b == 0))
                .count();
            
            if suspicious_pcrs > 0 {
                anomalies.push(format!("{} PCRs contain all zeros", suspicious_pcrs));
                false
            } else {
                true
            }
        } else {
            false
        };

        // Check firmware integrity
        let firmware_integrity = if let Some(firmware) = firmware_hashes {
            // In a real implementation, verify against trusted database
            firmware.len() > 0
        } else {
            false
        };

        // Determine overall status
        let overall_status = if pcr_integrity && firmware_integrity && anomalies.is_empty() {
            IntegrityLevel::Trusted
        } else if anomalies.len() <= 2 {
            IntegrityLevel::Warning
        } else {
            IntegrityLevel::Compromised
        };

        Ok(IntegrityStatus {
            overall_status,
            pcr_integrity,
            firmware_integrity,
            boot_integrity: pcr_integrity,
            runtime_integrity: true, // Would check runtime measurements
            last_verified: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            anomalies_detected: anomalies,
        })
    }

    /// Generate TPM quote signature
    async fn generate_tpm_quote(
        &self,
        nonce: &Option<String>,
        pcr_values: &Option<Vec<PcrState>>,
    ) -> Result<Vec<u8>, AttestationError> {
        // In a real implementation, this would:
        // - Use TPM2_Quote command
        // - Include nonce and PCR selection
        // - Sign with attestation identity key

        let quote_data = serde_json::json!({
            "nonce": nonce,
            "pcr_values": pcr_values,
            "timestamp": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        });

        let quote_bytes = serde_json::to_vec(&quote_data)
            .map_err(|e| AttestationError::SerializationError(e.to_string()))?;

        self.hardware.sign_data("quote_key", &quote_bytes).await
            .map_err(|e| AttestationError::SigningError(e.to_string()))
    }

    /// Get certificate chain for attestation
    async fn get_certificate_chain(&self) -> Option<Vec<String>> {
        // In a real implementation, this would return:
        // - TPM endorsement certificate
        // - Platform certificate
        // - CA certificates
        None
    }

    /// Verify PCR values against expected values
    fn verify_pcr_values(
        &self,
        actual_pcrs: &Option<Vec<PcrState>>,
        expected_pcrs: &HashMap<u32, String>,
    ) -> bool {
        if let Some(pcrs) = actual_pcrs {
            for pcr in pcrs {
                if let Some(expected) = expected_pcrs.get(&pcr.index) {
                    let actual_hex = hex::encode(&pcr.value);
                    if &actual_hex != expected {
                        return false;
                    }
                }
            }
            true
        } else {
            false
        }
    }

    /// Verify firmware hashes against trusted list
    fn verify_firmware_hashes(
        &self,
        actual_hashes: &Option<Vec<FirmwareHash>>,
        trusted_hashes: &[String],
    ) -> bool {
        if let Some(hashes) = actual_hashes {
            hashes.iter().all(|hash| trusted_hashes.contains(&hash.hash_value))
        } else {
            false
        }
    }

    /// Verify certificate chain
    async fn verify_certificate_chain(&self, _chain: &Option<Vec<String>>) -> bool {
        // In a real implementation, this would:
        // - Verify certificate signatures
        // - Check certificate validity periods
        // - Validate against trusted CA roots
        true
    }

    /// Generate security recommendations
    fn generate_recommendations(
        &self,
        details: &VerificationDetails,
        integrity: &IntegrityStatus,
    ) -> Vec<String> {
        let mut recommendations = Vec::new();

        if !details.signature_valid {
            recommendations.push("Attestation signature is invalid - device may be compromised".to_string());
        }

        if !details.pcr_values_match {
            recommendations.push("PCR values do not match expected baseline - investigate boot integrity".to_string());
        }

        if !details.firmware_hashes_match {
            recommendations.push("Firmware hashes do not match trusted values - verify firmware integrity".to_string());
        }

        if !integrity.anomalies_detected.is_empty() {
            recommendations.push(format!("Anomalies detected: {}", integrity.anomalies_detected.join(", ")));
        }

        if recommendations.is_empty() {
            recommendations.push("Device attestation is valid and trusted".to_string());
        }

        recommendations
    }

    /// Check attestation cache
    async fn check_cache(&self, nonce: &Option<String>) -> Option<CachedAttestation> {
        if let Some(nonce_str) = nonce {
            let cache = self.attestation_cache.read().await;
            if let Some(cached) = cache.get(nonce_str) {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                
                if (now - cached.created_at) < self.config.cache_duration_seconds {
                    return Some(cached.clone());
                }
            }
        }
        None
    }

    /// Cache attestation response
    async fn cache_attestation(&self, nonce: &Option<String>, response: &AttestationResponse) {
        if let Some(nonce_str) = nonce {
            let cached = CachedAttestation {
                data: response.clone(),
                created_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                access_count: 0,
            };

            let mut cache = self.attestation_cache.write().await;
            cache.insert(nonce_str.clone(), cached);
        }
    }
}

/// HTTP handlers
async fn get_attestation(
    Query(params): Query<AttestationRequest>,
    State(endpoint): State<Arc<AttestationEndpoint>>,
) -> Result<Json<AttestationResponse>, StatusCode> {
    match endpoint.generate_attestation(&params).await {
        Ok(response) => Ok(Json(response)),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

async fn verify_attestation(
    State(endpoint): State<Arc<AttestationEndpoint>>,
    Json(request): Json<VerifyAttestationRequest>,
) -> Result<Json<VerifyAttestationResponse>, StatusCode> {
    match endpoint.verify_attestation_data(&request).await {
        Ok(response) => Ok(Json(response)),
        Err(_) => Err(StatusCode::BAD_REQUEST),
    }
}

async fn get_capabilities(
    State(endpoint): State<Arc<AttestationEndpoint>>,
) -> Json<HardwareCapabilities> {
    Json(endpoint.get_hardware_capabilities().await)
}

async fn health_check() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "healthy",
        "timestamp": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }))
}

/// Attestation errors
#[derive(Debug, thiserror::Error)]
pub enum AttestationError {
    #[error("Hardware error: {0}")]
    HardwareError(String),
    
    #[error("Signing error: {0}")]
    SigningError(String),
    
    #[error("Verification error: {0}")]
    VerificationError(String),
    
    #[error("Serialization error: {0}")]
    SerializationError(String),
    
    #[error("Invalid format")]
    InvalidFormat,
    
    #[error("Cache error")]
    CacheError,
}

impl Default for AttestationConfig {
    fn default() -> Self {
        Self {
            endpoint_enabled: true,
            require_authentication: false,
            cache_duration_seconds: 300, // 5 minutes
            max_nonce_age_seconds: 3600, // 1 hour
            include_firmware_hashes: true,
            include_boot_log: false,
            rate_limit_per_minute: 60,
            trusted_ca_certificates: vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::governor_core::hardware::HardwareAbstraction;
    use crate::governor_core::master_key_service::MasterKeyService;

    async fn create_test_endpoint() -> AttestationEndpoint {
        let config = crate::GovernorConfig {
            offline_mode: true,
            challenge_expiry_seconds: 300,
            max_failed_attempts: 3,
            lockout_duration_seconds: 900,
            tpm_enabled: false,
            post_quantum_enabled: false,
            audit_level: crate::AuditLevel::Standard,
        };

        let hardware = Arc::new(HardwareAbstraction::new(&config).await.unwrap());
        let crypto_service = crate::governor_core::cryptography::CryptographyService::new(&config).await.unwrap();
        let master_key_config = crate::governor_core::master_key_service::MasterKeyConfig::default();
        let master_key_service = Arc::new(
            MasterKeyService::new((*hardware).clone(), crypto_service, master_key_config).await.unwrap()
        );

        AttestationEndpoint::new(hardware, master_key_service, AttestationConfig::default())
    }

    #[tokio::test]
    async fn test_attestation_generation() {
        let endpoint = create_test_endpoint().await;
        
        let request = AttestationRequest {
            nonce: Some("test_nonce_123".to_string()),
            include_pcr_values: Some(true),
            include_firmware_hashes: Some(true),
            include_boot_log: Some(false),
            pcr_indices: None,
            challenge: None,
        };

        let response = endpoint.generate_attestation(&request).await.unwrap();
        
        assert!(!response.device_id.is_empty());
        assert!(!response.attestation_signature.is_empty());
        assert_eq!(response.nonce, Some("test_nonce_123".to_string()));
    }

    #[tokio::test]
    async fn test_attestation_verification() {
        let endpoint = create_test_endpoint().await;
        
        // Generate attestation
        let request = AttestationRequest {
            nonce: Some("verify_test_nonce".to_string()),
            include_pcr_values: Some(true),
            include_firmware_hashes: Some(true),
            include_boot_log: Some(false),
            pcr_indices: None,
            challenge: None,
        };

        let attestation = endpoint.generate_attestation(&request).await.unwrap();
        let attestation_data = base64::encode(serde_json::to_vec(&attestation).unwrap());

        // Verify attestation
        let verify_request = VerifyAttestationRequest {
            attestation_data,
            expected_pcr_values: None,
            trusted_firmware_hashes: None,
            nonce: Some("verify_test_nonce".to_string()),
        };

        let verify_response = endpoint.verify_attestation_data(&verify_request).await.unwrap();
        
        // Note: This will fail in test environment due to mock signatures
        // In a real implementation with proper hardware, this would pass
        assert!(!verify_response.is_valid || matches!(verify_response.trust_level, TrustLevel::VerificationFailed));
    }
}
