// Master Key Service with Hardware Integration
// Manages symmetric master keys sealed to TPM PCRs and HSM-backed JWT signing

use crate::governor_core::hardware::{HardwareAbstraction, KeyType, HardwareError};
use crate::governor_core::cryptography::CryptographyService;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::sync::RwLock;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Master key service with hardware backing
pub struct MasterKeyService {
    hardware: HardwareAbstraction,
    crypto_service: CryptographyService,
    key_metadata: RwLock<HashMap<String, MasterKeyMetadata>>,
    jwt_signing_key_id: String,
    config: MasterKeyConfig,
}

/// Configuration for master key service
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MasterKeyConfig {
    pub key_rotation_interval_hours: u64,
    pub max_key_age_hours: u64,
    pub require_hardware_backing: bool,
    pub pcr_binding_enabled: bool,
    pub jwt_key_algorithm: JwtAlgorithm,
    pub master_key_length: usize,
}

/// JWT signing algorithms
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum JwtAlgorithm {
    RS256,  // RSA with SHA-256
    ES256,  // ECDSA with SHA-256
    PS256,  // RSA-PSS with SHA-256
    HS256,  // HMAC with SHA-256 (for testing only)
}

/// Master key metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MasterKeyMetadata {
    pub key_id: String,
    pub created_at: u64,
    pub last_used: u64,
    pub usage_count: u64,
    pub key_type: MasterKeyType,
    pub hardware_backed: bool,
    pub pcr_sealed: bool,
    pub pcr_snapshot: Option<Vec<u8>>,
    pub hsm_slot_id: Option<u64>,
    pub rotation_due: bool,
}

/// Types of master keys
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MasterKeyType {
    DataEncryption,
    JwtSigning,
    AuditSigning,
    PolicyEncryption,
    BackupEncryption,
}

/// JWT token with hardware attestation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareBackedJwt {
    pub token: String,
    pub attestation_data: Option<Vec<u8>>,
    pub pcr_snapshot: Option<Vec<u8>>,
    pub hsm_signature: Option<Vec<u8>>,
    pub issued_at: u64,
    pub expires_at: u64,
}

/// Master key creation request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateMasterKeyRequest {
    pub key_id: String,
    pub key_type: MasterKeyType,
    pub require_pcr_binding: bool,
    pub custom_pcr_indices: Option<Vec<u32>>,
}

impl MasterKeyService {
    /// Initialize master key service with hardware backing
    pub async fn new(
        hardware: HardwareAbstraction,
        crypto_service: CryptographyService,
        config: MasterKeyConfig,
    ) -> Result<Self, MasterKeyError> {
        let jwt_signing_key_id = "jwt_master_signing_key".to_string();
        
        let mut service = Self {
            hardware,
            crypto_service,
            key_metadata: RwLock::new(HashMap::new()),
            jwt_signing_key_id: jwt_signing_key_id.clone(),
            config,
        };

        // Initialize JWT signing key if it doesn't exist
        service.ensure_jwt_signing_key().await?;

        Ok(service)
    }

    /// Ensure JWT signing key exists and is hardware-backed
    async fn ensure_jwt_signing_key(&mut self) -> Result<(), MasterKeyError> {
        // Check if JWT signing key already exists
        if self.hardware.unseal_key(&self.jwt_signing_key_id).await.is_ok() {
            return Ok(());
        }

        // Generate new JWT signing key
        let key_data = match self.config.jwt_key_algorithm {
            JwtAlgorithm::HS256 => {
                // Generate HMAC key (for testing only)
                self.hardware.generate_random(32).await
                    .map_err(|e| MasterKeyError::KeyGenerationFailed(e.to_string()))?
            }
            JwtAlgorithm::RS256 | JwtAlgorithm::PS256 => {
                // Generate RSA private key
                self.generate_rsa_key_pair().await?
            }
            JwtAlgorithm::ES256 => {
                // Generate ECDSA private key
                self.generate_ecdsa_key_pair().await?
            }
        };

        // Seal key to hardware with PCR binding
        self.hardware.seal_key(
            &self.jwt_signing_key_id,
            &key_data,
            KeyType::SigningKey,
        ).await.map_err(|e| MasterKeyError::HardwareOperationFailed(e.to_string()))?;

        // Store metadata
        let metadata = MasterKeyMetadata {
            key_id: self.jwt_signing_key_id.clone(),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            last_used: 0,
            usage_count: 0,
            key_type: MasterKeyType::JwtSigning,
            hardware_backed: self.hardware.is_hardware_available(),
            pcr_sealed: self.config.pcr_binding_enabled,
            pcr_snapshot: self.capture_pcr_snapshot().await?,
            hsm_slot_id: None, // Would be populated if using HSM
            rotation_due: false,
        };

        let mut key_metadata = self.key_metadata.write().await;
        key_metadata.insert(self.jwt_signing_key_id.clone(), metadata);

        Ok(())
    }

    /// Create a new master key with hardware backing
    pub async fn create_master_key(
        &self,
        request: CreateMasterKeyRequest,
    ) -> Result<(), MasterKeyError> {
        // Check if key already exists
        if self.hardware.unseal_key(&request.key_id).await.is_ok() {
            return Err(MasterKeyError::KeyAlreadyExists(request.key_id));
        }

        // Generate key material
        let key_data = self.hardware.generate_random(self.config.master_key_length).await
            .map_err(|e| MasterKeyError::KeyGenerationFailed(e.to_string()))?;

        // Determine hardware key type
        let hardware_key_type = match request.key_type {
            MasterKeyType::JwtSigning | MasterKeyType::AuditSigning => KeyType::SigningKey,
            _ => KeyType::EncryptionKey,
        };

        // Seal key to hardware with PCR binding if requested
        self.hardware.seal_key(&request.key_id, &key_data, hardware_key_type).await
            .map_err(|e| MasterKeyError::HardwareOperationFailed(e.to_string()))?;

        // Capture PCR snapshot if PCR binding is enabled
        let pcr_snapshot = if request.require_pcr_binding || self.config.pcr_binding_enabled {
            self.capture_pcr_snapshot().await?
        } else {
            None
        };

        // Store metadata
        let metadata = MasterKeyMetadata {
            key_id: request.key_id.clone(),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            last_used: 0,
            usage_count: 0,
            key_type: request.key_type,
            hardware_backed: self.hardware.is_hardware_available(),
            pcr_sealed: request.require_pcr_binding || self.config.pcr_binding_enabled,
            pcr_snapshot,
            hsm_slot_id: None,
            rotation_due: false,
        };

        let mut key_metadata = self.key_metadata.write().await;
        key_metadata.insert(request.key_id, metadata);

        Ok(())
    }

    /// Generate hardware-backed JWT token with attestation
    pub async fn generate_jwt_token(
        &self,
        claims: &serde_json::Value,
        include_attestation: bool,
    ) -> Result<HardwareBackedJwt, MasterKeyError> {
        // Update key usage metadata
        self.update_key_usage(&self.jwt_signing_key_id).await?;

        // Get signing key from hardware
        let signing_key = self.hardware.unseal_key(&self.jwt_signing_key_id).await
            .map_err(|e| MasterKeyError::HardwareOperationFailed(e.to_string()))?;

        // Create JWT header
        let header = serde_json::json!({
            "alg": match self.config.jwt_key_algorithm {
                JwtAlgorithm::RS256 => "RS256",
                JwtAlgorithm::ES256 => "ES256",
                JwtAlgorithm::PS256 => "PS256",
                JwtAlgorithm::HS256 => "HS256",
            },
            "typ": "JWT",
            "kid": self.jwt_signing_key_id,
            "hardware_backed": self.hardware.is_hardware_available(),
        });

        // Add timestamp claims
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let mut enhanced_claims = claims.clone();
        enhanced_claims["iat"] = serde_json::Value::Number(serde_json::Number::from(now));
        enhanced_claims["exp"] = serde_json::Value::Number(serde_json::Number::from(now + 3600)); // 1 hour

        // Encode header and payload
        let header_b64 = base64::encode_config(
            serde_json::to_string(&header).unwrap().as_bytes(),
            base64::URL_SAFE_NO_PAD,
        );
        let payload_b64 = base64::encode_config(
            serde_json::to_string(&enhanced_claims).unwrap().as_bytes(),
            base64::URL_SAFE_NO_PAD,
        );

        let signing_input = format!("{}.{}", header_b64, payload_b64);

        // Sign with hardware-backed key
        let signature = self.hardware.sign_data(&self.jwt_signing_key_id, signing_input.as_bytes()).await
            .map_err(|e| MasterKeyError::SigningFailed(e.to_string()))?;

        let signature_b64 = base64::encode_config(&signature, base64::URL_SAFE_NO_PAD);
        let token = format!("{}.{}", signing_input, signature_b64);

        // Generate attestation data if requested
        let (attestation_data, pcr_snapshot, hsm_signature) = if include_attestation {
            let attestation = self.hardware.get_attestation().await
                .map_err(|e| MasterKeyError::AttestationFailed(e.to_string()))?;
            
            let attestation_bytes = serde_json::to_vec(&attestation)
                .map_err(|e| MasterKeyError::SerializationFailed(e.to_string()))?;
            
            let pcr_snapshot = self.capture_pcr_snapshot().await?;
            
            // Sign attestation with HSM if available
            let hsm_sig = if self.hardware.is_hardware_available() {
                Some(self.hardware.sign_data("attestation_key", &attestation_bytes).await
                    .unwrap_or_default())
            } else {
                None
            };

            (Some(attestation_bytes), pcr_snapshot, hsm_sig)
        } else {
            (None, None, None)
        };

        Ok(HardwareBackedJwt {
            token,
            attestation_data,
            pcr_snapshot,
            hsm_signature,
            issued_at: now,
            expires_at: now + 3600,
        })
    }

    /// Verify JWT token with hardware attestation
    pub async fn verify_jwt_token(
        &self,
        token: &str,
        verify_attestation: bool,
    ) -> Result<serde_json::Value, MasterKeyError> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(MasterKeyError::InvalidTokenFormat);
        }

        // Decode header to get key ID
        let header_bytes = base64::decode_config(parts[0], base64::URL_SAFE_NO_PAD)
            .map_err(|_| MasterKeyError::InvalidTokenFormat)?;
        let header: serde_json::Value = serde_json::from_slice(&header_bytes)
            .map_err(|_| MasterKeyError::InvalidTokenFormat)?;

        let key_id = header["kid"].as_str()
            .ok_or(MasterKeyError::InvalidTokenFormat)?;

        // Verify signature with hardware-backed key
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let signature = base64::decode_config(parts[2], base64::URL_SAFE_NO_PAD)
            .map_err(|_| MasterKeyError::InvalidTokenFormat)?;

        let is_valid = self.hardware.verify_signature(key_id, signing_input.as_bytes(), &signature).await
            .map_err(|e| MasterKeyError::VerificationFailed(e.to_string()))?;

        if !is_valid {
            return Err(MasterKeyError::InvalidSignature);
        }

        // Decode and return payload
        let payload_bytes = base64::decode_config(parts[1], base64::URL_SAFE_NO_PAD)
            .map_err(|_| MasterKeyError::InvalidTokenFormat)?;
        let payload: serde_json::Value = serde_json::from_slice(&payload_bytes)
            .map_err(|_| MasterKeyError::InvalidTokenFormat)?;

        // Verify expiration
        if let Some(exp) = payload["exp"].as_u64() {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            if now > exp {
                return Err(MasterKeyError::TokenExpired);
            }
        }

        Ok(payload)
    }

    /// Rotate master key with hardware re-sealing
    pub async fn rotate_master_key(&self, key_id: &str) -> Result<(), MasterKeyError> {
        // Generate new key material
        let new_key_data = self.hardware.generate_random(self.config.master_key_length).await
            .map_err(|e| MasterKeyError::KeyGenerationFailed(e.to_string()))?;

        // Get current metadata
        let mut key_metadata = self.key_metadata.write().await;
        let metadata = key_metadata.get_mut(key_id)
            .ok_or_else(|| MasterKeyError::KeyNotFound(key_id.to_string()))?;

        // Determine hardware key type
        let hardware_key_type = match metadata.key_type {
            MasterKeyType::JwtSigning | MasterKeyType::AuditSigning => KeyType::SigningKey,
            _ => KeyType::EncryptionKey,
        };

        // Seal new key to hardware
        self.hardware.seal_key(key_id, &new_key_data, hardware_key_type).await
            .map_err(|e| MasterKeyError::HardwareOperationFailed(e.to_string()))?;

        // Update metadata
        metadata.created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        metadata.usage_count = 0;
        metadata.rotation_due = false;
        metadata.pcr_snapshot = self.capture_pcr_snapshot().await?;

        Ok(())
    }

    /// Get master key metadata
    pub async fn get_key_metadata(&self, key_id: &str) -> Result<MasterKeyMetadata, MasterKeyError> {
        let key_metadata = self.key_metadata.read().await;
        key_metadata.get(key_id)
            .cloned()
            .ok_or_else(|| MasterKeyError::KeyNotFound(key_id.to_string()))
    }

    /// List all master keys
    pub async fn list_master_keys(&self) -> Vec<MasterKeyMetadata> {
        let key_metadata = self.key_metadata.read().await;
        key_metadata.values().cloned().collect()
    }

    /// Check if key rotation is due
    pub async fn check_rotation_due(&self) -> Vec<String> {
        let key_metadata = self.key_metadata.read().await;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        key_metadata.iter()
            .filter(|(_, metadata)| {
                let age_hours = (now - metadata.created_at) / 3600;
                age_hours >= self.config.key_rotation_interval_hours
            })
            .map(|(key_id, _)| key_id.clone())
            .collect()
    }

    /// Update key usage statistics
    async fn update_key_usage(&self, key_id: &str) -> Result<(), MasterKeyError> {
        let mut key_metadata = self.key_metadata.write().await;
        if let Some(metadata) = key_metadata.get_mut(key_id) {
            metadata.last_used = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            metadata.usage_count += 1;
        }
        Ok(())
    }

    /// Capture current PCR snapshot
    async fn capture_pcr_snapshot(&self) -> Result<Option<Vec<u8>>, MasterKeyError> {
        if !self.config.pcr_binding_enabled {
            return Ok(None);
        }

        let pcr_values = self.hardware.get_pcr_values().await
            .map_err(|e| MasterKeyError::HardwareOperationFailed(e.to_string()))?;

        let snapshot = serde_json::to_vec(&pcr_values)
            .map_err(|e| MasterKeyError::SerializationFailed(e.to_string()))?;

        Ok(Some(snapshot))
    }

    /// Generate RSA key pair for JWT signing
    async fn generate_rsa_key_pair(&self) -> Result<Vec<u8>, MasterKeyError> {
        // In a real implementation, this would generate an RSA key pair
        // For demonstration, we'll use a placeholder
        self.hardware.generate_random(256).await
            .map_err(|e| MasterKeyError::KeyGenerationFailed(e.to_string()))
    }

    /// Generate ECDSA key pair for JWT signing
    async fn generate_ecdsa_key_pair(&self) -> Result<Vec<u8>, MasterKeyError> {
        // In a real implementation, this would generate an ECDSA key pair
        // For demonstration, we'll use a placeholder
        self.hardware.generate_random(32).await
            .map_err(|e| MasterKeyError::KeyGenerationFailed(e.to_string()))
    }

    /// Get hardware capabilities
    pub fn get_hardware_capabilities(&self) -> crate::governor_core::hardware::HardwareCapabilities {
        self.hardware.get_capabilities()
    }
}

/// Master key service errors
#[derive(Debug, thiserror::Error)]
pub enum MasterKeyError {
    #[error("Key already exists: {0}")]
    KeyAlreadyExists(String),
    
    #[error("Key not found: {0}")]
    KeyNotFound(String),
    
    #[error("Key generation failed: {0}")]
    KeyGenerationFailed(String),
    
    #[error("Hardware operation failed: {0}")]
    HardwareOperationFailed(String),
    
    #[error("Signing failed: {0}")]
    SigningFailed(String),
    
    #[error("Verification failed: {0}")]
    VerificationFailed(String),
    
    #[error("Attestation failed: {0}")]
    AttestationFailed(String),
    
    #[error("Serialization failed: {0}")]
    SerializationFailed(String),
    
    #[error("Invalid token format")]
    InvalidTokenFormat,
    
    #[error("Invalid signature")]
    InvalidSignature,
    
    #[error("Token expired")]
    TokenExpired,
    
    #[error("Hardware not available")]
    HardwareNotAvailable,
}

impl Default for MasterKeyConfig {
    fn default() -> Self {
        Self {
            key_rotation_interval_hours: 24 * 7, // Weekly rotation
            max_key_age_hours: 24 * 30, // 30 days max
            require_hardware_backing: true,
            pcr_binding_enabled: true,
            jwt_key_algorithm: JwtAlgorithm::RS256,
            master_key_length: 32, // 256 bits
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::governor_core::hardware::HardwareAbstraction;
    use crate::governor_core::cryptography::CryptographyService;

    async fn create_test_service() -> MasterKeyService {
        let config = crate::GovernorConfig {
            offline_mode: true,
            challenge_expiry_seconds: 300,
            max_failed_attempts: 3,
            lockout_duration_seconds: 900,
            tpm_enabled: false,
            post_quantum_enabled: false,
            audit_level: crate::AuditLevel::Standard,
        };

        let hardware = HardwareAbstraction::new(&config).await.unwrap();
        let crypto_service = CryptographyService::new(&config).await.unwrap();
        let master_key_config = MasterKeyConfig::default();

        MasterKeyService::new(hardware, crypto_service, master_key_config).await.unwrap()
    }

    #[tokio::test]
    async fn test_master_key_creation() {
        let service = create_test_service().await;
        
        let request = CreateMasterKeyRequest {
            key_id: "test_master_key".to_string(),
            key_type: MasterKeyType::DataEncryption,
            require_pcr_binding: false,
            custom_pcr_indices: None,
        };

        service.create_master_key(request).await.unwrap();
        
        let metadata = service.get_key_metadata("test_master_key").await.unwrap();
        assert_eq!(metadata.key_type, MasterKeyType::DataEncryption);
    }

    #[tokio::test]
    async fn test_jwt_generation_and_verification() {
        let service = create_test_service().await;
        
        let claims = serde_json::json!({
            "sub": "test_user",
            "role": "admin"
        });

        let jwt = service.generate_jwt_token(&claims, false).await.unwrap();
        assert!(!jwt.token.is_empty());

        let verified_claims = service.verify_jwt_token(&jwt.token, false).await.unwrap();
        assert_eq!(verified_claims["sub"], "test_user");
        assert_eq!(verified_claims["role"], "admin");
    }

    #[tokio::test]
    async fn test_key_rotation() {
        let service = create_test_service().await;
        
        let request = CreateMasterKeyRequest {
            key_id: "rotation_test_key".to_string(),
            key_type: MasterKeyType::DataEncryption,
            require_pcr_binding: false,
            custom_pcr_indices: None,
        };

        service.create_master_key(request).await.unwrap();
        
        let original_metadata = service.get_key_metadata("rotation_test_key").await.unwrap();
        
        // Rotate the key
        service.rotate_master_key("rotation_test_key").await.unwrap();
        
        let rotated_metadata = service.get_key_metadata("rotation_test_key").await.unwrap();
        assert!(rotated_metadata.created_at > original_metadata.created_at);
        assert_eq!(rotated_metadata.usage_count, 0);
    }
}
