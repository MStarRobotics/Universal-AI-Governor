// Cryptography Service - High-assurance cryptographic operations
// Implements classical and post-quantum cryptographic primitives

use ring::{
    aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN},
    digest::{Context, SHA256},
    hkdf::{self, Prk},
    hmac::{self, Key},
    pbkdf2,
    rand::{SecureRandom, SystemRandom},
};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, Version};
use pqc_kyber::{keypair, encapsulate, decapsulate, KYBER_PUBLICKEYBYTES, KYBER_SECRETKEYBYTES, KYBER_CIPHERTEXTBYTES};
use serde::{Deserialize, Serialize};
use std::num::NonZeroU32;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Cryptography service providing all cryptographic operations
pub struct CryptographyService {
    rng: SystemRandom,
    argon2: Argon2<'static>,
    master_key: Option<MasterKey>,
}

/// Master key structure with automatic zeroization
#[derive(ZeroizeOnDrop)]
struct MasterKey {
    key: [u8; 32],
}

/// Key derivation parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyDerivationParams {
    pub salt: [u8; 32],
    pub iterations: u32,
    pub memory_kb: u32,
    pub parallelism: u32,
}

/// Encrypted data structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedData {
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; NONCE_LEN],
    pub salt: [u8; 32],
}

/// Post-quantum key pair
#[derive(Debug, Clone)]
pub struct PQKeyPair {
    pub public_key: [u8; KYBER_PUBLICKEYBYTES],
    pub secret_key: [u8; KYBER_SECRETKEYBYTES],
}

/// Argon2 password hashing parameters (OWASP recommended)
const ARGON2_MEMORY: u32 = 65536; // 64 MB
const ARGON2_ITERATIONS: u32 = 3;
const ARGON2_PARALLELISM: u32 = 4;
const ARGON2_OUTPUT_LEN: usize = 32;

impl CryptographyService {
    /// Create a new cryptography service
    pub fn new(config: &crate::GovernorConfig) -> Result<Self, CryptoError> {
        let rng = SystemRandom::new();
        
        // Configure Argon2 with secure parameters
        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            Version::V0x13,
            argon2::Params::new(
                ARGON2_MEMORY,
                ARGON2_ITERATIONS,
                ARGON2_PARALLELISM,
                Some(ARGON2_OUTPUT_LEN),
            ).map_err(|_| CryptoError::InvalidParameters)?,
        );
        
        Ok(Self {
            rng,
            argon2,
            master_key: None,
        })
    }
    
    /// Initialize with a master key from hardware
    pub fn set_master_key(&mut self, key: [u8; 32]) {
        self.master_key = Some(MasterKey { key });
    }
    
    /// Hash a password using Argon2id
    pub fn hash_password(&self, password: &str) -> Result<String, CryptoError> {
        // Generate random salt
        let mut salt = [0u8; 32];
        self.rng.fill(&mut salt).map_err(|_| CryptoError::RandomGenerationFailed)?;
        
        // Hash password with Argon2id
        let password_hash = self.argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|_| CryptoError::HashingFailed)?;
        
        Ok(password_hash.to_string())
    }
    
    /// Verify a password against its hash
    pub fn verify_password(&self, password: &str, hash: &str) -> Result<bool, CryptoError> {
        let parsed_hash = PasswordHash::new(hash)
            .map_err(|_| CryptoError::InvalidHash)?;
        
        match self.argon2.verify_password(password.as_bytes(), &parsed_hash) {
            Ok(()) => Ok(true),
            Err(argon2::password_hash::Error::Password) => Ok(false),
            Err(_) => Err(CryptoError::VerificationFailed),
        }
    }
    
    /// Encrypt data using AES-256-GCM
    pub fn encrypt_data(&self, plaintext: &[u8], context: &str) -> Result<EncryptedData, CryptoError> {
        let master_key = self.master_key.as_ref()
            .ok_or(CryptoError::NoMasterKey)?;
        
        // Generate random salt and nonce
        let mut salt = [0u8; 32];
        let mut nonce_bytes = [0u8; NONCE_LEN];
        self.rng.fill(&mut salt).map_err(|_| CryptoError::RandomGenerationFailed)?;
        self.rng.fill(&mut nonce_bytes).map_err(|_| CryptoError::RandomGenerationFailed)?;
        
        // Derive encryption key using HKDF
        let prk = hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, &master_key.key);
        let mut derived_key = [0u8; 32];
        prk.expand(&[context.as_bytes()], hkdf::HKDF_SHA256)
            .map_err(|_| CryptoError::KeyDerivationFailed)?
            .fill(&mut derived_key)
            .map_err(|_| CryptoError::KeyDerivationFailed)?;
        
        // Create AES-256-GCM key
        let unbound_key = UnboundKey::new(&AES_256_GCM, &derived_key)
            .map_err(|_| CryptoError::KeyCreationFailed)?;
        let key = LessSafeKey::new(unbound_key);
        
        // Encrypt data
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let mut ciphertext = plaintext.to_vec();
        key.seal_in_place_append_tag(nonce, Aad::empty(), &mut ciphertext)
            .map_err(|_| CryptoError::EncryptionFailed)?;
        
        // Zeroize derived key
        let mut derived_key = derived_key;
        derived_key.zeroize();
        
        Ok(EncryptedData {
            ciphertext,
            nonce: nonce_bytes,
            salt,
        })
    }
    
    /// Decrypt data using AES-256-GCM
    pub fn decrypt_data(&self, encrypted: &EncryptedData, context: &str) -> Result<Vec<u8>, CryptoError> {
        let master_key = self.master_key.as_ref()
            .ok_or(CryptoError::NoMasterKey)?;
        
        // Derive decryption key using HKDF
        let prk = hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, &master_key.key);
        let mut derived_key = [0u8; 32];
        prk.expand(&[context.as_bytes()], hkdf::HKDF_SHA256)
            .map_err(|_| CryptoError::KeyDerivationFailed)?
            .fill(&mut derived_key)
            .map_err(|_| CryptoError::KeyDerivationFailed)?;
        
        // Create AES-256-GCM key
        let unbound_key = UnboundKey::new(&AES_256_GCM, &derived_key)
            .map_err(|_| CryptoError::KeyCreationFailed)?;
        let key = LessSafeKey::new(unbound_key);
        
        // Decrypt data
        let nonce = Nonce::assume_unique_for_key(encrypted.nonce);
        let mut ciphertext = encrypted.ciphertext.clone();
        let plaintext = key.open_in_place(nonce, Aad::empty(), &mut ciphertext)
            .map_err(|_| CryptoError::DecryptionFailed)?;
        
        // Zeroize derived key
        let mut derived_key = derived_key;
        derived_key.zeroize();
        
        Ok(plaintext.to_vec())
    }
    
    /// Compute HMAC-SHA256
    pub fn compute_hmac(&self, key: &[u8], data: &[u8]) -> Result<[u8; 32], CryptoError> {
        let hmac_key = Key::new(hmac::HMAC_SHA256, key);
        let signature = hmac::sign(&hmac_key, data);
        
        let mut result = [0u8; 32];
        result.copy_from_slice(signature.as_ref());
        Ok(result)
    }
    
    /// Verify HMAC-SHA256
    pub fn verify_hmac(&self, key: &[u8], data: &[u8], expected: &[u8]) -> Result<bool, CryptoError> {
        let hmac_key = Key::new(hmac::HMAC_SHA256, key);
        match hmac::verify(&hmac_key, data, expected) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }
    
    /// Generate a cryptographically secure random key
    pub fn generate_random_key(&self, length: usize) -> Result<Vec<u8>, CryptoError> {
        let mut key = vec![0u8; length];
        self.rng.fill(&mut key).map_err(|_| CryptoError::RandomGenerationFailed)?;
        Ok(key)
    }
    
    /// Generate a session token
    pub fn generate_session_token(&self, user_id: &str) -> Result<String, CryptoError> {
        let mut token_data = [0u8; 32];
        self.rng.fill(&mut token_data).map_err(|_| CryptoError::RandomGenerationFailed)?;
        
        // Include user ID and timestamp in token
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let token_payload = format!("{}:{}:{}", 
            user_id, 
            timestamp, 
            hex::encode(token_data)
        );
        
        // Encode as base64
        Ok(base64::encode(token_payload))
    }
    
    /// Generate post-quantum key pair using Kyber
    pub fn generate_pq_keypair(&self) -> Result<PQKeyPair, CryptoError> {
        let mut rng_bytes = [0u8; 32];
        self.rng.fill(&mut rng_bytes).map_err(|_| CryptoError::RandomGenerationFailed)?;
        
        let (public_key, secret_key) = keypair(&rng_bytes);
        
        Ok(PQKeyPair {
            public_key,
            secret_key,
        })
    }
    
    /// Encapsulate a shared secret using Kyber
    pub fn pq_encapsulate(&self, public_key: &[u8; KYBER_PUBLICKEYBYTES]) -> Result<([u8; KYBER_CIPHERTEXTBYTES], [u8; 32]), CryptoError> {
        let mut rng_bytes = [0u8; 32];
        self.rng.fill(&mut rng_bytes).map_err(|_| CryptoError::RandomGenerationFailed)?;
        
        let (ciphertext, shared_secret) = encapsulate(public_key, &rng_bytes);
        Ok((ciphertext, shared_secret))
    }
    
    /// Decapsulate a shared secret using Kyber
    pub fn pq_decapsulate(
        &self, 
        ciphertext: &[u8; KYBER_CIPHERTEXTBYTES], 
        secret_key: &[u8; KYBER_SECRETKEYBYTES]
    ) -> Result<[u8; 32], CryptoError> {
        let shared_secret = decapsulate(ciphertext, secret_key);
        Ok(shared_secret)
    }
    
    /// Compute SHA-256 hash
    pub fn hash_sha256(&self, data: &[u8]) -> [u8; 32] {
        let mut context = Context::new(&SHA256);
        context.update(data);
        let digest = context.finish();
        
        let mut result = [0u8; 32];
        result.copy_from_slice(digest.as_ref());
        result
    }
    
    /// Derive key using PBKDF2 (for legacy compatibility)
    pub fn derive_key_pbkdf2(
        &self,
        password: &[u8],
        salt: &[u8],
        iterations: u32,
        output_len: usize,
    ) -> Result<Vec<u8>, CryptoError> {
        let mut output = vec![0u8; output_len];
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            NonZeroU32::new(iterations).ok_or(CryptoError::InvalidParameters)?,
            salt,
            password,
            &mut output,
        );
        Ok(output)
    }
    
    /// Secure memory comparison (constant-time)
    pub fn secure_compare(&self, a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        
        ring::constant_time::verify_slices_are_equal(a, b).is_ok()
    }
}

/// Cryptographic error types
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("Invalid parameters")]
    InvalidParameters,
    
    #[error("Random generation failed")]
    RandomGenerationFailed,
    
    #[error("Hashing failed")]
    HashingFailed,
    
    #[error("Invalid hash format")]
    InvalidHash,
    
    #[error("Verification failed")]
    VerificationFailed,
    
    #[error("No master key available")]
    NoMasterKey,
    
    #[error("Key derivation failed")]
    KeyDerivationFailed,
    
    #[error("Key creation failed")]
    KeyCreationFailed,
    
    #[error("Encryption failed")]
    EncryptionFailed,
    
    #[error("Decryption failed")]
    DecryptionFailed,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::GovernorConfig;
    
    fn create_test_config() -> GovernorConfig {
        GovernorConfig {
            offline_mode: true,
            challenge_expiry_seconds: 300,
            max_failed_attempts: 3,
            lockout_duration_seconds: 900,
            tmp_enabled: false,
            post_quantum_enabled: true,
            audit_level: crate::AuditLevel::Standard,
        }
    }
    
    #[test]
    fn test_password_hashing() {
        let config = create_test_config();
        let crypto = CryptographyService::new(&config).unwrap();
        
        let password = "test_password_123!";
        let hash = crypto.hash_password(password).unwrap();
        
        // Verify correct password
        assert!(crypto.verify_password(password, &hash).unwrap());
        
        // Verify incorrect password
        assert!(!crypto.verify_password("wrong_password", &hash).unwrap());
    }
    
    #[test]
    fn test_encryption_decryption() {
        let config = create_test_config();
        let mut crypto = CryptographyService::new(&config).unwrap();
        
        // Set a test master key
        let master_key = [0u8; 32];
        crypto.set_master_key(master_key);
        
        let plaintext = b"This is a test message for encryption";
        let context = "test_context";
        
        // Encrypt data
        let encrypted = crypto.encrypt_data(plaintext, context).unwrap();
        
        // Decrypt data
        let decrypted = crypto.decrypt_data(&encrypted, context).unwrap();
        
        assert_eq!(plaintext, decrypted.as_slice());
    }
    
    #[test]
    fn test_hmac_operations() {
        let config = create_test_config();
        let crypto = CryptographyService::new(&config).unwrap();
        
        let key = b"test_hmac_key";
        let data = b"test_data_to_authenticate";
        
        let hmac = crypto.compute_hmac(key, data).unwrap();
        assert!(crypto.verify_hmac(key, data, &hmac).unwrap());
        
        // Test with wrong data
        let wrong_data = b"wrong_data";
        assert!(!crypto.verify_hmac(key, wrong_data, &hmac).unwrap());
    }
    
    #[test]
    fn test_post_quantum_crypto() {
        let config = create_test_config();
        let crypto = CryptographyService::new(&config).unwrap();
        
        // Generate key pair
        let keypair = crypto.generate_pq_keypair().unwrap();
        
        // Encapsulate shared secret
        let (ciphertext, shared_secret1) = crypto.pq_encapsulate(&keypair.public_key).unwrap();
        
        // Decapsulate shared secret
        let shared_secret2 = crypto.pq_decapsulate(&ciphertext, &keypair.secret_key).unwrap();
        
        // Shared secrets should match
        assert_eq!(shared_secret1, shared_secret2);
    }
    
    #[test]
    fn test_session_token_generation() {
        let config = create_test_config();
        let crypto = CryptographyService::new(&config).unwrap();
        
        let user_id = "test_user";
        let token1 = crypto.generate_session_token(user_id).unwrap();
        let token2 = crypto.generate_session_token(user_id).unwrap();
        
        // Tokens should be different (due to timestamp and random data)
        assert_ne!(token1, token2);
        
        // Tokens should be valid base64
        assert!(base64::decode(&token1).is_ok());
        assert!(base64::decode(&token2).is_ok());
    }
}
