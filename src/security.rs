//! Security utilities for Universal AI Governor
//!
//! This module provides essential cryptographic and security utilities for the
//! Universal AI Governor. It is a critical component for establishing a "PhD level"
//! of trust and integrity within the AI governance framework. By implementing robust
//! hashing and HMAC functionalities, it ensures data authenticity and integrity,
//! which are vital for preventing "AI bypass" through data tampering or unauthorized
//! modifications. This foundational security contributes directly to the "humanization effect"
//! by safeguarding the reliability and trustworthiness of AI systems.

use ring::{digest, hmac};
use zeroize::Zeroize;

/// Manages cryptographic operations and security-related functionalities
/// for the Universal AI Governor. This includes data hashing and HMAC
/// signature creation and verification, crucial for ensuring the integrity
/// and authenticity of sensitive data and communications within the system.
#[derive(Debug)]
pub struct SecurityManager {
    /// The secret key used for HMAC operations. It is marked with `Zeroize`
    /// to ensure its secure erasure from memory when no longer needed,
    /// mitigating the risk of sensitive key leakage.
    key: Vec<u8>,
}

impl SecurityManager {
    /// Creates a new `SecurityManager` instance with a given secret key.
    /// The key is fundamental for cryptographic operations like HMAC, providing
    /// a basis for secure communication and data integrity checks.
    pub fn new(key: Vec<u8>) -> Self {
        Self { key }
    }

    /// Hashes the provided data using the SHA-256 algorithm.
    /// This function is used for creating fixed-size representations of data,
    /// which are essential for integrity checks and can serve as unique identifiers
    /// for data blocks, contributing to the auditable nature of the system.
    pub fn hash_data(&self, data: &[u8]) -> Vec<u8> {
        digest::digest(&digest::SHA256, data).as_ref().to_vec()
    }

    /// Creates an HMAC (Hash-based Message Authentication Code) signature for the given data.
    /// HMACs provide both data integrity and authenticity, ensuring that data has not been
    /// tampered with and originates from a trusted source. This is vital for securing
    /// critical AI governance messages and policy updates.
    pub fn create_signature(&self, data: &[u8]) -> crate::Result<Vec<u8>> {
        let key = hmac::Key::new(hmac::HMAC_SHA256, &self.key);
        let signature = hmac::sign(&key, data);
        Ok(signature.as_ref().to_vec())
    }

    /// Verifies an HMAC signature against the provided data and expected signature.
    /// This function is used to confirm the integrity and authenticity of received data,
    /// acting as a critical defense mechanism against unauthorized modifications or
    /// spoofing attempts within the AI governance ecosystem.
    pub fn verify_signature(&self, data: &[u8], signature: &[u8]) -> bool {
        let key = hmac::Key::new(hmac::HMAC_SHA256, &self.key);
        hmac::verify(&key, data, signature).is_ok()
    }
}

impl Drop for SecurityManager {
    /// Implements the `Drop` trait to ensure that the sensitive HMAC key is securely
    /// zeroized from memory when the `SecurityManager` instance is dropped.
    /// This is a crucial security measure to prevent key leakage and maintain
    /// the confidentiality of cryptographic materials.
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_manager() {
        let key = b"test-key-32-bytes-long-for-hmac!".to_vec();
        let manager = SecurityManager::new(key);

        let data = b"test data";
        let hash = manager.hash_data(data);
        assert!(!hash.is_empty());

        let signature = manager.create_signature(data).unwrap();
        assert!(manager.verify_signature(data, &signature));

        // Test with incorrect data
        let wrong_data = b"wrong data";
        assert!(!manager.verify_signature(wrong_data, &signature));

        // Test with incorrect signature
        let wrong_signature = b"wrong signature".to_vec();
        assert!(!manager.verify_signature(data, &wrong_signature));
    }
}
