//! Security utilities for Universal AI Governor

use ring::{digest, hmac};
use zeroize::Zeroize;

/// Security manager
#[derive(Debug)]
pub struct SecurityManager {
    key: Vec<u8>,
}

impl SecurityManager {
    /// Create a new security manager
    pub fn new(key: Vec<u8>) -> Self {
        Self { key }
    }
    
    /// Hash data using SHA-256
    pub fn hash_data(&self, data: &[u8]) -> Vec<u8> {
        digest::digest(&digest::SHA256, data).as_ref().to_vec()
    }
    
    /// Create HMAC signature
    pub fn create_signature(&self, data: &[u8]) -> crate::Result<Vec<u8>> {
        let key = hmac::Key::new(hmac::HMAC_SHA256, &self.key);
        let signature = hmac::sign(&key, data);
        Ok(signature.as_ref().to_vec())
    }
    
    /// Verify HMAC signature
    pub fn verify_signature(&self, data: &[u8], signature: &[u8]) -> bool {
        let key = hmac::Key::new(hmac::HMAC_SHA256, &self.key);
        hmac::verify(&key, data, signature).is_ok()
    }
}

impl Drop for SecurityManager {
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
    }
}
