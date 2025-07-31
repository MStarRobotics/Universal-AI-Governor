# Universal AI Governor - Sequence Diagrams

## Remote Attestation Flow

```mermaid
sequenceDiagram
    participant Client as SOC/Client
    participant API as Attestation API
    participant HAL as Hardware Abstraction
    participant TPM as TPM 2.0
    participant HSM as HSM/Enclave
    participant Audit as Enhanced Audit

    Note over Client,Audit: Remote Attestation Challenge-Response Flow

    Client->>API: GET /attestation?nonce=abc123&include_pcr=true
    API->>HAL: generate_attestation(request)
    
    HAL->>TPM: get_pcr_values([0,1,2,3,7])
    TPM-->>HAL: PCR values + measurements
    
    HAL->>TPM: tpm2_quote(nonce, pcr_selection)
    TPM-->>HAL: signed_quote + attestation_key_sig
    
    HAL->>HSM: sign_attestation(payload, attestation_key)
    HSM-->>HAL: hardware_signature
    
    HAL->>HAL: collect_firmware_hashes()
    HAL->>HAL: assess_integrity_status()
    
    HAL-->>API: AttestationResponse{device_id, pcr_values, quote, signature}
    
    API->>Audit: log_audit_entry(ATTESTATION_REQUEST, client_id)
    Audit->>HAL: capture_pcr_snapshot()
    HAL-->>Audit: current_pcr_state
    Audit->>HSM: sign_audit_entry(entry_data)
    HSM-->>Audit: audit_signature
    
    API-->>Client: {attestation_data, certificate_chain, integrity_status}
    
    Note over Client: Client Verification Process
    Client->>Client: verify_certificate_chain()
    Client->>Client: verify_tpm_quote(expected_pcrs)
    Client->>Client: assess_trust_level()
    
    alt Verification Successful
        Client->>API: POST /attestation/verify {attestation_data, expected_pcrs}
        API->>HAL: verify_attestation_data(request)
        HAL->>TPM: verify_quote_signature()
        TPM-->>HAL: signature_valid
        HAL->>HAL: compare_pcr_values(expected, actual)
        HAL-->>API: VerificationResult{valid: true, trust_level: TRUSTED}
        API-->>Client: {is_valid: true, trust_level: "FullyTrusted"}
    else Verification Failed (Tampered PCRs)
        Client->>API: POST /attestation/verify {attestation_data, expected_pcrs}
        API->>HAL: verify_attestation_data(request)
        HAL->>HAL: compare_pcr_values(expected, actual)
        Note over HAL: PCR mismatch detected!
        HAL-->>API: VerificationResult{valid: false, trust_level: COMPROMISED}
        API->>Audit: log_audit_entry(INTEGRITY_VIOLATION, client_id)
        API-->>Client: {is_valid: false, trust_level: "Untrusted", recommendations: ["Investigate boot integrity"]}
    end
```

## Hardware Fallback Hierarchy

```mermaid
sequenceDiagram
    participant App as Application
    participant MKS as Master Key Service
    participant HAL as Hardware Abstraction
    participant TPM as TPM 2.0
    participant SE as Secure Enclave
    participant SW as Software Fallback

    Note over App,SW: Hardware Selection and Fallback Logic

    App->>MKS: create_master_key(key_id, require_hardware=true)
    MKS->>HAL: seal_key(key_id, key_data, KeyType::MasterKey)
    
    HAL->>HAL: select_best_hardware()
    
    alt TPM Available (Highest Priority)
        HAL->>TPM: check_availability()
        TPM-->>HAL: available=true
        HAL->>TPM: get_pcr_values([0,1,2,3,7])
        TPM-->>HAL: pcr_snapshot
        HAL->>TPM: tpm2_create(key_data, pcr_policy)
        TPM-->>HAL: sealed_key_blob
        HAL->>TPM: tpm2_load(sealed_key_blob)
        TPM-->>HAL: key_handle
        Note over HAL: Key sealed to PCR values
        HAL-->>MKS: success(storage_method=TPM_SEALED)
        
    else TPM Unavailable, Secure Enclave Available
        HAL->>TPM: check_availability()
        TPM-->>HAL: available=false
        HAL->>SE: check_availability()
        SE-->>HAL: available=true
        HAL->>SE: generate_enclave_key(key_id, attributes)
        SE-->>HAL: key_reference (non-extractable)
        Note over SE: Key stored in hardware enclave
        HAL-->>MKS: success(storage_method=ENCLAVE_STORED)
        
    else All Hardware Unavailable
        HAL->>TPM: check_availability()
        TPM-->>HAL: available=false
        HAL->>SE: check_availability()
        SE-->>HAL: available=false
        HAL->>SW: store_key_encrypted(key_id, key_data)
        SW-->>HAL: encrypted_key_blob
        Note over SW: Key encrypted with derived key
        HAL-->>MKS: success(storage_method=SOFTWARE_FALLBACK)
    end
    
    MKS-->>App: key_created(hardware_backed=true/false)
    
    Note over App,SW: Key Usage with Fallback
    
    App->>MKS: generate_jwt_token(claims, include_attestation=true)
    MKS->>HAL: unseal_key(jwt_signing_key)
    
    alt Using TPM
        HAL->>TPM: verify_pcr_state()
        TPM-->>HAL: pcr_valid=true
        HAL->>TPM: tmp2_unseal(key_handle)
        TPM-->>HAL: key_data
        HAL->>TPM: tpm2_sign(key_handle, jwt_payload)
        TPM-->>HAL: hardware_signature
        
    else Using Secure Enclave
        HAL->>SE: enclave_sign(key_reference, jwt_payload)
        SE-->>HAL: enclave_signature
        
    else Using Software Fallback
        HAL->>SW: decrypt_key(encrypted_key_blob)
        SW-->>HAL: key_data
        HAL->>SW: software_sign(key_data, jwt_payload)
        SW-->>HAL: software_signature
    end
    
    HAL-->>MKS: signed_jwt_data
    MKS-->>App: HardwareBackedJWT{token, attestation_data, hardware_backed}
```

## Enhanced Audit Blockchain Flow

```mermaid
sequenceDiagram
    participant App as Application
    participant Audit as Enhanced Audit Logger
    participant HAL as Hardware Abstraction
    participant Chain as Integrity Chain
    participant TPM as TPM 2.0
    participant HSM as HSM

    Note over App,HSM: Tamper-Evident Audit Logging with Blockchain Integrity

    App->>Audit: log_audit_entry(CRYPTO_OPERATION, user, resource, action)
    
    Audit->>HAL: capture_pcr_snapshot()
    HAL->>TPM: get_pcr_values([0,1,2,3,7])
    TPM-->>HAL: current_pcr_state
    HAL-->>Audit: pcr_snapshot
    
    Audit->>Audit: collect_tamper_evidence()
    Note over Audit: System state hash, memory integrity, process list
    
    Audit->>Audit: generate_integrity_proof(base_entry)
    Audit->>Chain: get_last_entry_hash()
    Chain-->>Audit: previous_hash
    Audit->>Audit: calculate_merkle_root(entry_data)
    
    Audit->>HAL: sign_data(audit_signing_key, entry_data)
    HAL->>HSM: pkcs11_sign(audit_key_handle, entry_hash)
    HSM-->>HAL: hardware_signature
    HAL-->>Audit: entry_signature
    
    Audit->>HAL: sign_data(audit_mac_key, combined_data)
    HAL->>HSM: pkcs11_sign(mac_key_handle, combined_hash)
    HSM-->>HAL: hardware_mac
    HAL-->>Audit: hardware_mac
    
    Audit->>Audit: create_enhanced_audit_entry()
    Note over Audit: Combines base_entry + hardware_attestation + integrity_proof + tamper_evidence
    
    Audit->>Chain: update_integrity_chain(entry_id)
    
    alt Blockchain Integrity Enabled
        Chain->>Chain: calculate_block_merkle_root(entry_id)
        Chain->>Chain: mine_block(previous_hash, merkle_root, timestamp)
        Note over Chain: Simplified proof-of-work mining
        Chain->>HAL: sign_data(blockchain_key, block_data)
        HAL->>HSM: pkcs11_sign(blockchain_key_handle, block_hash)
        HSM-->>HAL: miner_signature
        HAL-->>Chain: signed_block
        Chain->>Chain: append_integrity_link(block)
    end
    
    Audit-->>App: audit_entry_id
    
    Note over App,HSM: Real-time Integrity Verification
    
    App->>Audit: verify_entry_integrity(entry_id)
    Audit->>Audit: retrieve_audit_entry(entry_id)
    
    Audit->>HAL: verify_signature(audit_signing_key, entry_data, signature)
    HAL->>HSM: pkcs11_verify(audit_key_handle, entry_hash, signature)
    HSM-->>HAL: signature_valid
    HAL-->>Audit: entry_signature_valid
    
    Audit->>HAL: verify_signature(attestation_key, attestation_data, attestation_sig)
    HAL->>TPM: tpm2_verify(attestation_key_handle, attestation_hash, signature)
    TPM-->>HAL: attestation_valid
    HAL-->>Audit: attestation_signature_valid
    
    alt Blockchain Verification
        Audit->>Chain: verify_integrity_chain(entry_id)
        Chain->>Chain: recalculate_merkle_roots()
        Chain->>Chain: verify_block_signatures()
        Chain-->>Audit: chain_integrity_valid
    end
    
    Audit->>Audit: assess_tamper_evidence()
    Note over Audit: Compare current system state with recorded evidence
    
    alt Integrity Verified
        Audit-->>App: integrity_valid=true
    else Tampering Detected
        Audit->>Audit: log_audit_entry(INTEGRITY_VIOLATION, system, audit_log, tamper_detected)
        Audit-->>App: integrity_valid=false, tamper_detected=true
        Note over App: Trigger security incident response
    end
```

## Master Key Lifecycle with Hardware Sealing

```mermaid
sequenceDiagram
    participant Admin as Administrator
    participant MKS as Master Key Service
    participant HAL as Hardware Abstraction
    participant TPM as TPM 2.0
    participant Crypto as Cryptography Service
    participant Audit as Enhanced Audit

    Note over Admin,Audit: Master Key Creation and Hardware Sealing

    Admin->>MKS: create_master_key(key_id="data_encryption_key", require_pcr_binding=true)
    
    MKS->>HAL: generate_random(32)
    HAL->>TPM: tpm2_getrandom(32)
    TPM-->>HAL: random_key_material
    HAL-->>MKS: master_key_data
    
    MKS->>HAL: get_pcr_values([0,1,2,3,7])
    HAL->>TPM: tpm2_pcrread(pcr_indices)
    TPM-->>HAL: current_pcr_values
    HAL-->>MKS: pcr_snapshot
    
    MKS->>HAL: seal_key(key_id, master_key_data, KeyType::EncryptionKey)
    HAL->>TPM: tpm2_create(key_data, pcr_policy_digest)
    TPM-->>HAL: sealed_key_blob + key_public
    HAL->>TPM: tpm2_load(sealed_key_blob)
    TPM-->>HAL: key_handle
    HAL-->>MKS: key_sealed_successfully
    
    MKS->>Audit: log_audit_entry(KEY_CREATION, admin, master_key_service, create_key)
    Audit->>HAL: capture_pcr_snapshot()
    HAL-->>Audit: pcr_state_at_creation
    Audit-->>MKS: audit_entry_logged
    
    MKS-->>Admin: master_key_created(hardware_backed=true, pcr_sealed=true)
    
    Note over Admin,Audit: Key Usage and PCR Verification
    
    Admin->>MKS: generate_jwt_token(claims, include_attestation=true)
    
    MKS->>HAL: unseal_key(jwt_signing_key)
    HAL->>TPM: tpm2_pcrread([0,1,2,3,7])
    TPM-->>HAL: current_pcr_values
    HAL->>HAL: verify_pcr_state(stored_pcrs, current_pcrs)
    
    alt PCR Values Match (System Integrity Maintained)
        HAL->>TPM: tpm2_unseal(key_handle)
        TPM-->>HAL: unsealed_key_data
        HAL->>TPM: tpm2_sign(key_handle, jwt_payload)
        TPM-->>HAL: hardware_signature
        HAL-->>MKS: jwt_signed_successfully
        
        MKS->>HAL: get_attestation()
        HAL->>TPM: tpm2_quote(nonce, pcr_selection)
        TPM-->>HAL: attestation_quote
        HAL-->>MKS: attestation_data
        
        MKS-->>Admin: HardwareBackedJWT{token, attestation, pcr_snapshot}
        
    else PCR Values Changed (Tampering Detected)
        HAL-->>MKS: PCR_VERIFICATION_FAILED
        MKS->>Audit: log_audit_entry(INTEGRITY_VIOLATION, system, tpm, pcr_mismatch)
        Audit-->>MKS: security_incident_logged
        MKS-->>Admin: ERROR: System integrity compromised, key access denied
        Note over Admin: Security incident response triggered
    end
    
    Note over Admin,Audit: Key Rotation with Hardware Re-sealing
    
    Admin->>MKS: rotate_master_key(key_id="data_encryption_key")
    
    MKS->>HAL: generate_random(32)
    HAL->>TPM: tpm2_getrandom(32)
    TPM-->>HAL: new_key_material
    HAL-->>MKS: new_master_key_data
    
    MKS->>HAL: get_pcr_values([0,1,2,3,7])
    HAL->>TPM: tpm2_pcrread(pcr_indices)
    TPM-->>HAL: current_pcr_values
    HAL-->>MKS: updated_pcr_snapshot
    
    MKS->>HAL: seal_key(key_id, new_master_key_data, KeyType::EncryptionKey)
    HAL->>TPM: tpm2_evictcontrol(old_key_handle)  # Remove old key
    TPM-->>HAL: old_key_evicted
    HAL->>TPM: tpm2_create(new_key_data, pcr_policy_digest)
    TPM-->>HAL: new_sealed_key_blob
    HAL->>TPM: tpm2_load(new_sealed_key_blob)
    TPM-->>HAL: new_key_handle
    HAL-->>MKS: key_rotated_successfully
    
    MKS->>Audit: log_audit_entry(KEY_ROTATION, admin, master_key_service, rotate_key)
    Audit-->>MKS: rotation_audit_logged
    
    MKS-->>Admin: key_rotation_completed(new_pcr_snapshot, hardware_backed=true)
```

## Secure Enclave Integration Flow

```mermaid
sequenceDiagram
    participant App as Application
    participant SEM as Secure Enclave Manager
    participant ASE as Apple Secure Enclave
    participant SGX as Intel SGX
    participant HAL as Hardware Abstraction
    participant Audit as Enhanced Audit

    Note over App,Audit: Cross-Platform Secure Enclave Operations

    App->>SEM: generate_enclave_key(key_id, attributes, preferred_enclave=None)
    
    SEM->>SEM: select_best_enclave(preferred=None)
    
    alt macOS with Apple Secure Enclave
        SEM->>ASE: check_availability()
        ASE-->>SEM: available=true, biometric_available=true
        SEM->>ASE: SecKeyCreateRandomKey(kSecAttrTokenIDSecureEnclave)
        ASE-->>SEM: SecKey reference (non-extractable)
        Note over ASE: Key stored in Secure Enclave, protected by biometrics
        SEM-->>App: key_generated(enclave_type=AppleSecureEnclave)
        
    else Linux/Windows with Intel SGX
        SEM->>SGX: check_sgx_availability()
        SGX-->>SEM: available=true, enclave_loaded=true
        SEM->>SGX: ecall_generate_key(key_id, attributes)
        Note over SGX: ECALL into SGX enclave
        SGX->>SGX: sgx_generate_key_pair()
        SGX-->>SEM: key_handle (enclave-bound)
        Note over SGX: Private key never leaves enclave
        SEM-->>App: key_generated(enclave_type=IntelSgx)
        
    else No Hardware Enclave Available
        SEM->>SEM: check_fallback_enabled()
        alt Fallback Enabled
            SEM->>HAL: seal_key(key_id, generated_key, KeyType::EncryptionKey)
            HAL-->>SEM: key_stored_in_software
            SEM-->>App: key_generated(enclave_type=SoftwareFallback)
        else Fallback Disabled
            SEM-->>App: ERROR: NoEnclaveAvailable
        end
    end
    
    Note over App,Audit: Secure Computation in Enclave
    
    App->>SEM: secure_compute(SecureComputationRequest{operation=Sign, data, key_id})
    
    SEM->>Audit: log_audit_entry(ENCLAVE_OPERATION, user, secure_enclave, sign_data)
    Audit-->>SEM: operation_logged
    
    alt Apple Secure Enclave Operation
        SEM->>ASE: SecKeyCreateSignature(key_ref, data, algorithm)
        Note over ASE: Biometric authentication may be required
        ASE->>ASE: Touch ID / Face ID verification
        ASE->>ASE: Sign data within Secure Enclave
        ASE-->>SEM: signature_bytes
        
        SEM->>ASE: generate_device_attestation()
        ASE-->>SEM: device_attestation_data
        
    else Intel SGX Operation
        SEM->>SGX: ecall_sign_data(key_handle, data)
        SGX->>SGX: sgx_sign_data(private_key, data)
        SGX-->>SEM: signature_bytes
        
        SEM->>SGX: ecall_generate_quote(report_data)
        SGX->>SGX: sgx_create_report(target_info, report_data)
        SGX->>SGX: sgx_get_quote(report)
        SGX-->>SEM: sgx_quote + certificate_chain
        
    else Software Fallback
        SEM->>HAL: unseal_key(key_id)
        HAL-->>SEM: key_data
        SEM->>SEM: software_sign(key_data, data)
        SEM-->>SEM: signature_bytes
        Note over SEM: No hardware attestation available
    end
    
    SEM-->>App: SecureComputationResponse{result, attestation, execution_time}
    
    Note over App,Audit: Remote Attestation of Enclave
    
    App->>SEM: generate_attestation(enclave_type)
    
    alt Apple Secure Enclave Attestation
        SEM->>ASE: DeviceCheck.generateToken()
        ASE-->>SEM: device_token
        SEM->>ASE: get_device_characteristics()
        ASE-->>SEM: device_info
        SEM->>SEM: create_attestation(device_token, device_info)
        
    else Intel SGX Attestation
        SEM->>SGX: ecall_create_report(challenge_nonce)
        SGX->>SGX: sgx_create_report(target_info, report_data)
        SGX-->>SEM: sgx_report
        SEM->>SGX: get_quote_from_report(sgx_report)
        SGX-->>SEM: sgx_quote
        SEM->>SEM: verify_quote_signature(sgx_quote)
        
    else Software Fallback
        SEM->>SEM: create_software_attestation()
        Note over SEM: Limited attestation capabilities
    end
    
    SEM-->>App: EnclaveAttestation{enclave_type, measurement, signature, certificate_chain}
    
    App->>App: verify_enclave_attestation(attestation)
    Note over App: Client verifies enclave integrity and authenticity
```

These sequence diagrams illustrate the complete hardware integration flows for our Universal AI Governor, showing how TPM, HSM, and Secure Enclave components work together to provide military-grade security with comprehensive audit trails and tamper detection.
