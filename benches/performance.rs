//! Performance benchmarks for Universal AI Governor

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use universal_ai_governor::{
    policy::{Policy, PolicyManager},
    audit::AuditLogger,
    security::SecurityManager,
};
use std::collections::HashMap;

fn benchmark_policy_operations(c: &mut Criterion) {
    c.bench_function("policy_creation", |b| {
        b.iter(|| {
            let policy = Policy {
                id: black_box("benchmark-policy".to_string()),
                name: black_box("Benchmark Policy".to_string()),
                description: black_box("Performance benchmark policy".to_string()),
                rules: black_box(HashMap::new()),
                enabled: black_box(true),
            };
            black_box(policy);
        })
    });

    c.bench_function("policy_manager_operations", |b| {
        b.iter(|| {
            let mut manager = PolicyManager::new();
            for i in 0..100 {
                let policy = Policy {
                    id: format!("policy-{}", i),
                    name: format!("Policy {}", i),
                    description: "Benchmark policy".to_string(),
                    rules: HashMap::new(),
                    enabled: true,
                };
                manager.add_policy(policy);
            }
            black_box(manager.get_policies().len());
        })
    });
}

fn benchmark_audit_logging(c: &mut Criterion) {
    c.bench_function("audit_log_creation", |b| {
        b.iter(|| {
            let mut logger = AuditLogger::new();
            for i in 0..100 {
                logger.log_action(
                    black_box(format!("user-{}", i)),
                    black_box("benchmark_action".to_string()),
                    black_box("benchmark_resource".to_string()),
                    black_box(HashMap::new()),
                    black_box(Some("127.0.0.1".to_string())),
                );
            }
            black_box(logger.get_logs().len());
        })
    });
}

fn benchmark_security_operations(c: &mut Criterion) {
    let key = b"benchmark-key-32-bytes-for-test!".to_vec();
    let manager = SecurityManager::new(key);
    let test_data = b"benchmark test data for performance measurement";

    c.bench_function("hash_data", |b| {
        b.iter(|| {
            black_box(manager.hash_data(black_box(test_data)));
        })
    });

    c.bench_function("create_signature", |b| {
        b.iter(|| {
            black_box(manager.create_signature(black_box(test_data)).unwrap());
        })
    });

    c.bench_function("verify_signature", |b| {
        let signature = manager.create_signature(test_data).unwrap();
        b.iter(|| {
            black_box(manager.verify_signature(black_box(test_data), black_box(&signature)));
        })
    });
}

criterion_group!(
    benches,
    benchmark_policy_operations,
    benchmark_audit_logging,
    benchmark_security_operations
);
criterion_main!(benches);
