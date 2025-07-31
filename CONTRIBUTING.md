# Contributing to Universal AI Governor

Thanks for considering contributing to this project! I started this as a personal project to solve some real problems I was seeing in AI security, and it's grown into something bigger than I expected.

```
+================================================================+
|                                                                |
|                    CONTRIBUTION GUIDELINES                     |
|                                                                |
|         Help me build better AI governance tools              |
|                                                                |
+================================================================+
```

## Before you start

I really appreciate contributions, but please take a few minutes to read this guide. It'll save both of us time and make the whole process smoother.

### What I'm looking for

**Bug fixes** - If something's broken, I want to know about it. Even small fixes are valuable.

**New features** - But please open an issue first to discuss it. I have some strong opinions about the direction of this project, and I'd hate for you to spend time on something that doesn't fit.

**Documentation improvements** - I try to write good docs, but I'm sure there are gaps. If something confused you, it probably confuses others too.

**Performance improvements** - Always welcome, especially if you can show benchmarks.

**Security enhancements** - This is a security-focused project, so security improvements are always appreciated.

### What I'm not looking for right now

- Major architectural changes without discussion
- Dependencies on proprietary software
- Features that compromise security for convenience
- Code that doesn't follow the existing patterns

---

## Getting started

### Setting up your development environment

```bash
# Fork the repo on GitHub first, then:
git clone https://github.com/YOUR_USERNAME/universal-ai-governor.git
cd universal-ai-governor

# Add my repo as upstream
git remote add upstream https://github.com/morningstarxcdcode/universal-ai-governor.git

# Run the setup script (this takes care of dependencies)
./scripts/setup.sh

# Make sure everything works
cargo test --all-features
```

If the setup script doesn't work on your system, please open an issue. I've tested it on Ubuntu, macOS, and a few other systems, but there are always edge cases.

### Development workflow

I use a pretty standard Git workflow:

1. **Create a branch** for your work: `git checkout -b fix-that-annoying-bug`
2. **Make your changes** in small, logical commits
3. **Test everything**: `./scripts/test.sh`
4. **Push and create a PR**

Please don't work directly on main - it makes things messy when I'm trying to merge multiple contributions.

---

## Code standards

I'm not super picky about code style, but there are a few things I care about:

### Rust style

**Use rustfmt**: `cargo fmt` before you commit. The CI will complain if you don't.

**Fix clippy warnings**: `cargo clippy --all-targets --all-features`. I have it set to deny warnings in CI.

**Write tests**: If you're adding new functionality, please include tests. If you're fixing a bug, add a test that would have caught it.

**Document public APIs**: Use rustdoc comments for anything that's part of the public API.

### Error handling

I'm pretty strict about error handling. Use `Result` types, don't panic in library code, and make sure errors have useful messages.

```rust
// Good
pub fn validate_policy(policy: &str) -> Result<Policy, ValidationError> {
    if policy.is_empty() {
        return Err(ValidationError::EmptyPolicy);
    }
    // ... rest of validation
}

// Bad
pub fn validate_policy(policy: &str) -> Policy {
    assert!(!policy.is_empty(), "Policy cannot be empty");
    // ... this will crash the whole program
}
```

### Security considerations

This is a security project, so I'm extra careful about:

- **No hardcoded secrets** - Use environment variables or config files
- **Input validation** - Validate everything that comes from outside
- **Constant-time operations** - For crypto operations, use constant-time comparisons
- **Memory safety** - One of the reasons I chose Rust, but still be careful with unsafe code

---

## Testing

I take testing seriously. The CI runs several types of tests:

**Unit tests**: `cargo test`
**Integration tests**: `cargo test --test '*'`
**Security tests**: `./scripts/test.sh --type security`
**Performance tests**: `cargo bench`

If you're adding new functionality, please add tests. If you're not sure what to test, look at the existing test files for examples.

### Writing good tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_validation_rejects_empty_policy() {
        let result = validate_policy("");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), ValidationError::EmptyPolicy);
    }

    #[tokio::test]
    async fn test_async_policy_evaluation() {
        let policy = Policy::from_rego("package test; allow = true");
        let result = evaluate_policy(&policy, &test_input()).await;
        assert!(result.is_ok());
    }
}
```

---

## Documentation

If you're changing user-facing functionality, please update the docs. The documentation lives in the `docs/` directory and is written in Markdown.

I try to keep the docs practical and example-heavy. If you're not sure how to document something, look at the existing docs for patterns.

### API documentation

For Rust code, use rustdoc comments:

```rust
/// Validates a governance policy against security rules.
///
/// This function performs comprehensive validation including syntax checking,
/// security rule compliance, and performance impact analysis.
///
/// # Arguments
///
/// * `policy` - The policy string to validate
/// * `context` - Validation context with security settings
///
/// # Returns
///
/// Returns `Ok(())` if validation passes, or `Err(ValidationError)` with
/// details about what failed.
///
/// # Examples
///
/// ```rust
/// use universal_ai_governor::validate_policy;
///
/// let policy = "package example; allow = true";
/// match validate_policy(policy, &context) {
///     Ok(()) => println!("Policy is valid"),
///     Err(e) => eprintln!("Validation failed: {}", e),
/// }
/// ```
pub fn validate_policy(policy: &str, context: &ValidationContext) -> Result<(), ValidationError> {
    // Implementation here
}
```

---

## Pull request process

When you're ready to submit your changes:

1. **Make sure tests pass**: `./scripts/test.sh`
2. **Update documentation** if needed
3. **Write a good PR description** - explain what you changed and why
4. **Be patient** - I try to review PRs quickly, but sometimes it takes a few days

### PR description template

I don't require a specific format, but here's what I find helpful:

```markdown
## What this changes

Brief description of what you changed.

## Why

Explain the problem you're solving or the feature you're adding.

## Testing

How did you test this? Any specific test cases I should look at?

## Breaking changes

Are there any breaking changes? How should users migrate?
```

---

## Code review process

I try to be thorough but fair in code reviews. Here's what I look for:

**Correctness** - Does the code do what it's supposed to do?
**Security** - Are there any security implications?
**Performance** - Will this impact performance significantly?
**Maintainability** - Is the code easy to understand and modify?
**Testing** - Are there adequate tests?

Don't take review comments personally - I'm trying to help make the code better, not criticize you personally.

---

## Community guidelines

I want this to be a welcoming project for everyone. Please:

- **Be respectful** in discussions and code reviews
- **Assume good intentions** - we're all trying to build something useful
- **Ask questions** if something isn't clear
- **Help others** when you can

I don't tolerate harassment, discrimination, or other toxic behavior. If you see something problematic, please reach out to me directly.

---

## Getting help

If you're stuck or have questions:

- **Check the docs** first - they might have the answer
- **Look at existing issues** - someone might have asked the same question
- **Open a new issue** if you can't find what you need
- **Reach out directly** if it's something sensitive

I'm usually pretty responsive, but please be patient if it takes me a day or two to get back to you.

---

## Recognition

Contributors get credit in several places:

- **Git history** - your commits will always be there
- **Release notes** - significant contributions get mentioned
- **Contributors file** - I maintain a list of everyone who's helped

I really appreciate everyone who contributes to this project, whether it's a one-line bug fix or a major feature.

---

```
+================================================================+
|                                                                |
|                    THANKS FOR CONTRIBUTING!                   |
|                                                                |
|         Every contribution makes this project better          |
|                                                                |
+================================================================+
```

**Questions?** Don't hesitate to ask. I'd rather answer questions upfront than deal with confusion later.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Contribution Types](#contribution-types)
- [Development Workflow](#development-workflow)
- [Code Standards](#code-standards)
- [Testing Requirements](#testing-requirements)
- [Documentation](#documentation)
- [Security Considerations](#security-considerations)
- [Review Process](#review-process)

---

## Code of Conduct

### Our Pledge

We are committed to making participation in this project a harassment-free experience for everyone, regardless of age, body size, disability, ethnicity, gender identity and expression, level of experience, nationality, personal appearance, race, religion, or sexual identity and orientation.

### Our Standards

**Positive behavior includes:**
- Using welcoming and inclusive language
- Being respectful of differing viewpoints and experiences
- Gracefully accepting constructive criticism
- Focusing on what is best for the community
- Showing empathy towards other community members

**Unacceptable behavior includes:**
- The use of sexualized language or imagery
- Trolling, insulting/derogatory comments, and personal or political attacks
- Public or private harassment
- Publishing others' private information without explicit permission
- Other conduct which could reasonably be considered inappropriate in a professional setting

---

## Getting Started

### Prerequisites

Before contributing, ensure you have:

- **Rust 1.70+** installed via [rustup](https://rustup.rs/)
- **Git** for version control
- **Docker** for containerized testing
- **Basic understanding** of AI security concepts
- **Familiarity** with Rust ecosystem and async programming

### First-Time Setup

```bash
# Fork the repository on GitHub
# Clone your fork
git clone https://github.com/YOUR_USERNAME/universal-ai-governor.git
cd universal-ai-governor

# Add upstream remote
git remote add upstream https://github.com/morningstarxcdcode/universal-ai-governor.git

# Run setup script
./scripts/setup.sh

# Verify installation
cargo test --all-features
```

---

## Development Setup

### Environment Configuration

1. **Copy environment template:**
```bash
cp .env.example .env
```

2. **Configure development settings:**
```bash
# Edit .env with your preferences
RUST_LOG=debug
DEVELOPMENT_MODE=true
TPM_ENABLED=false  # Set to true if you have TPM hardware
```

3. **Install development tools:**
```bash
# Code formatting and linting
rustup component add rustfmt clippy

# Additional tools
cargo install cargo-watch cargo-audit cargo-deny
```

### IDE Setup

**Recommended VS Code extensions:**
- rust-analyzer
- CodeLLDB (for debugging)
- Better TOML
- GitLens

**Recommended settings (.vscode/settings.json):**
```json
{
    "rust-analyzer.cargo.features": "all",
    "rust-analyzer.checkOnSave.command": "clippy",
    "editor.formatOnSave": true
}
```

---

## Contribution Types

### Bug Reports

When reporting bugs, please include:

```
**Bug Description:**
Clear description of the issue

**Steps to Reproduce:**
1. Step one
2. Step two
3. Step three

**Expected Behavior:**
What should happen

**Actual Behavior:**
What actually happens

**Environment:**
- OS: [e.g., Ubuntu 22.04]
- Rust version: [e.g., 1.70.0]
- Hardware: [e.g., TPM 2.0 available]

**Additional Context:**
Any other relevant information
```

### Feature Requests

For new features, please provide:

- **Problem statement**: What problem does this solve?
- **Proposed solution**: How should it work?
- **Alternatives considered**: Other approaches you've thought about
- **Implementation notes**: Technical considerations
- **Breaking changes**: Will this affect existing APIs?

### Code Contributions

We welcome contributions in these areas:

- **Core functionality**: Governor engine, policy enforcement
- **Hardware integration**: TPM, HSM, Secure Enclave support
- **AI components**: Policy synthesis, threat detection
- **Security features**: Cryptography, authentication, audit
- **Performance**: Optimization, benchmarking
- **Documentation**: Guides, examples, API docs
- **Testing**: Unit tests, integration tests, security tests

---

## Development Workflow

### Branch Strategy

```
main
├── develop
│   ├── feature/ai-policy-synthesis
│   ├── feature/tpm-integration
│   └── bugfix/memory-leak-fix
└── release/v1.0.0
```

### Workflow Steps

1. **Create feature branch:**
```bash
git checkout develop
git pull upstream develop
git checkout -b feature/your-feature-name
```

2. **Make changes:**
```bash
# Make your changes
# Test thoroughly
cargo test --all-features
./scripts/test.sh --type all
```

3. **Commit changes:**
```bash
git add .
git commit -m "feat: add AI policy synthesis engine

- Implement offline LLM integration
- Add policy generation from incidents
- Include comprehensive test suite
- Update documentation

Closes #123"
```

4. **Push and create PR:**
```bash
git push origin feature/your-feature-name
# Create pull request on GitHub
```

### Commit Message Format

We follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `perf`: Performance improvements
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

**Examples:**
```
feat(ai): add policy synthesis engine
fix(tpm): resolve key sealing issue
docs: update API documentation
test(security): add adversarial test cases
```

---

## Code Standards

### Rust Style Guide

We follow the official [Rust Style Guide](https://doc.rust-lang.org/nightly/style-guide/) with these additions:

**Formatting:**
```bash
# Format code before committing
cargo fmt --all
```

**Linting:**
```bash
# Fix clippy warnings
cargo clippy --all-targets --all-features -- -D warnings
```

**Code Organization:**
```rust
// File structure
src/
├── lib.rs              // Library root
├── main.rs             // Binary entry point
├── core/               // Core governance engine
├── hardware/           // Hardware abstraction
├── ai/                 // AI components
├── security/           // Security modules
├── compliance/         // Compliance engines
└── utils/              // Utility functions
```

**Error Handling:**
```rust
// Use Result types for fallible operations
pub fn validate_policy(policy: &Policy) -> Result<(), ValidationError> {
    // Implementation
}

// Use custom error types
#[derive(Debug, thiserror::Error)]
pub enum GovernorError {
    #[error("Policy validation failed: {reason}")]
    PolicyValidation { reason: String },
    
    #[error("Hardware operation failed")]
    Hardware(#[from] HardwareError),
}
```

**Documentation:**
```rust
/// Validates an AI governance policy against security rules.
///
/// This function performs comprehensive validation including:
/// - Syntax checking
/// - Security rule compliance
/// - Performance impact analysis
///
/// # Arguments
///
/// * `policy` - The policy to validate
/// * `context` - Validation context with security settings
///
/// # Returns
///
/// Returns `Ok(())` if validation passes, or `Err(ValidationError)`
/// with details about validation failures.
///
/// # Examples
///
/// ```rust
/// use universal_ai_governor::{Policy, ValidationContext};
///
/// let policy = Policy::from_rego("package example; allow = true");
/// let context = ValidationContext::default();
/// 
/// match validate_policy(&policy, &context) {
///     Ok(()) => println!("Policy is valid"),
///     Err(e) => eprintln!("Validation failed: {}", e),
/// }
/// ```
pub fn validate_policy(
    policy: &Policy, 
    context: &ValidationContext
) -> Result<(), ValidationError> {
    // Implementation
}
```

### Security Guidelines

**Sensitive Data:**
```rust
// Use zeroize for sensitive data
use zeroize::Zeroize;

#[derive(Zeroize)]
struct SecretKey {
    key: [u8; 32],
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}
```

**Cryptography:**
```rust
// Use established cryptographic libraries
use ring::aead;
use ring::rand::{SystemRandom, SecureRandom};

// Always use secure random number generation
let rng = SystemRandom::new();
let mut key = [0u8; 32];
rng.fill(&mut key)?;
```

---

## Testing Requirements

### Test Categories

**Unit Tests:**
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_validation() {
        let policy = Policy::from_rego("package test; allow = true");
        assert!(validate_policy(&policy).is_ok());
    }

    #[tokio::test]
    async fn test_async_operation() {
        let result = async_function().await;
        assert!(result.is_ok());
    }
}
```

**Integration Tests:**
```bash
# Run integration tests
cargo test --test integration_tests --all-features
```

**Security Tests:**
```bash
# Run security-specific tests
cargo test --test security_tests --all-features
```

**Performance Tests:**
```bash
# Run benchmarks
cargo bench
```

### Test Coverage

- **Minimum coverage**: 80% for new code
- **Critical paths**: 95% coverage required
- **Security functions**: 100% coverage required

```bash
# Generate coverage report
cargo tarpaulin --all-features --workspace --out Html
```

---

## Documentation

### Documentation Types

**Code Documentation:**
- All public APIs must have rustdoc comments
- Include examples for complex functions
- Document error conditions and edge cases

**User Documentation:**
- Update relevant guides in `docs/`
- Include configuration examples
- Add troubleshooting information

**Architecture Documentation:**
- Update architecture diagrams for structural changes
- Document design decisions
- Include security considerations

### Documentation Standards

```rust
/// Brief one-line description.
///
/// Longer description with more details about the function's
/// purpose, behavior, and any important considerations.
///
/// # Arguments
///
/// * `param1` - Description of parameter
/// * `param2` - Description of parameter
///
/// # Returns
///
/// Description of return value and possible variants.
///
/// # Errors
///
/// This function will return an error if:
/// - Condition 1 occurs
/// - Condition 2 happens
///
/// # Examples
///
/// ```rust
/// # use universal_ai_governor::*;
/// let result = function_name(param1, param2)?;
/// assert_eq!(result, expected_value);
/// ```
///
/// # Security
///
/// Important security considerations for this function.
pub fn function_name(param1: Type1, param2: Type2) -> Result<ReturnType, Error> {
    // Implementation
}
```

---

## Security Considerations

### Security Review Process

All security-related changes require:

1. **Security impact assessment**
2. **Threat model review**
3. **Cryptographic review** (if applicable)
4. **Hardware security validation** (if applicable)
5. **Penetration testing** (for major changes)

### Sensitive Areas

**High-security components:**
- Cryptographic operations
- Hardware integration (TPM, HSM, Secure Enclave)
- Authentication and authorization
- Policy enforcement engine
- Audit logging system

**Security checklist:**
- [ ] No hardcoded secrets or keys
- [ ] Proper input validation and sanitization
- [ ] Secure error handling (no information leakage)
- [ ] Constant-time operations for cryptographic functions
- [ ] Proper memory management for sensitive data
- [ ] Comprehensive logging for security events

---

## Review Process

### Pull Request Requirements

**Before submitting:**
- [ ] All tests pass locally
- [ ] Code is formatted (`cargo fmt`)
- [ ] No clippy warnings (`cargo clippy`)
- [ ] Documentation is updated
- [ ] Security considerations are addressed
- [ ] Performance impact is assessed

**PR Description Template:**
```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update
- [ ] Performance improvement
- [ ] Security enhancement

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] Manual testing performed
- [ ] Security testing performed

## Security Impact
Description of security implications

## Performance Impact
Description of performance implications

## Breaking Changes
List any breaking changes

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] Tests added/updated
- [ ] Security reviewed
```

### Review Criteria

**Code Quality:**
- Follows Rust best practices
- Proper error handling
- Clear and maintainable code
- Appropriate abstractions

**Security:**
- No security vulnerabilities
- Follows security best practices
- Proper handling of sensitive data
- Comprehensive input validation

**Performance:**
- No unnecessary performance regressions
- Efficient algorithms and data structures
- Proper resource management
- Benchmarks for performance-critical changes

**Documentation:**
- Clear and comprehensive documentation
- Updated user guides
- API documentation complete
- Examples provided

---

## Getting Help

### Communication Channels

- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: General questions and discussions
- **Email**: morningstar.xcd@gmail.com for security issues

### Resources

- **Rust Documentation**: https://doc.rust-lang.org/
- **Tokio Guide**: https://tokio.rs/tokio/tutorial
- **Security Best Practices**: See `docs/security.md`
- **Architecture Overview**: See `docs/architecture.md`

---

## Recognition

Contributors will be recognized in:

- **CONTRIBUTORS.md** file
- **Release notes** for significant contributions
- **GitHub contributors** page
- **Project documentation** for major features

---

```
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║                    THANK YOU FOR CONTRIBUTING!                   ║
║                                                                  ║
║         Your contributions make this project better for          ║
║                        everyone in the community                 ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
```

**Questions?** Feel free to reach out through any of our communication channels. We're here to help!
