# Pull Request

```
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║                    PULL REQUEST TEMPLATE                         ║
║                                                                  ║
║         Please fill out all sections before submitting          ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
```

## Description

**Summary:**
Brief description of the changes in this pull request.

**Related Issues:**
- Fixes #(issue number)
- Closes #(issue number)
- Related to #(issue number)

## Type of Change

Please mark the relevant option:

- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update
- [ ] Performance improvement
- [ ] Code refactoring
- [ ] Security enhancement
- [ ] Test improvement

## Changes Made

**Detailed Changes:**
- Change 1: Description
- Change 2: Description
- Change 3: Description

**Files Modified:**
- `src/core/mod.rs` - Added new functionality
- `src/security/mod.rs` - Enhanced security features
- `docs/api.md` - Updated documentation

## Testing

**Test Coverage:**
- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] Security tests added/updated
- [ ] Performance tests added/updated
- [ ] Manual testing performed

**Test Results:**
```bash
# Paste test results here
cargo test --all-features
```

**Coverage Report:**
Current coverage: XX%
Previous coverage: XX%
Coverage change: +/-XX%

## Security Impact

**Security Review:**
- [ ] No security impact
- [ ] Security impact assessed and documented
- [ ] Cryptographic changes reviewed
- [ ] Hardware security implications considered

**Security Checklist:**
- [ ] No hardcoded secrets or credentials
- [ ] Input validation implemented
- [ ] Output encoding applied where needed
- [ ] Error handling doesn't leak sensitive information
- [ ] Logging doesn't expose sensitive data

## Performance Impact

**Performance Analysis:**
- [ ] No performance impact
- [ ] Performance impact measured and acceptable
- [ ] Performance regression identified and addressed
- [ ] Benchmarks updated

**Benchmark Results:**
```
Before: XXXms
After:  XXXms
Change: +/-XX%
```

## Breaking Changes

**Breaking Changes:**
- [ ] No breaking changes
- [ ] Breaking changes documented below

**Migration Guide:**
If there are breaking changes, provide migration instructions:

```rust
// Old API
old_function(param1, param2);

// New API
new_function(param1, param2, param3);
```

## Documentation

**Documentation Updates:**
- [ ] Code comments updated
- [ ] API documentation updated
- [ ] User documentation updated
- [ ] Architecture documentation updated
- [ ] Configuration documentation updated

**Documentation Changes:**
- Updated `docs/api.md` with new endpoints
- Added examples to `docs/examples/`
- Updated configuration reference

## Deployment

**Deployment Considerations:**
- [ ] No deployment changes required
- [ ] Configuration changes required
- [ ] Database migrations required
- [ ] Infrastructure changes required

**Configuration Changes:**
```toml
# New configuration options
[new_section]
option = "value"
```

## Checklist

**Pre-submission Checklist:**
- [ ] Code follows the project's style guidelines
- [ ] Self-review of code completed
- [ ] Code is commented, particularly in hard-to-understand areas
- [ ] Corresponding changes to documentation made
- [ ] Changes generate no new warnings
- [ ] Tests added that prove the fix is effective or feature works
- [ ] New and existing unit tests pass locally
- [ ] Any dependent changes have been merged and published

**Quality Assurance:**
- [ ] `cargo fmt` applied
- [ ] `cargo clippy` passes without warnings
- [ ] `cargo test` passes all tests
- [ ] `cargo audit` shows no vulnerabilities
- [ ] Security review completed (if applicable)

**Communication:**
- [ ] Reviewers assigned
- [ ] Labels applied
- [ ] Milestone set (if applicable)
- [ ] Project board updated (if applicable)

## Additional Notes

**Implementation Notes:**
Any additional implementation details or design decisions.

**Future Work:**
Any follow-up work that should be done in future PRs.

**Questions for Reviewers:**
Specific questions or areas where you'd like focused review.

---

**Reviewer Guidelines:**

Please review:
1. **Code Quality**: Is the code well-structured and maintainable?
2. **Security**: Are there any security implications?
3. **Performance**: Does this impact system performance?
4. **Testing**: Is the test coverage adequate?
5. **Documentation**: Is the documentation clear and complete?
6. **Breaking Changes**: Are breaking changes properly documented?

Thank you for your contribution to Universal AI Governor!
