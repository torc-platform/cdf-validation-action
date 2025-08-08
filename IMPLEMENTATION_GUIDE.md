# Kickstart CDF Validation Action - Implementation Guide

## Overview

This GitHub Action provides comprehensive validation for Cloud Development Framework (CDF) patterns, ensuring:
- ✅ File integrity and tamper detection
- ✅ Prevention of unauthorized Terraform files
- ✅ Signature verification using keyless signing
- ✅ Centralized governance and enforcement

## Quick Start

### 1. Add the Action to Your Repository

```yaml
# .github/workflows/cdf-validation.yml
name: CDF Validation

on:
  pull_request:
    paths:
      - '**/*-cdf.*'
      - '**/cdf-*'
      - '**/cdf-meta.json'
    types: [opened, synchronize, reopened]

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ./.github/actions/kickstart-validate-action
        with:
          validation_level: 'full'
          fail_on_unauthorized_tf: 'true'
```

### 2. Configure Branch Protection

1. Go to repository Settings > Branches
2. Add rule for `main` branch
3. Enable "Require status checks to pass before merging"
4. Add `validate` as a required check

## Key Features

### 🔒 **Unauthorized Terraform File Prevention**

The action prevents injection of unauthorized Terraform files by:
- Reading the list of authorized files from `cdf-meta.json`
- Scanning for all `.tf` files in the repository
- Failing if any unauthorized Terraform files are found

```yaml
# This will fail if unauthorized .tf files are found
- uses: ./.github/actions/kickstart-validate-action
  with:
    fail_on_unauthorized_tf: 'true'
```

### 🔐 **Keyless Signature Verification**

Uses GitHub's OIDC for identity verification:
- No private keys to manage
- Verifies signatures against GitHub's public keys
- Validates attestation structure (SLSA format)

### 📋 **Flexible Validation Levels**

```yaml
# Basic validation (structure + integrity only)
validation_level: 'basic'

# Full validation (includes signatures)
validation_level: 'full'

# Strict validation (enhanced security)
validation_level: 'strict'
```

## Integration Patterns

### Pattern 1: Required PR Check

```yaml
name: Required CDF Validation

on:
  pull_request:
    types: [opened, synchronize, reopened]

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ./.github/actions/kickstart-validate-action
        id: validation
      
      - name: Fail on validation error
        if: steps.validation.outputs.validation_status == 'failed'
        run: |
          echo "❌ CDF validation failed"
          exit 1
```

### Pattern 2: Multiple Pattern Validation

```yaml
jobs:
  validate-patterns:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        pattern: [pattern1, pattern2, pattern3]
    steps:
      - uses: actions/checkout@v4
      - uses: ./.github/actions/kickstart-validate-action
        with:
          cdf_path: ${{ matrix.pattern }}
```

### Pattern 3: Conditional Validation

```yaml
jobs:
  validate:
    runs-on: ubuntu-latest
    if: contains(github.event.head_commit.message, '[cdf]')
    steps:
      - uses: actions/checkout@v4
      - uses: ./.github/actions/kickstart-validate-action
```

## Configuration Options

### Input Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `cdf_path` | string | `''` | Path to CDF pattern (auto-detected if empty) |
| `validation_level` | string | `'full'` | Validation level: basic, full, strict |
| `fail_on_unauthorized_tf` | boolean | `'true'` | Fail if unauthorized TF files found |
| `skip_signature_validation` | boolean | `'false'` | Skip signature validation |

### Output Values

| Output | Type | Description |
|--------|------|-------------|
| `validation_status` | string | `passed`, `failed`, or `skipped` |
| `error_count` | number | Number of validation errors |
| `file_count` | number | Number of files validated |

## Security Considerations

### 1. Unauthorized File Prevention

The action prevents security risks by:
- Only allowing Terraform files listed in `cdf-meta.json`
- Failing validation if unauthorized files are detected
- Providing clear error messages about unauthorized files

### 2. Tamper Detection

- SHA256 hash verification against `cdf-meta.json`
- Signature verification using Cosign
- Certificate validation

### 3. Keyless Signing Benefits

- No private key management
- Uses GitHub's OIDC for identity
- Verifiable signatures

## Troubleshooting

### Common Issues

1. **"Unauthorized Terraform file found"**
   ```bash
   # Add the file to cdf-meta.json and re-sign
   # Or temporarily disable the check:
   fail_on_unauthorized_tf: 'false'
   ```

2. **"Hash mismatch"**
   ```bash
   # Files were modified after signing
   # Re-run the CDF signing process
   ```

3. **"Signature verification failed"**
   ```bash
   # Check network connectivity to GitHub OIDC
   # Verify attestation files are properly signed
   ```

### Debug Mode

```yaml
env:
  ACTIONS_STEP_DEBUG: true
  ACTIONS_RUNNER_DEBUG: true
```

## Advanced Usage

### Custom Validation Rules

Modify `config/validation-rules.json` to customize:
- Required files and fields
- File size limits
- Allowed file extensions
- Error messages

### Integration with Existing Workflows

```yaml
# In your existing workflow
jobs:
  existing-job:
    runs-on: ubuntu-latest
    steps:
      # ... existing steps ...
      
      - name: Validate CDF before deployment
        uses: ./.github/actions/kickstart-validate-action
        with:
          validation_level: 'strict'
      
      # ... continue with deployment ...
```

### Conditional Validation

```yaml
- name: Validate CDF
  uses: ./.github/actions/kickstart-validate-action
  if: |
    github.event_name == 'pull_request' &&
    contains(github.event.pull_request.labels.*.name, 'cdf-pattern')
```

## Best Practices

### 1. Always Use Branch Protection

Configure branch protection rules to require validation:
- Prevents merging without validation
- Ensures all CDF patterns are validated
- Provides audit trail

### 2. Use Appropriate Validation Levels

- **Development**: Use `basic` for faster feedback
- **Production**: Use `full` or `strict` for security
- **Testing**: Use `skip_signature_validation: 'true'`

### 3. Monitor Validation Results

- Review validation logs regularly
- Address unauthorized file issues promptly
- Keep CDF patterns up to date

### 4. Document CDF Patterns

- Clearly document what each CDF pattern does
- Maintain up-to-date `cdf-meta.json` files
- Include validation requirements in documentation

## Migration from Existing Workflows

If you have existing validation workflows:

1. **Replace validation logic** with the action
2. **Update workflow files** to use the action
3. **Test thoroughly** with your CDF patterns
4. **Configure branch protection** rules
5. **Monitor results** and adjust as needed

## Support and Maintenance

### Getting Help

- Check the troubleshooting section
- Review validation logs for specific errors
- Create issues in the repository

### Updates and Maintenance

- Keep the action updated
- Monitor for security updates
- Review validation rules periodically

---

*This implementation guide provides everything you need to integrate CDF validation into your workflows and ensure secure, validated infrastructure patterns.* 