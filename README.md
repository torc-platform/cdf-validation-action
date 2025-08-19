# Kickstart CDF Validation Action

A GitHub Action for validating Cloud Development Framework (CDF) patterns, ensuring file integrity, signature verification, and preventing unauthorized Terraform files.

## Features

- ✅ **CDF Structure Validation**: Validates required files and JSON structure
- ✅ **File Integrity Checks**: Verifies SHA256 hashes against cdf-meta.json
- ✅ **Unauthorized TF Detection**: Prevents unauthorized Terraform files
- ✅ **Attestation Validation**: Validates SLSA format attestations
- ✅ **Signature Verification**: Uses Cosign for key-based signature verification
- ✅ **Flexible Configuration**: Multiple validation levels and options
- ✅ **PR Integration**: Automatic commenting and status reporting

## Usage

### Basic Usage

```yaml
- name: Validate CDF Pattern
  uses: ./.github/actions/kickstart-validate-action
```

### Advanced Usage

```yaml
- name: Validate CDF Pattern
  uses: ./.github/actions/kickstart-validate-action
  with:
    cdf_path: 'my-cdf-pattern'
    validation_level: 'strict'
    fail_on_unauthorized_tf: 'true'
    skip_signature_validation: 'false'
```

### In a Workflow

```yaml
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
      - name: Checkout code
        uses: actions/checkout@v4
        
      - name: Validate CDF Pattern
        uses: ./.github/actions/kickstart-validate-action
        with:
          validation_level: 'full'
          fail_on_unauthorized_tf: 'true'
```

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `cdf_path` | Path to CDF pattern directory (auto-detected if not specified) | No | `''` |
| `validation_level` | Validation level: `basic`, `full`, or `strict` | No | `'full'` |
| `fail_on_unauthorized_tf` | Fail if unauthorized Terraform files are found | No | `'true'` |
| `skip_signature_validation` | Skip signature validation (for testing only) | No | `'false'` |

## Outputs

| Output | Description |
|--------|-------------|
| `validation_status` | Validation result: `passed`, `failed`, or `skipped` |
| `error_count` | Number of validation errors found |
| `file_count` | Number of files validated |

## Validation Levels

### Basic
- CDF structure validation
- File integrity checks
- Unauthorized Terraform file detection

### Full (Default)
- All basic validations
- Attestation structure validation
- Signature verification with Cosign

### Strict
- All full validations
- Additional security checks
- Enhanced error reporting

## What Gets Validated

### 1. CDF Structure
- ✅ `cdf-meta.json` exists and is valid JSON
- ✅ Required fields: `cdf_version`, `pattern`, `files`
- ✅ File list is properly formatted

### 2. File Integrity
- ✅ All files listed in `cdf-meta.json` exist
- ✅ SHA256 hashes match expected values
- ✅ No tampering detected

### 3. Unauthorized Terraform Files
- ✅ Only Terraform files listed in `cdf-meta.json` are allowed
- ✅ Prevents injection of unauthorized infrastructure code
- ✅ Configurable failure behavior

### 4. Attestations (SLSA Format)
- ✅ Valid JSON structure
- ✅ Required fields: `_type`, `subject`, `predicateType`, `predicate`
- ✅ Signature and certificate files exist

### 5. Signature Verification
- ✅ Cosign public-key verification
- ✅ Optional certificate verification (if certs provided)

## Error Handling

The action provides detailed error reporting:

- **File not found**: Lists missing files
- **Hash mismatch**: Shows expected vs actual hashes
- **Unauthorized TF**: Lists unauthorized Terraform files
- **Invalid JSON**: Points to syntax errors
- **Signature failure**: Indicates verification issues

## Security Features

### Key-based Verification
- Uses a Cosign public key to verify signatures
- No external OIDC dependency
- Works in restricted/internal networks

### Unauthorized File Prevention
- Prevents injection of unauthorized Terraform files
- Ensures only signed, approved infrastructure code runs
- Configurable enforcement levels

### Tamper Detection
- SHA256 hash verification
- Signature validation
- Certificate verification

## Integration Examples

### Required PR Check

```yaml
# .github/workflows/required-checks.yml
name: Required Checks

on:
  pull_request:
    types: [opened, synchronize, reopened]

jobs:
  cdf-validation:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ./.github/actions/kickstart-validate-action
        with:
          validation_level: 'full'
          fail_on_unauthorized_tf: 'true'
```

### Branch Protection Rules

Configure branch protection rules to require this check:

1. Go to repository Settings > Branches
2. Add rule for `main` branch
3. Check "Require status checks to pass before merging"
4. Add the `cdf-validation` check

### Multiple Pattern Validation

```yaml
- name: Validate Multiple CDF Patterns
  uses: ./.github/actions/kickstart-validate-action
  with:
    cdf_path: 'pattern1'
    
- name: Validate Another Pattern
  uses: ./.github/actions/kickstart-validate-action
  with:
    cdf_path: 'pattern2'
```

## Troubleshooting

### Common Issues

1. **"cdf-meta.json not found"**
   - Ensure the CDF pattern directory contains `cdf-meta.json`
   - Check the `cdf_path` input parameter

2. **"Hash mismatch"**
   - Files may have been modified after signing
   - Re-run the CDF signing process

3. **"Unauthorized Terraform file"**
   - Add the file to `cdf-meta.json` and re-sign
   - Or set `fail_on_unauthorized_tf: 'false'` for testing

4. **"Signature verification failed"**
   - Check network connectivity to GitHub OIDC endpoints
   - Verify attestation files are properly signed

### Debug Mode

Enable debug output by setting the `ACTIONS_STEP_DEBUG` secret:

```yaml
env:
  ACTIONS_STEP_DEBUG: true
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

This action is licensed under the MIT License.

## Support

For issues and questions:
- Create an issue in this repository
- Check the troubleshooting section above
- Review the validation logs for specific error details 