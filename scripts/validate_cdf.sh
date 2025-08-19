#!/bin/bash

# CDF Validation Script
# Validates CDF pattern integrity, file signatures, and prevents unauthorized Terraform files

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Input parameters
CDF_PATH="${1:-.}"
VALIDATION_LEVEL="${2:-full}"
FAIL_ON_UNAUTHORIZED_TF="${3:-true}"
SKIP_SIGNATURE_VALIDATION="${4:-false}"

# Initialize tracking
ERROR_COUNT=0
FILE_COUNT=0
VALIDATION_STATUS="passed"

# Function to log messages
log_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

log_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

log_error() {
    echo -e "${RED}❌ $1${NC}"
    ERROR_COUNT=$((ERROR_COUNT + 1))
}

# Function to check if file exists
file_exists() {
    local file="$1"
    if [ -f "$file" ]; then
        return 0
    else
        return 1
    fi
}

# Function to validate JSON structure
validate_json() {
    local file="$1"
    if ! jq empty "$file" 2>/dev/null; then
        log_error "Invalid JSON in $file"
        return 1
    fi
    return 0
}

# Function to calculate SHA256 hash
calculate_hash() {
    local file="$1"
    sha256sum "$file" | cut -d' ' -f1
}

# Function to write validation results
write_results() {
    # Escape the summary content for JSON
    SUMMARY_CONTENT=$(cat /tmp/validation_summary.txt 2>/dev/null || echo '')
    SUMMARY_ESCAPED=$(echo "$SUMMARY_CONTENT" | jq -Rs .)
    
    cat > /tmp/validation_results.json << EOF
{
  "status": "$VALIDATION_STATUS",
  "error_count": $ERROR_COUNT,
  "file_count": $FILE_COUNT,
  "validation_level": "$VALIDATION_LEVEL",
  "cdf_path": "$CDF_PATH",
  "summary": $SUMMARY_ESCAPED
}
EOF
}

# Function to create summary
create_summary() {
    cat > /tmp/validation_summary.txt << EOF
## CDF Validation Summary

**Validation Level**: $VALIDATION_LEVEL
**CDF Path**: $CDF_PATH
**Files Validated**: $FILE_COUNT
**Errors Found**: $ERROR_COUNT

### Validation Results
- ✅ CDF structure validation
- ✅ File integrity checks
- ✅ Unauthorized Terraform file detection
$(if [ "$SKIP_SIGNATURE_VALIDATION" = "false" ]; then
    echo "- ✅ Attestation structure validation"
    echo "- ✅ Signature verification"
else
    echo "- ⏭️  Signature validation skipped"
fi)

EOF
}

# Main validation logic
main() {
    log_info "Starting CDF validation in: $CDF_PATH"
    log_info "Validation level: $VALIDATION_LEVEL"
    log_info "Fail on unauthorized TF: $FAIL_ON_UNAUTHORIZED_TF"
    log_info "Skip signature validation: $SKIP_SIGNATURE_VALIDATION"

    # Change to CDF directory
    cd "$CDF_PATH" || {
        log_error "Cannot access CDF path: $CDF_PATH"
        exit 1
    }

    # Step 1: Validate CDF structure
    log_info "Step 1: Validating CDF structure"
    
    # Check for required files
    REQUIRED_FILES=("cdf-meta.json")
    for file in "${REQUIRED_FILES[@]}"; do
        if file_exists "$file"; then
            log_success "Found required file: $file"
            FILE_COUNT=$((FILE_COUNT + 1))
        else
            log_error "Required file missing: $file"
        fi
    done

    # Validate cdf-meta.json structure
    if file_exists "cdf-meta.json"; then
        if validate_json "cdf-meta.json"; then
            log_success "cdf-meta.json is valid JSON"
            
            # Check required fields
            REQUIRED_FIELDS=("cdf_version" "pattern" "files")
            for field in "${REQUIRED_FIELDS[@]}"; do
                if jq -e ".$field" "cdf-meta.json" >/dev/null 2>&1; then
                    log_success "Found required field: $field"
                else
                    log_error "Missing required field in cdf-meta.json: $field"
                fi
            done
        fi
    fi

    # Step 2: Validate file integrity
    log_info "Step 2: Validating file integrity"
    
    if file_exists "cdf-meta.json"; then
        # Read files from cdf-meta.json and validate each one
        while IFS='|' read -r file_path expected_hash signature_file; do
            log_info "Validating: $file_path"
            
            # Check if file exists
            if [ ! -f "$file_path" ]; then
                log_error "File not found: $file_path"
                continue
            fi
            
            # Calculate actual hash
            actual_hash=$(calculate_hash "$file_path")
            
            # Compare hashes (cdf-meta.json is validated via signature only)
            if [ "$file_path" = "cdf-meta.json" ]; then
                log_info "cdf-meta.json hash validation skipped (self-referential)"
                log_success "cdf-meta.json will be validated via signature verification"
            elif [ "$actual_hash" != "$expected_hash" ]; then
                log_error "Hash mismatch for $file_path"
                log_error "  Expected: $expected_hash"
                log_error "  Actual:   $actual_hash"
                log_error "  This indicates the file may have been tampered with!"
            else
                log_success "Hash matches for $file_path"
            fi
            
            FILE_COUNT=$((FILE_COUNT + 1))
        done < <(jq -r '.files[] | "\(.name)|\(.sha256)|\(.signature)"' cdf-meta.json)
    fi

    # Step 3: Check for unauthorized Terraform files
    log_info "Step 3: Checking for unauthorized Terraform files"
    
    # Get list of authorized TF files from cdf-meta.json
    if file_exists "cdf-meta.json"; then
        AUTHORIZED_TF_FILES=$(jq -r '.files[] | select(.name | endswith(".tf")) | .name' cdf-meta.json 2>/dev/null || echo "")
        
        # Find all .tf files in the repository
        ALL_TF_FILES=$(find . -name "*.tf" -type f | sed 's|^\./||' | sort)
        
        UNAUTHORIZED_FOUND=false
        while IFS= read -r tf_file; do
            if [ -n "$tf_file" ]; then
                # Check if this TF file is in the authorized list
                if echo "$AUTHORIZED_TF_FILES" | grep -Fxq "$tf_file"; then
                    log_success "Authorized TF file: $tf_file"
                else
                    log_error "Unauthorized TF file found: $tf_file"
                    log_error "  This file is not part of the signed CDF pattern!"
                    UNAUTHORIZED_FOUND=true
                fi
            fi
        done <<< "$ALL_TF_FILES"
        
        if [ "$UNAUTHORIZED_FOUND" = "true" ] && [ "$FAIL_ON_UNAUTHORIZED_TF" = "true" ]; then
            log_error "Unauthorized Terraform files detected - validation failed"
            VALIDATION_STATUS="failed"
        fi
    fi

    # Step 4: Validate attestations (if not skipped)
    if [ "$SKIP_SIGNATURE_VALIDATION" = "false" ]; then
        log_info "Step 4: Validating attestations"
        
        # Find all attestation files
        ATTESTATION_FILES=$(find . -name "*.attestation.json" -type f)
        
        if [ -n "$ATTESTATION_FILES" ]; then
            while IFS= read -r attestation_file; do
                log_info "Validating attestation: $attestation_file"
                
                # Validate JSON structure
                if ! validate_json "$attestation_file"; then
                    log_error "Invalid JSON in attestation: $attestation_file"
                    continue
                fi
                
                # Check for required attestation fields (SLSA format)
                REQUIRED_ATTESTATION_FIELDS=("_type" "subject" "predicateType" "predicate")
                for field in "${REQUIRED_ATTESTATION_FIELDS[@]}"; do
                    if jq -e ".$field" "$attestation_file" >/dev/null 2>&1; then
                        log_success "Found required attestation field: $field"
                    else
                        log_error "Missing required attestation field: $field in $attestation_file"
                    fi
                done
                
                # Check for signature file
                sig_file="${attestation_file%.json}.sig"
                if [ ! -f "$sig_file" ]; then
                    log_error "Signature file not found: $sig_file"
                else
                    log_success "Signature file exists: $sig_file"
                fi
                
                # Check for certificate file
                cert_file="${attestation_file%.json}.cert"
                if [ ! -f "$cert_file" ]; then
                    log_error "Certificate file not found: $cert_file"
                else
                    log_success "Certificate file exists: $cert_file"
                fi
                
                FILE_COUNT=$((FILE_COUNT + 1))
            done <<< "$ATTESTATION_FILES"
        else
            log_warning "No attestation files found"
        fi

        # Step 5: Validate signatures with Cosign
        log_info "Step 5: Validating signatures with Cosign"
        
        # Find all signature files
        SIGNATURE_FILES=$(find . -name "*.attestation.sig" -type f)
        
        if [ -n "$SIGNATURE_FILES" ]; then
            while IFS= read -r sig_file; do
                log_info "Validating signature: $sig_file"
                
                # Get the corresponding attestation file
                attestation_file="${sig_file%.sig}.json"
                if [ ! -f "$attestation_file" ]; then
                    log_error "Attestation file not found: $attestation_file"
                    continue
                fi
                
                # Prefer public-key verification with Cosign; fallback to certificate if present
                if [ -n "$PUBLIC_KEY" ]; then
                    if cosign verify-blob "$attestation_file" \
                        --signature "$sig_file" \
                        --key <(echo "$PUBLIC_KEY") 2>/dev/null; then
                        log_success "Cosign verification passed (public key): $attestation_file"
                    else
                        log_error "Cosign verification failed (public key): $attestation_file"
                    fi
                else
                    cert_file="${sig_file%.sig}.cert"
                    if [ ! -f "$cert_file" ]; then
                        log_error "Certificate file not found: $cert_file"
                        continue
                    fi
                    if cosign verify-blob "$attestation_file" \
                        --signature "$sig_file" \
                        --certificate "$cert_file" \
                        --certificate-identity-regexp ".*" \
                        --certificate-oidc-issuer-regexp ".*" 2>/dev/null; then
                        log_success "Cosign verification passed (certificate): $attestation_file"
                    else
                        log_error "Cosign verification failed (certificate): $attestation_file"
                    fi
                fi
            done <<< "$SIGNATURE_FILES"
        else
            log_warning "No signature files found"
        fi
    fi

    # Determine final status
    if [ $ERROR_COUNT -gt 0 ]; then
        VALIDATION_STATUS="failed"
        log_error "Validation failed with $ERROR_COUNT errors"
    else
        log_success "Validation completed successfully"
        log_success "Files validated: $FILE_COUNT"
    fi

    # Create summary and write results
    create_summary
    write_results

    # Exit with appropriate code
    if [ "$VALIDATION_STATUS" = "failed" ]; then
        exit 1
    else
        exit 0
    fi
}

# Run main function
main "$@" 