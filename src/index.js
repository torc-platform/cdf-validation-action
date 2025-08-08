const core = require('@actions/core');
const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

async function run() {
  try {
    // Get inputs
    const cdfPath = core.getInput('cdf_path') || '';
    const validationLevel = core.getInput('validation_level') || 'full';
    const failOnUnauthorizedTf = core.getInput('fail_on_unauthorized_tf') || 'true';
    const skipSignatureValidation = core.getInput('skip_signature_validation') || 'false';

    // Install required tools
    console.log('🔧 Installing validation tools...');
    execSync('sudo apt-get update', { stdio: 'inherit' });
    execSync('sudo apt-get install -y jq', { stdio: 'inherit' });
    
    // Install Cosign
    execSync('curl -O -L "https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64"', { stdio: 'inherit' });
    execSync('sudo mv cosign-linux-amd64 /usr/local/bin/cosign', { stdio: 'inherit' });
    execSync('sudo chmod +x /usr/local/bin/cosign', { stdio: 'inherit' });
    execSync('cosign version', { stdio: 'inherit' });

    // Auto-detect CDF path if not specified
    let finalCdfPath = cdfPath;
    if (!finalCdfPath) {
      try {
        const result = execSync('find . -name "cdf-meta.json" -o -name "composition-cdf.json" | head -1 | xargs dirname', { encoding: 'utf8' });
        finalCdfPath = result.trim() || '.';
      } catch (error) {
        finalCdfPath = '.';
      }
    }

    console.log(`🔍 Validating CDF in: ${finalCdfPath}`);
    console.log(`🔍 Validation level: ${validationLevel}`);
    console.log(`🔍 Fail on unauthorized TF: ${failOnUnauthorizedTf}`);
    console.log(`🔍 Skip signature validation: ${skipSignatureValidation}`);

    // Run the validation script
    const scriptPath = path.join(__dirname, '..', 'scripts', 'validate_cdf.sh');
    execSync(`chmod +x "${scriptPath}"`, { stdio: 'inherit' });
    execSync(`"${scriptPath}" "${finalCdfPath}" "${validationLevel}" "${failOnUnauthorizedTf}" "${skipSignatureValidation}"`, { stdio: 'inherit' });

    // Read results
    let status = 'failed';
    let errorCount = '1';
    let fileCount = '0';

    if (fs.existsSync('/tmp/validation_results.json')) {
      const results = JSON.parse(fs.readFileSync('/tmp/validation_results.json', 'utf8'));
      status = results.status || 'failed';
      errorCount = results.error_count || '1';
      fileCount = results.file_count || '0';
    }

    // Set outputs
    core.setOutput('validation_status', status);
    core.setOutput('error_count', errorCount);
    core.setOutput('file_count', fileCount);

    // Create summary
    if (fs.existsSync('/tmp/validation_results.json')) {
      const results = JSON.parse(fs.readFileSync('/tmp/validation_results.json', 'utf8'));
      if (results.summary) {
        fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY || '/dev/null', results.summary);
      }
    }

    // Fail if validation failed
    if (status === 'failed') {
      core.setFailed('CDF validation failed');
    }

  } catch (error) {
    core.setFailed(error.message);
  }
}

run(); 