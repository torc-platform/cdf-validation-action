#!/usr/bin/env python3
import argparse
import json
import os
import subprocess
import sys
from pathlib import Path


def run(cmd):
    return subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)


def find_cdf_path(explicit: str) -> Path:
    if explicit:
        p = Path(explicit)
        return p if p.exists() else Path('')
    # Auto-detect: look for typical pattern dir under multi-service-compositions
    base = Path('.')
    candidates = list(base.glob('multi-service-compositions/*'))
    for c in candidates:
        if c.is_dir() and (c / 'cdf-config.json').exists():
            return c
    return Path('')


def list_tf_files(cdf_path: Path):
    return list(cdf_path.glob('**/*.tf'))


def is_cosign_available() -> bool:
    return run('command -v cosign').returncode == 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--cdf-path', default='')
    ap.add_argument('--validation-level', default='full')
    ap.add_argument('--fail-on-unauthorized-tf', default='true')
    ap.add_argument('--skip-signature-validation', default='false')
    args = ap.parse_args()

    cdf_path = find_cdf_path(args.cdf_path)
    if not cdf_path or not cdf_path.exists():
        print('No CDF path found to validate', flush=True)
        # emit outputs
        print('validation_status=skipped')
        print('error_count=0')
        print('file_count=0')
        with open(os.environ.get('GITHUB_OUTPUT', '/dev/null'), 'a') as f:
            f.write('validation_status=skipped\n')
            f.write('error_count=0\n')
            f.write('file_count=0\n')
        sys.exit(0)

    unauthorized_errors = 0
    signature_errors = 0

    # Unauthorized TF check (basic placeholder logic)
    tf_files = list_tf_files(cdf_path)
    file_count = len(tf_files)
    if args.fail_on_unauthorized_tf.lower() == 'true':
        # Example policy: no top-level *.tf at pattern root (adjust to real rules)
        for tf in tf_files:
            rel = tf.relative_to(cdf_path)
            if len(rel.parts) == 1:
                print(f"Unauthorized Terraform file at pattern root: {rel}")
                unauthorized_errors += 1

    # Signature verification (stub): only if not skipped and cosign available
    if args.skip_signature_validation.lower() != 'true':
        if not is_cosign_available():
            print('cosign not available; cannot perform signature validation')
            signature_errors += 1
        else:
            # Placeholder: list attestation files and verify blobs if policy requires
            # Extend with your actual attestation verification commands/policy
            pass

    total_errors = unauthorized_errors + signature_errors
    status = 'passed' if total_errors == 0 else 'failed'

    # Emit outputs
    out = os.environ.get('GITHUB_OUTPUT', '')
    if out:
        with open(out, 'a') as f:
            f.write(f'validation_status={status}\n')
            f.write(f'error_count={total_errors}\n')
            f.write(f'file_count={file_count}\n')
    else:
        print(f'validation_status={status}')
        print(f'error_count={total_errors}')
        print(f'file_count={file_count}')

    if total_errors > 0:
        sys.exit(1)


if __name__ == '__main__':
    main()


