#!/usr/bin/env python3
import argparse
import json
import os
import subprocess
import shutil
import sys
from pathlib import Path
import hashlib


def run(cmd_args):
    return subprocess.run(cmd_args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)


def find_cdf_path(explicit: str) -> Path:
    """Resolve the CDF pattern root.
    - If explicit path provided and contains cdf-meta.json, use it.
    - Else, search repo for first cdf-meta.json and use its parent.
    """
    if explicit:
        p = Path(explicit)
        if (p / 'cdf-meta.json').exists():
            return p
        # allow passing file directly
        if p.is_file() and p.name == 'cdf-meta.json':
            return p.parent
        return Path('')
    for meta in Path('.').rglob('cdf-meta.json'):
        return meta.parent
    return Path('')


def list_cdf_files(cdf_path: Path):
    """Find all files considered CDF artifacts by naming convention.
    Matches files with '-cdf' in name or starting with 'cdf-'.
    Returns relative paths from cdf_path.
    """
    results = []
    for root, _, files in os.walk(cdf_path):
        # skip .git
        if '.git' in root:
            continue
        for name in files:
            # Skip any attestation artifacts entirely
            if 'attestations' in root or '.attestation.' in name:
                continue
            if ('-cdf' in name) or name.startswith('cdf-'):
                full = Path(root) / name
                results.append(full.relative_to(cdf_path))
    return results


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()


def is_cosign_available() -> bool:
    return shutil.which('cosign') is not None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--cdf-path', default='')
    ap.add_argument('--validation-level', default='full')
    ap.add_argument('--fail-on-unauthorized-tf', default='true')
    ap.add_argument('--skip-signature-validation', default='false')
    ap.add_argument('--cert-identity-regex', default='.*')
    ap.add_argument('--cert-issuer-regex', default='.*')
    ap.add_argument('--insecure-ignore-tlog', default='true')
    ap.add_argument('--public-key', default='')
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

    # Load metadata if present
    meta_path = cdf_path / 'cdf-meta.json'
    meta = {}
    if meta_path.exists():
        try:
            meta = json.loads(meta_path.read_text())
        except Exception as e:
            print(f"Invalid cdf-meta.json: {e}")
            unauthorized_errors += 1

    # Discover CDF files by naming convention
    discovered = set(map(str, list_cdf_files(cdf_path)))
    file_count = len(discovered)

    # If metadata lists files, enforce whitelist
    meta_files = set()
    if meta and isinstance(meta.get('files'), list):
        for f in meta['files']:
            name = f.get('name')
            if name:
                meta_files.add(name)

        if args.fail_on_unauthorized_tf.lower() == 'true':
            unauthorized = discovered - meta_files
            for rel in sorted(unauthorized):
                print(f"Unauthorized CDF file not in metadata: {rel}")
                unauthorized_errors += 1

        # Hash verification
        for f in meta['files']:
            name = f.get('name')
            expected = f.get('sha256')
            if not name or not expected:
                continue
            # Do not verify the hash of cdf-meta.json itself or placeholder values
            if name == 'cdf-meta.json' or expected.startswith('placeholder_'):
                continue
            p = cdf_path / name
            if not p.exists():
                print(f"Missing file listed in metadata: {name}")
                unauthorized_errors += 1
                continue
            actual = sha256_file(p)
            if actual != expected:
                print(f"Hash mismatch for {name}: expected {expected}, got {actual}")
                unauthorized_errors += 1

        # Signature verification with cosign
        if args.skip_signature_validation.lower() != 'true':
            if not is_cosign_available():
                print('cosign not available; signature validation required but tool missing')
                signature_errors += 1
            else:
                for f in meta['files']:
                    name = f.get('name')
                    sig_path = f.get('signature')
                    if not name:
                        continue
                    if not sig_path:
                        print(f"Missing signature reference in metadata for {name}")
                        signature_errors += 1
                        continue
                    blob = cdf_path / name
                    sig = cdf_path / sig_path
                    cert = sig.with_suffix('.cert')
                    if not sig.exists():
                        print(f"Signature file missing for {name}: {sig_path}")
                        signature_errors += 1
                        continue
                    # Build cosign verify-blob command
                    cmd_parts = ["cosign", "verify-blob", "--signature", f"{sig}"]
                    # If a cert exists, use identity/issuer regex
                    if cert.exists():
                        cmd_parts += [
                            "--certificate", f"{cert}",
                            "--certificate-identity-regexp", args.cert_identity_regex,
                            "--certificate-oidc-issuer-regexp", args.cert_issuer_regex,
                        ]
                    # Optionally ignore TLOG (to avoid 400s in some envs)
                    if args.insecure_ignore_tlog.lower() == 'true':
                        cmd_parts += ["--insecure-ignore-tlog"]
                    # If a public key is provided (non-OIDC signatures), support key mode
                    if args.public_key:
                        # Write the key to a temp file
                        key_path = Path(os.environ.get('RUNNER_TEMP', '.')) / 'cosign-pubkey.pem'
                        try:
                            key_path.write_text(args.public_key)
                            cmd_parts += ["--key", f"{key_path}"]
                        except Exception as e:
                            print(f"Failed to write public key: {e}")
                    # FILE positional must be last
                    cmd = ' '.join(cmd_parts + [f"{blob}"])
                    # FILE must be the final positional argument
                    cmd_parts.append(str(blob))
                    res = run(cmd_parts)
                    if res.returncode != 0:
                        print(f"Signature verification failed for {name}:\n{res.stdout}")
                        signature_errors += 1

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


