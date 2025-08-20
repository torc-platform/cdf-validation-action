#!/usr/bin/env python3
import argparse
import json
import os
import subprocess
import shutil
import sys
from pathlib import Path
import base64
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


def list_tf_files(cdf_path: Path):
    """List Terraform files to check authorization (match old behavior):
    We look for cdf-main.tf under stable/ and unstable/ service directories.
    """
    results = []
    for root, _, files in os.walk(cdf_path):
        if '.git' in root:
            continue
        if not (('/stable/' in root) or ('/unstable/' in root)):
            continue
        for name in files:
            if name == 'cdf-main.tf':
                results.append((Path(root) / name).relative_to(cdf_path))
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
            print(f"❌ Invalid cdf-meta.json: {e}")
            unauthorized_errors += 1

    # Count CDF files by naming convention for reporting
    file_count = len(list(cdf_path.rglob('*cdf*')))

    # If metadata lists files, use those for integrity/signature checks
    meta_files = set()
    if meta and isinstance(meta.get('files'), list):
        for f in meta['files']:
            name = f.get('name')
            if name:
                meta_files.add(name)

        # Old behavior: Only check Terraform files "authorized"; do not fail on extra CDF files
        if args.fail_on_unauthorized_tf.lower() == 'true':
            tf_files = list_tf_files(cdf_path)
            for tf in tf_files:
                print(f"✅ Authorized TF file: {tf}")

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
                print(f"⚠️ Missing file listed in metadata: {name}")
                unauthorized_errors += 1
                continue
            actual = sha256_file(p)
            if actual != expected:
                print(f"❌ Hash mismatch for {name}: expected {expected}, got {actual}")
                unauthorized_errors += 1
            else:
                print(f"✅ Hash matches for {name}")

        # Prepare public key content (input > env > repo file)
        key_content = args.public_key
        if not key_content:
            env_pem = os.environ.get('COSIGN_PUBLIC_KEY_PEM', '')
            if env_pem:
                key_content = env_pem
        if not key_content:
            env_b64 = os.environ.get('COSIGN_PUBLIC_KEY_B64', '')
            if env_b64:
                try:
                    key_content = base64.b64decode(env_b64).decode('utf-8')
                except Exception as e:
                    print(f"Failed to decode COSIGN_PUBLIC_KEY_B64: {e}")
        if not key_content:
            for candidate in [Path('.github/keys/cosign.pub'), cdf_path / '.github/keys/cosign.pub']:
                try:
                    if candidate.exists():
                        key_content = candidate.read_text()
                        break
                except Exception:
                    pass

        pubkey_file = None
        if key_content:
            try:
                pubkey_file = Path(os.environ.get('RUNNER_TEMP', '.')) / 'cosign-pubkey.pem'
                pubkey_file.write_text(key_content)
                print("Using public key from inputs/env/repo for verification")
            except Exception as e:
                print(f"Failed to write public key: {e}")

        # Signature verification with cosign over attestation JSONs
        if args.skip_signature_validation.lower() != 'true':
            if not is_cosign_available():
                print('❌ cosign not available; signature validation required but tool missing')
                signature_errors += 1
            else:
                # Enumerate all attestation JSONs, validate structure, and verify signatures
                attested_total = 0
                attested_passed = 0
                for att in sorted(cdf_path.rglob('*.attestation.json')):
                    attested_total += 1
                    print(f"🔁Validating attestation: {att.relative_to(cdf_path)}")
                    try:
                        obj = json.loads(att.read_text())
                        for req in ["_type", "subject", "predicateType", "predicate"]:
                            if req not in obj:
                                print(f"❌ Attestation missing field {req}: {att.relative_to(cdf_path)}")
                                signature_errors += 1
                            else:
                                print(f"✅ Found required attestation field: {req}")
                    except Exception as e:
                        print(f"⚠️ Invalid attestation JSON {att.relative_to(cdf_path)}: {e}")
                        signature_errors += 1
                        continue
                    sig = att.with_suffix('.sig')
                    cert = att.with_suffix('.cert')
                    if not sig.exists():
                        print(f"Signature file missing for attestation: {att.relative_to(cdf_path)}")
                        signature_errors += 1
                        continue
                    cmd_parts = ["cosign", "verify-blob", "--signature", str(sig)]
                    if cert.exists():
                        cmd_parts += [
                            "--certificate", str(cert),
                            "--certificate-identity-regexp", args.cert_identity_regex,
                            "--certificate-oidc-issuer-regexp", args.cert_issuer_regex,
                        ]
                    if args.insecure_ignore_tlog.lower() == 'true':
                        cmd_parts += ["--insecure-ignore-tlog"]
                    if pubkey_file and pubkey_file.exists():
                        cmd_parts += ["--key", str(pubkey_file)]
                    cmd_parts.append(str(att))
                    res = run(cmd_parts)
                    if res.returncode != 0:
                        rel = att.relative_to(cdf_path)
                        print(f"Signature verification failed for {rel}:\n{res.stdout}")
                        signature_errors += 1
                    else:
                        attested_passed += 1
                        print(f"✅ Cosign verification passed: {att.relative_to(cdf_path)}")

                # Summary
                print(f"Cosign verified {attested_passed}/{attested_total} attestation(s)")

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


