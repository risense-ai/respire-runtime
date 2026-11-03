"""Build an explicitly marked local SDK fixture, restoring production SDK pins.

First build Core with RSRS_SDK_NATIVE_FAULT_TESTS=1 via build-core-sdk.mjs.
This script never promotes, stages, pushes, or publishes a package.
"""
import argparse
import hashlib
import json
import os
import pathlib
import shutil
import subprocess


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--sdk', type=pathlib.Path, required=True)
    parser.add_argument('--output', type=pathlib.Path, required=True)
    parser.add_argument('--target-dir', type=pathlib.Path)
    args = parser.parse_args()
    repo = pathlib.Path(__file__).resolve().parent.parent
    sdk = args.sdk.resolve()
    manifest_bytes = (sdk / 'manifest.json').read_bytes()
    manifest = json.loads(manifest_bytes)
    assert manifest['test_only'] == 'native-fault-tests', 'explicit test SDK required'
    output = args.output.resolve()
    assert not output.exists(), 'choose a fresh fixture output; no files are overwritten'
    lock_path = repo / 'crates/core-sdk/core-sdk.lock.json'
    original = lock_path.read_bytes()
    lock = json.loads(original)
    lock['targets'][manifest['target']].update(
        manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(), sdk_version=manifest['sdk_version'],
        url='test-only:local-manifest', archive_url='test-only:local-sdk',
        archive_sha256=None, redistribution='test-only')
    target = args.target_dir.resolve() if args.target_dir else repo / 'target'
    env = os.environ.copy()
    env.update(CARGO_TARGET_DIR=str(target), RSRS_CORE_SDK_DIR=str(sdk))
    output.mkdir(parents=True)
    (output / 'production-lock.backup.json').write_bytes(original)
    (output / 'fixture-manifest.json').write_bytes(manifest_bytes)
    (output / 'fixture-lock.json').write_text(json.dumps(lock, indent=2), encoding='utf-8')
    try:
        lock_path.write_text(json.dumps(lock, indent=2) + '\n', encoding='utf-8')
        with (output / 'build.log').open('wb') as log:
            subprocess.run(['cargo', 'build', '--locked', '--release', '-p', 'respire',
                            '--features', 'native-fault-tests'], cwd=repo, env=env,
                           stdout=log, stderr=log, check=True)
        executable = 'rsrs.exe' if os.name == 'nt' else 'rsrs'
        shutil.copy2(target / 'release' / executable, output / executable)
        for library in (target / 'release').iterdir():
            if library.is_file() and library.suffix in ('.dll', '.so', '.dylib'):
                shutil.copy2(library, output / library.name)
        value = json.loads(subprocess.check_output([str(output / executable), '--client-only', '--json', 'v']))
        assert value['summary']['test_only'] == 'native-fault-tests'
        version = subprocess.check_output([str(output / executable), '--client-only', '--version'], text=True)
        assert 'native fault fixture; not releasable' in version
        (output / 'build-receipt.json').write_text(json.dumps({
            'test_only': 'native-fault-tests', 'sdk_source': manifest['source_revision'],
            'binary_sha256': hashlib.sha256((output / executable).read_bytes()).hexdigest(),
            'source': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=repo, text=True).strip(),
            'production_lock_sha256': hashlib.sha256(original).hexdigest()}, indent=2), encoding='utf-8')
    finally:
        lock_path.write_bytes(original)


if __name__ == '__main__':
    main()
