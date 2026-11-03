"""Cache only four pinned public model files, never fixture state."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil


REVISION = "4de13258303883538bd53b696b452bf8099f0858"
FILES = {
    "tokenizer.json": "6710678b12670bc442b99edc952c4d996ae309a7020c1fa0096dd245c2faf790",
    "onnx/model_quantized.onnx": "0826f8c1ab9edf1801db86c61919d4d108e8bfc0b809ec823ad366882ff0b77d",
    "onnx/model_quantized.cpu-v1.ort": "7ff152e912bc234f5c90e4012f99897a7b2ce180f016db2321304057756b64ff",
    "onnx/model_fp16.onnx": "4f1a646a3d4f39985589e9991a717044ede8278617fe55e3d246838bc05055e9",
}


def cache_key():
    identity = json.dumps({"revision": REVISION, "files": FILES}, sort_keys=True, separators=(",", ":"))
    return "native-model-v1-" + hashlib.sha256(identity.encode()).hexdigest()


def verify_file(path, expected):
    if path.is_symlink() or path.is_junction() or not path.is_file():
        raise RuntimeError("Model input is missing or linked: " + str(path))
    with path.open("rb") as stream:
        if hashlib.file_digest(stream, "sha256").hexdigest() != expected:
            raise RuntimeError("Model input checksum differs: " + str(path))


def verify_cache(directory):
    directory = Path(directory)
    if directory.is_symlink() or directory.is_junction() or not directory.is_dir():
        raise RuntimeError("Model cache directory is missing or linked")
    for entry in directory.rglob("*"):
        name = entry.relative_to(directory).as_posix()
        if entry.is_symlink() or entry.is_junction() or (name != "onnx" and name not in FILES):
            raise RuntimeError("Unexpected model cache entry: " + name)
        if name == "onnx" and not entry.is_dir():
            raise RuntimeError("Model cache onnx entry is not a directory")
    for name, expected in FILES.items():
        verify_file(directory / name, expected)


def sources(model, legacy):
    return {name: Path(legacy if name == "onnx/model_fp16.onnx" else model) / name for name in FILES}


def verify_sources(model, legacy):
    files = sources(model, legacy)
    for name, source in files.items():
        verify_file(source, FILES[name])
    return files


def copy_file(source, destination):
    if destination.is_symlink() or destination.is_junction():
        raise RuntimeError("Model destination is linked: " + str(destination))
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)


def restore(directory, model, legacy):
    verify_cache(directory)
    for name, destination in sources(model, legacy).items():
        copy_file(Path(directory) / name, destination)


def stage(directory, model, legacy):
    files = verify_sources(model, legacy)
    Path(directory).mkdir(parents=True, exist_ok=False)
    for name, source in files.items():
        copy_file(source, Path(directory) / name)
    verify_cache(directory)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["key", "restore", "verify", "stage"])
    parser.add_argument("--cache-dir", default=".native-model-cache")
    parser.add_argument("--model-dir")
    parser.add_argument("--legacy-dir")
    args = parser.parse_args()
    if args.action == "key":
        print(cache_key())
        return
    if not args.model_dir or not args.legacy_dir:
        parser.error("--model-dir and --legacy-dir are required")
    if args.action == "restore":
        restore(args.cache_dir, args.model_dir, args.legacy_dir)
    elif args.action == "verify":
        verify_sources(args.model_dir, args.legacy_dir)
    else:
        stage(args.cache_dir, args.model_dir, args.legacy_dir)


if __name__ == "__main__":
    main()
