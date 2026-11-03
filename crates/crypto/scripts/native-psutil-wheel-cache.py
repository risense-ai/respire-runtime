"""Cache only the fixed Windows psutil wheel and its exact build provenance."""
import argparse
import ctypes
import hashlib
import importlib.metadata
import json
import pathlib
import shutil
import subprocess
import sys
import sysconfig
import tempfile


SOURCE_URL = "https://github.com/giampaolo/psutil/archive/078f2f08d2ccea916a42f9571ab8bd40d958e7a1.tar.gz"
SOURCE_SHA256 = "8073a6389894b1ea3edc4f0feb47dba742b5552eab93f28ba6f45d2b19f11e4b"
MANIFEST = "wheel-provenance.json"


def native_architecture():
    if sys.platform != "win32":
        raise ValueError("Native Windows Python is required")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    current_process = kernel.GetCurrentProcess
    current_process.argtypes = []
    current_process.restype = ctypes.c_void_p
    machine_types = kernel.IsWow64Process2
    machine_types.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ushort), ctypes.POINTER(ctypes.c_ushort)]
    machine_types.restype = ctypes.c_int
    process, native = ctypes.c_ushort(), ctypes.c_ushort()
    if not machine_types(current_process(), ctypes.byref(process), ctypes.byref(native)):
        raise ctypes.WinError(ctypes.get_last_error())
    if process.value != 0 or native.value not in (0x8664, 0xAA64):
        raise ValueError("Native Windows x64 or ARM64 Python is required; emulation is not supported")
    return {0x8664: "x64", 0xAA64: "arm64"}[native.value]


def build_inputs():
    if sys.prefix == sys.base_prefix:
        raise ValueError("Use the isolated upgrade venv Python")
    architecture = native_architecture()
    expected_platform = {"x64": "win-amd64", "arm64": "win-arm64"}[architecture]
    if sysconfig.get_platform() != expected_platform:
        raise ValueError("Python platform differs from native Windows architecture")
    return {
        "source_url": SOURCE_URL, "source_sha256": SOURCE_SHA256,
        "architecture": architecture, "python_version": sys.version,
        "implementation": sys.implementation.name, "cache_tag": sys.implementation.cache_tag,
        "soabi": sysconfig.get_config_var("SOABI"), "extension_suffix": sysconfig.get_config_var("EXT_SUFFIX"),
        "python_platform": expected_platform,
        "tools": {name: importlib.metadata.version(name) for name in ("pip", "setuptools", "wheel", "packaging")},
        "recipe_sha256": hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),
    }


def cache_key(inputs):
    digest = hashlib.sha256(json.dumps(inputs, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return f"native-psutil-wheel-v1-{inputs['architecture']}-{inputs['cache_tag']}-{digest}"


def pip(*arguments):
    subprocess.run([sys.executable, "-m", "pip", "--isolated", "--disable-pip-version-check", *arguments], check=True)


def compatible_wheel(directory, inputs):
    entries = list(directory.iterdir())
    wheels = [path for path in entries if path.suffix == ".whl"]
    if len(wheels) != 1:
        raise ValueError("Exactly one psutil wheel is required")
    wheel = wheels[0]
    platform_tag = inputs["python_platform"].replace("-", "_")
    if (wheel.is_symlink() or not wheel.is_file() or not wheel.name.startswith("psutil-")
            or len(wheel.stem.split("-")) not in (5, 6) or wheel.stem.rsplit("-", 1)[1] != platform_tag):
        raise ValueError("Wheel distribution or native platform differs")
    # pip accepts supported abi3 tags and rejects incompatible Python/ABI wheels offline.
    pip("install", "--dry-run", "--force-reinstall", "--no-index", "--no-deps", "--no-cache-dir", str(wheel.resolve()))
    return wheel


def validate(directory, inputs):
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("Wheel cache must be a real directory")
    manifest_path = directory / MANIFEST
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise ValueError("Wheel provenance is missing or unsafe")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if (set(manifest) != {"schema_version", "inputs", "wheel"} or manifest["schema_version"] != 1
            or manifest["inputs"] != inputs or set(manifest["wheel"]) != {"name", "sha256"}):
        raise ValueError("Wheel provenance differs from the fixed source, interpreter or build tools")
    entries = list(directory.iterdir())
    if len(entries) != 2 or any(path.name not in (MANIFEST, manifest["wheel"]["name"]) for path in entries):
        raise ValueError("Unexpected files in wheel cache")
    wheel = directory / manifest["wheel"]["name"]
    if wheel.is_symlink() or not wheel.is_file() or wheel.parent != directory:
        raise ValueError("Wheel provenance path is unsafe")
    if hashlib.sha256(wheel.read_bytes()).hexdigest() != manifest["wheel"]["sha256"]:
        raise ValueError("Wheel SHA256 differs from provenance")
    return compatible_wheel(directory, inputs)


def build(directory, inputs):
    if directory.is_symlink() or (directory.exists() and any(directory.iterdir())):
        raise ValueError("Build requires an empty wheel directory")
    directory.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="native-psutil-wheel-", dir=directory.parent) as temporary:
        temporary = pathlib.Path(temporary)
        pip("wheel", "--no-index", "--no-deps", "--no-build-isolation", "--no-cache-dir",
            "--wheel-dir", str(temporary.resolve()), SOURCE_URL + "#sha256=" + SOURCE_SHA256)
        wheel = compatible_wheel(temporary, inputs)
        if len(list(temporary.iterdir())) != 1:
            raise ValueError("Unexpected build outputs; only one wheel may be cached")
        manifest = {"schema_version": 1, "inputs": inputs,
                    "wheel": {"name": wheel.name, "sha256": hashlib.sha256(wheel.read_bytes()).hexdigest()}}
        shutil.move(str(wheel), directory / wheel.name)
        (directory / MANIFEST).write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["key", "build", "validate", "install"])
    parser.add_argument("--directory", type=pathlib.Path)
    args = parser.parse_args()
    if args.command != "key" and args.directory is None:
        parser.error("--directory is required for build, validate and install")
    inputs = build_inputs()
    if args.command == "key":
        print(cache_key(inputs))
    elif args.command == "build":
        build(args.directory, inputs)
    else:
        wheel = validate(args.directory, inputs)
        if args.command == "install":
            pip("install", "--force-reinstall", "--no-user", "--no-index", "--no-deps", "--no-cache-dir", str(wheel.resolve()))


if __name__ == "__main__":
    main()
