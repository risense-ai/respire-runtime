"""Share the pinned CPU container between disposable CI profiles only."""
import hashlib
from pathlib import Path
import shutil

CPU_NAME = "model_quantized.cpu-v1.ort"
CPU_SIZE = 569654128
CPU_SHA256 = "7ff152e912bc234f5c90e4012f99897a7b2ce180f016db2321304057756b64ff"


def share_cpu_container(root, env, model):
    root, model = Path(root).resolve(), Path(model).resolve()
    if model == root or not model.is_relative_to(root):
        raise RuntimeError("shared_model_must_be_owned_fixture_child")
    source = Path(env["RSRS_DATA_DIR"]) / "models/bge-m3/onnx" / CPU_NAME
    destination = model / "onnx" / CPU_NAME
    if not source.resolve().is_relative_to(root):
        raise RuntimeError("cpu_cache_must_be_owned_fixture_child")
    def verified(path):
        if path.is_symlink() or not path.is_file() or path.stat().st_size != CPU_SIZE:
            return False
        with path.open("rb") as stream:
            return hashlib.file_digest(stream, "sha256").hexdigest() == CPU_SHA256
    if verified(destination):
        return
    if not verified(source):
        raise RuntimeError("installed_cpu_container_missing_or_corrupt")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() or destination.is_symlink():
        raise RuntimeError("shared_cpu_container_destination_not_fresh")
    shutil.copyfile(source, destination)
    if not verified(destination):
        raise RuntimeError("shared_cpu_container_hash_mismatch")
