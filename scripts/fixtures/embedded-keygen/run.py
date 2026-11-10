"""Extra source-native regression, never candidate or GUI release acceptance."""
import argparse, hashlib, json, os, pathlib, re, shutil, socket, subprocess, tempfile

CLIENT2 = "b41808737e2ae8bd55c1c309dfbdb41222cdf77d"
MODELS = {
 "tokenizer.json":"6710678b12670bc442b99edc952c4d996ae309a7020c1fa0096dd245c2faf790",
 "onnx/model_quantized.onnx":"0826f8c1ab9edf1801db86c61919d4d108e8bfc0b809ec823ad366882ff0b77d",
 "onnx/model_quantized.cpu-v1.ort":"7ff152e912bc234f5c90e4012f99897a7b2ce180f016db2321304057756b64ff",
}
def digest(path):
 with path.open("rb") as source: return hashlib.file_digest(source,"sha256").hexdigest()
def regular(path):
 for p in (path,*path.parents):
  assert not p.is_symlink() and not (hasattr(p,"is_junction") and p.is_junction()), "linked input"
 assert path.is_file(), "regular input required"
def main():
 parser=argparse.ArgumentParser(); parser.add_argument("--client2",type=pathlib.Path,required=True); parser.add_argument("--payload",type=pathlib.Path,required=True); parser.add_argument("--models",type=pathlib.Path,required=True); parser.add_argument("--version",required=True); parser.add_argument("--binary-file",required=True); args=parser.parse_args()
 assert subprocess.check_output(["git","-C",str(args.client2),"rev-parse","HEAD"],text=True).strip()==CLIENT2,"Client2 source mismatch"
 assert not subprocess.check_output(["git","-C",str(args.client2),"status","--porcelain"],text=True).strip(),"Client2 source dirty"
 assert re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-dev\.[0-9]+)?",args.version), "invalid source version"
 payload=args.payload.resolve(); binary="rsrs-runtime.exe" if os.name=="nt" else "rsrs-runtime"
 source_binary=args.binary_file
 assert re.fullmatch(r"rsrs-runtime(?:-[a-z0-9_-]+)?(?:\.exe)?",source_binary), "invalid binary basename"
 assert source_binary.endswith(".exe") == (os.name=="nt"), "binary platform mismatch"
 regular(payload/source_binary); regular(payload/"core-runtime.json")
 inventory=json.loads((payload/"core-runtime.json").read_text()); assert inventory["schema_version"]==1 and inventory["files"]
 seen=set()
 for entry in inventory["files"]:
  name=entry["path"]; p=pathlib.PurePosixPath(name)
  assert name not in seen and not p.is_absolute() and all(part not in (".","..") for part in p.parts) and "\\" not in name and ":" not in name
  seen.add(name); regular(payload/name); assert digest(payload/name)==entry["sha256"]
 for name,expected in MODELS.items(): regular(args.models/name); assert digest(args.models/name)==expected
 test=args.client2/"internal/host/embedded_keygen_native_test.go"; assert not test.exists()
 temp=tempfile.mkdtemp(prefix="embedded-keygen-",dir=os.environ["RUNNER_TEMP"])
 launched=False
 try:
  root=pathlib.Path(temp)/"profile"; root.mkdir(); install=root/"client2/runtime"/args.version
  shutil.copytree(payload,install)
  if source_binary != binary:
   assert not (install/binary).exists(), "duplicate Runtime image"
   (install/source_binary).rename(install/binary)
   for entry in inventory["files"]:
    if entry["path"]==source_binary: entry["path"]=binary
   (install/"core-runtime.json").write_text(json.dumps(inventory))
  (root/"client2/runtime.json").write_text(json.dumps({"version":args.version,"sha256":digest(install/binary)}))
  models=root/"models/bge-m3"
  for name in MODELS:
   destination=models/name; destination.parent.mkdir(parents=True,exist_ok=True); shutil.copyfile(args.models/name,destination)
  with socket.socket() as sock: sock.bind(("127.0.0.1",0)); port=sock.getsockname()[1]
  env={k:v for k,v in os.environ.items() if not k.upper().startswith(("RSRS_","RESP_ENV_"))}
  env.update(RSRS_DATA_DIR=str(root),RSRS_RPC_PORT=str(port),RSRS_M3_DIR=str(models),RSRS_ENGINE="cpu",RESP_ENV_EMBEDDED_NATIVE="1")
  shutil.copyfile(pathlib.Path(__file__).with_name("embedded_keygen_native_test.go"),test)
  try:
   launched=True
   subprocess.run(["go","test","./internal/host","-run","^TestSourceNativeEmbeddedKeygen$","-count=1","-timeout=5m"],cwd=args.client2,env=env,check=True,timeout=360)
  finally: test.unlink()
 finally:
  # An unconfirmed child exit is not permission to remove a live profile.
  # Leave it private for explicit cleanup; no profile is uploaded.
  if not launched or (pathlib.Path(temp)/"profile"/"native-runtime-stopped").is_file():
   shutil.rmtree(temp)
  else:
   raise RuntimeError("owned Runtime exit unconfirmed; isolated profile retained")
if __name__=="__main__": main()
