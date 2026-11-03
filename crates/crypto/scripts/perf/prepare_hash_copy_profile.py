"""Extract the exact baseline/candidate hash functions into an isolated microbenchmark.
Run from repository root: python scripts/perf/prepare_hash_copy_profile.py OUTPUT_DIR BASE_COMMIT
Compile generated .rs files using rustc and the same built sha2 dependency for both.
"""
import pathlib, subprocess, sys
root=pathlib.Path(sys.argv[1]).resolve(); root.mkdir(parents=True,exist_ok=True)
base=sys.argv[2]
harness='''use std::{io::Read,path::Path,time::Instant}; use sha2::{Digest,Sha256};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    let path = args.get(1).ok_or("missing executable path")?;
    let count = args.get(2).ok_or("missing repeat count")?.parse::<usize>()?;
    let mut values = Vec::new();
    for _ in 0..count {
        let start = Instant::now();
        let first = file_sha256(Path::new(path))?;
        let second = file_sha256(Path::new(path))?;
        assert_eq!(first, second);
        std::hint::black_box(first);
        values.push(start.elapsed().as_secs_f64() * 1000.);
    }
    println!("{:?}", values);
    println!("{}", std::fs::read_to_string("/proc/self/status")?);
    println!("{}", std::fs::read_to_string("/proc/self/smaps_rollup")?);
    Ok(())
}
'''
for variant,source in [('baseline',subprocess.check_output(['git','show',f'{base}:cli/src/mcp.rs'],text=True)),('candidate',pathlib.Path('cli/src/mcp.rs').read_text())]:
    body=source[source.index('fn file_sha256('):source.index('\nfn tools()')]
    (root/f'hash-{variant}.rs').write_text(harness+body)
