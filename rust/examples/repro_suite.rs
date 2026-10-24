//! Fingerprint a carrier matrix and compare against a stored baseline.
//!
//! Sweeps every image in a directory over a set of payload sizes and
//! algorithms, all in reproducible mode, and records `sha256` + size per case.
//! The baseline is a JSON file that can be committed or attached to a bug
//! report: `--check` then tells you exactly which cases drifted.
//!
//! ```text
//! cargo run --release --example repro_suite -- temp/testhighres --out baseline.json
//! cargo run --release --example repro_suite -- temp/testhighres --check baseline.json
//! cargo run --release --example repro_suite -- temp/testhighres --algo juniward --sizes 1024
//! ```

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use sha2::{Digest, Sha256};
use strhide::stego::prng::deterministic_payload;
use strhide::stego::{Freshness, StegoOptions, embed_carrier};

const DEFAULT_SIZES: &[usize] = &[512, 1024, 16384, 65536];
const DEFAULT_ALGOS: &[&str] = &["uerd", "juniward"];
const DEFAULT_SEED: u64 = 1;

struct Args {
    dir: PathBuf,
    out: Option<PathBuf>,
    check: Option<PathBuf>,
    sizes: Vec<usize>,
    algos: Vec<String>,
    seed: u64,
}

fn parse_args() -> Result<Args, String> {
    let mut it = std::env::args().skip(1);
    let mut dir = None;
    let mut out = None;
    let mut check = None;
    let mut sizes = DEFAULT_SIZES.to_vec();
    let mut algos: Vec<String> = DEFAULT_ALGOS.iter().map(|s| s.to_string()).collect();
    let mut seed = DEFAULT_SEED;

    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--out" => out = Some(PathBuf::from(it.next().ok_or("--out needs a path")?)),
            "--check" => check = Some(PathBuf::from(it.next().ok_or("--check needs a path")?)),
            "--sizes" => {
                let raw = it.next().ok_or("--sizes needs a comma-separated list")?;
                sizes = raw
                    .split(',')
                    .map(|s| s.trim().parse::<usize>())
                    .collect::<Result<_, _>>()
                    .map_err(|_| "--sizes must be comma-separated numbers")?;
            }
            "--algo" => {
                let raw = it.next().ok_or("--algo needs a comma-separated list")?;
                algos = raw.split(',').map(|s| s.trim().to_string()).collect();
            }
            "--seed" => {
                seed = it
                    .next()
                    .ok_or("--seed needs a value")?
                    .parse()
                    .map_err(|_| "--seed must be a number")?;
            }
            "-h" | "--help" => return Err("help".into()),
            other => dir = Some(PathBuf::from(other)),
        }
    }

    Ok(Args {
        dir: dir.ok_or("missing carrier directory")?,
        out,
        check,
        sizes,
        algos,
        seed,
    })
}

fn digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn seed_bytes(seed: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, chunk) in out.chunks_mut(8).enumerate() {
        let v = seed
            .wrapping_mul(0x9E37_79B9_7F4A_7C15)
            .wrapping_add(i as u64);
        chunk.copy_from_slice(&v.to_le_bytes());
    }
    out
}

fn jpeg_carriers(dir: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return found;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let is_jpeg = path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| matches!(e.to_ascii_lowercase().as_str(), "jpg" | "jpeg"));
        if is_jpeg {
            found.push(path);
        }
    }
    found.sort();
    found
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) if e == "help" => {
            println!(
                "usage: repro_suite <carrier-dir> [--out FILE] [--check FILE] \
                 [--sizes 512,1024] [--algo uerd,juniward] [--seed N]"
            );
            return ExitCode::SUCCESS;
        }
        Err(e) => {
            eprintln!("repro_suite: {e}");
            return ExitCode::FAILURE;
        }
    };

    let carriers = jpeg_carriers(&args.dir);
    if carriers.is_empty() {
        eprintln!("repro_suite: no JPEG carriers in {}", args.dir.display());
        return ExitCode::FAILURE;
    }

    let seed = seed_bytes(args.seed);
    let mut rows: BTreeMap<String, (usize, String)> = BTreeMap::new();

    for carrier in &carriers {
        let bytes = match std::fs::read(carrier) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("repro_suite: skip {}: {e}", carrier.display());
                continue;
            }
        };
        let name = carrier
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("carrier")
            .to_string();

        for algo in &args.algos {
            for &len in &args.sizes {
                let options = StegoOptions {
                    algorithm: Some(algo.clone()),
                    freshness: Freshness::Seeded(seed),
                    ..Default::default()
                };
                let payload = deterministic_payload(len, args.seed);
                match embed_carrier(&bytes, &payload, &options) {
                    Ok(stego) => {
                        let key = format!("{name}|{algo}|{len}");
                        rows.insert(key, (stego.len(), digest(&stego)));
                    }
                    Err(e) => eprintln!("repro_suite: {name} {algo} {len}: {e}"),
                }
            }
        }
    }

    let mut json = String::from("{\n");
    json.push_str(&format!(
        "  \"strhide\": \"{}\",\n  \"git\": \"{}\",\n  \"seed\": {},\n  \"cases\": [\n",
        env!("CARGO_PKG_VERSION"),
        env!("STRHIDE_GIT_HASH"),
        args.seed
    ));
    let total = rows.len();
    for (i, (key, (bytes, sha))) in rows.iter().enumerate() {
        let comma = if i + 1 == total { "" } else { "," };
        json.push_str(&format!(
            "    {{ \"case\": \"{key}\", \"bytes\": {bytes}, \"sha256\": \"{sha}\" }}{comma}\n"
        ));
    }
    json.push_str("  ]\n}\n");

    if let Some(path) = &args.out {
        if let Err(e) = std::fs::write(path, &json) {
            eprintln!("repro_suite: cannot write {}: {e}", path.display());
            return ExitCode::FAILURE;
        }
        println!("wrote {} cases to {}", total, path.display());
    }

    match &args.check {
        Some(path) => {
            let baseline = match std::fs::read_to_string(path) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("repro_suite: cannot read {}: {e}", path.display());
                    return ExitCode::FAILURE;
                }
            };
            let expected = parse_cases(&baseline);
            let mut drifted = 0usize;
            for (key, (bytes, sha)) in rows.iter() {
                match expected.get(key) {
                    Some((want_bytes, want_sha)) => {
                        if want_bytes != bytes || want_sha != sha {
                            drifted += 1;
                            println!("DRIFT {key}");
                            println!("  baseline {want_bytes} bytes {want_sha}");
                            println!("  now      {bytes} bytes {sha}");
                        }
                    }
                    None => println!("NEW   {key}"),
                }
            }
            for key in expected.keys() {
                if !rows.contains_key(key) {
                    println!("GONE  {key}");
                }
            }
            println!("{} cases, {drifted} drifted", rows.len());
            if drifted > 0 {
                return ExitCode::FAILURE;
            }
        }
        None => {
            // With `--out` the digest already landed in the file; printing it
            // again just makes the terminal scroll.
            if args.out.is_none() {
                println!("{json}");
            }
        }
    }

    ExitCode::SUCCESS
}

/// Minimal reader for the shape this tool writes: `"case": ..., "bytes": ...,
/// "sha256": "..."` per line. Kept dependency-free on purpose so the baseline
/// stays hand-editable.
fn parse_cases(json: &str) -> BTreeMap<String, (usize, String)> {
    let mut out = BTreeMap::new();
    for line in json.lines() {
        let Some(case) = field(line, "\"case\": \"") else {
            continue;
        };
        let Some(bytes) = field(line, "\"bytes\": ") else {
            continue;
        };
        let Some(sha) = field(line, "\"sha256\": \"") else {
            continue;
        };
        if let Ok(n) = bytes.trim_end_matches(',').parse::<usize>() {
            out.insert(case.to_string(), (n, sha.to_string()));
        }
    }
    out
}

fn field<'a>(line: &'a str, marker: &str) -> Option<&'a str> {
    let start = line.find(marker)? + marker.len();
    let rest = &line[start..];
    let end = rest.find(['"', ',']).unwrap_or(rest.len());
    Some(rest[..end].trim())
}
