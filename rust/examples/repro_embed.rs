//! Embed one deterministic payload into one carrier and print the digest.
//!
//! Everything that could vary is pinned: the salt and nonce come from a seed,
//! and the payload comes from the same seed, so two runs on the same build
//! produce byte-identical output. Useful when a bug only shows up "sometimes".
//!
//! ```text
//! cargo run --release --example repro_embed -- cover.jpg
//! cargo run --release --example repro_embed -- cover.jpg --bytes 65536 --seed 7
//! cargo run --release --example repro_embed -- cover.jpg --algo juniward --out out.jpg
//! ```

use std::process::ExitCode;

use sha2::{Digest, Sha256};
use strhide::core::payload::Payload;
use strhide::stego::prng::deterministic_payload;
use strhide::stego::{
    EmbedOptions, ExtractOptions, Freshness, HevcMode, JpegAlgorithm, SpatialAlgorithm,
    StegoTuning, embed_carrier, extract_carrier,
};

const DEFAULT_BYTES: usize = 1024;
const DEFAULT_SEED: u64 = 1;

struct Args {
    carrier: String,
    bytes: usize,
    seed: u64,
    algorithm: Option<String>,
    password: Option<String>,
    out: Option<String>,
}

fn parse_args() -> Result<Args, String> {
    let mut it = std::env::args().skip(1);
    let mut carrier = None;
    let mut bytes = DEFAULT_BYTES;
    let mut seed = DEFAULT_SEED;
    let mut algorithm = None;
    let mut password = None;
    let mut out = None;

    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--bytes" => {
                bytes = it
                    .next()
                    .ok_or("--bytes needs a value")?
                    .parse()
                    .map_err(|_| "--bytes must be a number")?;
            }
            "--seed" => {
                seed = it
                    .next()
                    .ok_or("--seed needs a value")?
                    .parse()
                    .map_err(|_| "--seed must be a number")?;
            }
            "--algo" => algorithm = Some(it.next().ok_or("--algo needs a value")?),
            "--password" => password = Some(it.next().ok_or("--password needs a value")?),
            "--out" => out = Some(it.next().ok_or("--out needs a value")?),
            "-h" | "--help" => return Err("help".into()),
            other => carrier = Some(other.to_string()),
        }
    }

    Ok(Args {
        carrier: carrier.ok_or("missing carrier path")?,
        bytes,
        seed,
        algorithm,
        password,
        out,
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

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) if e == "help" => {
            println!(
                "usage: repro_embed <carrier> [--bytes N] [--seed N] [--algo NAME] \
                 [--password P] [--out FILE]"
            );
            return ExitCode::SUCCESS;
        }
        Err(e) => {
            eprintln!("repro_embed: {e}");
            return ExitCode::FAILURE;
        }
    };

    let carrier = match std::fs::read(&args.carrier) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("repro_embed: cannot read {}: {e}", args.carrier);
            return ExitCode::FAILURE;
        }
    };

    let payload = deterministic_payload(args.bytes, args.seed);

    let tuning = match tuning_for(args.algorithm.as_deref()) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("repro_embed: {e}");
            return ExitCode::FAILURE;
        }
    };
    let options = EmbedOptions {
        password: args.password.as_deref(),
        tuning,
        freshness: Freshness::Seeded(seed_bytes(args.seed)),
        ..Default::default()
    };

    let stego = match embed_carrier(&carrier, &Payload::bytes(&payload), &options) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("repro_embed: embed failed: {e}");
            return ExitCode::FAILURE;
        }
    };

    // Round-trip immediately: a reproducible digest of the wrong payload is
    // worse than no digest at all.
    let read_options = ExtractOptions {
        password: args.password.as_deref(),
        ..Default::default()
    };
    match extract_carrier(&stego, &read_options) {
        Ok(back) if back == payload => {}
        Ok(_) => {
            eprintln!("repro_embed: extracted payload does not match");
            return ExitCode::FAILURE;
        }
        Err(e) => {
            eprintln!("repro_embed: extract failed: {e}");
            return ExitCode::FAILURE;
        }
    }

    println!("carrier   {}", args.carrier);
    println!("algorithm {}", args.algorithm.as_deref().unwrap_or("auto"));
    println!("payload   {} bytes (seed {})", args.bytes, args.seed);
    println!("stego     {} bytes", stego.len());
    println!("sha256    {}", digest(&stego));

    if let Some(path) = args.out {
        if let Err(e) = std::fs::write(&path, &stego) {
            eprintln!("repro_embed: cannot write {path}: {e}");
            return ExitCode::FAILURE;
        }
        println!("written   {path}");
    }

    ExitCode::SUCCESS
}

/// Map `--algo` onto a typed tuning arm.
///
/// The name already says which format's model it is, so the carrier does not
/// have to be sniffed first; a mismatched carrier is rejected by the engine.
fn tuning_for(algorithm: Option<&str>) -> Result<StegoTuning, String> {
    let Some(name) = algorithm else {
        return Ok(StegoTuning::Auto);
    };
    let name = name.trim();
    if name == "auto" {
        return Ok(StegoTuning::Auto);
    }
    if let Some(model) = SpatialAlgorithm::from_name(name) {
        return Ok(StegoTuning::Png {
            model,
            params: Default::default(),
        });
    }
    if let Some(model) = JpegAlgorithm::from_name(name) {
        return Ok(StegoTuning::Jpeg {
            model,
            params: Default::default(),
        });
    }
    if let Some(mode) = HevcMode::from_name(name) {
        return Ok(StegoTuning::hevc(mode));
    }
    Err(format!("unknown algorithm '{name}'"))
}

/// Spread the 64-bit seed over 32 bytes so every seed maps to a distinct key.
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
