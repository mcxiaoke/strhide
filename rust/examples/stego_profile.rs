// Copyright (c) 2026 strhide developers
// SPDX-License-Identifier: Apache-2.0

//! Comprehensive step-by-step profiling tool for content-adaptive steganography.
//!
//! Evaluates and prints detailed phase-by-phase breakdown for PNG (HILL, S-UNIWARD)
//! and JPEG (UERD, J-UNIWARD) carriers under custom payloads and images.

use std::path::{Path, PathBuf};
use std::time::Instant;

use strhide::stego::format::DEFAULT_JPEG_FORMAT;
use strhide::stego::jpeg::cost::{JuniwardCostModel, UerdCostModel};
use strhide::stego::jpeg::engine::{embed_jpeg, extract_jpeg};
use strhide::stego::jpeg::geometry::geometry_for_carrier;
use strhide::stego::params::{ExtractParams, JpegParams, PngParams, StegoOptions};
use strhide::stego::png::cost::{HillCostModel, SuniwardCostModel};
use strhide::stego::png::engine::{decode_png, embed_png, encode_png, extract_png};
use strhide::stego::prng::deterministic_payload;
use strhide::stego::traits::{JpegCostModel, PngCostModel};

const DEFAULT_PAYLOAD_SIZE: usize = 65536; // 64 KiB
const DEFAULT_SEED: u64 = 42;
const DEFAULT_PASSWORD: &str = "profile-password";

struct CliArgs {
    files: Vec<PathBuf>,
    payload_size: usize,
    algo: String,
    password: String,
}

fn print_help() {
    println!(
        r#"strhide stego profiling tool - evaluate bottleneck across pipeline stages

USAGE:
    cargo run --release --example stego_profile -- [OPTIONS] [CARRIER_FILES]...

ARGS:
    <CARRIER_FILES>...    Image files to profile (PNG or JPEG). If omitted, defaults
                          to test images in temp/profile_test/

OPTIONS:
    -s, --size <SIZE>     Payload size to embed (e.g. 16k, 64k, 256k, 1m, or bytes).
                          [default: 64k]
    -a, --algo <ALGO>     Steganography distortion algorithm to profile:
                          - PNG: hill, suniward
                          - JPEG: uerd, juniward
                          - all: run all compatible algorithms for comparison [default: all]
    -p, --password <PWD>  Password for key derivation [default: "profile-password"]
    -h, --help            Print help information and exit

EXAMPLES:
    # Profile default test images with default 64 KiB payload and all algorithms
    cargo run --release --example stego_profile

    # Profile custom PNG with 128 KiB payload on both HILL and S-UNIWARD
    cargo run --release --example stego_profile -- temp/profile_test/test_large.png -s 128k

    # Profile custom JPEG specifically with J-UNIWARD algorithm and 256 KiB payload
    cargo run --release --example stego_profile -- temp/profile_test/test_large.jpg -a juniward -s 256k

    # Profile multiple files
    cargo run --release --example stego_profile -- img1.png img2.jpg -s 64k
"#
    );
}

fn parse_size(s: &str) -> Result<usize, String> {
    let clean = s.trim().to_lowercase();
    if let Some(num) = clean.strip_suffix("kb").or_else(|| clean.strip_suffix('k')) {
        let val: usize = num
            .parse()
            .map_err(|e| format!("Invalid size '{s}': {e}"))?;
        Ok(val * 1024)
    } else if let Some(num) = clean.strip_suffix("mb").or_else(|| clean.strip_suffix('m')) {
        let val: usize = num
            .parse()
            .map_err(|e| format!("Invalid size '{s}': {e}"))?;
        Ok(val * 1024 * 1024)
    } else {
        clean
            .parse::<usize>()
            .map_err(|e| format!("Invalid size '{s}': {e}"))
    }
}

fn parse_args() -> Result<Option<CliArgs>, String> {
    let mut args = std::env::args().skip(1);
    let mut files = Vec::new();
    let mut payload_size = DEFAULT_PAYLOAD_SIZE;
    let mut algo = "all".to_string();
    let mut password = DEFAULT_PASSWORD.to_string();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                print_help();
                return Ok(None);
            }
            "-s" | "--size" => {
                let val = args.next().ok_or("Missing value for --size")?;
                payload_size = parse_size(&val)?;
            }
            "-a" | "--algo" => {
                algo = args
                    .next()
                    .ok_or("Missing value for --algo")?
                    .to_lowercase();
            }
            "-p" | "--password" => {
                password = args.next().ok_or("Missing value for --password")?;
            }
            val if val.starts_with('-') => {
                return Err(format!("Unknown option '{val}'. Use -h for help."));
            }
            file => {
                files.push(PathBuf::from(file));
            }
        }
    }

    Ok(Some(CliArgs {
        files,
        payload_size,
        algo,
        password,
    }))
}

fn format_duration(dur: std::time::Duration) -> String {
    let us = dur.as_micros();
    if us < 1000 {
        format!("{us} µs")
    } else if us < 1_000_000 {
        format!("{:.2} ms", us as f64 / 1000.0)
    } else {
        format!("{:.3} s", us as f64 / 1_000_000.0)
    }
}

#[allow(clippy::too_many_arguments)]
fn profile_png_with_model(
    path: &Path,
    file_bytes: &[u8],
    image: &strhide::stego::png::engine::RawImage,
    d_decode: std::time::Duration,
    d_encode: std::time::Duration,
    payload: &[u8],
    model: &dyn PngCostModel,
    password: &str,
) {
    println!(
        "\n  >>> Algorithm: [{}] ({})",
        model.id(),
        model.description()
    );

    let png_params = PngParams::default();
    let t1 = Instant::now();
    let costs = model.compute_cost(
        &image.pixels,
        image.width as usize,
        image.height as usize,
        image.channels,
        &png_params,
    );
    let d_cost = t1.elapsed();
    println!(
        "    -> Step 2 [Cost Model: {}]: {}",
        model.id(),
        format_duration(d_cost)
    );

    let t2 = Instant::now();
    // Price a representative slot subset (green-channel pixels, every 16th):
    // direction costs are per-slot since the payload-sized working-set change.
    let slot_count = (image.width as usize * image.height as usize).div_ceil(16);
    let slots: Vec<usize> = (0..slot_count).map(|i| i * 16).collect();
    let (_plus, _minus) = model.direction_costs(
        &costs,
        &image.pixels,
        image.width as usize,
        image.height as usize,
        image.channels,
        1, // green channel
        &slots,
    );
    let d_dir = t2.elapsed();
    println!(
        "    -> Step 3 [Direction Costs]: {}",
        format_duration(d_dir)
    );

    let options = StegoOptions {
        password: Some(password.into()),
        ..Default::default()
    };
    let t4 = Instant::now();
    let stego_png = match embed_png(
        file_bytes,
        payload,
        options.password.as_deref(),
        options.domain.as_deref(),
        &strhide::stego::format::OFFICIAL_PNG_FORMAT,
        model,
        &options.png_params,
        strhide::stego::SafetyPolicy::default(),
        options.freshness,
    ) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("    [!] Embed failed with algorithm '{}': {e}", model.id());
            return;
        }
    };
    let d_total_embed = t4.elapsed();

    println!(
        "    ==> [Full Spatial Embed Total]: {}",
        format_duration(d_total_embed)
    );
    println!(
        "        Breakdown: Decode={:.1}%, Cost={:.1}%, DirCosts={:.1}%, Encode={:.1}%, Coding/Sort={:.1}%",
        d_decode.as_secs_f64() / d_total_embed.as_secs_f64() * 100.0,
        d_cost.as_secs_f64() / d_total_embed.as_secs_f64() * 100.0,
        d_dir.as_secs_f64() / d_total_embed.as_secs_f64() * 100.0,
        d_encode.as_secs_f64() / d_total_embed.as_secs_f64() * 100.0,
        (d_total_embed.as_secs_f64()
            - d_decode.as_secs_f64()
            - d_cost.as_secs_f64()
            - d_dir.as_secs_f64()
            - d_encode.as_secs_f64())
        .max(0.0)
            / d_total_embed.as_secs_f64()
            * 100.0
    );

    let t5 = Instant::now();
    let extracted = match extract_png(
        &stego_png,
        options.password.as_deref(),
        options.domain.as_deref(),
        &strhide::stego::format::OFFICIAL_PNG_FORMAT,
        model,
        &options.png_params,
    ) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!(
                "    [!] Extract failed with algorithm '{}': {e}",
                model.id()
            );
            return;
        }
    };
    let d_total_extract = t5.elapsed();
    assert_eq!(
        extracted,
        payload,
        "Payload verification failed for {}!",
        path.display()
    );
    println!(
        "    ==> [Full Spatial Extract Total]: {}",
        format_duration(d_total_extract)
    );
    println!(
        "        Note (PNG Extract requires re-evaluating cost map): Cost={:.1}%, Decode={:.1}%, Other={:.1}%",
        d_cost.as_secs_f64() / d_total_extract.as_secs_f64() * 100.0,
        d_decode.as_secs_f64() / d_total_extract.as_secs_f64() * 100.0,
        (d_total_extract.as_secs_f64() - d_cost.as_secs_f64() - d_decode.as_secs_f64()).max(0.0)
            / d_total_extract.as_secs_f64()
            * 100.0
    );
}

fn profile_png(path: &Path, payload: &[u8], algo: &str, password: &str) {
    println!("\n=======================================================");
    println!(" [PNG Profile] File: {}", path.display());
    println!("=======================================================");

    let file_bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Failed to read {}: {e}", path.display());
            return;
        }
    };
    println!("File size: {:.2} MB", file_bytes.len() as f64 / 1_048_576.0);
    println!(
        "Payload size: {:.2} KB ({} bytes)",
        payload.len() as f64 / 1024.0,
        payload.len()
    );

    let t0 = Instant::now();
    let image = match decode_png(&file_bytes) {
        Ok(img) => img,
        Err(e) => {
            eprintln!("PNG decode failed: {e}");
            return;
        }
    };
    let d_decode = t0.elapsed();
    let total_pixels = image.width as usize * image.height as usize;
    println!(
        "Image resolution: {}x{} ({} channels, {:.2} MPixels)",
        image.width,
        image.height,
        image.channels,
        total_pixels as f64 / 1_000_000.0
    );
    println!(
        "  -> Step 1 [Decode PNG + Filter]: {}",
        format_duration(d_decode)
    );

    let t3 = Instant::now();
    let _re_encoded = encode_png(&image).unwrap();
    let d_encode = t3.elapsed();
    println!(
        "  -> Step 4 [Re-encode PNG + Deflate]: {}",
        format_duration(d_encode)
    );

    let hill = HillCostModel;
    let suniward = SuniwardCostModel;

    let models: Vec<&dyn PngCostModel> = match algo {
        "hill" => vec![&hill],
        "suniward" => vec![&suniward],
        _ => vec![&hill, &suniward],
    };

    for model in models {
        profile_png_with_model(
            path,
            &file_bytes,
            &image,
            d_decode,
            d_encode,
            payload,
            model,
            password,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn profile_jpeg_with_model(
    path: &Path,
    file_bytes: &[u8],
    coeffs: &dct_io::JpegCoefficients,
    geometry: &strhide::stego::traits::JpegGeometry,
    d_read_dct: std::time::Duration,
    d_write_dct: std::time::Duration,
    payload: &[u8],
    model: &dyn JpegCostModel,
    password: &str,
) {
    println!(
        "\n  >>> Algorithm: [{}] ({})",
        model.id(),
        model.description()
    );

    let jpeg_params = JpegParams::default();
    let t2 = Instant::now();
    let _costs = model.compute_cost(coeffs, geometry, &jpeg_params);
    let d_cost = t2.elapsed();
    println!(
        "    -> Step 3 [Cost Model: {}]: {}",
        model.id(),
        format_duration(d_cost)
    );

    let options = StegoOptions {
        password: Some(password.into()),
        ..Default::default()
    };
    let t4 = Instant::now();
    let stego_jpg = match embed_jpeg(
        file_bytes,
        payload,
        options.password.as_deref(),
        options.domain.as_deref(),
        &DEFAULT_JPEG_FORMAT,
        &options.jpeg_params,
        strhide::stego::SafetyPolicy::default(),
        model,
        options.freshness,
    ) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("    [!] Embed failed with algorithm '{}': {e}", model.id());
            return;
        }
    };
    let d_total_embed = t4.elapsed();

    println!(
        "    ==> [Full JPEG Embed Total]: {}",
        format_duration(d_total_embed)
    );
    println!(
        "        Breakdown: ReadCoeffs={:.1}%, Cost={:.1}%, WriteCoeffs={:.1}%, STC/KDF/Perm={:.1}%",
        d_read_dct.as_secs_f64() / d_total_embed.as_secs_f64() * 100.0,
        d_cost.as_secs_f64() / d_total_embed.as_secs_f64() * 100.0,
        d_write_dct.as_secs_f64() / d_total_embed.as_secs_f64() * 100.0,
        (d_total_embed.as_secs_f64()
            - d_read_dct.as_secs_f64()
            - d_cost.as_secs_f64()
            - d_write_dct.as_secs_f64())
        .max(0.0)
            / d_total_embed.as_secs_f64()
            * 100.0
    );

    let t5 = Instant::now();
    let extracted = match extract_jpeg(
        &stego_jpg,
        options.password.as_deref(),
        options.domain.as_deref(),
        &DEFAULT_JPEG_FORMAT,
        &ExtractParams::default(),
    ) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!(
                "    [!] Extract failed with algorithm '{}': {e}",
                model.id()
            );
            return;
        }
    };
    let d_total_extract = t5.elapsed();
    assert_eq!(
        extracted,
        payload,
        "Payload verification failed for {}!",
        path.display()
    );
    println!(
        "    ==> [Full JPEG Extract Total]: {}",
        format_duration(d_total_extract)
    );
    println!(
        "        Note (JPEG Extract requires NO cost evaluation): ReadCoeffs={:.1}%, STC/PBKDF2/Dec={:.1}%",
        d_read_dct.as_secs_f64() / d_total_extract.as_secs_f64() * 100.0,
        (d_total_extract.as_secs_f64() - d_read_dct.as_secs_f64()).max(0.0)
            / d_total_extract.as_secs_f64()
            * 100.0
    );
}

fn profile_jpeg(path: &Path, payload: &[u8], algo: &str, password: &str) {
    println!("\n=======================================================");
    println!(" [JPEG Profile] File: {}", path.display());
    println!("=======================================================");

    let file_bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Failed to read {}: {e}", path.display());
            return;
        }
    };
    println!("File size: {:.2} MB", file_bytes.len() as f64 / 1_048_576.0);
    println!(
        "Payload size: {:.2} KB ({} bytes)",
        payload.len() as f64 / 1024.0,
        payload.len()
    );

    let t0 = Instant::now();
    let coeffs = match dct_io::read_coefficients(&file_bytes) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("dct_io read failed: {e}");
            return;
        }
    };
    let d_read_dct = t0.elapsed();
    let block_count = coeffs
        .components
        .first()
        .map(|c| c.blocks.len())
        .unwrap_or(0);
    println!(
        "DCT Components: {}, Y-Blocks: {} ({:.2} MPixels equivalent)",
        coeffs.components.len(),
        block_count,
        (block_count * 64) as f64 / 1_000_000.0
    );
    println!(
        "  -> Step 1 [dct_io Read Coefficients]: {}",
        format_duration(d_read_dct)
    );

    let t1 = Instant::now();
    let geometry = match geometry_for_carrier(&file_bytes, 0, block_count) {
        Ok(g) => g,
        Err(e) => {
            eprintln!("Geometry failed: {e}");
            return;
        }
    };
    let d_geom = t1.elapsed();
    println!(
        "  -> Step 2 [Geometry Analysis]: {}",
        format_duration(d_geom)
    );

    let t3 = Instant::now();
    let _re_written = match dct_io::write_coefficients(&file_bytes, &coeffs) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("dct_io write failed: {e}");
            return;
        }
    };
    let d_write_dct = t3.elapsed();
    println!(
        "  -> Step 4 [dct_io Write Coefficients]: {}",
        format_duration(d_write_dct)
    );

    let uerd = UerdCostModel;
    let juniward = JuniwardCostModel;

    let models: Vec<&dyn JpegCostModel> = match algo {
        "uerd" => vec![&uerd],
        "juniward" => vec![&juniward],
        _ => vec![&uerd, &juniward],
    };

    for model in models {
        profile_jpeg_with_model(
            path,
            &file_bytes,
            &coeffs,
            &geometry,
            d_read_dct,
            d_write_dct,
            payload,
            model,
            password,
        );
    }
}

fn main() {
    let args = match parse_args() {
        Ok(Some(a)) => a,
        Ok(None) => return,
        Err(e) => {
            eprintln!("Error: {e}\n");
            print_help();
            std::process::exit(1);
        }
    };

    let payload = deterministic_payload(args.payload_size, DEFAULT_SEED);

    let target_files = if !args.files.is_empty() {
        args.files
    } else {
        let defaults = [
            PathBuf::from("temp/profile_test/test_large.png"),
            PathBuf::from("temp/profile_test/test_large.jpg"),
        ];
        defaults.into_iter().filter(|p| p.exists()).collect()
    };

    if target_files.is_empty() {
        eprintln!("No carrier images found or specified. Run with -h for help.");
        std::process::exit(1);
    }

    println!("=======================================================");
    println!(" Stego Performance Profiler");
    println!(
        " Payload Size: {:.2} KB ({} bytes)",
        payload.len() as f64 / 1024.0,
        payload.len()
    );
    println!(" Target Algorithm Filter: {}", args.algo);
    println!(" Target Files: {}", target_files.len());
    println!("=======================================================");

    for file in &target_files {
        let ext = file
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();
        if ext == "png" {
            profile_png(file, &payload, &args.algo, &args.password);
        } else if ext == "jpg" || ext == "jpeg" {
            profile_jpeg(file, &payload, &args.algo, &args.password);
        } else {
            eprintln!("Skipping unsupported file extension: {}", file.display());
        }
    }
}
