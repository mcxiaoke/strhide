// Copyright (c) 2026 strhide developers
// SPDX-License-Identifier: Apache-2.0

//! Embed and extract without touching the filesystem.
//!
//! ```text
//! cargo run --example in_memory
//! ```
//!
//! The `*_carrier_bytes` entry points take a carrier as `&[u8]` and return the
//! stego image as `Vec<u8>`. That is the shape a web handler or a microservice
//! needs: an upload arrives as bytes, the answer leaves as bytes, and no
//! temporary file is ever created (which also removes the temp-dir permission
//! and cleanup problems that come with one).
//!
//! What is **not** provided, and why:
//!
//! - no atomic commit — you own the buffer, so there is no half-written state;
//! - no `<carrier>.bak` — the original bytes are still in `cover`;
//! - no timestamp cloning — there is no inode to stamp.
//!
//! The envelope format, the AEAD path and the self-verification are the same
//! code as the file API, so a carrier written in memory is readable from disk
//! and vice versa.

use strhide::params::{LocalParams, Profile};
use strhide::structure::{
    PayloadSource, WriteOptions, read_carrier_bytes, remove_carrier_bytes, write_carrier_bytes,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Pretend this came from an HTTP upload.
    let cover = std::fs::read("rust/tests/assets/minimal.png")
        .or_else(|_| std::fs::read("tests/assets/minimal.png"))?;
    let secret_message = b"the payload can just as well be a ZIP or a JSON blob";

    let options = WriteOptions {
        password: Some("correct horse battery staple"),
        ..WriteOptions::default()
    };

    let (stego, wrote) = write_carrier_bytes(
        &cover,
        PayloadSource::Bytes(secret_message),
        &options,
        &LocalParams::default(),
        &Profile::default(),
    )?;
    println!(
        "embedded {} bytes of payload into a {}-byte envelope ({} -> {} carrier bytes, strategy {})",
        wrote.raw_size,
        wrote.ube_size,
        cover.len(),
        stego.len(),
        wrote.strategy
    );

    // Extraction never needs the write-time options, only the password: the
    // profile is a read/write-must-agree parameter, the rest travels inside.
    let read = read_carrier_bytes(&stego, options.password, &Profile::default())?;
    assert_eq!(read.data, secret_message);
    println!(
        "recovered {} bytes (filename '{}', encrypted: {})",
        read.data.len(),
        read.filename,
        read.is_encrypted
    );

    // The inverse operation proves it was lossless: the restored bytes must be
    // identical to the cover that went in.
    let (restored, removed) = remove_carrier_bytes(&stego, options.password, &Profile::default())?;
    assert_eq!(restored, cover, "restore must be bit-for-bit");
    println!(
        "removed the envelope, verified identical: {} ({} bytes)",
        removed.verified_identical, removed.restored_size
    );

    Ok(())
}
