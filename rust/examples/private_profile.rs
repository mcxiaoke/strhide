// Copyright (c) 2026 strhide developers
// SPDX-License-Identifier: Apache-2.0

//! A private dialect: carriers only *your* deployment can read.
//!
//! ```text
//! cargo run --example private_profile
//! ```
//!
//! With no password, the envelope key and the header-slot permutation come from
//! constants that live in this source tree, so every strhide build can read a
//! no-password carrier. [`Profile`] replaces those constants:
//!
//! | knob | what it changes |
//! |---|---|
//! | `default_secret` | the structure-domain envelope key used when no password is given |
//! | `stealth_domain` | the HKDF domain of the password-derived stealth magics |
//! | `magic` | the standard header/trailer magics (this removes the "looks like a strhide file" signature) |
//! | `stego.default_secret` | the content-domain (image) no-password secret |
//!
//! The compatibility rule is all-or-nothing and worth stating plainly: two ends
//! with the **same** profile interoperate; a private profile and the official
//! one **must not** — and the failure is indistinguishable from a wrong
//! password, because a distinguishable error would tell an attacker that an
//! envelope exists but the dialect is wrong.

use strhide::errors::StrHideError;
use strhide::params::{LocalParams, MagicPair, Profile};
use strhide::structure::{PayloadSource, WriteOptions, read_carrier_bytes, write_carrier_bytes};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cover = std::fs::read("rust/tests/assets/minimal.png")
        .or_else(|_| std::fs::read("tests/assets/minimal.png"))?;

    // Application-specific magics: the first eight bytes no longer read
    // "\x89STRHIDE", so a scanner that greps for the public signature finds
    // nothing. Trailer magic is four bytes.
    //
    // The whole dialect is declared `const` (zero runtime cost) because every
    // field is a `'static` borrow.
    const PRIVATE: Profile = Profile::new()
        .with_default_secret("acme-deployment-envelope-key-2026")
        .with_stealth_domain(b"acme-stealth-domain-v1")
        .with_magic(MagicPair {
            header: *b"\xAC\x4D\x45\x00\x01\x02\x03\x04",
            trailer: *b"\xAC\x4D\x54\x01",
        })
        .with_stego_secret("acme-image-stego-key-2026");

    let (stego, _) = write_carrier_bytes(
        &cover,
        PayloadSource::Bytes(b"intended for acme only"),
        &WriteOptions::default(),
        &LocalParams::default(),
        &PRIVATE,
    )?;

    // Same profile: works.
    let read = read_carrier_bytes(&stego, None, &PRIVATE)?;
    assert_eq!(read.data, b"intended for acme only");
    println!("private profile read back {} bytes", read.data.len());

    // Official profile: must fail, and must fail as "nothing here" rather than
    // as "an envelope is here but you used the wrong dialect".
    match read_carrier_bytes(&stego, None, &Profile::default()) {
        Ok(_) => println!("UNEXPECTED: the official profile read a private carrier"),
        Err(e @ StrHideError::NoHiddenData(_)) => {
            println!("official profile correctly reports no data: {e}");
        }
        Err(e) => println!("official profile failed as expected, but differently: {e}"),
    }

    Ok(())
}
