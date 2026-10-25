// Copyright (c) 2026 strhide developers
// SPDX-License-Identifier: Apache-2.0

use strhide::errors::StrHideError;
use strhide::stego::{StegoOptions, embed_carrier, extract_carrier};

#[test]
fn test_heif_bridge_unsupported_carrier_fails_gracefully() {
    // Synthetic minimal HEIF container without any bridgeable item (ftyp + free)
    let mut stub = Vec::new();
    stub.extend_from_slice(&24u32.to_be_bytes());
    stub.extend_from_slice(b"ftypheic");
    stub.extend_from_slice(&0u32.to_be_bytes());
    stub.extend_from_slice(b"mif1heic");
    stub.extend_from_slice(&8u32.to_be_bytes());
    stub.extend_from_slice(b"free");

    let payload = b"test payload";
    let opts = StegoOptions::default();
    let res = embed_carrier(&stub, payload, &opts);
    assert!(
        matches!(res, Err(StrHideError::UnsupportedFormat(_))),
        "HEIF with no bridgeable thumbnail must return UnsupportedFormat, got {:?}",
        res
    );

    let ext_res = extract_carrier(&stub, &opts);
    assert!(
        matches!(ext_res, Err(StrHideError::NoHiddenData(_))),
        "Extracting from HEIF with no bridgeable thumbnail must return NoHiddenData, got {:?}",
        ext_res
    );
}
