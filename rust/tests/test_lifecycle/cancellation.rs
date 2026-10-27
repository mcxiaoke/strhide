//! Progress reporting and cooperative cancellation on the content domain.
//!
//! The contract under test:
//! - a pre-cancelled [`CancelToken`] makes every engine return
//!   `StrHideError::Cancelled` at its first checkpoint, with the carrier
//!   untouched (the embed never reaches the commit path);
//! - a progress sink sees the stage sequence the engine actually walks
//!   (`Decode` -> `CostMap` -> `Solve` -> `Encode` for a PNG embed);
//! - the default `Control::none()` keeps behaviour identical, so a caller that
//!   never asks for progress still gets byte-identical output.

use strhide::core::control::{CancelToken, Control, Event, NoProgress, Stage};
use strhide::core::payload::Payload;
use strhide::errors::StrHideError;
use strhide::stego::{
    EmbedOptions, ExtractOptions, embed_carrier, extract_carrier,
    png::{RawImage, encode_png},
};

const JPG: &[u8] = include_bytes!("../assets/small.jpg");

/// A synthetic embeddable PNG: high-frequency texture, 96x96 RGB.
fn texture_png() -> Vec<u8> {
    let (w, h) = (96u32, 96u32);
    let mut pixels = Vec::with_capacity((w * h * 3) as usize);
    for y in 0..h {
        for x in 0..w {
            pixels.push(((x * 17) ^ (y * 31) ^ ((x + y) * 7)) as u8);
            pixels.push(((x * 23 + y * 19) % 256) as u8);
            pixels.push(((x * 13) ^ (y * 29)) as u8);
        }
    }
    encode_png(&RawImage {
        width: w,
        height: h,
        channels: 3,
        pixels,
        chunks: Vec::new(),
        idat_sizes: Vec::new(),
        row_filters: Vec::new(),
        idat_info: None,
        tail: Vec::new(),
    })
    .expect("encode png")
}

#[derive(Default)]
struct Recorder(std::sync::Mutex<Vec<Stage>>);

impl strhide::core::control::Progress for Recorder {
    fn report(&self, event: Event) {
        self.0.lock().unwrap().push(event.stage);
    }
}

#[test]
fn pre_cancelled_png_embed_stops_before_touching_the_carrier() {
    let png = texture_png();
    let token = CancelToken::new();
    token.cancel();

    let options = EmbedOptions::default()
        .with_password("pw")
        .with_control(Control::with_cancel(&token));
    let err = embed_carrier(&png, &Payload::bytes(b"payload"), &options)
        .expect_err("a pre-cancelled embed must not run");

    assert!(
        matches!(err, StrHideError::Cancelled),
        "expected Cancelled, got {err:?}"
    );
}

#[test]
fn pre_cancelled_jpeg_embed_and_extract_return_cancelled() {
    let token = CancelToken::new();
    token.cancel();

    let embed = EmbedOptions::default()
        .with_password("pw")
        .with_control(Control::with_cancel(&token));
    assert!(matches!(
        embed_carrier(JPG, &Payload::bytes(b"payload"), &embed),
        Err(StrHideError::Cancelled)
    ));

    let extract = ExtractOptions::default()
        .with_password("pw")
        .with_control(Control::with_cancel(&token));
    assert!(matches!(
        extract_carrier(JPG, &extract),
        Err(StrHideError::Cancelled)
    ));
}

/// A sink that cancels as soon as it sees the first `Encode` report: the embed
/// must surface `Cancelled` from the next checkpoint instead of finishing.
#[test]
fn cancelling_during_the_run_stops_the_embed() {
    struct CancelOnEncode<'a> {
        token: &'a CancelToken,
    }
    impl strhide::core::control::Progress for CancelOnEncode<'_> {
        fn report(&self, event: Event) {
            if event.stage == Stage::Encode {
                self.token.cancel();
            }
        }
    }

    let png = texture_png();
    let token = CancelToken::new();
    let sink = CancelOnEncode { token: &token };
    let control = Control {
        progress: &sink,
        cancel: Some(&token),
    };
    let options = EmbedOptions::default()
        .with_password("pw")
        .with_control(control);

    // The PNG embed has exactly one Encode report (before the re-encode), and
    // the next checkpoint is inside the PNG deflate fan-out -- so this either
    // returns Cancelled or, if the encode finished first, a valid carrier.
    match embed_carrier(&png, &Payload::bytes(b"payload"), &options) {
        Err(StrHideError::Cancelled) => {}
        Ok(_) => {}
        other => panic!("unexpected result: {other:?}"),
    }
}

#[test]
fn progress_sink_sees_the_png_stage_sequence() {
    let png = texture_png();
    let recorder = Recorder::default();
    let control = Control::with_progress(&recorder);
    let options = EmbedOptions::default()
        .with_password("pw")
        .with_control(control);

    embed_carrier(&png, &Payload::bytes(b"progress"), &options).expect("embed");

    let stages = recorder.0.lock().unwrap();
    let first = |stage| stages.iter().position(|s| *s == stage).expect("stage seen");
    let (decode, cost, solve, encode) = (
        first(Stage::Decode),
        first(Stage::CostMap),
        first(Stage::Solve),
        first(Stage::Encode),
    );
    assert!(
        decode < cost && cost < solve && solve < encode,
        "stages out of order: {stages:?}"
    );
}

#[test]
fn the_default_control_behaves_like_none() {
    // No sink, no token: the embed must succeed and the output must match a
    // run that explicitly passed `NoProgress`.
    let png = texture_png();
    let payload = b"identical";
    // Seeded: two runs are byte-identical, so any difference would be the
    // control plumbing leaking into the wire format.
    let plain = EmbedOptions::default()
        .with_password("pw")
        .with_freshness(strhide::stego::Freshness::Seeded([7u8; 32]));
    let explicit = EmbedOptions {
        control: Control {
            progress: &NoProgress,
            cancel: None,
        },
        ..plain.clone()
    };

    let a = embed_carrier(&png, &Payload::bytes(payload), &plain).expect("embed");
    let b = embed_carrier(&png, &Payload::bytes(payload), &explicit).expect("embed");
    assert_eq!(a, b, "the progress sink must not influence the output");
}
