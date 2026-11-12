use super::*;
use crate::structure::adapters::HostAdapter;
use crate::structure::envelope::{STANDARD_TRAILER_MAGIC, TRAILER_SIZE};
use std::io::Cursor;

/// Classic PDF with `/Size 2` and `/Root`: the smallest carrier the
/// incremental strategy accepts.
fn minimal_pdf() -> Vec<u8> {
    minimal_pdf_with_size(2)
}

/// Minimal classic PDF whose `/Size` (i.e. next object number) is `size`.
fn minimal_pdf_with_size(size: u64) -> Vec<u8> {
    format!(
        "%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n\
             xref\n0 2\n0000000000 65535 f \n0000000009 00000 n \n\
             trailer\n<< /Size {size} /Root 1 0 R >>\nstartxref\n9\n%%EOF\n"
    )
    .into_bytes()
}

/// Full UBE (payload + trailer) for `payload_len` bytes of body.
fn ube_of(payload_len: usize, ube_offset: u64) -> Vec<u8> {
    let mut ube = vec![0x7Bu8; payload_len];
    let total = payload_len as u64 + TRAILER_SIZE as u64;
    ube.extend_from_slice(
        &EnvelopeTrailer::create(ube_offset, total, STANDARD_TRAILER_MAGIC).pack(),
    );
    ube
}

/// `calc_prefix_len` is the writer's own offset accounting: it must equal
/// the number of bytes `inject` writes between `%%EOF` and the envelope,
/// for every payload length (the `/Length` digits change the width).
#[test]
fn calc_prefix_len_matches_the_injected_offset() {
    for payload_len in [0usize, 1, 9, 10, 99, 100, 9_999, 10_000, 123_456] {
        let host = minimal_pdf();
        let ube = ube_of(payload_len, 0); // offset ignored by the carrier
        let ube_size = ube.len() as u64;

        let prefix = PdfAdapter::calc_prefix_len(&mut Cursor::new(&host), ube_size).unwrap();
        assert_eq!(
            prefix,
            pdf_obj_header(2, ube_size).len() as u64,
            "prefix must be the object header for /Size 2 and {ube_size} bytes"
        );

        let mut out = Vec::new();
        let InjectCoordinates {
            offset: inject_offset,
            size: inject_size,
            ..
        } = PdfAdapter
            .inject(
                &mut Cursor::new(host.clone()),
                &mut Cursor::new(ube.clone()),
                &mut out,
                "incremental",
            )
            .unwrap();

        assert_eq!(inject_offset, host.len() as u64);
        assert_eq!(
            &out[inject_offset as usize..(inject_offset + prefix) as usize],
            pdf_obj_header(2, ube_size).as_bytes(),
            "bytes before the envelope must be exactly the object header"
        );
        assert_eq!(
            &out[(inject_offset + prefix) as usize..(inject_offset + prefix) as usize + ube.len()],
            &ube[..],
            "envelope must start at inject_offset + calc_prefix_len"
        );
        assert!(
            out[(inject_offset + prefix + ube_size) as usize..]
                .starts_with(b"\nendstream\nendobj\n"),
            "the envelope stream must be closed right after the envelope bytes"
        );
        assert_eq!(
            inject_size,
            (out.len() as u64) - inject_offset,
            "inject_size must cover the object, the xref section and the new trailer"
        );
    }
}

/// A 10-digit object number plus a 9-digit `/Length` makes the incremental
/// object header 65 bytes, which the old 64-byte limit could not record.
/// `MAX_OFFSET_DELTA` is 128 now, so the reachable worst case fits and auto
/// must pick the lossless-in-place strategy instead of the EOF overlay.
///
/// The template is `46 + digits(N) + digits(L)`; both inputs are `u64`, so
/// no parseable PDF can produce a header longer than 86 bytes. Asserting
/// that keeps the limit and the template from drifting apart again.
#[test]
fn ten_digit_object_numbers_fit_the_recordable_shift() {
    let host = minimal_pdf_with_size(1_000_000_001);
    let mut cursor = Cursor::new(&host);
    assert_eq!(
        PdfAdapter.choose_auto_strategy(&mut cursor, 100_000_000),
        "incremental",
        "65 bytes of shift must be recordable under MAX_OFFSET_DELTA = 128"
    );

    let worst = pdf_obj_header(u64::MAX, u64::MAX);
    assert!(
        worst.len() <= crate::structure::envelope::MAX_OFFSET_DELTA as usize,
        "the longest representable object header is {} bytes, over the {}-byte limit",
        worst.len(),
        crate::structure::envelope::MAX_OFFSET_DELTA
    );
}

/// Two consecutive incremental updates: the second carrier's `/Size` has
/// grown, so its object number (and therefore the prefix length) changes.
/// Reading back the first envelope must still work afterwards.
#[test]
fn prefix_len_follows_successive_incremental_updates() {
    let host = minimal_pdf();
    let mut prev = host.clone();

    for round in 0..2 {
        let expected_obj = 2 + round as u64;
        let ube = ube_of(64, 0);
        let ube_size = ube.len() as u64;

        let prefix = PdfAdapter::calc_prefix_len(&mut Cursor::new(&prev), ube_size).unwrap();
        assert_eq!(
            prefix,
            pdf_obj_header(expected_obj, ube_size).len() as u64,
            "round {round}: next object number must follow /Size"
        );

        let mut out = Vec::new();
        let InjectCoordinates {
            offset: inject_offset,
            ..
        } = PdfAdapter
            .inject(
                &mut Cursor::new(prev.clone()),
                &mut Cursor::new(ube.clone()),
                &mut out,
                "incremental",
            )
            .unwrap();
        assert_eq!(
            &out[(inject_offset + prefix) as usize..(inject_offset + prefix) as usize + ube.len()],
            &ube[..],
            "round {round}: envelope offset drifted"
        );
        assert!(
            out.windows(9)
                .any(|w| w == format!("\n{expected_obj} 0 obj\n").as_bytes()),
            "round {round}: injected object number missing"
        );

        // The newest trailer must still declare a /Root and a larger /Size.
        let info = parse_pdf_trailer_info(&mut Cursor::new(out.clone())).unwrap();
        assert_eq!(info.new_obj_num, expected_obj + 1);
        prev = out;
    }
}

/// PDF 1.5+ XRef-stream document whose compressed stream data is larger than
/// the 64 KiB tail window.
///
/// The window then holds nothing but stream bytes, so neither
/// `trailer << /Size >>` nor the `N G obj` scan can find the next object
/// number: the only place it exists is the XRef stream dictionary at
/// `startxref`. Deriving it from the tail instead under-reports (objects
/// inside an object stream never appear as `N G obj`), which makes the
/// incremental update collide with an existing object.
#[test]
fn xref_stream_size_comes_from_the_stream_dictionary() {
    let mut pdf = Vec::new();
    pdf.extend_from_slice(
        b"%PDF-1.5
",
    );
    for obj in [
        "1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
",
        "2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
",
        "3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>
endobj
",
    ] {
        pdf.extend_from_slice(obj.as_bytes());
    }
    let xref_obj_offset = pdf.len() as u64;
    // A dictionary whose compressed payload is far larger than the tail
    // window: the window ends up holding stream bytes only.
    let dict = "<< /Length 70000 /Type /XRef /Root 1 0 R /Size 10 /W [1 2 1] >>";
    pdf.extend_from_slice(
        format!(
            "4 0 obj
{dict}
stream
"
        )
        .as_bytes(),
    );
    pdf.extend_from_slice(&[0u8; 70_000]);
    pdf.extend_from_slice(
        b"
endstream
endobj
",
    );
    pdf.extend_from_slice(
        format!(
            "startxref
{xref_obj_offset}
%%EOF
"
        )
        .as_bytes(),
    );

    let info = parse_pdf_tail_info(&mut Cursor::new(pdf.clone())).expect("must parse");
    assert_eq!(info.prev_startxref, xref_obj_offset);
    assert_eq!(
        info.new_obj_num,
        Some(10),
        "/Size from the XRef stream dictionary is the next object number"
    );
    assert_eq!(info.root_ref.as_deref(), Some("1 0 R"));

    // ...and the writer can therefore name a free object.
    assert_eq!(
        PdfAdapter::calc_prefix_len(&mut Cursor::new(pdf), 88).unwrap(),
        pdf_obj_header(10, 88).len() as u64
    );
}

#[test]
fn classic_trailer_still_wins_over_the_xref_stream_scan() {
    // A hybrid document whose newest section is a classic table: an older
    // XRef stream sits in the tail window, but /Size must come from the
    // trailer that follows the table `startxref` points at.
    let mut pdf = Vec::new();
    pdf.extend_from_slice(
        b"%PDF-1.4
1 0 obj
<< /Type /Catalog >>
endobj
",
    );
    pdf.extend_from_slice(
        b"2 0 obj
<< /Length 4 /Type /XRef /Size 3 >>
stream
0000
endstream
endobj
",
    );
    let classic_xref_offset = pdf.len() as u64;
    pdf.extend_from_slice(
        b"xref
0 2
0000000000 65535 f 
0000000009 00000 n 
trailer
<< /Size 7 /Root 1 0 R >>
",
    );
    pdf.extend_from_slice(
        format!(
            "startxref
{classic_xref_offset}
%%EOF
"
        )
        .as_bytes(),
    );

    let info = parse_pdf_tail_info(&mut Cursor::new(pdf)).expect("must parse");
    assert_eq!(info.new_obj_num, Some(7));
    assert_eq!(info.root_ref.as_deref(), Some("1 0 R"));
    assert!(!info.uses_xref_stream);
}

/// Revision 1 is a classic `xref`/`trailer` document, revision 2 replaces
/// Verifies that incremental updates on XRef-stream documents ignore earlier classic trailers.
#[test]
fn xref_stream_revision_ignores_the_earlier_classic_trailer() {
    let mut pdf = Vec::new();
    pdf.extend_from_slice(
        b"%PDF-1.4
1 0 obj
<< /Type /Catalog >>
endobj
",
    );
    let rev1_xref = pdf.len() as u64;
    pdf.extend_from_slice(
        format!(
            "xref
0 2
0000000000 65535 f 
0000000009 00000 n 
trailer
<< /Size 2 /Root 1 0 R >>
startxref
{rev1_xref}
%%EOF
"
        )
        .as_bytes(),
    );
    let rev2_xref = pdf.len() as u64;
    pdf.extend_from_slice(
        b"2 0 obj
<< /Type /XRef /Root 1 0 R /Size 3 /Length 7 >>
stream
",
    );
    pdf.extend_from_slice(&[1u8, 0, 0, 0, 0, 0, 0]);
    pdf.extend_from_slice(
        format!(
            "
endstream
endobj
startxref
{rev2_xref}
%%EOF
"
        )
        .as_bytes(),
    );

    let info = parse_pdf_tail_info(&mut Cursor::new(pdf.clone())).expect("must parse");
    assert_eq!(
        info.new_obj_num,
        Some(3),
        "the XRef stream's /Size must win over the stale rev-1 trailer"
    );
    assert!(info.uses_xref_stream);

    let original_len = pdf.len();
    let ube = ube_of(32, 0);
    let mut out = Vec::new();
    PdfAdapter
        .inject(
            &mut Cursor::new(pdf),
            &mut Cursor::new(ube),
            &mut out,
            "incremental",
        )
        .unwrap();
    let tail = &out[original_len..];
    assert!(
        tail.windows(9).any(|w| w == b"\n3 0 obj\n"),
        "the envelope object must take /Size 3, not the colliding rev-1 value"
    );
    assert!(
        tail.windows(11).any(|w| w == b"/Type /XRef"),
        "an XRef-stream revision must receive an XRef-stream update"
    );
    assert!(
        !tail.windows(6).any(|w| w == b"\nxref\n"),
        "a classic xref table must not be appended to an XRef-stream revision"
    );
}

#[test]
fn parse_pdf_tail_info_with_trailer_comment_after_startxref() {
    let pdf_data = b"%PDF-1.7\n\
1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n\
2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n\
trailer\n\
<< /Size 4 /Root 1 0 R >>\n\
startxref\n\
9\n\
% appended comment mentioning trailer written here\n\
%%EOF\n";
    let mut cur = Cursor::new(pdf_data.to_vec());
    let info = parse_pdf_tail_info(&mut cur).expect("must not panic and succeed");
    assert_eq!(info.new_obj_num, Some(4));
    assert_eq!(info.root_ref.as_deref(), Some("1 0 R"));
}

#[test]
fn test_balanced_dict_end_edge_cases() {
    // 1. Basic nested dict
    let text1 = "1 0 obj << /Type /XRef /DecodeParms << /Columns 5 >> /Size 10 >> stream";
    let end1 = balanced_dict_end(text1).unwrap();
    assert_eq!(
        &text1[..end1],
        "1 0 obj << /Type /XRef /DecodeParms << /Columns 5 >> /Size 10 >>"
    );

    // 2. Dict containing string with unbalanced >>
    let text2 = "<< /Title (Chapter 1 >> Intro) /Size 20 >> tail";
    let end2 = balanced_dict_end(text2).unwrap();
    assert_eq!(&text2[..end2], "<< /Title (Chapter 1 >> Intro) /Size 20 >>");

    // 3. Dict containing escaped parentheses in string
    let text3 = r"<< /Title (Nested \( >> \) paren) /Root 1 0 R >>";
    let end3 = balanced_dict_end(text3).unwrap();
    assert_eq!(&text3[..end3], text3);

    // 4. Dict containing comment with >>
    let text4 = "<< /Size 5\n% Comment with >> marker\n/Root 2 0 R\n>>";
    let end4 = balanced_dict_end(text4).unwrap();
    assert_eq!(&text4[..end4], text4);

    // 5. Malformed text without <<
    assert_eq!(balanced_dict_end("no dictionary here"), None);

    // 6. Malformed text with premature unclosed <<
    assert_eq!(balanced_dict_end("<< /Size 5 /Root 1 0 R"), None);

    // 7. Extra >> before << should not cause underflow or panic
    let text7 = ">> >> << /Size 1 >>";
    let end7 = balanced_dict_end(text7).unwrap();
    assert_eq!(&text7[..end7], ">> >> << /Size 1 >>");
}
