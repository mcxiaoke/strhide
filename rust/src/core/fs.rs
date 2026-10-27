//! Small filesystem helpers shared by both domains.
//!
//! Nothing here knows about carriers or formats: these are the path and naming
//! rules that every "write a payload somewhere" path must apply, including the
//! content domain's `extract_file` and the CLI.

/// Sanitize an untrusted metadata filename down to a safe bare file name.
///
/// Envelope metadata (especially in unencrypted envelopes) is attacker-controlled
/// input: `../../etc/passwd` style values must never escape the output directory.
/// Only the final path component is kept; empty results and `.`/`..` fall back to
/// "extracted.bin".
///
/// Both `/` and `\` are treated as separators on every platform: an envelope may
/// be written on one OS and read on another, so the sanitized name must not depend
/// on the host's path rules (a Windows-style name read on Unix would otherwise
/// keep its backslashes verbatim). Names carrying a `:` (drive prefix like `C:`) are
/// rejected as well, so they cannot turn into uncreatable files on Windows.
pub fn sanitize_filename(name: &str) -> String {
    let candidate = name.rsplit(['/', '\\']).find(|seg| !seg.is_empty());
    match candidate {
        Some(n) if n != "." && n != ".." && !n.contains(':') => n.to_string(),
        _ => "extracted.bin".to_string(),
    }
}

/// Output name for one carrier of a batch whose payload recorded no filename.
///
/// Deriving from the *carrier* is what makes `read a.png b.png -o out/` write
/// two distinct files instead of colliding on `extracted.bin` (and then
/// silently overwriting the first with the second).
pub fn batch_payload_name(carrier: &std::path::Path, recorded: &str, is_file: bool) -> String {
    if !recorded.is_empty() {
        return sanitize_filename(recorded);
    }
    let stem = carrier
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("extracted");
    let stem = sanitize_filename(stem);
    let ext = if is_file { "bin" } else { "txt" };
    format!("{stem}.{ext}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_plain_names() {
        assert_eq!(sanitize_filename("report.pdf"), "report.pdf");
        assert_eq!(sanitize_filename("a b.txt"), "a b.txt");
    }

    #[test]
    fn strips_every_kind_of_traversal() {
        assert_eq!(sanitize_filename("../../etc/passwd"), "passwd");
        assert_eq!(sanitize_filename(r"..\..\windows\system32\x.dll"), "x.dll");
        assert_eq!(sanitize_filename("/absolute/path/name.bin"), "name.bin");
        assert_eq!(sanitize_filename("dir/"), "dir");
    }

    #[test]
    fn batch_names_prefer_the_recorded_filename() {
        let carrier = std::path::Path::new("dir/photo.png");
        assert_eq!(
            batch_payload_name(carrier, "secret.pdf", true),
            "secret.pdf"
        );
        assert_eq!(
            batch_payload_name(carrier, "../../etc/passwd", true),
            "passwd",
            "the recorded name is still untrusted"
        );
        assert_eq!(
            batch_payload_name(carrier, "", true),
            "photo.bin",
            "an unnamed binary payload is named after its carrier"
        );
        assert_eq!(batch_payload_name(carrier, "", false), "photo.txt");
    }

    #[test]
    fn rejects_dot_names_and_drive_prefixes() {
        assert_eq!(sanitize_filename("."), "extracted.bin");
        assert_eq!(sanitize_filename(".."), "extracted.bin");
        assert_eq!(sanitize_filename(""), "extracted.bin");
        assert_eq!(sanitize_filename("C:evil.txt"), "extracted.bin");
    }
}
