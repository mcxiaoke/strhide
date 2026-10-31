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
    let Some(n) = candidate else {
        return FALLBACK_NAME.to_string();
    };
    if n == "." || n == ".." || n.contains(':') {
        return FALLBACK_NAME.to_string();
    }

    // Terminal escape sequences and other control bytes must not reach a log
    // line or a file name; Windows also rejects these characters outright.
    let mut cleaned: String = n
        .chars()
        .map(|c| {
            if c.is_control() || matches!(c, '<' | '>' | '"' | '|' | '?' | '*') {
                '_'
            } else {
                c
            }
        })
        .collect();

    // Windows silently drops trailing dots and spaces, which lets two distinct
    // names collide on disk; strip them on every platform so the result does
    // not depend on the host.
    while cleaned.ends_with('.') || cleaned.ends_with(' ') {
        cleaned.pop();
    }
    if cleaned.is_empty() || cleaned == "." || cleaned == ".." {
        return FALLBACK_NAME.to_string();
    }

    // `CON`, `NUL`, `COM1`... are device names, not files, on Windows.
    let stem = cleaned.split('.').next().unwrap_or(&cleaned);
    if is_windows_reserved_device(stem) {
        cleaned.insert(0, '_');
    }
    cleaned
}

pub(crate) const FALLBACK_NAME: &str = "extracted.bin";

fn is_windows_reserved_device(stem: &str) -> bool {
    let upper = stem.to_ascii_uppercase();
    if matches!(upper.as_str(), "CON" | "PRN" | "AUX" | "NUL") {
        return true;
    }
    for prefix in ["COM", "LPT"] {
        if let Some(digit) = upper.strip_prefix(prefix) {
            return matches!(digit, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9");
        }
    }
    false
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

/// Render attacker-controlled text safe for a terminal.
///
/// The password hint lives in the envelope but is *not* covered by the header
/// AAD, so a crafted carrier can put `ESC [ ...` or OSC sequences in it and
/// have the CLI print them verbatim: cursor movement, screen wipes, even an
/// OSC 52 clipboard write (review R3 P2-2). Control characters become `\u{NN}`
/// escapes; a tab survives because it cannot drive a terminal.
pub fn escape_control_chars(text: &str) -> std::borrow::Cow<'_, str> {
    use std::borrow::Cow;

    fn is_unsafe(c: char) -> bool {
        (c.is_control() && c != '\t')
            || matches!(
                c,
                '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
            )
    }

    if !text.chars().any(is_unsafe) {
        return Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len() + 8);
    for c in text.chars() {
        if is_unsafe(c) {
            use std::fmt::Write;
            // Writing into a String cannot fail.
            let _ = write!(out, "\\u{{{:x}}}", c as u32);
        } else {
            out.push(c);
        }
    }
    Cow::Owned(out)
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

    #[test]
    fn neutralises_control_bytes_and_windows_special_names() {
        // A terminal escape sequence must not survive into logs or file names.
        assert_eq!(sanitize_filename("evil\x1b[31m.txt"), "evil_[31m.txt");
        assert_eq!(sanitize_filename("a\nb.txt"), "a_b.txt");
        // Windows-rejected characters become underscores.
        assert_eq!(sanitize_filename("a<b>c?.txt"), "a_b_c_.txt");
        // Trailing dots/spaces would be silently dropped by Windows otherwise.
        assert_eq!(sanitize_filename("evil. "), "evil");
        // Reserved device names are prefixed instead of rejected outright.
        assert_eq!(sanitize_filename("CON.txt"), "_CON.txt");
        assert_eq!(sanitize_filename("com1.bin"), "_com1.bin");
        assert_eq!(sanitize_filename("LPT9"), "_LPT9");
        assert_eq!(
            sanitize_filename("COM0.txt"),
            "COM0.txt",
            "COM0 is not a device name"
        );
        assert_eq!(sanitize_filename("\u{7}"), "_");
    }

    #[test]
    fn escapes_terminal_control_sequences() {
        assert_eq!(escape_control_chars("plain hint"), "plain hint");
        assert_eq!(
            escape_control_chars("evil\u{1b}[31mred"),
            "evil\\u{1b}[31mred"
        );
        // Tabs cannot drive a terminal, so they survive.
        assert_eq!(escape_control_chars("a\tb"), "a\tb");
        // A right-to-left override is a formatting control, not `is_control()`.
        assert_eq!(escape_control_chars("\u{202e}gpj.exe"), "\\u{202e}gpj.exe");
    }
}
