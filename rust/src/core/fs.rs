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
#[allow(dead_code)]
pub(crate) fn batch_payload_name(
    carrier: &std::path::Path,
    recorded: &str,
    is_file: bool,
) -> String {
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

/// `desired` with ` (n)` inserted before its extension (`stem (n).ext`).
///
/// The one place the "numbered alternative" spelling is defined: the CLI batch
/// and the GUI's save path both build their candidates from it, so the two
/// cannot drift into `stem(n).ext` / `stem (n) (n).ext`.
fn numbered_name(desired: &str, n: u32) -> String {
    let split = desired
        .rfind('.')
        .filter(|&i| i > 0)
        .unwrap_or(desired.len());
    let (stem, ext) = desired.split_at(split);
    format!("{stem} ({n}){ext}")
}

/// Pick a destination under `dir` for `desired` without colliding with a file
/// already on disk.
///
/// Unlike [`unique_batch_path`], the desired name itself is checked too: the
/// GUI writes next to the carrier and must never overwrite an unrelated file
/// silently. Used by the GUI's save path for structure writes, content embeds
/// and extraction, so all of them share the numbering rule.
pub fn unique_free_path(dir: &std::path::Path, desired: &str) -> std::path::PathBuf {
    let initial = dir.join(desired);
    if !initial.exists() {
        return initial;
    }
    for n in 1u32..=9999 {
        let candidate = dir.join(numbered_name(desired, n));
        if !candidate.exists() {
            return candidate;
        }
    }
    // Every alternative is taken; fall back to the caller's choice so the
    // overwrite guard (not the namer) decides what happens next.
    initial
}

/// Pick a destination under `dir` for `desired` without colliding with an
/// output this batch already produced.
///
/// Two carriers can record the *same* payload filename; writing both to
/// `dir/name` would silently overwrite the first with `--overwrite` and abort
/// the batch without it. Generated alternatives skip paths that already exist
/// on disk as well, so a fresh name is used instead of clobbering an unrelated
/// user file. A pre-existing `desired` itself is left to `check_overwrite`,
/// which keeps the single-carrier behaviour unchanged.
#[allow(dead_code)]
pub(crate) fn unique_batch_path(
    dir: &std::path::Path,
    desired: &str,
    used: &std::collections::HashSet<std::path::PathBuf>,
) -> std::path::PathBuf {
    let initial = dir.join(desired);
    if !used.contains(&initial) {
        return initial;
    }
    let mut n = 1u32;
    loop {
        let candidate = dir.join(numbered_name(desired, n));
        if !used.contains(&candidate) && !candidate.exists() {
            return candidate;
        }
        n += 1;
    }
}

/// Render attacker-controlled text safe for a terminal.
///
/// The password hint lives in the envelope but is not covered by the header
/// AAD, so an untrusted carrier could contain escape or OSC sequences
/// (e.g. cursor movement, screen clears, OSC 52 clipboard writes).
/// Control characters become `\u{NN}` escapes; tabs are preserved.
#[allow(dead_code)]
pub(crate) fn escape_control_chars(text: &str) -> std::borrow::Cow<'_, str> {
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

/// Render attacker-controlled **payload text** safe for a terminal.
///
/// Same threat as [`escape_control_chars`], different constraint: an extracted
/// payload is usually a text document, so line breaks and tabs have to survive
/// or `extract --stdout` becomes unreadable. Everything a terminal can act on
/// (C0/C1 controls except `\n`, `\r`, `\t`, plus the bidi overrides) is escaped
/// as `\u{NN}`, which blocks `ESC [ ...` sequences and OSC 52 clipboard writes
/// without touching legitimate multi-line text.
#[allow(dead_code)]
pub(crate) fn escape_terminal_text(text: &str) -> std::borrow::Cow<'_, str> {
    use std::borrow::Cow;

    fn is_unsafe(c: char) -> bool {
        (c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
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

    #[test]
    fn numbered_names_insert_the_counter_before_the_extension() {
        assert_eq!(numbered_name("report.pdf", 2), "report (2).pdf");
        assert_eq!(numbered_name("archive.tar.gz", 1), "archive.tar (1).gz");
        // A leading dot is part of the name, not an extension.
        assert_eq!(numbered_name(".env", 1), ".env (1)");
        assert_eq!(numbered_name("README", 7), "README (7)");
    }

    #[test]
    fn free_path_skips_files_already_on_disk() {
        let dir = std::env::temp_dir().join(format!(
            "strhide-fs-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("report.pdf"), b"x").unwrap();
        std::fs::write(dir.join("report (1).pdf"), b"x").unwrap();

        assert_eq!(
            unique_free_path(&dir, "report.pdf"),
            dir.join("report (2).pdf")
        );
        assert_eq!(unique_free_path(&dir, "fresh.pdf"), dir.join("fresh.pdf"));
        assert_eq!(unique_free_path(&dir, "README"), dir.join("README"));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn payload_text_keeps_its_line_structure_but_loses_escapes() {
        // A text payload must still print as text.
        assert_eq!(
            escape_terminal_text("line one\nline two\tcol\r\nend"),
            "line one\nline two\tcol\r\nend"
        );
        // Terminal drivers do not: CSI, OSC 52 and the C1 CSI alias all die.
        assert_eq!(
            escape_terminal_text("\u{1b}[31mred\u{1b}]52;c;aGk=\u{7}"),
            "\\u{1b}[31mred\\u{1b}]52;c;aGk=\\u{7}"
        );
        assert_eq!(escape_terminal_text("\u{9b}2J"), "\\u{9b}2J");
        // Bidi overrides stay escaped, as in the hint renderer.
        assert_eq!(escape_terminal_text("a\u{202e}b"), "a\\u{202e}b");
    }
}
