//! Unit and integration tests for security rejection pre-checks
//! (ported from Python `test_rejection.py`).

use std::io::Cursor;
use strhide::rejection::{
    check_jar_signature, check_pdf_signature, check_pe_authenticode, check_signature_file,
    check_unsupported_apk,
};

#[test]
fn test_signature_file_extension() {
    assert!(check_signature_file(Some("test.sig")).is_some());
    assert!(check_signature_file(Some("release.asc")).is_some());
    assert!(check_signature_file(Some("cert.p7s")).is_some());
    assert!(check_signature_file(Some("cert.p7b")).is_some());
    assert!(check_signature_file(Some("test.png")).is_none());
    assert!(check_signature_file(Some("document.pdf")).is_none());
    assert!(check_signature_file(None).is_none());
}

#[test]
fn test_apk_rejection() {
    assert!(check_unsupported_apk(Some("app.apk")).is_some());
    assert!(check_unsupported_apk(Some("APP.APK")).is_some());
    assert!(check_unsupported_apk(Some("app.zip")).is_none());
    assert!(check_unsupported_apk(None).is_none());
}

#[test]
fn test_pdf_signed_rejection() {
    // 1. Clean unsigned PDF
    let clean_pdf = b"%PDF-1.4\n1 0 obj\n<< /Title (Clean Test) >>\nendobj\n%%EOF\n";
    let mut clean_cursor = Cursor::new(clean_pdf.to_vec());
    assert!(check_pdf_signature(&mut clean_cursor).unwrap().is_none());

    // 2. Signed PDF with /ByteRange and /Type /Sig
    let signed_pdf =
        b"%PDF-1.4\n1 0 obj\n<< /Type /Sig /ByteRange [0 100 200 300] >>\nendobj\n%%EOF\n";
    let mut signed_cursor = Cursor::new(signed_pdf.to_vec());
    let sig_err = check_pdf_signature(&mut signed_cursor).unwrap();
    assert!(sig_err.is_some());
    assert!(sig_err.unwrap().contains("signature"));

    // 3. Not a PDF
    let not_pdf = b"NOT A PDF DOCUMENT AT ALL";
    let mut not_pdf_cursor = Cursor::new(not_pdf.to_vec());
    assert!(check_pdf_signature(&mut not_pdf_cursor).unwrap().is_none());
}

#[test]
fn test_pe_authenticode_rejection() {
    // Synthetic PE with Authenticode
    // MZ at 0, e_lfanew at 0x3C
    let mut buf = vec![0u8; 1024];
    buf[0..2].copy_from_slice(b"MZ");
    let e_lfanew = 0x80u32;
    buf[0x3C..0x40].copy_from_slice(&e_lfanew.to_le_bytes());

    // PE Header at 0x80
    let pe_off = e_lfanew as usize;
    buf[pe_off..pe_off + 4].copy_from_slice(b"PE\0\0");

    // COFF Header (20 bytes)
    // SizeOfOptionalHeader at +16
    buf[pe_off + 20..pe_off + 22].copy_from_slice(&240u16.to_le_bytes());

    // Optional Header at pe_off + 24
    let opt_off = pe_off + 24;
    // Magic 0x20B (PE32+)
    buf[opt_off..opt_off + 2].copy_from_slice(&0x20Bu16.to_le_bytes());

    // For PE32+, Security directory is at opt_off + 144
    let sec_offset = opt_off + 144;
    let virt_addr = 0x1000u32;
    let size = 0x200u32;
    buf[sec_offset..sec_offset + 4].copy_from_slice(&virt_addr.to_le_bytes());
    buf[sec_offset + 4..sec_offset + 8].copy_from_slice(&size.to_le_bytes());

    let mut stream = Cursor::new(buf.clone());
    let pe_err = check_pe_authenticode(&mut stream).unwrap();
    assert!(pe_err.is_some());
    assert!(pe_err.unwrap().contains("Authenticode"));

    // Zero out security directory -> should pass clean
    buf[sec_offset..sec_offset + 8].copy_from_slice(&[0u8; 8]);
    let mut clean_stream = Cursor::new(buf);
    assert!(check_pe_authenticode(&mut clean_stream).unwrap().is_none());
}

#[test]
fn test_jar_signature_rejection() {
    // Synthetic clean ZIP (no META-INF signatures)
    let clean_zip = make_zip_archive(&[("content.txt", b"regular text")]);
    let mut clean_cursor = Cursor::new(clean_zip);
    assert!(
        check_jar_signature(&mut clean_cursor, Some("archive.zip"))
            .unwrap()
            .is_none()
    );

    // Synthetic signed JAR with META-INF/SIGN.SF
    let signed_jar = make_zip_archive(&[
        ("content.txt", b"regular text"),
        ("META-INF/SIGN.SF", b"Signature-Version: 1.0"),
    ]);
    let mut signed_cursor = Cursor::new(signed_jar);
    let jar_err = check_jar_signature(&mut signed_cursor, Some("app.jar")).unwrap();
    assert!(jar_err.is_some());
    assert!(jar_err.unwrap().contains("signature"));
}

fn make_zip_archive(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut cd = Vec::new();

    for (name, data) in entries {
        let crc = crc32fast::hash(data);
        let local_off = out.len() as u32;

        out.extend_from_slice(b"PK\x03\x04");
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(data);

        cd.extend_from_slice(b"PK\x01\x02");
        cd.extend_from_slice(&20u16.to_le_bytes());
        cd.extend_from_slice(&20u16.to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&crc.to_le_bytes());
        cd.extend_from_slice(&(data.len() as u32).to_le_bytes());
        cd.extend_from_slice(&(data.len() as u32).to_le_bytes());
        cd.extend_from_slice(&(name.len() as u16).to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&0u32.to_le_bytes());
        cd.extend_from_slice(&local_off.to_le_bytes());
        cd.extend_from_slice(name.as_bytes());
    }

    let cd_off = out.len() as u32;
    let cd_size = cd.len() as u32;
    out.extend_from_slice(&cd);

    out.extend_from_slice(b"PK\x05\x06");
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&cd_size.to_le_bytes());
    out.extend_from_slice(&cd_off.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}
