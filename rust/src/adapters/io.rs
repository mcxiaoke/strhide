//! I/O helper routines shared across host adapters.

use crate::errors::StrHideError;
use std::io::{Read, Seek, SeekFrom, Write};

const BUFFER_SIZE: usize = 64 * 1024;

/// Copy exactly `count` bytes from `reader` to `writer`.
///
/// Returns `Err(StrHideError::CorruptedData)` if `reader` reaches EOF before `count` bytes are read.
pub fn copy_exact<R: Read + ?Sized, W: Write + ?Sized>(
    reader: &mut R,
    writer: &mut W,
    count: u64,
) -> Result<(), StrHideError> {
    let mut remaining = count;
    let mut buf = [0u8; BUFFER_SIZE];
    while remaining > 0 {
        let to_read = std::cmp::min(remaining, buf.len() as u64) as usize;
        let n = reader.read(&mut buf[..to_read])?;
        if n == 0 {
            return Err(StrHideError::CorruptedData(
                "Unexpected EOF while copying stream".into(),
            ));
        }
        writer.write_all(&buf[..n])?;
        remaining -= n as u64;
    }
    Ok(())
}

/// Copy from `reader` to `writer` until EOF, returning the total bytes copied.
pub fn copy_stream<R: Read + ?Sized, W: Write + ?Sized>(
    reader: &mut R,
    writer: &mut W,
) -> Result<u64, StrHideError> {
    let mut buf = [0u8; BUFFER_SIZE];
    let mut total = 0u64;
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        writer.write_all(&buf[..n])?;
        total += n as u64;
    }
    Ok(total)
}

/// Execute a closure `f` with `reader` and restore `reader`'s stream position upon completion.
pub fn with_restored_position<R: Seek + ?Sized, T, F>(
    reader: &mut R,
    f: F,
) -> Result<T, StrHideError>
where
    F: FnOnce(&mut R) -> Result<T, StrHideError>,
{
    let pos = reader.stream_position()?;
    let res = f(reader);
    let _ = reader.seek(SeekFrom::Start(pos));
    res
}
