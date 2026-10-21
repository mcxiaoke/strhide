use crate::adapters::{HostAdapter, SeekRead, SeekWrite, StrategyCapacity};
use crate::envelope::{EnvelopeHeader, EnvelopeTrailer};
use crate::errors::StrHideError;
use std::io::{SeekFrom, Write};

pub struct EofAdapter;

impl HostAdapter for EofAdapter {
    fn format_name(&self) -> &'static str {
        "GENERIC"
    }

    fn detect(&self, _reader: &mut dyn SeekRead) -> bool {
        true
    }

    fn supported_strategies(&self) -> Vec<&'static str> {
        vec!["eof"]
    }

    fn choose_auto_strategy(&self, _reader: &mut dyn SeekRead, _ube_size: u64) -> &'static str {
        "eof"
    }

    fn strategy_capacities(&self, _reader: Option<&mut dyn SeekRead>) -> Vec<StrategyCapacity> {
        vec![StrategyCapacity {
            strategy: "eof".into(),
            capacity_bytes: None,
            available: true,
            limit: "unlimited (file grows)".into(),
            note: Some("appended at file EOF".into()),
        }]
    }

    fn inject(
        &self,
        host_in: &mut dyn SeekRead,
        ube_in: &mut dyn SeekRead,
        out: &mut dyn Write,
        strategy: &str,
    ) -> Result<(u64, u64, u32, u32), StrHideError> {
        if strategy != "eof" {
            return Err(StrHideError::UnsupportedFormat(format!(
                "Strategy '{strategy}' not supported by EOF adapter"
            )));
        }

        host_in.seek(SeekFrom::Start(0))?;
        let host_len = crate::adapters::io::copy_stream(host_in, out)?;

        let inject_offset = host_len;
        ube_in.seek(SeekFrom::Start(0))?;
        let ube_len = crate::adapters::io::copy_stream(ube_in, out)?;

        Ok((inject_offset, ube_len, 0, 0))
    }

    fn locate(
        &self,
        stego_in: &mut dyn SeekRead,
        expected_trailer_magic: Option<&[u8; 4]>,
    ) -> Result<Option<(u64, u64, String)>, StrHideError> {
        let trailer = match EnvelopeTrailer::read_from_tail(stego_in, expected_trailer_magic)? {
            Some(t) => t,
            None => return Ok(None),
        };

        let file_size = stego_in.seek(SeekFrom::End(0))?;
        if trailer.ube_offset.checked_add(trailer.ube_total_size) == Some(file_size) {
            Ok(Some((
                trailer.ube_offset,
                trailer.ube_total_size,
                "eof".into(),
            )))
        } else {
            Ok(None)
        }
    }

    fn strip(
        &self,
        stego_in: &mut dyn SeekRead,
        out: &mut dyn SeekWrite,
        header: &EnvelopeHeader,
    ) -> Result<(), StrHideError> {
        stego_in.seek(SeekFrom::Start(0))?;
        crate::adapters::io::copy_exact(stego_in, out, header.orig_host_size)?;
        Ok(())
    }

    fn verify_structure(
        &self,
        stego_in: &mut dyn SeekRead,
    ) -> Result<(bool, String), StrHideError> {
        let file_size = stego_in.seek(SeekFrom::End(0))?;
        let trailer = match EnvelopeTrailer::read_from_tail(stego_in, None)? {
            Some(t) => t,
            None => return Ok((false, "Locator trailer not found at end of file".into())),
        };

        if trailer.ube_offset.checked_add(trailer.ube_total_size) != Some(file_size) {
            return Ok((
                false,
                format!(
                    "Trailer boundary mismatch: offset({}) + size({}) != total({})",
                    trailer.ube_offset, trailer.ube_total_size, file_size
                ),
            ));
        }

        Ok((true, "EOF envelope structure verified successfully".into()))
    }
}
