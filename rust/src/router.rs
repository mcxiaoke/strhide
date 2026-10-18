//! Format sniffing and strategy routing module.

use crate::adapters::{
    HostAdapter, SeekRead, eof::EofAdapter, jpeg::JpegAdapter, mp4::Mp4Adapter, pdf::PdfAdapter,
    pe::PeAdapter, png::PngAdapter, zip::ZipAdapter,
};

pub static ADAPTERS: &[&dyn HostAdapter] = &[
    &PngAdapter,
    &JpegAdapter,
    &Mp4Adapter,
    &ZipAdapter,
    &PdfAdapter,
    &PeAdapter,
    &EofAdapter,
];

pub fn strategy_to_id(strategy: &str) -> u8 {
    match strategy {
        "eof" => 1,
        "chunk" => 2,
        "box_uuid" => 3,
        "pre_cd_inject" => 4,
        "app_segment" => 5,
        "incremental" => 6,
        "pe_overlay" => 7,
        "pe_codebits" => 8,
        _ => 1,
    }
}

pub fn id_to_strategy(id: u8) -> &'static str {
    match id {
        1 => "eof",
        2 => "chunk",
        3 => "box_uuid",
        4 => "pre_cd_inject",
        5 => "app_segment",
        6 => "incremental",
        7 => "pe_overlay",
        8 => "pe_codebits",
        _ => "eof",
    }
}

pub fn find_adapter(reader: &mut dyn SeekRead) -> &'static dyn HostAdapter {
    for adapter in ADAPTERS {
        if adapter.detect(reader) {
            return *adapter;
        }
    }
    &EofAdapter
}

pub fn list_all_strategies(reader: &mut dyn SeekRead) -> Vec<&'static str> {
    let adapter = find_adapter(reader);
    adapter.supported_strategies()
}
