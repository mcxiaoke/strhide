//! Minimal DHT / SOS reader: what the luma AC Huffman table can actually encode.
//!
//! `dct-io` does not expose the Huffman tables, yet the V3 engine needs one
//! fact from them: whether `(run, category)` for the symbol it is about to write
//! exists. A table that covers all 162 AC symbols (160 combinations plus EOB and
//! ZRL) is the normal case and needs no per-slot work at all; an *optimal* table
//! (`ffmpeg -huffman optimal`, some camera firmware) may be missing symbols, and
//! writing one makes `dct-io` fail with a bare `CorruptEntropy`.
//!
//! So this module parses just enough of the JPEG container to answer:
//!
//! * [`luma_ac_symbols`] — the AC symbol set of the table the first scan
//!   component uses (the luminance table in every baseline file);
//! * [`can_encode_move`] — check whether a candidate coefficient move leaves
//!   the block encodable;
//! * [`first_missing_symbol`] — replay the AC symbol sequence of a *stego* block
//!   and report the first symbol the table cannot encode.
//!
//! Parsing is read-only and never fails hard: an unparsable table simply yields
//! `None`, and the engine falls back to "assume complete" (which reproduces the
//! previous behaviour of trusting the encoder).

use crate::errors::StrHideError;

/// Zigzag position -> natural (row-major) coefficient index.
#[rustfmt::skip]
pub const ZIGZAG: [u8; 64] = [
     0,  1,  8, 16,  9,  2,  3, 10,
    17, 24, 32, 25, 18, 11,  4,  5,
    12, 19, 26, 33, 40, 48, 41, 34,
    27, 20, 13,  6,  7, 14, 21, 28,
    35, 42, 49, 56, 57, 50, 43, 36,
    29, 22, 15, 23, 30, 37, 44, 51,
    58, 59, 52, 45, 38, 31, 39, 46,
    53, 60, 61, 54, 47, 55, 62, 63,
];

/// Natural coefficient index -> zigzag position.
pub const ZZ_POS: [u8; 64] = {
    let mut out = [0u8; 64];
    let mut i = 0;
    while i < 64 {
        out[ZIGZAG[i] as usize] = i as u8;
        i += 1;
    }
    out
};

/// EOB symbol.
pub const SYMBOL_EOB: u8 = 0x00;
/// ZRL (16 zeros) symbol.
pub const SYMBOL_ZRL: u8 = 0xF0;

/// The set of AC symbols a Huffman table defines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcSymbolSet {
    present: [bool; 256],
}

impl AcSymbolSet {
    /// Empty set, for the parser to fill in.
    pub const EMPTY: AcSymbolSet = AcSymbolSet {
        present: [false; 256],
    };

    /// Whether the table defines `symbol` (packed as `(run << 4) | category`).
    pub fn has(&self, symbol: u8) -> bool {
        self.present[symbol as usize]
    }

    fn insert(&mut self, symbol: u8) {
        self.present[symbol as usize] = true;
    }

    /// Every `(run, category)` pair a baseline AC table may need, plus EOB and
    /// ZRL.
    ///
    /// `category` runs 1..=10: `category(1023) == 10`, and the V3 legality rule
    /// keeps `|c| <= 1023` so category 11 is never produced.
    pub fn is_complete(&self) -> bool {
        self.has(SYMBOL_EOB)
            && self.has(SYMBOL_ZRL)
            && (0..16u8).all(|run| (1..=10u8).all(|cat| self.has((run << 4) | cat)))
    }

    /// Number of defined symbols (diagnostics only).
    pub fn len(&self) -> usize {
        self.present.iter().filter(|&&p| p).count()
    }

    /// Whether no symbol is defined at all.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// AC symbol table set used by the luma component of the first scan.
///
/// Returns `None` when the file has no DHT before the first SOS, or the scan's
/// table selector points at a table that was never defined. The caller treats
/// `None` as "cannot check" rather than as a failure.
pub fn luma_ac_symbols(jpeg: &[u8]) -> Option<AcSymbolSet> {
    let mut ac_tables: [Option<AcSymbolSet>; 4] = [None; 4];
    let mut pos = 2usize; // after SOI
    while pos + 1 < jpeg.len() {
        if jpeg[pos] != 0xFF {
            return None;
        }
        // Skip fill bytes.
        let mut marker_pos = pos + 1;
        while marker_pos < jpeg.len() && jpeg[marker_pos] == 0xFF {
            marker_pos += 1;
        }
        if marker_pos >= jpeg.len() {
            return None;
        }
        let marker = jpeg[marker_pos];
        pos = marker_pos + 1;

        // Standalone markers carry no length.
        match marker {
            0x01 | 0xD0..=0xD8 => continue,
            0xD9 => return None, // EOI before any scan
            _ => {}
        }
        if pos + 2 > jpeg.len() {
            return None;
        }
        let len = u16::from_be_bytes([jpeg[pos], jpeg[pos + 1]]) as usize;
        if len < 2 || pos + len > jpeg.len() {
            return None;
        }
        let payload = &jpeg[pos + 2..pos + len];

        match marker {
            0xC4 => parse_dht(payload, &mut ac_tables),
            0xDA => {
                // SOS: Ns at payload[0], then (Cs, Td/Ta) per component. The
                // first component is luminance in every baseline file, and the
                // engine only embeds there.
                if payload.len() < 4 {
                    return None;
                }
                let ta = (payload[2] & 0x0F) as usize;
                return ac_tables.get(ta).copied().flatten();
            }
            0xDB | 0xC0 | 0xC1 | 0xC2 | 0xDD | 0xE0..=0xEF | 0xFE => {}
            _ => return None,
        }
        pos += len;
    }
    None
}

/// Parse one DHT segment payload (possibly several tables back to back).
fn parse_dht(mut payload: &[u8], ac_tables: &mut [Option<AcSymbolSet>; 4]) {
    while payload.len() >= 17 {
        let class_and_id = payload[0];
        let class = class_and_id >> 4;
        let id = (class_and_id & 0x0F) as usize;
        let mut total = 0usize;
        for &count in &payload[1..17] {
            total += count as usize;
        }
        let header = 17usize;
        if payload.len() < header + total {
            return;
        }
        if class == 1 && id < ac_tables.len() {
            let mut set = AcSymbolSet::EMPTY;
            for &symbol in &payload[header..header + total] {
                set.insert(symbol);
            }
            ac_tables[id] = Some(set);
        }
        payload = &payload[header + total..];
    }
}

/// JPEG magnitude category: 0 for zero, otherwise the bit length of `|v|`.
///
/// The JPEG baseline range caps this at 15; `i16::MIN` is the one value whose
/// bit length is 16 and whose low nibble would collide with the run bits of a
/// `(run << 4) | category` symbol (0xN0 reads as ZRL). Real carriers never hold
/// it -- the V3 legality rule bounds `|c|` by 1023 -- so the value only shows
/// up in crafted files, and it is capped here rather than asserted: this is
/// data-driven input, so a debug-only panic would be a denial of service on
/// the debug builds the test suite runs on.
pub fn category(v: i16) -> u8 {
    if v == 0 {
        0
    } else {
        ((16 - v.unsigned_abs().leading_zeros()) as u8).min(15)
    }
}

/// Zero run in front of zigzag position `zz` (`1..=63`) of a block.
/// Zero run in front of every natural coefficient index, in one zigzag pass.
pub fn zero_runs(block: &[i16; 64]) -> [u8; 64] {
    let mut runs = [0u8; 64];
    let mut run = 0u8;
    for &zigzag_index in ZIGZAG.iter().skip(1) {
        let k = zigzag_index as usize;
        runs[k] = run;
        if block[k] == 0 {
            run = (run + 1) % 16;
        } else {
            run = 0;
        }
    }
    runs
}

/// Check whether writing `new_val` at natural index `k` leaves the block encodable by `table`.
pub fn can_encode_move(block: &[i16; 64], k: usize, new_val: i16, table: &AcSymbolSet) -> bool {
    let mut modified = *block;
    modified[k] = new_val;
    first_missing_symbol(&modified, table).is_none()
}

/// Per-block zigzag state for O(1) move checks.
///
/// `can_encode_move` copies the whole 64-coefficient block and replays every
/// symbol. This state records only what a single `±1` move can change:
///
/// * creating a non-zero at `z` splits one zero run and changes the run of the
///   next non-zero coefficient;
/// * removing a non-zero at `z` merges the runs on both sides;
/// * changing a non-zero's magnitude only changes the category at `z`.
///
/// The state is only valid while the block is unchanged. `plan_slots` caches
/// one state per block for the duration of one slot set.
#[derive(Clone, Copy, Debug)]
pub struct BlockZigzagState {
    /// Bit `z` (1..=63) is set iff `block[ZIGZAG[z]] != 0`.
    nz_mask: u64,
    /// Magnitude category at every zigzag position (index 0 is the DC slot).
    zz_cat: [u8; 64],
}

impl BlockZigzagState {
    pub fn from_block(block: &[i16; 64]) -> Self {
        let mut nz_mask = 0u64;
        let mut zz_cat = [0u8; 64];
        for z in 1..64 {
            let value = block[ZIGZAG[z] as usize];
            if value != 0 {
                nz_mask |= 1u64 << z;
                zz_cat[z] = category(value);
            }
        }
        Self { nz_mask, zz_cat }
    }

    /// Zero run in front of zigzag position `z` (`1..=63`).
    #[inline]
    pub fn run_before(&self, k: usize) -> usize {
        let z = ZZ_POS[k] as usize;
        let mask = self.nz_mask & ((1u64 << z) - 1) & !1u64;
        let prev = if mask == 0 {
            0
        } else {
            63 - mask.leading_zeros() as usize
        };
        z - prev - 1
    }

    /// Next non-zero zigzag position after `z`, if any.
    #[inline]
    fn next_nonzero(&self, z: usize) -> Option<usize> {
        if z >= 63 {
            return None;
        }
        let mask = self.nz_mask >> (z + 1);
        if mask == 0 {
            None
        } else {
            Some(z + 1 + mask.trailing_zeros() as usize)
        }
    }

    /// Identifier of the zero run that contains zigzag position `k`.
    ///
    /// A run is keyed by the non-zero coefficient that terminates it; the
    /// trailing run (no following non-zero) uses key 0, which cannot collide
    /// with a real non-zero position (those start at 1).
    #[inline]
    pub fn run_key(&self, k: usize) -> usize {
        let z = ZZ_POS[k] as usize;
        self.next_nonzero(z).unwrap_or(0)
    }

    /// Whether replacing the coefficient at natural index `k` with `new_val`
    /// leaves the block encodable by `table`.
    ///
    /// Precondition: the block this state was built from is encodable by
    /// `table` (always true for a cover JPEG that decoded successfully).
    #[inline]
    pub fn can_move(&self, k: usize, new_val: i16, table: &AcSymbolSet) -> bool {
        self.can_move_with_slots(k, new_val, table, None)
    }

    /// [`Self::can_move`] with a conservative cross-slot check.
    ///
    /// `slots_in_block` has bit `z` set for every coefficient that may be
    /// modified in the same solve. When the coefficient after a `0 -> ±1`
    /// insertion is also a slot, its own move may change its category (for
    /// example `1 -> 2` after `±1 -> 0` is forbidden), so the shifted run must
    /// be encodable for *every* category that coefficient can take. This closes
    /// the residual interaction that a per-slot check cannot see; it is
    /// deliberately conservative and is only applied to large slot sets.
    #[inline]
    pub fn can_move_with_slots(
        &self,
        k: usize,
        new_val: i16,
        table: &AcSymbolSet,
        slots_in_block: Option<u64>,
    ) -> bool {
        let z = ZZ_POS[k] as usize;
        let old_nonzero = self.nz_mask & (1u64 << z) != 0;
        let new_nonzero = new_val != 0;
        match (old_nonzero, new_nonzero) {
            (false, false) => true,
            (false, true) => {
                if !symbol_ok(self.run_before(k), 1, table) {
                    return false;
                }
                match self.next_nonzero(z) {
                    Some(next) => {
                        let run_after = next - z - 1;
                        let next_cat = self.zz_cat[next];
                        if !symbol_ok(run_after, next_cat, table) {
                            return false;
                        }
                        if slots_in_block.is_some_and(|m| m & (1u64 << next) != 0)
                            && !category_variants_ok(run_after, next_cat, table)
                        {
                            return false;
                        }
                        true
                    }
                    // The new coefficient is now the last AC coefficient: EOB
                    // is needed unless it sits at position 63.
                    None => z == 63 || table.has(SYMBOL_EOB),
                }
            }
            (true, false) => {
                let run_before = self.run_before(k);
                let run_after = match self.next_nonzero(z) {
                    Some(next) => next - z - 1,
                    None => 63 - z,
                };
                let merged = run_before + 1 + run_after;
                match self.next_nonzero(z) {
                    Some(next) => symbol_ok(merged, self.zz_cat[next], table),
                    // Everything after the removed coefficient is zero, so the
                    // block ends with an EOB.
                    None => table.has(SYMBOL_EOB),
                }
            }
            (true, true) => symbol_ok(self.run_before(k), category(new_val), table),
        }
    }
}

/// Every category a non-zero coefficient with `cat` can take after one `±1`
/// move (excluding the forbidden `±1 -> 0`). Conservative at category edges.
fn category_variants_ok(run: usize, cat: u8, table: &AcSymbolSet) -> bool {
    if cat == 1 {
        return symbol_ok(run, 2, table);
    }
    let lo = cat.saturating_sub(1).max(1);
    let hi = (cat + 1).min(10);
    (lo..=hi).all(|c| symbol_ok(run, c, table))
}

/// Whether a `(run, category)` symbol is encodable, including any ZRL chunks.
#[inline]
fn symbol_ok(run: usize, category: u8, table: &AcSymbolSet) -> bool {
    if run >= 16 && !table.has(SYMBOL_ZRL) {
        return false;
    }
    table.has(((run % 16) as u8) << 4 | category)
}

/// Replay the AC symbol sequence of a block and report the first symbol the
/// table cannot encode.
///
/// Mirrors `dct-io`'s encoder: zigzag order, ZRL every 16 zeros, EOB unless the
/// last non-zero coefficient sits at position 63.
pub fn first_missing_symbol(block: &[i16; 64], table: &AcSymbolSet) -> Option<u8> {
    let last_nonzero_zz = (1..64).rev().find(|&i| block[ZIGZAG[i] as usize] != 0);

    let mut run = 0usize;
    if let Some(last) = last_nonzero_zz {
        for k in 1..=last {
            let value = block[ZIGZAG[k] as usize];
            if value == 0 {
                run += 1;
                if run == 16 {
                    if !table.has(SYMBOL_ZRL) {
                        return Some(SYMBOL_ZRL);
                    }
                    run = 0;
                }
            } else {
                let symbol = ((run as u8) << 4) | category(value);
                if !table.has(symbol) {
                    return Some(symbol);
                }
                run = 0;
            }
        }
    }
    let needs_eob = last_nonzero_zz.is_none_or(|p| p < 63);
    if needs_eob && !table.has(SYMBOL_EOB) {
        return Some(SYMBOL_EOB);
    }
    None
}

/// Render a missing symbol for a human-readable diagnostic.
pub fn describe_symbol(symbol: u8) -> String {
    match symbol {
        SYMBOL_EOB => "EOB (0x00)".into(),
        SYMBOL_ZRL => "ZRL (0xF0)".into(),
        other => format!(
            "(run {}, category {}) = 0x{other:02X}",
            other >> 4,
            other & 0x0F
        ),
    }
}

/// Error raised when a write would need a symbol the carrier's table lacks.
pub fn missing_symbol_error(symbol: u8) -> StrHideError {
    StrHideError::UnsupportedFormat(format!(
        "This JPEG's Huffman table is over-optimised: it cannot encode {} and the modified coefficients need it. Please re-save the carrier with a standard (Annex K) table.",
        describe_symbol(symbol)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a DHT segment with one AC table from a symbol list.
    fn dht_segment(id: u8, symbols: &[u8]) -> Vec<u8> {
        // Spread the symbols over the 16 length buckets, one symbol per bucket
        // until they run out: the parse only needs the total count.
        let mut counts = [0u8; 16];
        for i in 0..symbols.len() {
            counts[i % 16] = counts[i % 16].saturating_add(1);
        }
        let mut seg = vec![0xFF, 0xC4];
        let payload_len = 2 + 1 + 16 + symbols.len();
        seg.extend_from_slice(&(payload_len as u16).to_be_bytes());
        seg.push(0x10 | (id & 0x0F));
        seg.extend_from_slice(&counts);
        seg.extend_from_slice(symbols);
        seg
    }

    fn sos_segment(ta: u8) -> Vec<u8> {
        vec![
            0xFF, 0xDA, 0x00, 0x08, // length 8
            0x01, // Ns
            0x01, // Cs
            ta,   // Td/Ta
            0x00, 0x3F, 0x00, // Ss, Se, Ah/Al
        ]
    }

    fn full_symbol_set() -> Vec<u8> {
        let mut out = vec![SYMBOL_EOB, SYMBOL_ZRL];
        for run in 0..16u8 {
            for cat in 1..=10u8 {
                out.push((run << 4) | cat);
            }
        }
        out
    }

    #[test]
    fn zigzag_tables_are_inverse() {
        for i in 0..64usize {
            assert_eq!(ZZ_POS[ZIGZAG[i] as usize] as usize, i);
        }
        assert_eq!(ZIGZAG[0], 0);
        assert_eq!(ZIGZAG[1], 1);
        assert_eq!(ZIGZAG[2], 8);
        assert_eq!(ZIGZAG[63], 63);
    }

    #[test]
    fn category_matches_the_baseline_limits() {
        assert_eq!(category(0), 0);
        assert_eq!(category(1), 1);
        assert_eq!(category(-1), 1);
        assert_eq!(category(2), 2);
        assert_eq!(category(3), 2);
        assert_eq!(category(1023), 10);
        assert_eq!(category(-1023), 10);
        // The V3 legality rule makes this unreachable in a written carrier.
        assert_eq!(category(1024), 11);
    }

    #[test]
    fn category_caps_the_crafted_sixteen_bit_magnitude() {
        // `i16::MIN` has bit length 16; the low nibble of `(run << 4) | 16`
        // would read as ZRL, so the value is capped at the baseline maximum.
        assert_eq!(category(i16::MIN), 15);
        assert_eq!(category(-32767), 15);
        assert_eq!(category(32767), 15);
    }

    #[test]
    fn complete_and_sparse_tables_are_classified() {
        let mut set = AcSymbolSet::EMPTY;
        for s in full_symbol_set() {
            set.insert(s);
        }
        assert!(set.is_complete());
        assert_eq!(set.len(), 162);

        let mut sparse = AcSymbolSet::EMPTY;
        for s in full_symbol_set() {
            if s != 0x21 {
                sparse.insert(s);
            }
        }
        assert!(!sparse.is_complete());
        assert!(!sparse.has(0x21));
    }

    #[test]
    fn parses_the_luma_table_before_the_first_scan() {
        let symbols = full_symbol_set();
        let mut jpeg = vec![0xFF, 0xD8];
        jpeg.extend_from_slice(&dht_segment(0, &symbols));
        jpeg.extend_from_slice(&sos_segment(0));
        let set = luma_ac_symbols(&jpeg).expect("table");
        assert!(set.is_complete());
        assert_eq!(set.len(), 162);

        // Selecting an undefined table yields None (cannot check).
        let mut jpeg_missing = vec![0xFF, 0xD8];
        jpeg_missing.extend_from_slice(&dht_segment(0, &symbols));
        jpeg_missing.extend_from_slice(&sos_segment(1));
        assert!(luma_ac_symbols(&jpeg_missing).is_none());

        // No DHT at all.
        let mut bare = vec![0xFF, 0xD8];
        bare.extend_from_slice(&sos_segment(0));
        assert!(luma_ac_symbols(&bare).is_none());
    }

    #[test]
    fn test_can_encode_move() {
        let mut full = AcSymbolSet::EMPTY;
        for s in full_symbol_set() {
            full.insert(s);
        }
        let block = [0i16; 64];
        assert!(can_encode_move(&block, 1, 1, &full));

        let mut sparse = full;
        sparse.present[0x01] = false; // run 0, cat 1
        assert!(!can_encode_move(&block, 1, 1, &sparse));
    }

    /// The O(1) state machine must agree with the whole-block replay for every
    /// ternary move on an encodable cover block.
    #[test]
    fn block_zigzag_state_matches_the_slow_replay() {
        struct Rng(u64);
        impl Rng {
            fn next(&mut self) -> u64 {
                self.0 ^= self.0 << 13;
                self.0 ^= self.0 >> 7;
                self.0 ^= self.0 << 17;
                self.0
            }
        }

        let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
        let mut compared = 0usize;
        for case in 0..4000 {
            let mut block = [0i16; 64];
            // Sparse natural blocks, with occasional long zero runs.
            let density = (rng.next() % 9) as usize;
            for z in 1..64 {
                if (rng.next() as usize) % 10 < density {
                    block[ZIGZAG[z] as usize] = (rng.next() % 7) as i16 - 3;
                }
            }
            if rng.next().is_multiple_of(17) {
                block[ZIGZAG[63] as usize] = 1;
            }

            // Full table minus a random subset: 0%, 10% or 30% missing.
            let missing_pct = [0usize, 10, 30][(rng.next() % 3) as usize];
            let mut table = AcSymbolSet::EMPTY;
            for s in full_symbol_set() {
                if missing_pct == 0 || (rng.next() as usize) % 100 >= missing_pct {
                    table.insert(s);
                }
            }
            if first_missing_symbol(&block, &table).is_some() {
                continue;
            }

            let state = BlockZigzagState::from_block(&block);
            for k in 1..64 {
                for step in [-1i16, 1] {
                    let new_val = block[k] + step;
                    if new_val.abs() > 1023 {
                        continue;
                    }
                    let slow = can_encode_move(&block, k, new_val, &table);
                    let fast = state.can_move(k, new_val, &table);
                    assert_eq!(
                        slow, fast,
                        "case {case} k={k} old={} new={new_val} missing_pct={missing_pct}",
                        block[k]
                    );
                    compared += 1;
                }
            }
        }
        assert!(compared > 50_000, "only {compared} moves compared");
    }

    #[test]
    fn test_luma_ac_symbols_out_of_bounds_ta() {
        // Construct minimal JPEG segment with SOS having Ta = 15 (>= 4).
        let mut jpeg = vec![0xFF, 0xD8]; // SOI
        // SOS with Ta = 15
        jpeg.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x0F, 0x00, 0x3F, 0x00]);
        jpeg.extend_from_slice(&[0xFF, 0xD9]); // EOI
        assert_eq!(luma_ac_symbols(&jpeg), None);
    }

    #[test]
    fn replay_finds_missing_symbols() {
        let mut full = AcSymbolSet::EMPTY;
        for s in full_symbol_set() {
            full.insert(s);
        }
        let mut block = [0i16; 64];
        block[1] = 3; // zigzag position 1
        assert_eq!(first_missing_symbol(&block, &full), None);

        let mut sparse = full;
        sparse.present[0x12] = false; // run 1, category 2
        let mut block = [0i16; 64];
        block[ZIGZAG[2] as usize] = 2;
        assert_eq!(first_missing_symbol(&block, &sparse), Some(0x12));

        // A block with no AC coefficients needs EOB.
        let empty = [0i16; 64];
        let mut no_eob = full;
        no_eob.present[0x00] = false;
        assert_eq!(first_missing_symbol(&empty, &no_eob), Some(SYMBOL_EOB));
        // ... unless the last coefficient is non-zero at position 63.
        let mut dense = [0i16; 64];
        dense[ZIGZAG[63] as usize] = 1;
        assert_eq!(first_missing_symbol(&dense, &no_eob), None);
    }
}
