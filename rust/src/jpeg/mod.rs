//! JPEG container-segment parsing shared by the stego and analysis modules.
//!
//! `dct-io` deliberately stops at the entropy-coded data and does not expose
//! the quantization tables, so anything that needs the *file's own* tables
//! (UERD's cost weights, the calibrated steganalysis reference) parses the
//! DQT segments here. Tables are returned in **natural** (row-major)
//! frequency order to line up with `dct-io`'s coefficient layout (its decoder
//! writes `block[ZIGZAG[k]] = value`, i.e. blocks are natural order despite
//! the crate doc saying "zigzag").

pub mod dqt;
