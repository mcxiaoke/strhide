//! Block-grid geometry for JPEG DCT cost models.
//!
//! # Why this module exists
//!
//! `dct-io` returns each component's blocks in **MCU-interleaved** order: the
//! decoder walks MCUs in raster order and appends every scan component's data
//! units per MCU (`comp_blocks[comp_idx][block_idx] = block`, index
//! monotonically increasing per component). For a subsampled component that
//! is *not* a plain row-major raster of its block grid: with 4:2:0 the four Y
//! blocks of one MCU are appended top-left, top-right, bottom-left,
//! bottom-right, so block index 2 sits *below* index 1, not to its right.
//!
//! Any neighbourhood-based cost model (UERD's 8-neighbourhood block-energy
//! smoothing) therefore needs the index -> (row, col) mapping, not just a
//! grid width. Verified empirically on 2026-10-20 with synthetic gradient
//! carriers (DC constant along x, varying with y): under the true mapping
//! horizontal neighbours share an identical DC (score 0.000), under a raster
//! assumption they do not (~49). Consequences for the previous guesses:
//!
//! - `ceil(sqrt(n))`: correct only for square images whose dimensions are
//!   multiples of 16 (e.g. the 500x500 4:4:4 corpus sample).
//! - `ceil(width/8)`: correct only for 4:4:4/4:2:2, or for 4:2:0 widths that
//!   are multiples of 16 -- wrong for e.g. 3000-wide 4:2:0 carriers.
//!
//! The decoder also allocates blocks per MCU, so the block array covers the
//! **padded** grid (`mcu_cols * h_samp` x `mcu_rows * v_samp`), which can be
//! larger than the visible `ceil(width/8) x ceil(height/8)` grid; those
//! padding blocks are real coefficients in the file and get real positions.

use dct_io::JpegInfo;

use crate::formats::jpeg_segments::{STANDARD_LUMA_QT, parse_luma_dqt};
use crate::stego::traits::JpegGeometry;

/// Build the block geometry of one component plus the file's luma table.
///
/// `n_blocks` must be the component's decoded block count
/// (`coeffs.components[comp_idx].blocks.len()`). For any baseline
/// single-scan JPEG the returned `positions` has exactly that length.
pub fn geometry_for_carrier(
    carrier: &[u8],
    comp_idx: usize,
    n_blocks: usize,
) -> Result<JpegGeometry, dct_io::DctError> {
    let info = dct_io::inspect(carrier)?;
    let mut geometry = component_geometry(&info, comp_idx, n_blocks);
    geometry.luma_q = parse_luma_dqt(carrier).unwrap_or(STANDARD_LUMA_QT);
    Ok(geometry)
}

/// Index -> (row, col) mapping for one component's MCU-padded block grid.
///
/// `luma_q` is left at the Annex K fallback; use [`geometry_for_carrier`]
/// when the file's own table should be resolved.
pub fn component_geometry(info: &JpegInfo, comp_idx: usize, n_blocks: usize) -> JpegGeometry {
    let max_h = info
        .components
        .iter()
        .map(|c| c.h_samp as usize)
        .max()
        .unwrap_or(1)
        .max(1);
    let max_v = info
        .components
        .iter()
        .map(|c| c.v_samp as usize)
        .max()
        .unwrap_or(1)
        .max(1);
    let mcu_cols = (info.width as usize).div_ceil(max_h * 8);
    let mcu_rows = (info.height as usize).div_ceil(max_v * 8);

    let (hs, vs) = if comp_idx < info.components.len() {
        let ci = &info.components[comp_idx];
        (ci.h_samp as usize, ci.v_samp as usize)
    } else {
        (1, 1)
    };
    let grid_w = mcu_cols * hs;
    let grid_h = mcu_rows * vs;

    // Replay the decoder's traversal: MCUs in raster order, and inside each
    // MCU the component's h*v data units left-to-right, top-to-bottom.
    let mut positions = Vec::with_capacity(n_blocks);
    'scan: for mr in 0..mcu_rows {
        for mc in 0..mcu_cols {
            for dv in 0..vs {
                for dh in 0..hs {
                    positions.push((mr * vs + dv, mc * hs + dh));
                    if positions.len() == n_blocks {
                        break 'scan;
                    }
                }
            }
        }
    }

    JpegGeometry {
        grid_w,
        grid_h,
        positions,
        luma_q: STANDARD_LUMA_QT,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(width: u16, height: u16, samps: &[(u8, u8)]) -> JpegInfo {
        JpegInfo {
            width,
            height,
            components: samps
                .iter()
                .enumerate()
                .map(|(i, &(h, v))| dct_io::ComponentInfo {
                    id: i as u8 + 1,
                    h_samp: h,
                    v_samp: v,
                    block_count: 0,
                })
                .collect(),
        }
    }

    #[test]
    fn grayscale_is_plain_raster() {
        // 64x64, one component, no subsampling: MCU == block.
        let g = component_geometry(&info(64, 64, &[(1, 1)]), 0, 64);
        assert_eq!((g.grid_w, g.grid_h), (8, 8));
        for bi in 0..64 {
            assert_eq!(g.positions[bi], (bi / 8, bi % 8));
        }
    }

    #[test]
    fn yuv_444_is_plain_raster() {
        let g = component_geometry(&info(64, 64, &[(1, 1), (1, 1), (1, 1)]), 0, 64);
        for bi in 0..64 {
            assert_eq!(g.positions[bi], (bi / 8, bi % 8));
        }
    }

    #[test]
    fn yuv_422_is_plain_raster() {
        // v_samp == 1 makes MCU-interleaved order coincide with raster order.
        let g = component_geometry(&info(64, 64, &[(2, 1), (1, 1), (1, 1)]), 0, 64);
        for bi in 0..64 {
            assert_eq!(g.positions[bi], (bi / 8, bi % 8));
        }
    }

    #[test]
    fn yuv_420_interleaves_block_rows() {
        // 32x16 4:2:0: two 16x16 MCUs, four Y blocks each. The MCU's four
        // blocks are appended TL, TR, BL, BR -- index 2 is BELOW index 1.
        let g = component_geometry(&info(32, 16, &[(2, 2), (1, 1), (1, 1)]), 0, 8);
        assert_eq!((g.grid_w, g.grid_h), (4, 2));
        assert_eq!(
            g.positions,
            vec![
                (0, 0),
                (0, 1),
                (1, 0),
                (1, 1),
                (0, 2),
                (0, 3),
                (1, 2),
                (1, 3)
            ]
        );
    }

    #[test]
    fn non_multiple_of_16_pads_the_grid() {
        // 66x50 4:2:0: visible grid is 9x7 = 63 blocks, but the decoder
        // allocates the padded 10x8 = 80 blocks.
        let g = component_geometry(&info(66, 50, &[(2, 2), (1, 1), (1, 1)]), 0, 80);
        assert_eq!((g.grid_w, g.grid_h), (10, 8));
        assert_eq!(g.positions.len(), 80);
        // Every position must land inside the padded grid, and the mapping
        // must be a bijection onto the grid cells.
        let mut seen = vec![false; g.grid_w * g.grid_h];
        for &(r, c) in &g.positions {
            assert!(r < g.grid_h && c < g.grid_w);
            let idx = r * g.grid_w + c;
            assert!(!seen[idx], "duplicate position");
            seen[idx] = true;
        }
        assert!(seen.iter().all(|&s| s), "every grid cell must be covered");
    }

    #[test]
    fn sqrt_guess_would_be_wrong_for_420_nonsquare() {
        // 1920x1080 4:2:0: 32640 blocks. sqrt ~ 180.7 -- neither the true
        // padded width (240) nor any row-major interpretation.
        let n = 32640;
        let g = component_geometry(&info(1920, 1080, &[(2, 2), (1, 1), (1, 1)]), 0, n);
        assert_eq!(g.grid_w, 240);
        assert_ne!(g.grid_w, (n as f64).sqrt().ceil() as usize);
        // First MCU row: four Y blocks per MCU, 120 MCUs across.
        assert_eq!(g.positions[0], (0, 0));
        assert_eq!(g.positions[2], (1, 0)); // below, not right
        assert_eq!(g.positions[4], (0, 2)); // next MCU to the right
    }
}
