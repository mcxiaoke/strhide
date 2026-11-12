//! Spatial domain steganographic extraction pipeline (PNG).

use crate::core::control::{Control, Stage};
use crate::core::crypto::{CipherSuiteId, Credential};
use crate::core::payload::Payload;
use crate::errors::StrHideError;
use crate::stego::StegoCodec;
use crate::stego::coding::{StcTrellis, hamming_extract_bytes};
use crate::stego::envelope::{build_v4_aad_with, unpack_v4_envelope_parts};
use crate::stego::format::{derive_l2_locator_keys, derive_l3_session_keys, derive_locator_master};
use crate::stego::header::{
    PNG_AUDIO_BASE_HEADER_BYTES, PNG_AUDIO_BASE_SLOTS, SpatialHeaderV4, TLV_CRITICAL,
    parse_extension,
};
use crate::stego::params::{ExtractParams, PngParams};
use crate::stego::prng::permute_indices;
use crate::stego::traits::PngCostModel;

use super::PNG_FORMAT_ID;
use super::codec::{RawImage, decode_png, trace};
use super::layout::{
    ChannelMode, SlotPlan, check_pipeline_budget, header_layout, header_pool, png_pre_salt,
    read_slot_bytes,
};

/// Extract a payload from a PNG carrier with content-adaptive spatial steganography.
///
/// The complete expert entry. The carrier declares its cost model in the
/// feature word, so `cost_model` is only a hint; `params` must repeat the
/// embed-time filter windows because the body slot ranking is recomputed from
/// the cost map.
#[allow(clippy::too_many_arguments)]
pub fn extract_png(
    carrier_bytes: &[u8],
    cred: Credential<'_>,
    domain: Option<&str>,
    spatial: &crate::stego::format::PngFormatProfile,
    cost_model: &dyn PngCostModel,
    params: &PngParams,
    limits: &ExtractParams,
    control: &Control<'_>,
) -> Result<Payload<'static>, StrHideError> {
    params.validate()?;
    control.stage(Stage::Decode);
    let image = decode_png(carrier_bytes)?;
    control.check()?;
    extract_png_image(
        &image, cred, domain, spatial, cost_model, params, limits, control,
    )
}

/// L1/L2 outputs shared by extract, inspect and verify.
///
/// `verify` needs the locator keys for its header level *and* for its payload
/// level; deriving them twice paid the 200k-iteration L1 twice for one user
/// request. This value is derived once and passed down.
pub(crate) struct PngKeys {
    pub(super) master: [u8; 32],
    pub(super) locator: crate::stego::format::HeaderLocatorKeys,
}

/// Derive the per-carrier L1 master and L2 locator keys.
pub(crate) fn png_keys(
    image: &RawImage,
    cred: Credential<'_>,
    domain: Option<&str>,
    spatial: &crate::stego::format::PngFormatProfile,
) -> Result<PngKeys, StrHideError> {
    let cipher = spatial.cipher;
    let pre_salt = png_pre_salt(image, spatial);
    let master = derive_locator_master(cred, domain, cipher, &pre_salt)?;
    let locator = derive_l2_locator_keys(&master, cipher, b"strhide-v4-hdr-magic", domain)?;
    Ok(PngKeys { master, locator })
}

/// Whether a policy is willing to pay the fixed V4 L1 cost.
pub(super) fn l1_allowed(cred: &Credential<'_>, limits: &ExtractParams) -> bool {
    !matches!(cred, Credential::Password(_))
        || limits.max_pbkdf2_iterations >= crate::crypto::CONTENT_L1_PBKDF2_ITERATIONS
}

/// Base header and extension area every PNG reader must decode first.
pub(super) struct OpenedPngHeader {
    pub(super) header: SpatialHeaderV4,
    pub(super) base_bytes: [u8; PNG_AUDIO_BASE_HEADER_BYTES],
    pub(super) extension: Vec<u8>,
    pub(super) base_layout: Vec<usize>,
}

/// Why the shared header bootstrap stopped.
pub(super) enum OpenedPngHeaderError {
    /// The pool is large enough but the keyed slot read came back short: an
    /// anomaly worth a diagnostic note in `inspect`, not the ordinary
    /// "nothing hidden here" answer.
    HeaderSlotsShort { carrier_slots: usize, needed: usize },
    /// Everything else: no readable header, a malformed extension, or a
    /// digit that violates the caller's policy. Readers fold this into their
    /// own "no payload" / empty-info semantics.
    Rejected,
}

/// Read and validate the base header + extension area.
///
/// `extract_png_with_keys` and `inspect_png_with_keys` used to carry two
/// copies of this bootstrap (base header, extension decode, critical-TLV
/// rejection, policy limits). Keeping one implementation is what makes
/// "inspect says readable" and "extract says no payload" unable to disagree.
pub(super) fn open_png_header(
    image: &RawImage,
    locator: &crate::stego::format::HeaderLocatorKeys,
    limits: &ExtractParams,
) -> Result<OpenedPngHeader, OpenedPngHeaderError> {
    let carrier_slots = header_pool(image).len();
    if carrier_slots < PNG_AUDIO_BASE_SLOTS {
        return Err(OpenedPngHeaderError::Rejected);
    }

    let base_layout = header_layout(image, &locator.locate_seed, 0);
    let base_bytes: [u8; PNG_AUDIO_BASE_HEADER_BYTES] =
        read_slot_bytes(image, &base_layout[..PNG_AUDIO_BASE_SLOTS], 64)
            .try_into()
            .map_err(|_| OpenedPngHeaderError::HeaderSlotsShort {
                carrier_slots,
                needed: PNG_AUDIO_BASE_SLOTS,
            })?;
    let header = SpatialHeaderV4::decode(&base_bytes, PNG_FORMAT_ID)
        .map_err(|_| OpenedPngHeaderError::Rejected)?;

    let ext_len = header.ext_len as usize;
    let header_slot_count = PNG_AUDIO_BASE_SLOTS + 8 * ext_len;
    if header_slot_count > carrier_slots {
        return Err(OpenedPngHeaderError::Rejected);
    }
    let full_layout = header_layout(image, &locator.locate_seed, ext_len);
    let extension = read_slot_bytes(
        image,
        &full_layout[PNG_AUDIO_BASE_SLOTS..header_slot_count],
        ext_len,
    );

    // The extension area is authenticated by the AAD, but its structure must
    // be sane first: an unknown critical TLV is fatal, non-critical ones are
    // ignored. `validate_ext_critical` also cross-checks the flags.
    header
        .validate_ext_critical(&extension)
        .map_err(|_| OpenedPngHeaderError::Rejected)?;
    let records = parse_extension(&extension).map_err(|_| OpenedPngHeaderError::Rejected)?;
    if records
        .iter()
        .any(|(type_id, _)| type_id & TLV_CRITICAL != 0)
    {
        return Err(OpenedPngHeaderError::Rejected);
    }

    // Policy checks run after the base header and extension are decoded but
    // before any body slot is computed or allocated.
    limits
        .validate_header(
            header.suite_id,
            header.body_len,
            header_slot_count,
            carrier_slots,
        )
        .map_err(|_| OpenedPngHeaderError::Rejected)?;

    Ok(OpenedPngHeader {
        header,
        base_bytes,
        extension,
        base_layout,
    })
}

/// Body of [`extract_png`] for an already-decoded image.
///
/// `verify_png` decodes once and reuses the pixels across all three levels
/// instead of running the full PNG decode three times.
#[allow(clippy::too_many_arguments)]
pub(super) fn extract_png_image(
    image: &RawImage,
    cred: Credential<'_>,
    domain: Option<&str>,
    spatial: &crate::stego::format::PngFormatProfile,
    cost_model: &dyn PngCostModel,
    params: &PngParams,
    limits: &ExtractParams,
    control: &Control<'_>,
) -> Result<Payload<'static>, StrHideError> {
    params.validate()?;
    // Refuse a policy that cannot pay the one fixed L1 cost before running it.
    if !l1_allowed(&cred, limits) {
        return Err(StrHideError::NoHiddenData("No valid payload found".into()));
    }
    let keys = png_keys(image, cred, domain, spatial)?;
    extract_png_with_keys(
        image, &keys, domain, spatial, cost_model, params, limits, control,
    )
}

/// Extraction over a pre-derived L1/L2 key set.
#[allow(clippy::too_many_arguments)]
pub(super) fn extract_png_with_keys(
    image: &RawImage,
    keys: &PngKeys,
    domain: Option<&str>,
    spatial: &crate::stego::format::PngFormatProfile,
    cost_model: &dyn PngCostModel,
    params: &PngParams,
    limits: &ExtractParams,
    control: &Control<'_>,
) -> Result<Payload<'static>, StrHideError> {
    params.validate()?;
    let no_hidden = || StrHideError::NoHiddenData("No valid payload found".into());
    // `HeaderLocatorKeys` is not `Copy` (it wipes itself on drop), so borrow it
    // instead of moving it out of the shared reference. `master` is a plain
    // array and stays a value copy.
    let master = keys.master;
    let locator = &keys.locator;

    let w = image.width as usize;
    let h = image.height as usize;
    let cipher = spatial.cipher;

    let OpenedPngHeader {
        header,
        base_bytes,
        extension,
        base_layout,
    } = open_png_header(image, locator, limits).map_err(|_| no_hidden())?;
    let ext_len = header.ext_len as usize;

    // The carrier names its cost model. An id this build does not know means a
    // carrier written by a newer tool -- reported exactly like "no payload",
    // because guessing a model would silently decode noise.
    let resolved = crate::stego::png::registry::spatial_model_from_wire_id(header.algorithm_id)
        .ok_or_else(no_hidden)?;
    if resolved.id() != cost_model.id() {
        // The carrier is authoritative; the caller's choice is only a hint.
        trace(format_args!(
            "carrier declares '{}', caller asked for '{}': using the carrier's",
            resolved.id(),
            cost_model.id()
        ));
    }

    // The carrier is self-describing about every hyperparameter that shapes
    // the cost map: exclusion percentile, HILL's windows and epsilon, and the
    // sigma model option. Whatever the caller configured is a hint only --
    // the wire values are what the embedder actually computed with.
    let mut effective_params = params.clone();
    effective_params.exclusion_percentile = (header.exclusion_permille as f64) / 1000.0;
    effective_params.p1_window = header.p1_window as usize;
    effective_params.p2_window = header.p2_window as usize;
    effective_params.epsilon = 2f64.powi(-(header.neg_log2_epsilon as i32));
    if resolved.id() == "suniward" {
        effective_params
            .algorithm_options
            .insert("sigma".to_string(), header.sigma as f64);
    } else if resolved.id() == "mipod" {
        effective_params
            .algorithm_options
            .insert("alpha".to_string(), (header.sigma as f64).clamp(0.01, 0.90));
    }
    effective_params.validate()?;

    // Distortion cost map of the declared model. Identical to what the embedder
    // computed, because header/feature pixels never leave their eight-value
    // class, so the map is bit-identical on the stego.
    let costs = resolved.compute_cost(&image.pixels, w, h, image.channels, &effective_params);
    control.check()?;
    // Body ranking needs costs; the header layout inside this plan is the same
    // cost-free one read above, so the two cannot disagree.
    let plan = SlotPlan::build(
        image,
        &costs,
        &locator.locate_seed,
        ext_len,
        header.exclusion_permille,
    )?;
    debug_assert_eq!(
        plan.permuted.get(..PNG_AUDIO_BASE_SLOTS),
        Some(&base_layout[..PNG_AUDIO_BASE_SLOTS]),
        "the header layout must not depend on the cost map"
    );

    // The body's channel mode arrives in the header. An unknown value, or one
    // the carrier cannot support, means the header landed on the wrong slots --
    // folded into the same generic failure as an AEAD reject.
    let mode = ChannelMode::from_wire(header.channel_mode).ok_or_else(no_hidden)?;
    if !mode.available(image.channels) {
        return Err(no_hidden());
    }
    let codec = match header.codec_id {
        0 => StegoCodec::Hamming,
        1 => StegoCodec::Stc,
        _ => return Err(no_hidden()),
    };
    let suite = CipherSuiteId::from_u16(header.suite_id).ok_or_else(no_hidden)?;
    if !limits.allows_suite(header.suite_id) {
        return Err(no_hidden());
    }

    // `body_len` is the AEAD ciphertext length including the 16-byte tag.
    let ciphertext_len = header.body_len as usize;
    let ciphertext_bits = ciphertext_len * 8;
    let needed_body_slots =
        crate::stego::coding::slots_for_codec(ciphertext_bits, codec, header.stc_h, header.stc_u)
            .map_err(|_| no_hidden())?;

    // Same budget the writer applies: a header claiming a payload this large
    // would otherwise have the reader allocate its way into an OOM abort before
    // it ever gets to reject the carrier.
    check_pipeline_budget(
        image.width as usize * image.height as usize,
        needed_body_slots,
        match codec {
            StegoCodec::Hamming => None,
            _ => Some(header.stc_h),
        },
    )
    .map_err(|_| no_hidden())?;

    // `body_slots_upto` stops as soon as `needed_body_slots` are collected and
    // its length check below rejects short pools, so a separate full-image
    // `count_body_slots` pass only doubled the scan without changing the
    // verdict.
    let mut body_slots = plan.body_slots_upto(image, header.class_rule, mode, needed_body_slots);
    trace(format_args!(
        "extract mode={:?} class_rule={} body_len={ciphertext_len} needed={needed_body_slots} pool={}",
        mode,
        header.class_rule,
        body_slots.len()
    ));
    // Short pool == the carrier is smaller than the header claims: no payload.
    if body_slots.len() < needed_body_slots {
        return Err(no_hidden());
    }
    let session = derive_l3_session_keys(cipher, suite, &master, &header.salt, domain)
        .map_err(|_| no_hidden())?;
    permute_indices(&mut body_slots, &session.perm_seed);

    let slot_vals: Vec<u8> = body_slots.iter().map(|&slot| image.pixels[slot]).collect();

    let ciphertext = match codec {
        StegoCodec::Hamming => hamming_extract_bytes(
            &slot_vals,
            ciphertext_len,
            crate::stego::coding::DEFAULT_HAMMING_K,
        )
        .map_err(|_| no_hidden())?,
        StegoCodec::Stc | StegoCodec::Auto => {
            let trellis =
                StcTrellis::from_seed_grouped(session.stc_seed, header.stc_h, header.stc_u)
                    .map_err(|_| no_hidden())?;
            trellis.extract(&slot_vals, ciphertext_bits)
        }
    };

    let aad = build_v4_aad_with(cipher.aad_prefix, PNG_FORMAT_ID, &base_bytes, &extension);
    // AEAD failure (and every structural failure before it) already collapsed
    // to `NoHiddenData` inside the envelope code. Once the tag verifies the
    // carrier is provably ours, so a broken frame / oversized payload must
    // surface as `CorruptedData` / capacity instead of "no payload here".
    unpack_v4_envelope_parts(
        suite,
        &session.enc_key,
        &header.nonce,
        &aad,
        &ciphertext,
        limits,
    )
}
