//! Batch orchestration: the multi-carrier policy shared by every front end.
//!
//! Before stage 4 these six functions lived inside `cli.rs`, which meant the
//! GUI and an HTTP service would have had to copy them — and drift: the
//! `.bak`-naming and default-output rules are user-visible behaviour, not
//! presentation (plan §5.1).
//!
//! Nothing here knows a carrier format. `preflight_batch` takes the caller's
//! own validator callback, so the CLI passes the adapter router while a service
//! embedding the library can pass its own check (or none).
//!
//! Dependency direction: this is `core`, so it may not reference
//! `structure`/`stego`/`formats`; the callback is how the format knowledge
//! stays on the caller's side (plan §2.1 rule 6).

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::core::i18n::Msg;
use crate::errors::StrHideError;
use crate::t;

/// Run `action` over every carrier.
///
/// Single-carrier runs keep the plain behaviour: no summary line, and the
/// caller still prints `[ERROR]` once. Multi-carrier runs stop at the first
/// failure and report how far they got — each write/restore is atomic per
/// carrier, so "N succeeded, M not attempted" is accurate, but earlier carriers
/// stay modified.
pub fn for_each_carrier<F>(
    carriers: &[PathBuf],
    quiet: bool,
    mut action: F,
) -> Result<(), StrHideError>
where
    F: FnMut(&Path) -> Result<(), StrHideError>,
{
    let total = carriers.len();
    let mut done = 0usize;
    for carrier in carriers {
        match action(carrier) {
            Ok(()) => done += 1,
            Err(e) => {
                if total > 1 && !quiet {
                    eprintln!("{}", t!(Msg::FailCarrier, path = carrier.display()));
                    let unattempted = total - done - 1;
                    println!(
                        "{}",
                        t!(
                            Msg::SummaryBatchPartial,
                            done = done,
                            total = total,
                            unattempted = unattempted
                        )
                    );
                }
                return Err(e);
            }
        }
    }
    if total > 1 && !quiet {
        println!("{}", t!(Msg::SummaryBatchAll, done = done, total = total));
    }
    Ok(())
}

/// Batch `-o` rule: with more than one carrier the target must be an existing
/// directory, because one file path cannot name several outputs.
///
/// An existing directory is accepted for a *single* carrier too and means "put
/// the result inside it, keeping the carrier's name" — the same semantics
/// `read -o <dir>` already had.
///
/// `action` is a verb phrase used in the error message ("writing to 3
/// carriers").
pub fn batch_output_dir<'a>(
    output: Option<&'a Path>,
    multi: bool,
    action: &str,
) -> Result<Option<&'a Path>, StrHideError> {
    let Some(path) = output else {
        return Ok(None);
    };
    if path.is_dir() {
        return Ok(Some(path));
    }
    if multi {
        return Err(StrHideError::General(format!(
            "'-o {}' must be an existing directory when {action} multiple carriers",
            path.display()
        )));
    }
    Ok(None)
}

/// Derive a default output path by appending `suffix` before the extension,
/// e.g. `photo.png` -> `photo-out.png`.
pub fn derive_default_output_path(carrier: &Path, suffix: &str) -> PathBuf {
    let parent = carrier.parent();
    let file_name = carrier
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("output");
    let (stem, ext) = match carrier.extension().and_then(|s| s.to_str()) {
        Some(ext) if !ext.is_empty() => {
            let stem = carrier
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or(file_name);
            (stem, Some(ext))
        }
        _ => (file_name, None),
    };
    let new_name = match ext {
        Some(ext) => format!("{stem}{suffix}.{ext}"),
        None => format!("{stem}{suffix}"),
    };
    match parent {
        Some(p) if !p.as_os_str().is_empty() => p.join(new_name),
        _ => PathBuf::from(new_name),
    }
}

/// Refuse to write over an existing file unless the caller said `overwrite`.
pub fn check_overwrite(target: &Path, overwrite: bool) -> Result<(), StrHideError> {
    if target.exists() && !overwrite {
        return Err(StrHideError::AlreadyExists(target.to_path_buf()));
    }
    Ok(())
}

/// Determine where a carrier's output should be written:
/// - in place: `Ok(None)`;
/// - `output_dir`: `Some(dir.join(carrier.file_name()))`;
/// - explicit `output`: `Some(output)`;
/// - otherwise the `-out` default from [`derive_default_output_path`].
pub fn resolve_carrier_target(
    carrier: &Path,
    in_place: bool,
    output: Option<&Path>,
    output_dir: Option<&Path>,
) -> Result<Option<PathBuf>, StrHideError> {
    if in_place {
        return Ok(None);
    }
    if let Some(dir) = output_dir {
        let name = carrier.file_name().ok_or_else(|| {
            StrHideError::General(format!(
                "Cannot derive an output filename from '{}'",
                carrier.display()
            ))
        })?;
        return Ok(Some(dir.join(name)));
    }
    if let Some(out) = output {
        return Ok(Some(out.to_path_buf()));
    }
    Ok(Some(derive_default_output_path(carrier, "-out")))
}

/// Carrier validation supplied by the caller: existence and "is this a format
/// we can handle" are format knowledge, so the caller injects it rather than
/// `core` depending on a format registry.
pub type CarrierValidator<'a> = &'a dyn Fn(&Path) -> Result<(), StrHideError>;

/// Everything `preflight_batch` needs, including the caller's own carrier
/// validation callback.
pub struct BatchPreflight<'a> {
    /// Carriers the command was given, in command-line order.
    pub carriers: &'a [PathBuf],
    /// Whether the command rewrites carriers in place.
    pub in_place: bool,
    /// The explicit `-o` value, if any.
    pub output: Option<&'a Path>,
    /// `-o` resolved to a directory ([`batch_output_dir`]).
    pub output_dir: Option<&'a Path>,
    /// Whether an existing destination may be replaced.
    pub overwrite: bool,
    /// Carrier validation supplied by the caller: existence and "is this a
    /// format we can handle" are format knowledge, so the caller injects it.
    pub validate: Option<CarrierValidator<'a>>,
}

/// Validate a whole batch before the first carrier is modified: every carrier
/// must exist, be a regular file, pass the caller's validation, and resolve to a
/// unique output.
pub fn preflight_batch(batch: BatchPreflight<'_>) -> Result<(), StrHideError> {
    let mut seen_carriers = HashSet::new();
    let mut seen_targets = HashSet::new();
    for carrier in batch.carriers {
        if !carrier.exists() {
            return Err(StrHideError::General(format!(
                "Carrier file '{}' not found",
                carrier.display()
            )));
        }
        if carrier.is_dir() {
            return Err(StrHideError::General(format!(
                "'{}' is a directory, not a carrier file",
                carrier.display()
            )));
        }
        if let Some(validate) = batch.validate {
            validate(carrier)?;
        }
        let identity = std::fs::canonicalize(carrier).unwrap_or_else(|_| carrier.clone());
        if !seen_carriers.insert(identity.clone()) {
            return Err(StrHideError::General(format!(
                "Carrier '{}' is listed more than once",
                carrier.display()
            )));
        }
        let target = match resolve_carrier_target(
            carrier,
            batch.in_place,
            batch.output,
            batch.output_dir,
        )? {
            Some(t) => t,
            None => identity,
        };
        if !batch.in_place {
            check_overwrite(&target, batch.overwrite)?;
        }
        if !seen_targets.insert(target.clone()) {
            return Err(StrHideError::General(format!(
                "Two carriers would write to the same file '{}'. Rename one of them or keep them in separate directories.",
                target.display()
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("strhide_pipeline_{name}_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create scratch dir");
        dir
    }

    #[test]
    fn default_output_path_inserts_suffix_before_extension() {
        assert_eq!(
            derive_default_output_path(Path::new("a/photo.png"), "-out"),
            PathBuf::from("a/photo-out.png")
        );
        assert_eq!(
            derive_default_output_path(Path::new("noext"), "-out"),
            PathBuf::from("noext-out")
        );
        assert_eq!(
            derive_default_output_path(Path::new("a.b/c.tar.gz"), "-out"),
            PathBuf::from("a.b/c.tar-out.gz")
        );
    }

    #[test]
    fn resolve_target_covers_all_four_shapes() {
        let dir = Path::new("out");
        assert_eq!(
            resolve_carrier_target(Path::new("c.png"), true, None, None).unwrap(),
            None
        );
        assert_eq!(
            resolve_carrier_target(Path::new("c.png"), false, Some(Path::new("x.png")), None)
                .unwrap(),
            Some(PathBuf::from("x.png"))
        );
        assert_eq!(
            resolve_carrier_target(Path::new("sub/c.png"), false, None, Some(dir)).unwrap(),
            Some(PathBuf::from("out/c.png"))
        );
        assert_eq!(
            resolve_carrier_target(Path::new("c.png"), false, None, None).unwrap(),
            Some(PathBuf::from("c-out.png"))
        );
    }

    #[test]
    fn batch_output_dir_requires_a_directory_only_for_multi() {
        let dir = scratch("batchdir");
        let file = dir.join("f.txt");
        fs::write(&file, b"x").unwrap();

        assert!(
            batch_output_dir(None, true, "writing to")
                .unwrap()
                .is_none()
        );
        assert_eq!(
            batch_output_dir(Some(&dir), true, "writing to").unwrap(),
            Some(dir.as_path())
        );
        assert!(
            batch_output_dir(Some(&file), true, "writing to").is_err(),
            "a file path cannot name several outputs"
        );
        assert!(
            batch_output_dir(Some(&file), false, "writing to")
                .unwrap()
                .is_none(),
            "single-carrier runs keep the file path as-is"
        );
    }

    #[test]
    fn check_overwrite_refuses_existing_targets() {
        let dir = scratch("overwrite");
        let target = dir.join("exists.bin");
        fs::write(&target, b"x").unwrap();

        assert!(matches!(
            check_overwrite(&target, false),
            Err(StrHideError::AlreadyExists(_))
        ));
        assert!(check_overwrite(&target, true).is_ok());
        assert!(check_overwrite(&dir.join("missing.bin"), false).is_ok());
    }

    #[test]
    fn preflight_rejects_missing_duplicate_and_colliding_carriers() {
        let dir = scratch("preflight");
        let a = dir.join("a.png");
        let b = dir.join("b.png");
        fs::write(&a, b"a").unwrap();
        fs::write(&b, b"b").unwrap();

        // Missing carrier.
        let missing = vec![dir.join("nope.png")];
        let err = preflight_batch(BatchPreflight {
            carriers: &missing,
            in_place: false,
            output: None,
            output_dir: None,
            overwrite: true,
            validate: None,
        })
        .unwrap_err();
        assert!(err.to_string().contains("not found"));

        // Duplicate carrier.
        let dup = vec![a.clone(), a.clone()];
        let err = preflight_batch(BatchPreflight {
            carriers: &dup,
            in_place: false,
            output: None,
            output_dir: None,
            overwrite: true,
            validate: None,
        })
        .unwrap_err();
        assert!(err.to_string().contains("more than once"));

        // Two carriers that resolve to the same output name in one directory.
        let sub1 = dir.join("one");
        let sub2 = dir.join("two");
        fs::create_dir_all(&sub1).unwrap();
        fs::create_dir_all(&sub2).unwrap();
        let c1 = sub1.join("same.png");
        let c2 = sub2.join("same.png");
        fs::write(&c1, b"1").unwrap();
        fs::write(&c2, b"2").unwrap();
        let out = dir.join("out");
        fs::create_dir_all(&out).unwrap();
        let colliding = vec![c1, c2];
        let err = preflight_batch(BatchPreflight {
            carriers: &colliding,
            in_place: false,
            output: Some(&out),
            output_dir: Some(&out),
            overwrite: true,
            validate: None,
        })
        .unwrap_err();
        assert!(err.to_string().contains("same file"));
    }

    #[test]
    fn preflight_runs_the_caller_validator() {
        let dir = scratch("preflight_validate");
        let a = dir.join("a.png");
        fs::write(&a, b"a").unwrap();
        let carriers = vec![a];
        let reject = |_: &Path| Err(StrHideError::UnsupportedFormat("nope".into()));
        let err = preflight_batch(BatchPreflight {
            carriers: &carriers,
            in_place: true,
            output: None,
            output_dir: None,
            overwrite: true,
            validate: Some(&reject),
        })
        .unwrap_err();
        assert!(matches!(err, StrHideError::UnsupportedFormat(_)));
    }

    #[test]
    fn for_each_carrier_stops_at_the_first_failure() {
        let carriers = vec![PathBuf::from("a"), PathBuf::from("b"), PathBuf::from("c")];
        let mut seen = Vec::new();
        let err = for_each_carrier(&carriers, true, |c| {
            seen.push(c.to_path_buf());
            if c == Path::new("b") {
                return Err(StrHideError::General("boom".into()));
            }
            Ok(())
        })
        .unwrap_err();
        assert!(err.to_string().contains("boom"));
        assert_eq!(
            seen,
            vec![PathBuf::from("a"), PathBuf::from("b")],
            "carriers after the failure must not run"
        );
    }
}
