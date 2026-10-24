//! Atomic carrier commit shared by the structure domain and the content domain.
//!
//! Both `engine::write_carrier_with` and `stego::io::embed_carrier_file` need
//! the same "write a temp file, rename over the target, keep a backup, clone
//! timestamps" behaviour, so it lives here ungated and is re-exported from
//! `engine` for compatibility.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rand::RngExt;

use crate::errors::StrHideError;

/// Whether two paths refer to the same file.
///
/// The lexical comparison stays as the last resort, so a missing file still
/// gets the old answer instead of a guess.
pub fn same_file(a: &Path, b: &Path) -> bool {
    if a == b {
        return true;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let identity = |p: &Path| {
            let m = std::fs::metadata(p).ok()?;
            Some((m.dev(), m.ino()))
        };
        if let (Some(x), Some(y)) = (identity(a), identity(b)) {
            return x == y;
        }
    }

    let resolved = |p: &Path| std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    let (ra, rb) = (resolved(a), resolved(b));
    if ra == rb {
        return true;
    }

    #[cfg(windows)]
    {
        // Same file, different letter case: `C:\dir\PHOTO.PNG` and
        // `C:\dir\photo.png` are one file on NTFS.
        let ka = ra.as_os_str().to_string_lossy().to_lowercase();
        let kb = rb.as_os_str().to_string_lossy().to_lowercase();
        if ka == kb {
            return true;
        }
    }

    false
}

/// RAII guard removing an uncommitted temporary file on drop.
///
/// Any error return between creating the temp file and the successful atomic
/// rename leaves a half-written `*.strhide.tmp` behind without this guard.
/// Call `commit()` once the rename succeeded; afterwards the guard is inert.
pub(crate) struct TmpGuard {
    path: Option<PathBuf>,
}

impl TmpGuard {
    pub(crate) fn new(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }

    pub(crate) fn commit(&mut self) {
        self.path = None;
    }
}

impl Drop for TmpGuard {
    fn drop(&mut self) {
        if let Some(p) = &self.path {
            let _ = std::fs::remove_file(p);
        }
    }
}

///
/// In-place writes create `<carrier>.bak`; writing again would silently replace
/// the previous backup. Collisions fall back to `<carrier>.bak-<timestamp>` and a suffix.
pub(crate) fn next_backup_path(carrier: &Path) -> PathBuf {
    let with_suffix = |suffix: &str| {
        let mut os = carrier.as_os_str().to_os_string();
        os.push(suffix);
        PathBuf::from(os)
    };

    let base = with_suffix(".bak");
    if !base.exists() {
        return base;
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let candidate = with_suffix(&format!(".bak-{now}"));
    if !candidate.exists() {
        return candidate;
    }
    let pid = std::process::id();
    for suffix in 1..=10u32 {
        let candidate = with_suffix(&format!(".bak-{now}-{pid}-{suffix}"));
        if !candidate.exists() {
            return candidate;
        }
    }
    with_suffix(&format!(".bak-{now}-{pid}-{}", rand::rng().random::<u32>()))
}

/// Safely commit stego bytes to `target_path` with an atomic rename, a
/// crash-safe temporary file guard, collision-free `.bak` backup on in-place
/// writes, and preservation of the original carrier's permissions and timestamps.
pub fn commit_carrier_bytes(
    carrier_path: &Path,
    target_path: &Path,
    stego_bytes: &[u8],
    backup: bool,
    preserve_time: bool,
) -> Result<Option<PathBuf>, StrHideError> {
    let meta = std::fs::metadata(carrier_path)?;
    let orig_permissions = meta.permissions();
    let orig_atime = filetime::FileTime::from_last_access_time(&meta);
    let orig_mtime = filetime::FileTime::from_last_modification_time(&meta);

    let is_inplace = same_file(target_path, carrier_path);
    let mut backup_path = None;
    if is_inplace && backup {
        let bak = next_backup_path(carrier_path);
        std::fs::copy(carrier_path, &bak)?;
        backup_path = Some(bak);
    }

    let mut tmp_os = target_path.as_os_str().to_os_string();
    tmp_os.push(".strhide.tmp");
    let tmp_target = PathBuf::from(tmp_os);
    let mut tmp_guard = TmpGuard::new(tmp_target.clone());

    std::fs::write(&tmp_target, stego_bytes)?;

    std::fs::rename(&tmp_target, target_path)?;
    tmp_guard.commit();

    let _ = std::fs::set_permissions(target_path, orig_permissions);
    if preserve_time {
        let _ = filetime::set_file_times(target_path, orig_atime, orig_mtime);
    }

    Ok(backup_path)
}
