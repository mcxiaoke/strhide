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

/// Target file commit configuration shared across structure and content domains.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileTarget<'a> {
    /// None = overwrite carrier in place; Some(path) = write to destination path.
    pub output_path: Option<&'a Path>,
    /// Whether to keep `<carrier>.bak` on in-place commits.
    pub backup: bool,
    /// Whether to clone original carrier atime/mtime timestamps onto target.
    pub preserve_time: bool,
    /// Whether to allow overwriting an existing destination file when output_path is Some.
    pub overwrite: bool,
}

impl Default for FileTarget<'_> {
    fn default() -> Self {
        Self {
            output_path: None,
            backup: true,
            preserve_time: true,
            overwrite: false,
        }
    }
}

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

/// Reject an extracted-payload destination that resolves to an input carrier.
///
/// `read -i carrier -o carrier` (or a batch whose output name matches another
/// input carrier) truncates the carrier before the payload is written, which
/// destroys the only copy of the hidden data. `same_file` normalises symlinks,
/// relative paths and Windows case differences, so all of them are covered.
pub fn reject_carrier_output(dest: &Path, carriers: &[PathBuf]) -> Result<(), StrHideError> {
    for carrier in carriers {
        if same_file(dest, carrier) {
            return Err(StrHideError::Rejection(format!(
                "Refusing to write the extracted payload over carrier '{}': choose a different output path",
                carrier.display()
            )));
        }
    }
    Ok(())
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

/// Generate a collision-free temporary file path alongside `path` using process ID and random salt.
pub fn temp_path_for(path: &Path) -> PathBuf {
    let mut os = path.as_os_str().to_os_string();
    let pid = std::process::id();
    let r: u32 = rand::rng().random();
    os.push(format!(".strhide.{pid}.{r}.tmp"));
    PathBuf::from(os)
}

/// Copy `src` into a freshly created `dst`.
///
/// `create_new` refuses to follow a pre-existing file or symlink (review P2-2);
/// callers that race on a backup name retry with another candidate via
/// [`create_carrier_backup`].
fn copy_file_to_new(src: &Path, dst: &Path) -> std::io::Result<()> {
    use std::fs::OpenOptions;
    let mut input = std::fs::File::open(src)?;
    let mut output = OpenOptions::new().write(true).create_new(true).open(dst)?;
    std::io::copy(&mut input, &mut output)?;
    output.sync_all()?;
    drop(output);
    // `std::fs::copy` also clones the source permissions; keep that behaviour.
    let permissions = std::fs::metadata(src)?.permissions();
    std::fs::set_permissions(dst, permissions)?;
    Ok(())
}

/// Copy `src` to `dst` and flush the copy before returning.
///
/// `std::fs::copy` does not `fsync` the destination, so a crash right after the
/// caller renames the new carrier over the original could leave a zero-length
/// or unwritten `.bak` next to an already overwritten carrier — both copies
/// lost. The handle is opened for writing so `sync_all` works on Windows too.
pub fn copy_file_durable(src: &Path, dst: &Path) -> Result<(), StrHideError> {
    copy_file_to_new(src, dst).map_err(StrHideError::from)
}

/// Create the `<carrier>.bak` for an in-place commit, retrying when the name
/// chosen by [`next_backup_path`] is created concurrently before `create_new`
/// runs. The retry re-runs the collision check, so a second writer can never
/// truncate the first writer's backup (review P2-2).
pub(crate) fn create_carrier_backup(carrier: &Path) -> Result<PathBuf, StrHideError> {
    for _ in 0..16 {
        let candidate = next_backup_path(carrier);
        match copy_file_to_new(carrier, &candidate) {
            Ok(()) => return Ok(candidate),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Err(StrHideError::General(
        "could not allocate a unique backup path".into(),
    ))
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
        backup_path = Some(create_carrier_backup(carrier_path)?);
    }

    write_bytes_atomic(target_path, stego_bytes)?;

    if let Err(e) = std::fs::set_permissions(target_path, orig_permissions) {
        eprintln!(
            "warning: failed to restore file permissions for '{}': {e}",
            target_path.display()
        );
    }
    if preserve_time && let Err(e) = filetime::set_file_times(target_path, orig_atime, orig_mtime) {
        eprintln!(
            "warning: failed to preserve file timestamps for '{}': {e}",
            target_path.display()
        );
    }

    Ok(backup_path)
}

/// Clear the write protection `fs::copy` cloned from the source.
///
/// `commit_carrier_patches` copies the carrier to a temp file before opening it
/// for writing. A read-only carrier (mode `0o444`, Windows read-only attribute)
/// would otherwise make that open fail with `PermissionDenied` even when the
/// caller asked for a fresh `-o <path>` target (review P2-18). The original
/// permissions are restored on the committed target afterwards.
// `set_readonly(false)` is Windows-only here; the Unix branch below adds the
// owner write bit instead of making the file world-writable.
#[allow(clippy::permissions_set_readonly_false)]
fn make_writable(path: &Path) -> std::io::Result<()> {
    let mut permissions = std::fs::metadata(path)?.permissions();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        permissions.set_mode(permissions.mode() | 0o200);
    }
    #[cfg(windows)]
    permissions.set_readonly(false);
    std::fs::set_permissions(path, permissions)
}

/// Safely commit in-place stego patches to `target_path` by streaming the original
/// carrier via `fs::copy` and rewriting only the modified spans, with an atomic rename,
/// crash-safe temporary file guard, and `.bak` backup.
pub fn commit_carrier_patches(
    carrier_path: &Path,
    target_path: &Path,
    patches: &[(std::ops::Range<usize>, Vec<u8>)],
    backup: bool,
    preserve_time: bool,
) -> Result<Option<PathBuf>, StrHideError> {
    use std::fs::OpenOptions;
    use std::io::{Seek, SeekFrom, Write};

    let meta = std::fs::metadata(carrier_path)?;
    let orig_permissions = meta.permissions();
    let orig_atime = filetime::FileTime::from_last_access_time(&meta);
    let orig_mtime = filetime::FileTime::from_last_modification_time(&meta);

    let is_inplace = same_file(target_path, carrier_path);
    let mut backup_path = None;
    if is_inplace && backup {
        backup_path = Some(create_carrier_backup(carrier_path)?);
    }

    let tmp_path = temp_path_for(target_path);
    let mut guard = TmpGuard::new(tmp_path.clone());

    // 1. Kernel-level stream copy (zero user-space heap allocation)
    std::fs::copy(carrier_path, &tmp_path)?;
    // The copy inherits the carrier's read-only bits; the patch step needs to
    // write it, and the original permissions are restored after the rename.
    make_writable(&tmp_path)?;

    // 2. Open for in-place patch overwrite
    {
        let mut file = OpenOptions::new().read(true).write(true).open(&tmp_path)?;
        // Every span comes from a byte stream that was read before the copy.
        // If the carrier changed underneath us (or a caller ever hands us a
        // bad span), `write_all` past EOF silently *extends* the file and the
        // rename publishes a corrupted carrier with a truncated tail. Bound
        // each write by the real length instead (review R2 P0-6).
        let file_len = file.metadata()?.len();
        for (span, patch) in patches {
            let start = span.start as u64;
            let end = start
                .checked_add(patch.len() as u64)
                .ok_or_else(|| StrHideError::CorruptedData("Patch span overflows".into()))?;
            if end > file_len {
                return Err(StrHideError::CorruptedData(format!(
                    "Patch span [{start}, {end}) exceeds carrier length {file_len}; \
                     the carrier changed while it was being modified"
                )));
            }
            file.seek(SeekFrom::Start(start))?;
            file.write_all(patch)?;
        }
        file.sync_all()?;
    }

    rename_with_retry(&tmp_path, target_path)?;
    guard.commit();
    sync_parent_dir(target_path);

    if let Err(e) = std::fs::set_permissions(target_path, orig_permissions) {
        eprintln!(
            "warning: failed to restore file permissions for '{}': {e}",
            target_path.display()
        );
    }
    if preserve_time && let Err(e) = filetime::set_file_times(target_path, orig_atime, orig_mtime) {
        eprintln!(
            "warning: failed to preserve file timestamps for '{}': {e}",
            target_path.display()
        );
    }

    Ok(backup_path)
}

/// Write `bytes` to `path` through a sibling temp file, then rename over it.
///
/// The temp file is `fsync`ed before the rename: renaming first and syncing
/// later leaves a window where a power cut can expose the new name with
/// zero-length or partially written contents. The parent directory is synced
/// afterwards so the rename itself survives on ext4/xfs; on Windows the rename
/// is journaled by NTFS and the call is a no-op.
///
/// Errors leave no `*.strhide.tmp` behind (the guard removes it on unwind).
///
/// Public because every caller that writes a payload out — CLI `read`, the
/// library, and the Tauri backend — must land it the same way. A plain
/// `fs::write` truncates an existing target before the new bytes are durable
/// (and follows a symlink instead of replacing it).
pub fn write_bytes_atomic(path: &Path, bytes: &[u8]) -> Result<(), StrHideError> {
    use std::io::Write as _;

    let tmp_path = temp_path_for(path);
    let mut guard = TmpGuard::new(tmp_path.clone());

    {
        let mut file = std::fs::File::create(&tmp_path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    rename_with_retry(&tmp_path, path)?;
    guard.commit();
    sync_parent_dir(path);
    Ok(())
}

/// Rename `from` to `to` with bounded exponential backoff retries when encountering
/// file sharing violations (Windows error 32 / 33) or permission denied errors caused
/// by media preview components or external processes holding open handles.
pub fn rename_with_retry(from: &Path, to: &Path) -> Result<(), StrHideError> {
    const BACKOFF_MS: [u64; 3] = [20, 50, 100];
    match std::fs::rename(from, to) {
        Ok(()) => return Ok(()),
        Err(e) if !is_sharing_or_permission_error(&e) => return Err(StrHideError::Io(e)),
        Err(_) => {}
    }
    for &wait_ms in &BACKOFF_MS {
        std::thread::sleep(std::time::Duration::from_millis(wait_ms));
        match std::fs::rename(from, to) {
            Ok(()) => return Ok(()),
            Err(e) if !is_sharing_or_permission_error(&e) => return Err(StrHideError::Io(e)),
            Err(_) => {}
        }
    }
    Err(StrHideError::TargetBusy(to.to_path_buf()))
}

fn is_sharing_or_permission_error(err: &std::io::Error) -> bool {
    #[cfg(windows)]
    {
        if let Some(raw) = err.raw_os_error() {
            // ERROR_SHARING_VIOLATION = 32, ERROR_LOCK_VIOLATION = 33, ERROR_ACCESS_DENIED = 5
            if raw == 32 || raw == 33 || raw == 5 {
                return true;
            }
        }
        err.kind() == std::io::ErrorKind::PermissionDenied
    }
    #[cfg(not(windows))]
    {
        let _ = err;
        false
    }
}

/// Flush the directory entry created by a rename (no-op off unix).
pub(crate) fn sync_parent_dir(path: &Path) {
    #[cfg(unix)]
    {
        let parent = match path.parent() {
            Some(p) if !p.as_os_str().is_empty() => p,
            _ => Path::new("."),
        };
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "strhide_test_{tag}_{}",
            rand::rng().random::<u32>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn copy_file_durable_never_overwrites_an_existing_destination() {
        let dir = scratch_dir("copy_new");
        let src = dir.join("source.bin");
        let dst = dir.join("destination.bin");
        std::fs::write(&src, b"source").unwrap();
        std::fs::write(&dst, b"sentinel").unwrap();

        let err = copy_file_durable(&src, &dst).unwrap_err();
        assert!(
            matches!(&err, StrHideError::Io(e) if e.kind() == std::io::ErrorKind::AlreadyExists),
            "create_new must refuse an existing target: {err:?}"
        );
        assert_eq!(
            std::fs::read(&dst).unwrap(),
            b"sentinel",
            "the existing destination must be left untouched"
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn carrier_backups_never_collide_or_overwrite() {
        let dir = scratch_dir("backup_collision");
        let carrier = dir.join("carrier.bin");
        std::fs::write(&carrier, b"payload").unwrap();

        let first = create_carrier_backup(&carrier).unwrap();
        let second = create_carrier_backup(&carrier).unwrap();
        assert_ne!(first, second, "each backup must get a fresh path");
        assert_eq!(std::fs::read(&first).unwrap(), b"payload");
        assert_eq!(std::fs::read(&second).unwrap(), b"payload");

        let _ = std::fs::remove_dir_all(dir);
    }

    /// Remove every write-protection bit the test set, so the scratch
    /// directory can be deleted on Windows.
    #[allow(clippy::permissions_set_readonly_false)]
    fn clear_read_only(path: &Path) {
        if let Ok(meta) = std::fs::metadata(path) {
            let mut permissions = meta.permissions();
            permissions.set_readonly(false);
            let _ = std::fs::set_permissions(path, permissions);
        }
    }

    #[test]
    fn commit_carrier_patches_accepts_a_read_only_carrier() {
        let dir = scratch_dir("read_only_patches");
        let src = dir.join("carrier.bin");
        let dst = dir.join("out.bin");
        std::fs::write(&src, vec![0x11u8; 64]).unwrap();

        let mut permissions = std::fs::metadata(&src).unwrap().permissions();
        permissions.set_readonly(true);
        std::fs::set_permissions(&src, permissions).unwrap();

        // A fresh `-o <path>` target must still work: the temp copy inherits
        // the carrier's read-only bits, and the patch step opens it for
        // writing (review P2-18).
        let patches = vec![(0..2usize, vec![0xAA, 0xBB])];
        let result = commit_carrier_patches(&src, &dst, &patches, false, false);
        let backup = result.expect("a read-only carrier must not block patching a new target");
        let committed = std::fs::read(&dst).unwrap();

        clear_read_only(&dst);
        clear_read_only(&src);
        let _ = std::fs::remove_dir_all(&dir);

        assert!(backup.is_none());
        assert_eq!(committed[0..2], [0xAA, 0xBB]);
    }

    #[test]
    fn commit_carrier_patches_applies_correctly() {
        let temp_dir = scratch_dir("patches");
        let src_file = temp_dir.join("carrier.bin");
        let dst_file = temp_dir.join("carrier_out.bin");

        let original_data = vec![0x11u8; 1024];
        std::fs::write(&src_file, &original_data).unwrap();

        let patches = vec![
            (10..15, vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE]),
            (100..102, vec![0x99, 0x88]),
        ];

        let bak = commit_carrier_patches(&src_file, &dst_file, &patches, false, false).unwrap();
        assert!(bak.is_none());
        assert!(dst_file.exists());

        let result = std::fs::read(&dst_file).unwrap();
        assert_eq!(result.len(), 1024);
        assert_eq!(&result[10..15], &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE]);
        assert_eq!(&result[100..102], &[0x99, 0x88]);
        assert_eq!(&result[0..10], &[0x11; 10]);
        assert_eq!(&result[15..100], &[0x11; 85]);

        let _ = std::fs::remove_dir_all(temp_dir);
    }
}
