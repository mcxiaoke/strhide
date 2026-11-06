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

/// Refuse a target the OS marks read-only before a temp copy is built.
///
/// On Windows renaming over a read-only file fails with `ERROR_ACCESS_DENIED`
/// (raw OS error 5). [`rename_with_retry`] treats that code like a sharing
/// violation, retries it, and finally reports [`StrHideError::TargetBusy`] —
/// "in use by another process" — which sends the user looking for a phantom
/// lock instead of the file attribute. Detect the attribute up front and report
/// it as the permission problem it is. A target that does not exist yet is
/// fine: the rename creates it.
pub fn reject_read_only_target(target: &Path) -> Result<(), StrHideError> {
    if !target.exists() {
        return Ok(());
    }
    match std::fs::metadata(target) {
        Ok(meta) if meta.permissions().readonly() => Err(StrHideError::Io(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "Target file '{}' is read-only; make it writable or choose another -o path",
                target.display()
            ),
        ))),
        Ok(_) => Ok(()),
        Err(e) => Err(StrHideError::Io(e)),
    }
}

/// Cross-process writer lock beside the target.
///
/// Two writers that raced on the same carrier each staged a temp file and
/// renamed it over the target, so the later rename silently replaced the
/// earlier envelope while both reported success. A hidden
/// `.<name>.strhide.lock` marker created with `create_new` makes the second
/// writer fail with [`StrHideError::TargetBusy`] instead.
///
/// `create_new` is the mutex: only the creator can remove the marker, so there
/// is no unlink race, and the guard deletes it on every normal return. An
/// abnormal exit (kill, Ctrl+C, crash) leaves the marker behind with the
/// writer's PID inside; a later writer reclaims it only when that PID is
/// provably dead. Reclamation renames the stale marker out of the way instead
/// of unlinking it, so two reclaimers cannot delete each other's newly
/// acquired lock.
///
/// Creating the marker can fail for reasons the commit itself will report
/// better (a missing or read-only output directory), so those failures fall
/// back to "unlocked" rather than aborting with a lock-specific error.
#[derive(Debug)]
pub struct TargetLock {
    /// `None` when the marker could not be created; the write then runs
    /// unguarded and fails later with the real filesystem error.
    path: Option<PathBuf>,
}

impl TargetLock {
    /// Lock `target` for the duration of a carrier commit.
    pub fn acquire(target: &Path) -> Result<Self, StrHideError> {
        let path = lock_path_for(target);
        let mut reclaimed = false;
        loop {
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(mut file) => {
                    use std::io::Write as _;
                    let _ = writeln!(file, "{}", std::process::id());
                    return Ok(Self { path: Some(path) });
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    if !reclaimed && reclaim_if_stale(&path) {
                        reclaimed = true;
                        continue;
                    }
                    return Err(StrHideError::TargetBusy(target.to_path_buf()));
                }
                Err(_) => return Ok(Self { path: None }),
            }
        }
    }
}

/// Move a marker left by a dead writer out of the way, then report whether it
/// was reclaimed. The rename (not unlink) sequence lets concurrent reclaimers
/// race safely: only one of them can move the stale file, and the winner then
/// competes for `create_new` like any other writer.
fn reclaim_if_stale(path: &Path) -> bool {
    let Some(pid) = read_lock_pid(path) else {
        return false;
    };
    if pid == 0 || process_is_alive(pid) {
        return false;
    }
    let quarantine = quarantine_path(path);
    if std::fs::rename(path, &quarantine).is_err() {
        return false;
    }
    let _ = std::fs::remove_file(&quarantine);
    true
}

fn read_lock_pid(path: &Path) -> Option<u32> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn quarantine_path(path: &Path) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static QUARANTINE_SEQ: AtomicU64 = AtomicU64::new(0);
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "lock".to_string());
    let seq = QUARANTINE_SEQ.fetch_add(1, Ordering::Relaxed);
    path.with_file_name(format!("{name}.stale-{}-{seq}", std::process::id()))
}

#[cfg(windows)]
fn process_is_alive(pid: u32) -> bool {
    use std::ffi::c_void;

    const SYNCHRONIZE: u32 = 0x0010_0000;
    const WAIT_TIMEOUT: u32 = 0x0000_0102;
    const WAIT_FAILED: u32 = 0xFFFF_FFFF;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn OpenProcess(
            dw_desired_access: u32,
            b_inherit_handle: i32,
            dw_process_id: u32,
        ) -> *mut c_void;
        fn WaitForSingleObject(h_handle: *mut c_void, dw_milliseconds: u32) -> u32;
        fn CloseHandle(h_object: *mut c_void) -> i32;
    }

    // SAFETY: `OpenProcess` only requests a synchronize handle. A null return
    // means either the PID does not exist (`ERROR_INVALID_PARAMETER`, dead) or
    // it belongs to a process we may not inspect (`ERROR_ACCESS_DENIED`, alive).
    // `WaitForSingleObject(0)` is a non-blocking liveness probe and the handle
    // is closed before returning.
    unsafe {
        let handle = OpenProcess(SYNCHRONIZE, 0, pid);
        if handle.is_null() {
            // 5 = ERROR_ACCESS_DENIED: the process exists but is not ours.
            return std::io::Error::last_os_error().raw_os_error() == Some(5);
        }
        let state = WaitForSingleObject(handle, 0);
        let _ = CloseHandle(handle);
        // WAIT_TIMEOUT (258) means running; WAIT_OBJECT_0 (0) means exited.
        // WAIT_FAILED is unknown, so stay conservative and keep the marker.
        state == WAIT_TIMEOUT || state == WAIT_FAILED
    }
}

#[cfg(all(unix, not(target_os = "linux")))]
fn process_is_alive(pid: u32) -> bool {
    const EPERM: i32 = 1;
    const SIG_NONE: i32 = 0;

    #[link(name = "c")]
    unsafe extern "C" {
        fn kill(pid: i32, sig: i32) -> i32;
    }

    // SAFETY: signal 0 performs permission/existence checking only; it never
    // delivers a signal.
    if unsafe { kill(pid as i32, SIG_NONE) } == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() == Some(EPERM)
}

#[cfg(target_os = "linux")]
fn process_is_alive(pid: u32) -> bool {
    if pid == 0 {
        return true;
    }
    std::path::Path::new(&format!("/proc/{pid}")).exists()
}

#[cfg(not(any(windows, unix)))]
fn process_is_alive(_pid: u32) -> bool {
    // Unknown platform: never reclaim a marker, since liveness cannot be proven.
    true
}

impl Drop for TargetLock {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// `.<name>.strhide.lock` next to `target`.
fn lock_path_for(target: &Path) -> PathBuf {
    let name = target
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "carrier".to_string());
    let dir = target
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    dir.join(format!(".{name}.strhide.lock"))
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
    reject_read_only_target(target_path)?;
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

    // Timestamps first, permissions second: a read-only target cannot have its
    // timestamps changed, so restoring the carrier's read-only attribute before
    // this point would drop them silently even though the write succeeded.
    if preserve_time && let Err(e) = filetime::set_file_times(target_path, orig_atime, orig_mtime) {
        eprintln!(
            "warning: failed to preserve file timestamps for '{}': {e}",
            target_path.display()
        );
    }
    if let Err(e) = std::fs::set_permissions(target_path, orig_permissions) {
        eprintln!(
            "warning: failed to restore file permissions for '{}': {e}",
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

    reject_read_only_target(target_path)?;
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

    // Same order as `commit_carrier_bytes`: stamp first, then restore the
    // carrier's read-only attribute.
    if preserve_time && let Err(e) = filetime::set_file_times(target_path, orig_atime, orig_mtime) {
        eprintln!(
            "warning: failed to preserve file timestamps for '{}': {e}",
            target_path.display()
        );
    }
    if let Err(e) = std::fs::set_permissions(target_path, orig_permissions) {
        eprintln!(
            "warning: failed to restore file permissions for '{}': {e}",
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

    reject_read_only_target(path)?;
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

    /// Two writers that pick the same target must not both stage and rename:
    /// the second one fails fast instead of silently replacing the first
    /// envelope. Releasing the guard makes the target writable again.
    #[test]
    fn a_second_writer_on_the_same_target_is_reported_busy() {
        let dir = scratch_dir("target_lock");
        let target = dir.join("carrier.bin");
        std::fs::write(&target, b"carrier").unwrap();

        let marker = dir.join(".carrier.bin.strhide.lock");
        let first = TargetLock::acquire(&target).expect("first lock");
        assert!(marker.exists(), "the marker must appear while held");
        let busy = TargetLock::acquire(&target).expect_err("second lock must fail");
        drop(first);
        assert!(!marker.exists(), "the marker must go away on drop");
        let again = TargetLock::acquire(&target).expect("drop releases the lock");
        drop(again);

        let _ = std::fs::remove_dir_all(dir);
        assert!(
            matches!(busy, StrHideError::TargetBusy(ref path) if path == &target),
            "expected TargetBusy for the contested target, got {busy:?}"
        );
    }

    /// A missing output directory cannot host the marker; acquisition falls
    /// back to unlocked so the commit reports the real filesystem error.
    #[test]
    fn locking_a_target_in_a_missing_directory_is_best_effort() {
        let dir = scratch_dir("target_lock_missing");
        let target = dir.join("absent-dir").join("brand-new.bin");

        let lock = TargetLock::acquire(&target).expect("a missing directory is not fatal");
        drop(lock);

        let _ = std::fs::remove_dir_all(dir);
    }

    /// A read-only target used to fail inside `rename_with_retry`, which
    /// treats Windows' `ERROR_ACCESS_DENIED` like a sharing violation and
    /// finally reports `TargetBusy`. The attribute is detected up front so
    /// callers get a permission error instead of a phantom lock.
    #[test]
    fn read_only_target_is_reported_as_a_permission_problem() {
        let dir = scratch_dir("read_only_target");
        let target = dir.join("target.bin");
        std::fs::write(&target, b"existing").unwrap();
        let mut permissions = std::fs::metadata(&target).unwrap().permissions();
        permissions.set_readonly(true);
        std::fs::set_permissions(&target, permissions).unwrap();

        let err = reject_read_only_target(&target).unwrap_err();

        clear_read_only(&target);
        let _ = std::fs::remove_dir_all(&dir);

        assert!(
            matches!(&err, StrHideError::Io(e) if e.kind() == std::io::ErrorKind::PermissionDenied),
            "a read-only target must not be reported as busy: {err:?}"
        );
        assert!(err.to_string().contains("read-only"), "{err}");
    }

    /// The carrier's read-only attribute is cloned onto the output; stamping
    /// the timestamps after that restore makes the update fail on Windows. The
    /// stamp must happen first, so the cloned timestamps survive.
    #[test]
    fn timestamps_are_stamped_before_restoring_read_only_permissions() {
        let dir = scratch_dir("read_only_time");
        let carrier = dir.join("carrier.bin");
        let out = dir.join("out.bin");
        std::fs::write(&carrier, b"carrier").unwrap();

        let old = filetime::FileTime::from_unix_time(1_000_000_000, 0);
        filetime::set_file_times(&carrier, old, old).unwrap();
        let mut permissions = std::fs::metadata(&carrier).unwrap().permissions();
        permissions.set_readonly(true);
        std::fs::set_permissions(&carrier, permissions).unwrap();

        commit_carrier_bytes(&carrier, &out, b"stego", false, true)
            .expect("a read-only carrier must not block a fresh target output");

        let out_meta = std::fs::metadata(&out).unwrap();
        let out_mtime = filetime::FileTime::from_last_modification_time(&out_meta);
        let out_read_only = out_meta.permissions().readonly();

        clear_read_only(&out);
        clear_read_only(&carrier);
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(
            out_mtime.unix_seconds(),
            old.unix_seconds(),
            "the carrier's timestamps must be stamped before the read-only bit is restored"
        );
        assert!(out_read_only, "the read-only attribute must be cloned");
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

    #[test]
    fn stale_lock_from_a_dead_writer_is_reclaimed() {
        let temp_dir = scratch_dir("stale_lock_reclaim");
        let target = temp_dir.join("carrier.png");
        std::fs::write(&target, b"carrier").unwrap();
        let lock = lock_path_for(&target);
        // u32::MAX is never a live writer on either supported platform.
        std::fs::write(&lock, format!("{}", u32::MAX)).unwrap();

        let guard = TargetLock::acquire(&target).expect("stale marker must not block the write");
        assert!(lock.exists(), "the reclaimed target must be locked again");
        drop(guard);
        assert!(!lock.exists(), "the new guard must remove its marker");

        let _ = std::fs::remove_dir_all(temp_dir);
    }

    #[test]
    fn lock_owned_by_a_live_pid_is_kept() {
        let temp_dir = scratch_dir("live_lock_kept");
        let target = temp_dir.join("carrier.png");
        std::fs::write(&target, b"carrier").unwrap();
        let lock = lock_path_for(&target);
        std::fs::write(&lock, format!("{}", std::process::id())).unwrap();

        let err = TargetLock::acquire(&target).expect_err("a live owner must keep the lock");
        assert!(matches!(err, StrHideError::TargetBusy(_)), "got: {err}");
        assert!(lock.exists(), "the live marker must not be touched");

        let _ = std::fs::remove_dir_all(temp_dir);
    }

    #[test]
    fn unreadable_lock_payload_is_not_reclaimed() {
        let temp_dir = scratch_dir("garbage_lock_kept");
        let target = temp_dir.join("carrier.png");
        std::fs::write(&target, b"carrier").unwrap();
        let lock = lock_path_for(&target);
        // A writer that was killed between `create_new` and writing its PID
        // leaves an empty/garbage marker; liveness cannot be proven, so keep it.
        std::fs::write(&lock, b"not-a-pid").unwrap();

        let err = TargetLock::acquire(&target).expect_err("unknown marker stays");
        assert!(matches!(err, StrHideError::TargetBusy(_)), "got: {err}");

        let _ = std::fs::remove_dir_all(temp_dir);
    }
}
