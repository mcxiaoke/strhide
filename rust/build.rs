use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::SystemTime;

fn find_git_dir() -> Option<PathBuf> {
    for candidate in [Path::new("../.git"), Path::new(".git")] {
        if candidate.is_dir() {
            return Some(candidate.to_path_buf());
        } else if candidate.is_file()
            && let Ok(content) = fs::read_to_string(candidate)
            && let Some(rest) = content.trim().strip_prefix("gitdir:")
        {
            let p = candidate
                .parent()
                .unwrap_or_else(|| Path::new(""))
                .join(rest.trim());
            if p.is_dir() {
                return Some(p);
            }
        }
    }
    None
}

fn get_git_hash() -> String {
    if let Ok(hash) = env::var("STRHIDE_GIT_HASH").or_else(|_| env::var("GIT_HASH")) {
        let trimmed = hash.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }

    let output = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output();

    if let Ok(out) = output
        && out.status.success()
    {
        let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !s.is_empty() {
            return s;
        }
    }

    "unknown".to_string()
}

fn format_utc_timestamp(epoch_secs: u64) -> String {
    let secs = epoch_secs % 60;
    let mins = (epoch_secs / 60) % 60;
    let hours = (epoch_secs / 3600) % 24;
    let days = epoch_secs / 86400; // days since 1970-01-01

    // Howard Hinnant algorithm for civil date from days since 1970-01-01
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    format!("{y:04}-{m:02}-{d:02}T{hours:02}:{mins:02}:{secs:02}Z")
}

fn get_build_time() -> String {
    if let Ok(bt) = env::var("STRHIDE_BUILD_TIME") {
        let trimmed = bt.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }

    if let Ok(source_date) = env::var("SOURCE_DATE_EPOCH")
        && let Ok(secs) = source_date.trim().parse::<u64>()
    {
        return format_utc_timestamp(secs);
    }

    let now_secs = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    format_utc_timestamp(now_secs)
}

fn track_git_changes() {
    println!("cargo:rerun-if-env-changed=STRHIDE_GIT_HASH");
    println!("cargo:rerun-if-env-changed=GIT_HASH");
    println!("cargo:rerun-if-env-changed=STRHIDE_BUILD_TIME");
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");

    if let Some(git_dir) = find_git_dir() {
        let head_path = git_dir.join("HEAD");
        if head_path.exists() {
            println!("cargo:rerun-if-changed={}", head_path.display());
            if let Ok(head_content) = fs::read_to_string(&head_path) {
                let trimmed = head_content.trim();
                if let Some(ref_path) = trimmed.strip_prefix("ref:") {
                    let target = git_dir.join(ref_path.trim());
                    if target.exists() {
                        println!("cargo:rerun-if-changed={}", target.display());
                    }
                }
            }
        }
        let packed_refs = git_dir.join("packed-refs");
        if packed_refs.exists() {
            println!("cargo:rerun-if-changed={}", packed_refs.display());
        }
    }
}

fn main() {
    track_git_changes();

    let git_hash = get_git_hash();
    let build_time = get_build_time();
    let pkg_version = env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.0.0".to_string());

    let version_info = format!("{pkg_version} (commit: {git_hash}, built: {build_time})");

    println!("cargo:rustc-env=STRHIDE_GIT_HASH={git_hash}");
    println!("cargo:rustc-env=STRHIDE_BUILD_TIME={build_time}");
    println!("cargo:rustc-env=STRHIDE_VERSION_INFO={version_info}");
}
