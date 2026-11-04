//! Physical-memory enquiries for admission control.
//!
//! The content engines cannot always know their peak footprint up front, so
//! the callers that run several jobs at once need the machine's own figure
//! rather than a hard-coded budget. `std` has no portable API; the two
//! platforms this project ships on report it directly (`GlobalMemoryStatusEx`
//! on Windows, `/proc/meminfo` on Linux). Everywhere else the answer is
//! `None`, and callers fall back to their conservative single-job limit.

/// Bytes of physical memory currently available to new allocations.
pub fn available_physical_memory() -> Option<u64> {
    imp::available()
}

#[cfg(windows)]
mod imp {
    use std::mem::size_of;

    #[repr(C)]
    struct MemoryStatusEx {
        length: u32,
        memory_load: u32,
        total_phys: u64,
        avail_phys: u64,
        total_page_file: u64,
        avail_page_file: u64,
        total_virtual: u64,
        avail_virtual: u64,
        avail_extended_virtual: u64,
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GlobalMemoryStatusEx(buffer: *mut MemoryStatusEx) -> i32;
    }

    pub(super) fn available() -> Option<u64> {
        let mut status = MemoryStatusEx {
            length: size_of::<MemoryStatusEx>() as u32,
            memory_load: 0,
            total_phys: 0,
            avail_phys: 0,
            total_page_file: 0,
            avail_page_file: 0,
            total_virtual: 0,
            avail_virtual: 0,
            avail_extended_virtual: 0,
        };
        // SAFETY: `status.length` declares the struct's exact size and the
        // pointer is valid for the duration of the call.
        let ok = unsafe { GlobalMemoryStatusEx(&mut status) };
        (ok != 0).then_some(status.avail_phys)
    }
}

#[cfg(target_os = "linux")]
mod imp {
    pub(super) fn available() -> Option<u64> {
        let text = std::fs::read_to_string("/proc/meminfo").ok()?;
        let line = text
            .lines()
            .find_map(|line| line.strip_prefix("MemAvailable:"))?;
        let kb: u64 = line.split_whitespace().next()?.parse().ok()?;
        Some(kb.saturating_mul(1024))
    }
}

#[cfg(not(any(windows, target_os = "linux")))]
mod imp {
    pub(super) fn available() -> Option<u64> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_a_positive_figure_when_the_platform_can() {
        if cfg!(any(windows, target_os = "linux")) {
            assert!(available_physical_memory().is_some_and(|bytes| bytes > 0));
        }
    }
}
