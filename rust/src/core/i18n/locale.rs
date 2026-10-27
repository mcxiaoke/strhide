//! System and environment locale detection.

use crate::core::i18n::Lang;

/// Detect interface language with standard priority chain:
/// 1. Explicit CLI argument `--lang`
/// 2. `STRHIDE_LANG` / `STRHIDE_LANGUAGE` environment variable
/// 3. `config.toml` file `lang` key
/// 4. System OS locale
/// 5. Fallback: English (`Lang::En`)
pub fn detect(cli_lang: Option<&str>, config_lang: Option<&str>) -> Lang {
    cli_lang
        .and_then(Lang::parse)
        .or_else(|| {
            std::env::var("STRHIDE_LANG")
                .ok()
                .or_else(|| std::env::var("STRHIDE_LANGUAGE").ok())
                .and_then(|s| Lang::parse(&s))
        })
        .or_else(|| config_lang.and_then(Lang::parse))
        .or_else(system_lang)
        .unwrap_or(Lang::En)
}

fn system_lang() -> Option<Lang> {
    for var in ["LC_ALL", "LC_MESSAGES", "LANG"] {
        if let Ok(v) = std::env::var(var)
            && let Some(l) = Lang::parse(&v)
        {
            return Some(l);
        }
    }
    #[cfg(windows)]
    {
        if let Some(name) = windows_locale_name()
            && let Some(l) = Lang::parse(&name)
        {
            return Some(l);
        }
    }
    None
}

#[cfg(windows)]
fn windows_locale_name() -> Option<String> {
    use std::os::windows::ffi::OsStringExt;
    const MAX: usize = 85; // LOCALE_NAME_MAX_LENGTH
    let mut buf = [0u16; MAX];
    unsafe extern "system" {
        fn GetUserDefaultLocaleName(lp: *mut u16, cch: i32) -> i32;
    }
    let n = unsafe { GetUserDefaultLocaleName(buf.as_mut_ptr(), MAX as i32) };
    if n <= 1 {
        return None;
    }
    Some(
        std::ffi::OsString::from_wide(&buf[..n as usize - 1])
            .to_string_lossy()
            .into_owned(),
    )
}
