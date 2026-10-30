//! Internationalization (i18n) module for strhide.
//!
//! Provides two-letter language representation, thread-local language state,
//! formatting utilities for named placeholders, and message catalogs.

pub mod locale;
pub mod messages;

pub use messages::Msg;

/// Supported user interface languages.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Lang {
    #[default]
    En,
    Zh,
}

impl Lang {
    /// Parse locale string (e.g. "en", "zh", "zh-CN", "zh_Hans", "zh_cn.UTF-8").
    /// Other languages or "C"/"POSIX" fall back to `None` (= default English).
    pub fn parse(s: &str) -> Option<Lang> {
        let head = s.trim().split(['.', '@']).next().unwrap_or("");
        let norm = head.to_ascii_lowercase().replace('_', "-");
        let norm = norm.as_str();
        if norm == "c" || norm == "posix" || norm.is_empty() {
            return None;
        }
        if norm.starts_with("zh") {
            Some(Lang::Zh)
        } else if norm.starts_with("en") {
            Some(Lang::En)
        } else {
            None
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Lang::En => "en",
            Lang::Zh => "zh",
        }
    }
}

use std::sync::atomic::{AtomicU8, Ordering};

static CURRENT_LANG: AtomicU8 = AtomicU8::new(0); // 0 = En, 1 = Zh

/// Set the default interface language across threads.
pub fn set_lang(lang: Lang) {
    CURRENT_LANG.store(
        match lang {
            Lang::En => 0,
            Lang::Zh => 1,
        },
        Ordering::Relaxed,
    );
}

/// Get the current interface language.
pub fn lang() -> Lang {
    match CURRENT_LANG.load(Ordering::Relaxed) {
        1 => Lang::Zh,
        _ => Lang::En,
    }
}

/// Explicit rendering context for GUI / multi-language requests.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RenderCtx {
    pub lang: Lang,
}

impl RenderCtx {
    pub const fn new(lang: Lang) -> Self {
        Self { lang }
    }

    pub fn current() -> Self {
        Self { lang: lang() }
    }
}

/// Declare the bilingual message catalog.
/// Generates `enum Msg` and `(Msg, Lang) -> &'static str` lookup table.
#[macro_export]
macro_rules! i18n_messages {
    (
        $(
            $name:ident:
                en = $en:expr,
                zh = $zh:expr;
        )*
    ) => {
        #[derive(Clone, Copy, PartialEq, Eq, Debug)]
        pub enum Msg {
            $($name,)*
        }

        impl Msg {
            pub const fn id(self) -> &'static str {
                match self {
                    $(Msg::$name => stringify!($name),)*
                }
            }

            pub fn text(self, lang: $crate::core::i18n::Lang) -> &'static str {
                match (self, lang) {
                    $(
                        (Msg::$name, $crate::core::i18n::Lang::En) => $en,
                        (Msg::$name, $crate::core::i18n::Lang::Zh) => $zh,
                    )*
                }
            }
        }

        impl serde::Serialize for Msg {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(self.id())
            }
        }
    };
}

/// Retrieve message text (without arguments) or render with named arguments.
#[macro_export]
macro_rules! t {
    (ctx = $ctx:expr, $msg:path) => {
        $msg.text($ctx.lang).to_string()
    };
    (ctx = $ctx:expr, $msg:path, $($key:ident = $val:expr),+ $(,)?) => {
        $crate::core::i18n::format_msg(
            $msg.text($ctx.lang),
            &[ $( (stringify!($key), &$val as &dyn std::fmt::Display) ),+ ],
        )
    };
    ($msg:path) => {
        $msg.text($crate::core::i18n::lang()).to_string()
    };
    ($msg:path, $($key:ident = $val:expr),+ $(,)?) => {
        $crate::core::i18n::format_msg(
            $msg.text($crate::core::i18n::lang()),
            &[ $( (stringify!($key), &$val as &dyn std::fmt::Display) ),+ ],
        )
    };
}
#[allow(unused_imports)]
pub(crate) use t;

/// Render named placeholders `{name}`; `{{` / `}}` are escaped to literal `{` / `}`.
/// Stream-parsed so argument values containing `}}` or `{}` are not corrupted.
/// Missing arguments panic in debug mode and retain literal placeholder text in release mode.
pub fn format_msg(tpl: &str, args: &[(&str, &dyn std::fmt::Display)]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(tpl.len());
    let mut rest = tpl;
    while !rest.is_empty() {
        let next_brace = rest.find(['{', '}']);
        let pos = match next_brace {
            Some(p) => p,
            None => {
                out.push_str(rest);
                break;
            }
        };
        out.push_str(&rest[..pos]);
        let c = rest[pos..].chars().next().unwrap();
        let after = &rest[pos + c.len_utf8()..];
        if c == '{' {
            if let Some(stripped) = after.strip_prefix('{') {
                out.push('{');
                rest = stripped;
            } else if let Some(end) = after.find('}') {
                let raw_key = after[..end].trim();
                let (key, spec) = match raw_key.split_once(':') {
                    Some((k, s)) => (k.trim(), Some(s.trim())),
                    None => (raw_key, None),
                };
                match args.iter().find(|(k, _)| *k == key) {
                    Some((_, v)) => {
                        // Argument values are type-erased to `&dyn Display`, so
                        // a precision specifier cannot be forwarded to `write!`
                        // directly. Numeric values are the only ones that use
                        // one, and `f64::from_str` round-trips their `Display`
                        // output, so honour `{x:.2}` by re-rendering the parsed
                        // number; everything else keeps plain `Display`
                        // (review R2 P2-7: the specifier used to be dropped and
                        // dry-run percentages printed at full precision).
                        let rendered = v.to_string();
                        let mut wrote = false;
                        if let Some(prec) = spec
                            .and_then(|s| s.strip_prefix('.'))
                            .filter(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
                            .and_then(|p| p.parse::<usize>().ok())
                            && let Ok(num) = rendered.parse::<f64>()
                            && num.is_finite()
                        {
                            wrote = write!(out, "{num:.prec$}").is_ok();
                        }
                        if !wrote {
                            let _ = out.write_str(&rendered);
                        }
                    }
                    None => {
                        debug_assert!(false, "i18n: missing arg `{key}` in template: {tpl}");
                        out.push('{');
                        out.push_str(&after[..end + 1]);
                    }
                }
                rest = &after[end + 1..];
            } else {
                out.push('{');
                rest = after;
            }
        } else {
            // c == '}'
            if let Some(stripped) = after.strip_prefix('}') {
                out.push('}');
                rest = stripped;
            } else {
                out.push('}');
                rest = after;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lang_parse() {
        assert_eq!(Lang::parse("en"), Some(Lang::En));
        assert_eq!(Lang::parse("en_US"), Some(Lang::En));
        assert_eq!(Lang::parse("en-US.UTF-8"), Some(Lang::En));
        assert_eq!(Lang::parse("zh"), Some(Lang::Zh));
        assert_eq!(Lang::parse("zh_CN"), Some(Lang::Zh));
        assert_eq!(Lang::parse("zh-CN.UTF-8"), Some(Lang::Zh));
        assert_eq!(Lang::parse("zh-Hans-CN"), Some(Lang::Zh));
        assert_eq!(Lang::parse("C"), None);
        assert_eq!(Lang::parse("POSIX"), None);
        assert_eq!(Lang::parse("fr_FR"), None);
        assert_eq!(Lang::parse(""), None);
    }

    #[test]
    fn test_format_msg_basic_and_escapes() {
        let tpl = "Hello {name}! Count: {count}. Literal: {{brace}} and }}alone.";
        let res = format_msg(tpl, &[("name", &"Alice"), ("count", &42)]);
        assert_eq!(res, "Hello Alice! Count: 42. Literal: {brace} and }alone.");
    }

    #[test]
    fn test_format_msg_value_contains_braces() {
        let tpl = "Path: {path}";
        let malicious_val = "foo}}bar{{baz}";
        let res = format_msg(tpl, &[("path", &malicious_val)]);
        assert_eq!(res, "Path: foo}}bar{{baz}");
    }

    #[test]
    fn test_format_msg_spec_prefix_stripped() {
        let tpl = "Size: {kib:.1} KiB";
        let res = format_msg(tpl, &[("kib", &"12.3")]);
        assert_eq!(res, "Size: 12.3 KiB");
    }

    #[test]
    fn test_format_msg_precision_applies_to_numbers() {
        // A `f64` argument is rendered through `Display`, so the precision had
        // to be honoured by re-rendering the parsed value; without it the
        // dry-run line printed `12.345678901234567%`.
        let value = 12.3456789_f64;
        assert_eq!(format_msg("~{pct:.2}%", &[("pct", &value)]), "~12.35%");
        assert_eq!(format_msg("{pct:.1}", &[("pct", &0.0_f64)]), "0.0");
        // Text arguments are unaffected.
        assert_eq!(format_msg("{name:.2}", &[("name", &"abc")]), "abc");
    }

    #[test]
    fn test_atomic_lang_cross_thread_and_msg_id() {
        set_lang(Lang::En);
        assert_eq!(lang(), Lang::En);

        // Msg ID stable key test
        assert_eq!(Msg::ErrIo.id(), "ErrIo");
        assert_eq!(Msg::ErrPassword.id(), "ErrPassword");

        // Msg serialization to stable key
        let json = serde_json::to_string(&Msg::ErrPassword).expect("serialize");
        assert_eq!(json, "\"ErrPassword\"");

        // Atomic lang across spawned threads
        set_lang(Lang::Zh);
        let handle = std::thread::spawn(|| {
            assert_eq!(lang(), Lang::Zh);
            let ctx = RenderCtx::current();
            assert_eq!(ctx.lang, Lang::Zh);
        });
        handle.join().unwrap();

        // Restore default
        set_lang(Lang::En);
    }
}
