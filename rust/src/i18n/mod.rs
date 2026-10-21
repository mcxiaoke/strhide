//! Internationalization (i18n) module for strhide.
//!
//! Provides two-letter language representation, thread-local language state,
//! formatting utilities for named placeholders, and message catalogs.

pub mod locale;
pub mod messages;

pub use messages::Msg;

use std::cell::Cell;

/// Supported user interface languages.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
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

thread_local! {
    static CURRENT: Cell<Lang> = const { Cell::new(Lang::En) };
}

/// Set the current thread's interface language.
pub fn set_lang(lang: Lang) {
    CURRENT.with(|c| c.set(lang));
}

/// Get the current thread's interface language.
pub fn lang() -> Lang {
    CURRENT.with(Cell::get)
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
            pub fn text(self, lang: $crate::i18n::Lang) -> &'static str {
                match (self, lang) {
                    $(
                        (Msg::$name, $crate::i18n::Lang::En) => $en,
                        (Msg::$name, $crate::i18n::Lang::Zh) => $zh,
                    )*
                }
            }
        }
    };
}

/// Retrieve message text (without arguments) or render with named arguments.
#[macro_export]
macro_rules! t {
    ($msg:path) => {
        $msg.text($crate::i18n::lang()).to_string()
    };
    ($msg:path, $($key:ident = $val:expr),+ $(,)?) => {
        $crate::i18n::format_msg(
            $msg.text($crate::i18n::lang()),
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
                let key = raw_key
                    .split_once(':')
                    .map(|(k, _)| k.trim())
                    .unwrap_or(raw_key);
                match args.iter().find(|(k, _)| *k == key) {
                    Some((_, v)) => {
                        let _ = write!(out, "{v}");
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
}
