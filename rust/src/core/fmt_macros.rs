//! Formatting macros shared by the option structs.
//!
//! Every options struct needs the same two manual impls: a `Debug` that
//! redacts credentials and thread pools, and a `PartialEq` that either
//! compares plain fields or compares pools by pointer identity. Spelling
//! those out by hand let the field lists drift apart, so both are generated
//! from one field list instead.

/// Generates a redacting [`std::fmt::Debug`] impl.
///
/// Each field is annotated with how it should render:
///
/// - `plain`: as-is;
/// - `secret`: `Option` mapped to `"<redacted>"`;
/// - `pool`: `Option<Arc<_>>` mapped to `"<ThreadPool>"`;
/// - `pool_present`: `Option<Arc<_>>` rendered as a boolean.
///
/// Field order is the invocation order, matching the struct declaration.
macro_rules! redacted_debug {
    ($ty:ty, $name:literal, $($field:ident : $kind:ident),* $(,)?) => {
        impl std::fmt::Debug for $ty {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_struct($name)
                    $(.field(
                        stringify!($field),
                        &redacted_debug!(@value self.$field, $kind),
                    ))*
                    .finish()
            }
        }
    };
    (@value $value:expr, plain) => { $value };
    (@value $value:expr, secret) => { $value.map(|_| "<redacted>") };
    (@value $value:expr, pool) => { $value.as_ref().map(|_| "<ThreadPool>") };
    (@value $value:expr, pool_present) => { $value.is_some() };
}

/// Generates a [`PartialEq`] impl comparing the listed fields in order.
///
/// The `pool_ptr_eq` tail additionally compares `pool: Option<Arc<_>>` by
/// pointer identity. Structs whose equality deliberately ignores the pool
/// omit it.
#[cfg(feature = "content-base")]
macro_rules! option_partial_eq {
    ($ty:ty, $($field:ident),* $(,)?) => {
        impl PartialEq for $ty {
            fn eq(&self, other: &Self) -> bool {
                true $(&& self.$field == other.$field)*
            }
        }
    };
    ($ty:ty, $($field:ident),* $(,)? ; pool_ptr_eq) => {
        impl PartialEq for $ty {
            fn eq(&self, other: &Self) -> bool {
                true $(&& self.$field == other.$field)*
                    && match (&self.pool, &other.pool) {
                        (None, None) => true,
                        (Some(a), Some(b)) => std::sync::Arc::ptr_eq(a, b),
                        _ => false,
                    }
            }
        }
    };
}

#[cfg(feature = "content-base")]
pub(crate) use option_partial_eq;
pub(crate) use redacted_debug;
