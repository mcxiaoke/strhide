//! Unified security, rejection policy, and stealth integration tests suite.
//!
//! Submodules:
//! - `rejection`: carrier safety checks and refusal of signed binaries, JARs, and APKs.
//! - `stealth`: uniform encryption, magic masking, and plausible deniability.
//! - `password_hint`: security boundaries and mutual exclusion of password hints.

#[path = "common/mod.rs"]
pub mod common;

#[path = "test_security/password_hint.rs"]
mod password_hint;
#[path = "test_security/rejection.rs"]
mod rejection;
#[path = "test_security/stealth.rs"]
mod stealth;
