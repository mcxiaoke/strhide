use super::enforce_safety;
use crate::errors::StrHideError;
use crate::stego::{SafetyEnforcement, SafetyLevel, SafetyPolicy};

fn policy(enforcement: SafetyEnforcement) -> SafetyPolicy {
    SafetyPolicy::default()
        .with_level(SafetyLevel::High)
        .with_enforcement(enforcement)
}

#[test]
fn advisory_policy_never_blocks_an_over_tier_payload() {
    let p = policy(SafetyEnforcement::Advisory);
    assert!(enforce_safety(10_000, 4_788, 16_618, p).is_ok());
}

#[test]
fn enforced_policy_blocks_an_over_tier_payload() {
    let p = policy(SafetyEnforcement::Enforced);
    let err = enforce_safety(9_216, 4_788, 16_618, p).expect_err("must be refused");
    assert!(
        matches!(err, StrHideError::SafetyThreshold { .. }),
        "expected SafetyThreshold, got {err:?}"
    );
    let text = err.to_string();
    assert!(text.contains("4788") && text.contains("9216"), "{text}");
}

#[test]
fn enforced_policy_allows_a_payload_at_the_recommended_boundary() {
    let p = policy(SafetyEnforcement::Enforced);
    assert!(enforce_safety(4_788, 4_788, 16_618, p).is_ok());
    assert!(enforce_safety(0, 4_788, 16_618, p).is_ok());
}
