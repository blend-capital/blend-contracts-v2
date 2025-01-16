use crate::test_fixture::SCALAR_7;
use soroban_fixed_point_math::FixedPoint;

pub fn assert_approx_eq_abs(a: i128, b: i128, delta: i128) {
    assert!(
        a > b - delta && a < b + delta,
        "assertion failed: `(left != right)` \
         (left: `{:?}`, right: `{:?}`, epsilon: `{:?}`)",
        a,
        b,
        delta
    );
}

/// Assert that `a` is approximately equal to `b` within a relative error of `delta`.
///
/// delta is a percentage such that 15% is 0_1500000
pub fn assert_approx_eq_rel(a: i128, b: i128, delta: i128) {
    let abs_delta = b.fixed_mul_floor(delta, SCALAR_7).unwrap();
    assert_approx_eq_abs(a, b, abs_delta);
}
