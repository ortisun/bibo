//! Division that rounds half to even, and the integer square root rounded up.

use super::MetricError;

/// Divides and rounds half to even: a result exactly halfway between two integers goes to the
/// even one. So 5 / 2 is 2, 7 / 2 is 4 and -5 / 2 is -2.
///
/// The denominator is a count or a scale and must be positive. `what` names the quantity in the
/// error message.
pub fn divide_half_even(
    numerator: i128,
    denominator: i128,
    what: &'static str,
) -> Result<i128, MetricError> {
    if denominator <= 0 {
        return Err(MetricError::DenominatorNotPositive { what });
    }
    // Floor division: `remainder` is in 0..denominator, also for a negative numerator.
    let floor = numerator.div_euclid(denominator);
    let remainder = numerator.rem_euclid(denominator);
    // Compare the remainder with what is left to the next integer. This is the comparison of
    // `2 * remainder` with `denominator`, written so that it cannot overflow.
    let to_next = denominator - remainder;
    let round_up = remainder > to_next || (remainder == to_next && floor.rem_euclid(2) == 1);
    if round_up {
        floor.checked_add(1).ok_or(MetricError::OutOfRange { what })
    } else {
        Ok(floor)
    }
}

/// The smallest integer whose square is at least `value`.
pub(super) fn square_root_rounded_up(value: u128) -> u128 {
    let floor = value.isqrt();
    // `floor * floor <= value` always holds, so the product cannot overflow.
    if floor * floor == value {
        floor
    } else {
        floor + 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn divide(numerator: i128, denominator: i128) -> i128 {
        divide_half_even(numerator, denominator, "test").expect("valid division")
    }

    #[test]
    fn ties_go_to_the_even_neighbour() {
        assert_eq!(divide(1, 2), 0);
        assert_eq!(divide(3, 2), 2);
        assert_eq!(divide(5, 2), 2);
        assert_eq!(divide(7, 2), 4);
        assert_eq!(divide(-1, 2), 0);
        assert_eq!(divide(-3, 2), -2);
        assert_eq!(divide(-5, 2), -2);
        assert_eq!(divide(-7, 2), -4);
    }

    #[test]
    fn values_off_the_tie_go_to_the_nearest() {
        assert_eq!(divide(0, 7), 0);
        assert_eq!(divide(1, 1), 1);
        assert_eq!(divide(10, 4), 2); // 2.5, tie, even
        assert_eq!(divide(11, 4), 3); // 2.75
        assert_eq!(divide(9, 4), 2); // 2.25
        assert_eq!(divide(-9, 4), -2);
        assert_eq!(divide(-11, 4), -3);
        assert_eq!(divide(1, 3), 0);
        assert_eq!(divide(2, 3), 1);
    }

    #[test]
    fn a_denominator_of_zero_or_below_is_refused() {
        for denominator in [0, -1, i128::MIN] {
            assert_eq!(
                divide_half_even(1, denominator, "test"),
                Err(MetricError::DenominatorNotPositive { what: "test" })
            );
        }
    }

    #[test]
    fn the_extremes_of_the_type_do_not_overflow() {
        assert_eq!(divide(i128::MAX, 1), i128::MAX);
        assert_eq!(divide(i128::MIN, 1), i128::MIN);
        assert_eq!(divide(i128::MAX, i128::MAX), 1);
        assert_eq!(divide(i128::MIN, i128::MAX), -1);
        // i128::MAX is odd: MAX / 2 is a tie at ...63.5, and ...63 is odd, so it goes up.
        assert_eq!(divide(i128::MAX, 2), i128::MAX / 2 + 1);
        assert_eq!(divide(i128::MAX - 1, i128::MAX), 1);
        assert_eq!(divide(1, i128::MAX), 0);
    }

    #[test]
    fn the_square_root_rounds_up() {
        assert_eq!(square_root_rounded_up(0), 0);
        assert_eq!(square_root_rounded_up(1), 1);
        assert_eq!(square_root_rounded_up(2), 2);
        assert_eq!(square_root_rounded_up(4), 2);
        assert_eq!(square_root_rounded_up(5), 3);
        assert_eq!(square_root_rounded_up(9), 3);
        assert_eq!(square_root_rounded_up(u128::MAX), 1 << 64);
    }

    proptest! {
        /// The result is the nearest integer: twice the error never exceeds the denominator.
        #[test]
        fn the_result_is_within_half_of_the_exact_value(
            numerator in -1_000_000_000_000i128..1_000_000_000_000,
            denominator in 1i128..1_000_000,
        ) {
            let result = divide(numerator, denominator);
            let error = (numerator - result * denominator).abs();
            prop_assert!(2 * error <= denominator);
            if 2 * error == denominator {
                prop_assert_eq!(result.rem_euclid(2), 0);
            }
        }

        #[test]
        fn the_rounded_up_root_brackets_the_value(value in 0u128..(1u128 << 100)) {
            let root = square_root_rounded_up(value);
            prop_assert!(root * root >= value);
            prop_assert!(root == 0 || (root - 1) * (root - 1) < value);
        }
    }
}
