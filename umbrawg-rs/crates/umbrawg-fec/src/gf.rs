const MODULUS: u16 = 0x11d;
const ORDER: usize = 255;
const EXP_LEN: usize = 512;

struct Tables {
    exp: [u8; EXP_LEN],
    log: [u8; 256],
}

const fn build_tables() -> Tables {
    let mut exp = [0u8; EXP_LEN];
    let mut log = [0u8; 256];
    let mut value: u16 = 1;
    let mut power = 0;
    while power < ORDER {
        exp[power] = value as u8;
        log[value as usize] = power as u8;
        value <<= 1;
        if value & 0x100 != 0 {
            value ^= MODULUS;
        }
        power += 1;
    }
    let mut index = ORDER;
    while index < EXP_LEN {
        exp[index] = exp[index - ORDER];
        index += 1;
    }
    Tables { exp, log }
}

static TABLES: Tables = build_tables();

fn tables() -> &'static Tables {
    &TABLES
}

pub(crate) fn mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    let table = tables();
    table.exp[usize::from(table.log[usize::from(a)]) + usize::from(table.log[usize::from(b)])]
}

pub(crate) fn inv(a: u8) -> u8 {
    if a == 0 {
        return 0;
    }
    let table = tables();
    table.exp[ORDER - usize::from(table.log[usize::from(a)])]
}

pub(crate) fn mul_add_assign(dst: &mut [u8], src: &[u8], coefficient: u8) {
    if coefficient == 0 {
        return;
    }
    if coefficient == 1 {
        for (d, s) in dst.iter_mut().zip(src.iter()) {
            *d ^= *s;
        }
        return;
    }
    let table = tables();
    let log_coefficient = usize::from(table.log[usize::from(coefficient)]);
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        if *s != 0 {
            *d ^= table.exp[log_coefficient + usize::from(table.log[usize::from(*s)])];
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exp_table_is_a_full_cycle() {
        let table = tables();
        let mut seen = [false; 256];
        for power in 0..ORDER {
            let value = table.exp[power];
            assert_ne!(value, 0, "exp[{power}] must be non-zero");
            assert!(!seen[usize::from(value)], "exp table repeats at {power}");
            seen[usize::from(value)] = true;
        }
        assert!(seen[1..].iter().all(|flag| *flag));
    }

    #[test]
    fn log_and_exp_are_inverse() {
        let table = tables();
        for power in 0..ORDER {
            assert_eq!(usize::from(table.log[usize::from(table.exp[power])]), power);
        }
        assert_eq!(mul(1, 1), 1);
        assert_eq!(mul(1, 0x53), 0x53);
        assert_eq!(mul(0, 0x53), 0);
    }

    #[test]
    fn field_axioms_hold() {
        let values = [1u8, 2, 3, 7, 13, 0x53, 0x8d, 0xfe, 0xff];
        for &a in &values {
            assert_eq!(mul(a, inv(a)), 1);
            for &b in &values {
                assert_eq!(mul(a, b), mul(b, a));
                for &c in &values {
                    assert_eq!(mul(mul(a, b), c), mul(a, mul(b, c)));
                    assert_eq!(mul(a, b ^ c), mul(a, b) ^ mul(a, c));
                }
            }
        }
    }

    #[test]
    fn mul_add_matches_scalar_product() {
        let src = [1u8, 2, 0, 0xff, 0x11];
        for coefficient in [0u8, 1, 2, 0x8d] {
            let mut dst = [0xa5u8; 5];
            mul_add_assign(&mut dst, &src, coefficient);
            for (index, &byte) in src.iter().enumerate() {
                assert_eq!(dst[index], 0xa5 ^ mul(coefficient, byte));
            }
        }
    }

    #[test]
    fn inverse_of_zero_is_zero() {
        assert_eq!(inv(0), 0);
    }
}
