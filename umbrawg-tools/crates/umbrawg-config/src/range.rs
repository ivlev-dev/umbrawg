use std::fmt;
use std::str::FromStr;

use crate::error::Error;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct U16Range {
    lo: u16,
    hi: u16,
}

impl U16Range {
    pub const fn new(lo: u16, hi: u16) -> Self {
        Self { lo, hi }
    }

    pub const fn single(value: u16) -> Self {
        Self {
            lo: value,
            hi: value,
        }
    }

    pub fn from_lo_hi(lo: u16, hi: u16) -> Result<Self, Error> {
        if lo > hi {
            return Err(Error::InvalidRange(format!("{lo}-{hi}")));
        }
        Ok(Self { lo, hi })
    }

    pub const fn lo(self) -> u16 {
        self.lo
    }

    pub const fn hi(self) -> u16 {
        self.hi
    }

    pub const fn is_zero(self) -> bool {
        self.lo == 0 && self.hi == 0
    }

    pub const fn pack(self) -> u32 {
        ((self.hi as u32) << 16) | (self.lo as u32)
    }

    pub const fn unpack(value: u32) -> Self {
        Self {
            lo: (value & 0xffff) as u16,
            hi: (value >> 16) as u16,
        }
    }

    pub fn parse(spec: &str) -> Result<Self, Error> {
        let (lo, hi) = parse_two(spec)?;
        let lo = u16::try_from(lo).map_err(|_| Error::InvalidRange(spec.to_owned()))?;
        let hi = u16::try_from(hi).map_err(|_| Error::InvalidRange(spec.to_owned()))?;
        if lo > hi {
            return Err(Error::InvalidRange(spec.to_owned()));
        }
        Ok(Self { lo, hi })
    }
}

impl fmt::Display for U16Range {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.lo == self.hi {
            write!(f, "{}", self.lo)
        } else {
            write!(f, "{}-{}", self.lo, self.hi)
        }
    }
}

impl FromStr for U16Range {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct U32Range {
    lo: u32,
    hi: u32,
}

impl U32Range {
    pub const fn new(lo: u32, hi: u32) -> Self {
        Self { lo, hi }
    }

    pub const fn single(value: u32) -> Self {
        Self {
            lo: value,
            hi: value,
        }
    }

    pub fn from_lo_hi(lo: u32, hi: u32) -> Result<Self, Error> {
        if lo > hi {
            return Err(Error::InvalidRange(format!("{lo}-{hi}")));
        }
        Ok(Self { lo, hi })
    }

    pub const fn lo(self) -> u32 {
        self.lo
    }

    pub const fn hi(self) -> u32 {
        self.hi
    }

    pub const fn is_zero(self) -> bool {
        self.lo == 0 && self.hi == 0
    }

    pub const fn pack(self) -> u64 {
        ((self.hi as u64) << 32) | (self.lo as u64)
    }

    pub const fn unpack(value: u64) -> Self {
        Self {
            lo: (value & 0xffff_ffff) as u32,
            hi: (value >> 32) as u32,
        }
    }

    pub fn parse(spec: &str) -> Result<Self, Error> {
        let (lo, hi) = parse_two(spec)?;
        let lo = u32::try_from(lo).map_err(|_| Error::InvalidRange(spec.to_owned()))?;
        let hi = u32::try_from(hi).map_err(|_| Error::InvalidRange(spec.to_owned()))?;
        if lo > hi {
            return Err(Error::InvalidRange(spec.to_owned()));
        }
        Ok(Self { lo, hi })
    }
}

impl fmt::Display for U32Range {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.lo == self.hi {
            write!(f, "{}", self.lo)
        } else {
            write!(f, "{}-{}", self.lo, self.hi)
        }
    }
}

impl FromStr for U32Range {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

fn parse_two(spec: &str) -> Result<(u64, u64), Error> {
    let mut parts = spec.splitn(2, '-');
    let lo_text = parts.next().unwrap_or_default();
    if lo_text.is_empty() || !lo_text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Error::InvalidRange(spec.to_owned()));
    }
    let lo = lo_text
        .parse::<u64>()
        .map_err(|_| Error::InvalidRange(spec.to_owned()))?;
    let hi = match parts.next() {
        Some(text) => {
            if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(Error::InvalidRange(spec.to_owned()));
            }
            text.parse::<u64>()
                .map_err(|_| Error::InvalidRange(spec.to_owned()))?
        }
        None => lo,
    };
    Ok((lo, hi))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn u32_range_round_trip() {
        let range = U32Range::parse("61220074-118999195").expect("valid");
        assert_eq!(range.lo(), 61_220_074);
        assert_eq!(range.hi(), 118_999_195);
        assert_eq!(range.to_string(), "61220074-118999195");
        assert_eq!(U32Range::unpack(range.pack()), range);
    }

    #[test]
    fn u32_range_single_value() {
        let range = U32Range::parse("25").expect("valid");
        assert_eq!(range.lo(), range.hi());
        assert_eq!(range.to_string(), "25");
    }

    #[test]
    fn u32_range_rejects_invalid() {
        assert!(U32Range::parse("").is_err());
        assert!(U32Range::parse("10-5").is_err());
        assert!(U32Range::parse("-5").is_err());
        assert!(U32Range::parse("5-").is_err());
        assert!(U32Range::parse("1-2-3").is_err());
        assert!(U32Range::parse("4294967296").is_err());
        assert!(U32Range::parse(" 5").is_err());
        assert!(U32Range::parse("+5").is_err());
    }

    #[test]
    fn u16_range_round_trip() {
        let range = U16Range::parse("10-20").expect("valid");
        assert_eq!(range.pack(), 20 << 16 | 10);
        assert_eq!(U16Range::unpack(range.pack()), range);
        assert_eq!(range.to_string(), "10-20");
    }

    #[test]
    fn u16_range_rejects_overflow() {
        assert!(U16Range::parse("65536").is_err());
        assert!(U16Range::parse("1-70000").is_err());
        assert!(U16Range::parse("0-65535").is_ok());
    }

    #[test]
    fn zero_detection() {
        assert!(U16Range::default().is_zero());
        assert!(U32Range::default().is_zero());
        assert!(!U16Range::single(1).is_zero());
        assert!(!U32Range::single(1).is_zero());
    }
}
