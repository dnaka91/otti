//! # Otti Gen(erator)
//!
//! Generator component of the **Otti** OTP manager. It allows to create new OTPs for any account
//! from the [`otti_core`] component.

#![deny(rust_2018_idioms, clippy::all, clippy::pedantic)]
#![allow(clippy::missing_errors_doc, clippy::cast_possible_truncation)]

use std::{
    fmt::{self, Display},
    time::{SystemTimeError, UNIX_EPOCH},
};

use hmac::{
    crypto_mac::InvalidKeyLength,
    digest::{BlockInput, FixedOutput, Reset, Update},
    Hmac, Mac, NewMac,
};
use otti_core::ExposeSecret;
pub use otti_core::{Key, Otp};
pub use sha1::Sha1;
pub use sha2::{Sha256, Sha512};

/// Most common amount of digits for OTPs.
const DEFAULT_DIGITS: u8 = 6;
/// Default amount of "digits" for the [`Otp::Steam`] variant. The name digits is misleading as this
/// variant uses a mixture of alphanumeric characters.
const DEFAULT_STEAM_DIGITS: u8 = 5;

/// Alphabet for the [`Otp::Steam`] variant.
const STEAM_CHARS: &[char] = &[
    '2', '3', '4', '5', '6', '7', '8', '9', 'B', 'C', 'D', 'F', 'G', 'H', 'J', 'K', 'M', 'N', 'P',
    'Q', 'R', 'T', 'V', 'W', 'X', 'Y',
];

/// Errors that can occur when generating an OTP.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Failed to get a timestamp from the system.
    #[error("failed to get time since unix epoch")]
    Time(#[from] SystemTimeError),
    /// The provided key was too short.
    #[error("the given key is too short")]
    KeyLength(#[from] InvalidKeyLength),
}

/// A digest like [`Sha1`] that allows to create a hash of fixed sized over any kind of input that
/// can be represented as raw bytes.
pub trait Digest: Update + BlockInput + FixedOutput + Reset + Default + Clone {}

impl Digest for Sha1 {}
impl Digest for Sha256 {}
impl Digest for Sha512 {}

/// Create a new OTP from the given `key`, `otp` variant and optional amount of `digits`.
///
/// This operation may fail if the key is too short or the system wasn't able to provide the current
/// time (depending on the OTP variant used).
pub fn generate<D: Digest>(key: &Key, otp: &Otp, digits: Option<u8>) -> Result<OtpCode, Error> {
    let digits = digits.unwrap_or(match otp {
        Otp::Hotp { .. } | Otp::Totp { .. } => DEFAULT_DIGITS,
        Otp::Steam { .. } => DEFAULT_STEAM_DIGITS,
    });

    let code = match otp {
        Otp::Hotp { counter } => {
            generate_hotp::<D>(key.expose_secret(), *counter, digits)?.to_string()
        }
        Otp::Totp { window } => {
            generate_totp::<D>(key.expose_secret(), *window, digits)?.to_string()
        }
        Otp::Steam { period } => generate_steam::<D>(key.expose_secret(), *period, digits)?,
    };

    Ok(OtpCode { code, digits })
}

fn generate_hotp<D: Digest>(key: &[u8], counter: u64, digits: u8) -> Result<u32, Error> {
    let digest = mac::<D>(key, counter)?;
    let code = digit(&digest, digits);

    Ok(code)
}

fn generate_totp<D: Digest>(key: &[u8], window: u64, digits: u8) -> Result<u32, Error> {
    let time = UNIX_EPOCH.elapsed()?.as_secs();
    generate_hotp::<D>(key, time / window, digits)
}

fn generate_steam<D: Digest>(key: &[u8], period: u64, digits: u8) -> Result<String, Error> {
    let mut code = generate_totp::<D>(key, period, digits)?;
    let mut steam = String::with_capacity(digits as usize);

    for _ in 0..digits {
        steam.push(STEAM_CHARS[code as usize % STEAM_CHARS.len()]);
        code /= STEAM_CHARS.len() as u32;
    }

    Ok(steam)
}

fn mac<D: Digest>(key: &[u8], counter: u64) -> Result<[u8; 20], Error> {
    let mut digest = [0_u8; 20];

    let mut mac = <Hmac<D>>::new_from_slice(key)?;
    mac.update(&counter.to_be_bytes());
    digest.copy_from_slice(&mac.finalize().into_bytes()[..20]);

    Ok(digest)
}

fn digit(bytes: &[u8; 20], digits: u8) -> u32 {
    let offset = (bytes[19] & 0xf) as usize;
    let bin_code = (u32::from(bytes[offset]) & 0x7f) << 24
        | u32::from(bytes[offset + 1]) << 16
        | u32::from(bytes[offset + 2]) << 8
        | u32::from(bytes[offset + 3]);

    bin_code % 10_u32.pow(u32::from(digits))
}

/// A generated OTP code that can be used to verify identity against a service.
///
/// It contains the code as well as the amount of digits as the generated code might be shorter than
/// the needed amount of digits and must be shifted with zeroes to fullfill the length.
///
/// Call `to_string()` on an instance to get the final code.
pub struct OtpCode {
    /// Generated code as string. Some variants use characters instead of just numbers. Therefore,
    /// the code is kept as string to allow more flexibility.
    pub code: String,
    /// The desired amount of digits of the OTP. The `code` may be shorter in case it's directly
    /// converted from an integer and must be shifted with `0`es in the final representation.
    pub digits: u8,
}

impl Display for OtpCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:0>1$}", self.code, self.digits as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::DEFAULT_DIGITS;

    #[test]
    fn digit() {
        let bytes = [
            0x1f, 0x86, 0x98, 0x69, 0x0e, 0x02, 0xca, 0x16, 0x61, 0x85, 0x50, 0xef, 0x7f, 0x19,
            0xda, 0x8e, 0x94, 0x5b, 0x55, 0x5a,
        ];

        assert_eq!(872_921, super::digit(&bytes, DEFAULT_DIGITS));
    }

    #[test]
    fn code_display() {
        let code = super::OtpCode {
            code: "123".to_owned(),
            digits: 6,
        };
        assert_eq!("000123", code.to_string());
    }
}
