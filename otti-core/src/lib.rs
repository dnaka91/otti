//! # Otti Core
//!
//! Core component of **Otti** that is shared between all other components and serves as building
//! block. The main piece of interest is the [`Account`] and its related data. They describe a
//! single entry in the database and contain all information needed to create new OTPs.

#![deny(rust_2018_idioms, clippy::all, clippy::pedantic)]
#![allow(clippy::inline_always, clippy::missing_errors_doc)]

use std::{collections::BTreeMap, str::FromStr};

pub use key::Key;
pub use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};

#[cfg(feature = "otpurl")]
pub use self::url::ParseError;

pub mod de;
mod key;
#[cfg(feature = "otpurl")]
mod url;

/// Otti account that contains the information to create OTPs for a single service.
#[derive(Serialize, Deserialize)]
#[cfg_attr(test, derive(Debug, PartialEq))]
pub struct Account {
    /// Free form label to describe this account.
    pub label: String,
    /// The secret key to generate correct OTPs.
    pub secret: Key,
    /// Amount of digits to produce as OTP.
    pub digits: u8,
    /// The variation of OTP to use.
    pub otp: Otp,
    /// Algorithm that is used to generate OTPs.
    pub algorithm: Algorithm,
    /// Optional issuer of the OTP account.
    pub issuer: Option<String>,
    /// Additional metadata for Otti.
    pub meta: Metadata,
    /// Additional free-form values, mostly used to carry unsupported import data.
    ///
    /// This allows to keep extra data that would otherwise be lost during import. When exporting
    /// again, all information can be restored.
    #[serde(default)]
    pub extras: BTreeMap<String, Vec<u8>>,
}

#[cfg(feature = "otpurl")]
impl FromStr for Account {
    type Err = crate::url::ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        crate::url::parse(s)
    }
}

/// Base information about the OTP used. The most common are HOTP and TOTP but there are many
/// platform specific variations in the wild, like for Steam.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, PartialOrd))]
pub enum Otp {
    /// Counter based, using a counter as base of the OTP generation.
    ///
    /// Generally not recommended, as the counter must be kept in sync between different clients.
    Hotp {
        /// Atomic counter that serves as calculation base for new OTPs. Incremented by `1` after
        /// each use.
        counter: u64,
    },
    /// Time based, using the current time with a maximum delay (the `window`).
    ///
    /// Generated OTPs are considered valid from the point of generation until the window, which
    /// describes seconds, has passed. As there can be timing differences between client and server,
    /// it is common that the server accepts at least 1-2 old OTPs. Otherwise the input could fail
    /// due to being generated at the end of the window, giving no time for the user to copy in and
    /// send the OTP.
    Totp {
        /// Seconds that an OTP is considered valid.
        window: u64,
    },
    /// Steam specific OTP, very similar to [`Self::Totp`] but uses a different alphabet to generate
    /// codes.
    Steam {
        /// Same as the `window` in a TOTP, describing the amount of time in seconds an OTP is
        /// considered valid.
        period: u64,
    },
}

/// Algorithm used in the OTP generation to create the final code.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, PartialOrd))]
pub enum Algorithm {
    /// SHA-1 algorithm, most common.
    Sha1,
    /// SHA(2)-256 algorithm.
    Sha256,
    /// SHA(2)-512 algorithm.
    Sha512,
}

/// Additional metadata that is specific to **Otti** and mostly user provided.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, PartialOrd))]
pub struct Metadata {
    /// Free list of tags to classify or group accounts.
    pub tags: Vec<String>,
}
