use std::{collections::BTreeMap, convert::TryFrom, str::FromStr};

use serde::Deserialize;

use crate::{Account, Algorithm, Key, Metadata, Otp};

/// Any error that can happen when parsing an [`Account`](crate::Account) from an URL.
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    /// The input didn't form a valid URL.
    #[error("the URL is not valid")]
    InvalidUrl(#[from] url::ParseError),
    /// An unknown scheme was used in the URL.
    #[error("the scheme `{0}` is not supported, only `otpauth`")]
    InvalidScheme(String),
    /// The host part of the URL was missing.
    #[error("host is missing")]
    MissingHost,
    /// The host part of the URL was unsupported.
    #[error("host (otp type) is `{0}` but only `hotp`, `totp` or `steam` are supported")]
    InvalidHost(String),
    /// Parameters of the URL failed to deserialize.
    #[error("parameters failed to deserialize")]
    Deserialize(#[from] serde_qs::Error),
    /// The input was no proper UTF-8.
    #[error("string is not valid UTF-8")]
    InvalidUtf8(#[from] std::str::Utf8Error),
}

#[derive(Debug, Deserialize)]
struct Params {
    #[serde(with = "super::de::base32_string")]
    secret: Vec<u8>,
    issuer: Option<String>,
    #[serde(default = "default_algorithm")]
    algorithm: ParamsAlgorithm,
    digits: Option<u8>,
    #[serde(default = "default_period")]
    period: u64,
    counter: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(try_from = "&str")]
struct ParamsAlgorithm(Algorithm);

impl TryFrom<&str> for ParamsAlgorithm {
    type Error = String;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Ok(Self(if s.eq_ignore_ascii_case("sha1") {
            Algorithm::Sha1
        } else if s.eq_ignore_ascii_case("sha256") {
            Algorithm::Sha256
        } else if s.eq_ignore_ascii_case("sha512") {
            Algorithm::Sha512
        } else {
            return Err(format!("unsupported algorithm `{}`", s));
        }))
    }
}

#[derive(Clone, Copy, Debug, Deserialize)]
enum OtpType {
    Hotp,
    Totp,
    Steam,
}

impl OtpType {
    fn default_digits(self) -> u8 {
        match self {
            Self::Hotp | Self::Totp => 6,
            Self::Steam => 5,
        }
    }
}

impl FromStr for OtpType {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(if s.eq_ignore_ascii_case("hotp") {
            Self::Hotp
        } else if s.eq_ignore_ascii_case("totp") {
            Self::Totp
        } else if s.eq_ignore_ascii_case("steam") {
            Self::Steam
        } else {
            return Err(ParseError::InvalidHost(s.to_owned()));
        })
    }
}

#[inline(always)]
fn default_algorithm() -> ParamsAlgorithm {
    ParamsAlgorithm(Algorithm::Sha1)
}

#[inline(always)]
fn default_period() -> u64 {
    30
}

pub fn parse(value: &str) -> Result<Account, ParseError> {
    let url = url::Url::parse(value)?;

    if url.scheme() != "otpauth" {
        return Err(ParseError::InvalidScheme(url.scheme().to_owned()));
    }

    let otp_type = url
        .host_str()
        .ok_or(ParseError::MissingHost)?
        .parse::<OtpType>()?;

    let query = url.query().unwrap_or_default();
    let params = serde_qs::from_str::<Params>(query)?;

    let path = url.path();
    let label = path.strip_prefix('/').unwrap_or(path);
    let label = percent_encoding::percent_decode_str(label).decode_utf8()?;

    let mut parts = label.splitn(2, ':');
    let (label, issuer) = if let (Some(issuer), Some(label)) = (parts.next(), parts.next()) {
        (label, Some(issuer))
    } else {
        (label.as_ref(), None)
    };

    Ok(Account {
        label: label.to_owned(),
        secret: Key::new(params.secret),
        digits: params.digits.unwrap_or_else(|| otp_type.default_digits()),
        otp: match otp_type {
            OtpType::Hotp => Otp::Hotp {
                counter: params.counter.unwrap_or_default(),
            },
            OtpType::Totp => Otp::Totp {
                window: params.period,
            },
            OtpType::Steam => Otp::Steam {
                period: params.period,
            },
        },
        algorithm: params.algorithm.0,
        issuer: params.issuer.or_else(|| issuer.map(ToOwned::to_owned)),
        meta: Metadata::default(),
        extras: BTreeMap::default(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Key;

    #[test]
    fn account_from_string() {
        let account= parse("otpauth://totp/Test%20This:me?secret=JBSWY3DPEHPK3PXP&algorithm=sha256&digits=8&period=60").unwrap();
        let expect = Account {
            label: "me".to_owned(),
            secret: Key::new(vec![72, 101, 108, 108, 111, 33, 222, 173, 190, 239]),
            digits: 8,
            otp: Otp::Totp { window: 60 },
            algorithm: Algorithm::Sha256,
            issuer: Some("Test This".to_owned()),
            meta: Metadata::default(),
            extras: BTreeMap::default(),
        };

        assert_eq!(expect, account);
    }
}
