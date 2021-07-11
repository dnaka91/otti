//! # Otti - Provier `andOTP`
//!
//! Import/Export component that allows to transform between the Otti accounts and backups from/to
//! the [`andOTP - Android OTP Authenticator`](https://github.com/andOTP/andOTP).

#![deny(rust_2018_idioms, clippy::all, clippy::pedantic)]
#![allow(clippy::missing_errors_doc, clippy::single_match_else)]

use aes_gcm::{
    aead::generic_array::{ArrayLength, GenericArray},
    AeadInPlace, Aes256Gcm, NewAead,
};
pub use bytes::{Buf, BufMut};
use hmac::Hmac;
use otti_core::{ExposeSecret, Key};
use rand::prelude::*;
use serde::{Deserialize, Serialize};
use sha1::Sha1;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("the import data is too short")]
    InputTooShort,
    #[error("data en-/decryption failed")]
    AesGcm(#[from] aes_gcm::Error),
    #[error("JSON (de-)serialization failed")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Serialize, Deserialize)]
struct Account {
    #[serde(with = "otti_core::de::base32_string")]
    secret: Vec<u8>,
    issuer: String,
    label: String,
    #[serde(default)]
    digits: u8,
    #[serde(default, skip_serializing_if = "is_zero")]
    period: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    counter: u64,
    #[serde(rename = "type")]
    ty: OtpType,
    algorithm: Algorithm,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    tags: Vec<String>,
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_zero(value: &u64) -> bool {
    *value == 0
}

impl From<Account> for otti_core::Account {
    fn from(a: Account) -> Self {
        Self {
            label: a.label,
            secret: Key::new(a.secret),
            digits: a.digits,
            otp: match a.ty {
                OtpType::Hotp => otti_core::Otp::Hotp { counter: a.counter },
                OtpType::Totp => otti_core::Otp::Totp { window: a.period },
                OtpType::Steam => otti_core::Otp::Steam { period: a.period },
            },
            algorithm: a.algorithm.into(),
            issuer: Some(a.issuer),
            meta: otti_core::Metadata { tags: a.tags },
        }
    }
}

impl From<&otti_core::Account> for Account {
    fn from(a: &otti_core::Account) -> Self {
        Self {
            secret: a.secret.expose_secret().clone(),
            issuer: a.issuer.clone().unwrap_or_default(),
            label: a.label.clone(),
            digits: a.digits,
            period: match a.otp {
                otti_core::Otp::Hotp { .. } => 0,
                otti_core::Otp::Totp { window } => window,
                otti_core::Otp::Steam { period } => period,
            },
            counter: match a.otp {
                otti_core::Otp::Hotp { counter } => counter,
                otti_core::Otp::Totp { .. } | otti_core::Otp::Steam { .. } => 0,
            },
            ty: match a.otp {
                otti_core::Otp::Hotp { .. } => OtpType::Hotp,
                otti_core::Otp::Totp { .. } => OtpType::Totp,
                otti_core::Otp::Steam { .. } => OtpType::Steam,
            },
            algorithm: a.algorithm.into(),
            tags: a.meta.tags.clone(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
enum OtpType {
    Totp,
    Hotp,
    Steam,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

impl From<Algorithm> for otti_core::Algorithm {
    fn from(a: Algorithm) -> Self {
        match a {
            Algorithm::Sha1 => Self::Sha1,
            Algorithm::Sha256 => Self::Sha256,
            Algorithm::Sha512 => Self::Sha512,
        }
    }
}

impl From<otti_core::Algorithm> for Algorithm {
    fn from(a: otti_core::Algorithm) -> Self {
        match a {
            otti_core::Algorithm::Sha1 => Self::Sha1,
            otti_core::Algorithm::Sha256 => Self::Sha256,
            otti_core::Algorithm::Sha512 => Self::Sha512,
        }
    }
}

fn decrypt(data: &mut impl Buf, password: impl AsRef<[u8]>) -> Result<Vec<u8>, Error> {
    if data.remaining() <= 28 {
        return Err(Error::InputTooShort);
    }

    let pbkdf2_iterations = data.get_u32();
    let pbkdf2_salt = data.copy_to_bytes(12);
    let aes_iv = data.copy_to_bytes(12);

    let mut key = [0_u8; 32];

    pbkdf2::pbkdf2::<Hmac<Sha1>>(password.as_ref(), &pbkdf2_salt, pbkdf2_iterations, &mut key);

    let key = GenericArray::from_slice(&key);
    let cipher = Aes256Gcm::new(key);

    let aes_iv = GenericArray::from_slice(&aes_iv);

    let mut buf = vec![0_u8; data.remaining()];
    data.copy_to_slice(&mut buf);

    cipher.decrypt_in_place(aes_iv, &[], &mut buf)?;

    Ok(buf)
}

fn encrypt(wr: &mut impl BufMut, data: &[u8], password: impl AsRef<[u8]>) -> Result<(), Error> {
    let pbkdf2_iterations = random_iterations();
    let pbkdf2_salt = random_salt();
    let aes_iv = random_array();

    let mut key = [0_u8; 32];

    pbkdf2::pbkdf2::<Hmac<Sha1>>(password.as_ref(), &pbkdf2_salt, pbkdf2_iterations, &mut key);

    let key = GenericArray::from_slice(&key);
    let cipher = Aes256Gcm::new(key);

    let mut buf = data.to_owned();

    cipher.encrypt_in_place(&aes_iv, &[], &mut buf)?;

    wr.put_u32(pbkdf2_iterations);
    wr.put(&pbkdf2_salt[..]);
    wr.put(&aes_iv[..]);

    wr.put(&buf[..]);

    Ok(())
}

fn random_iterations() -> u32 {
    if cfg!(test) {
        140_000
    } else {
        rand::thread_rng().gen_range(140_000..=160_000)
    }
}

fn random_salt() -> [u8; 12] {
    if cfg!(test) {
        [0; 12]
    } else {
        rand::thread_rng().gen()
    }
}

fn random_array<U: ArrayLength<u8>>() -> GenericArray<u8, U> {
    let mut array = GenericArray::default();
    if cfg!(not(test)) {
        rand::thread_rng().fill_bytes(&mut array);
    }

    array
}

pub fn load(
    data: &mut impl Buf,
    password: Option<impl AsRef<[u8]>>,
) -> Result<Vec<otti_core::Account>, Error> {
    let json = match password {
        Some(pw) => decrypt(data, pw)?,
        None => {
            let mut buf = vec![0_u8; data.remaining()];
            data.copy_to_slice(&mut buf);
            buf
        }
    };

    Ok(serde_json::from_slice::<Vec<Account>>(&json)?
        .into_iter()
        .map(Into::into)
        .collect())
}

pub fn save(
    buf: &mut impl BufMut,
    data: &[otti_core::Account],
    password: Option<impl AsRef<[u8]>>,
) -> Result<(), Error> {
    let json = serde_json::to_vec(&data.iter().map(Into::into).collect::<Vec<Account>>())?;

    match password {
        Some(pw) => encrypt(buf, &json, pw),
        None => {
            buf.put(json.as_ref());
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;
    use serde_json::json;

    use super::*;

    #[test]
    fn roundtrip_plain() {
        let file = include_bytes!("../import/otp_accounts.json");
        let accounts = load(&mut &file[..], None::<&str>).unwrap();

        let mut file = Vec::new();
        save(&mut file, &accounts, None::<&str>).unwrap();

        load(&mut file.as_slice(), None::<&str>).unwrap();
    }

    #[test]
    fn roundtrip_encrypted() {
        let file = include_bytes!("../import/otp_accounts.json.aes");
        let accounts = load(&mut &file[..], Some("123")).unwrap();

        let mut file = Vec::new();
        save(&mut file, &accounts, Some("abc")).unwrap();

        load(&mut file.as_slice(), Some("abc")).unwrap();
    }

    #[test]
    fn export_plain() {
        let mut export = Vec::new();
        let data = [otti_core::Account {
            label: "Entry 1".to_owned(),
            secret: Key::new(vec![0; 10]),
            digits: 6,
            otp: otti_core::Otp::Totp { window: 30 },
            algorithm: otti_core::Algorithm::Sha1,
            issuer: Some("Provider 1".to_owned()),
            meta: otti_core::Metadata {
                tags: vec!["Tag 1".to_owned()],
            },
        }];

        save(&mut export, &data, None::<&str>).unwrap();

        let output = serde_json::from_slice::<serde_json::Value>(&export).unwrap();
        let expected = json! {[{
            "secret": "AAAAAAAAAAAAAAAA",
            "issuer": "Provider 1",
            "label": "Entry 1",
            "digits": 6,
            "type": "TOTP",
            "algorithm": "SHA1",
            "period": 30,
            "tags": ["Tag 1"]
        }]};

        assert_eq!(expected, output);
    }

    #[test]
    fn export_encrypted() {
        let mut export = Vec::new();
        let data = [otti_core::Account {
            label: "Entry 1".to_owned(),
            secret: Key::new(vec![0; 10]),
            digits: 6,
            otp: otti_core::Otp::Totp { window: 30 },
            algorithm: otti_core::Algorithm::Sha1,
            issuer: Some("Provider 1".to_owned()),
            meta: otti_core::Metadata {
                tags: vec!["Tag 1".to_owned()],
            },
        }];

        save(&mut export, &data, Some("123")).unwrap();

        let expected = &[
            0, 2, 34, 224, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            250, 20, 76, 80, 153, 125, 227, 57, 156, 218, 81, 56, 116, 107, 180, 59, 171, 211, 105,
            7, 144, 171, 56, 249, 230, 250, 195, 65, 45, 142, 78, 42, 254, 64, 123, 17, 126, 126,
            172, 61, 188, 31, 229, 97, 172, 244, 91, 119, 78, 12, 156, 108, 204, 188, 109, 27, 203,
            190, 160, 111, 246, 16, 124, 80, 164, 210, 141, 104, 251, 69, 155, 139, 119, 25, 40,
            136, 216, 55, 120, 104, 135, 150, 145, 142, 226, 155, 40, 188, 11, 160, 129, 25, 136,
            172, 155, 95, 137, 12, 2, 176, 208, 72, 49, 192, 113, 117, 143, 66, 184, 184, 182, 208,
            235, 170, 14, 12, 134, 226, 73, 86, 164, 96, 152, 96, 219, 19, 6, 154, 252, 205, 47,
            180, 208, 91, 57, 116, 223, 213, 49, 87, 46, 188, 231, 235, 3, 163, 169, 236, 88, 228,
            119, 186, 100, 147, 97, 57, 252, 112, 245, 228,
        ];

        assert_eq!(expected, export.as_slice());
    }
}
