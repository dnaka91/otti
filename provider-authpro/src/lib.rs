use std::convert::{TryFrom, TryInto};

use aes::{
    cipher::{
        block_padding::Pkcs7,
        generic_array::{ArrayLength, GenericArray},
        BlockDecryptMut, BlockEncryptMut, KeyIvInit,
    },
    Aes256,
};
use bytes::{Buf, BufMut};
use hmac::Hmac;
use otti_core::{ExposeSecret, Key};
use rand::{Rng, RngCore};
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use sha1::Sha1;

mod de;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("the import data is too short")]
    InputTooShort,
    #[error("data decryption failed")]
    Aes(#[from] block_padding::UnpadError),
    #[error("JSON (de-)serialization failed")]
    Json(#[from] serde_json::Error),
    #[error("the OTP type `{0:?}` is not supported yet")]
    UnsupportedOtpType(OtpType),
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Backup {
    authenticators: Vec<Authenticator>,
    categories: Vec<Category>,
    authenticator_categories: Vec<AuthenticatorCategory>,
    custom_icons: Vec<CustomIcon>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Authenticator {
    #[serde(rename = "Type")]
    ty: OtpType,
    icon: Option<String>,
    issuer: String,
    username: String,
    #[serde(with = "otti_core::de::base32_string")]
    secret: Vec<u8>,
    algorithm: Algorithm,
    digits: u8,
    period: u64,
    counter: u64,
    ranking: u64,
}

struct AuthenticatorWithCategories<'a>(Authenticator, Vec<&'a Category>);

impl<'a> TryFrom<AuthenticatorWithCategories<'a>> for otti_core::Account {
    type Error = Error;

    fn try_from(ac: AuthenticatorWithCategories<'a>) -> Result<Self, Self::Error> {
        let (a, c) = (ac.0, ac.1);

        Ok(Self {
            label: a.username,
            secret: Key::new(a.secret),
            digits: a.digits,
            otp: match a.ty {
                OtpType::Hotp => otti_core::Otp::Hotp { counter: a.counter },
                OtpType::Totp => otti_core::Otp::Totp { window: a.period },
                OtpType::Steam => otti_core::Otp::Steam { period: a.period },
                OtpType::Motp => return Err(Error::UnsupportedOtpType(a.ty)),
            },
            algorithm: a.algorithm.into(),
            issuer: Some(a.issuer),
            meta: otti_core::Metadata {
                tags: c.iter().map(|c| c.name.clone()).collect(),
            },
        })
    }
}

impl From<&otti_core::Account> for Authenticator {
    fn from(a: &otti_core::Account) -> Self {
        Self {
            ty: match a.otp {
                otti_core::Otp::Hotp { .. } => OtpType::Hotp,
                otti_core::Otp::Totp { .. } => OtpType::Totp,
                otti_core::Otp::Steam { .. } => OtpType::Steam,
            },
            icon: None,
            issuer: a.issuer.clone().unwrap_or_default(),
            username: a.label.clone(),
            secret: a.secret.expose_secret().clone(),
            algorithm: a.algorithm.into(),
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
            ranking: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum OtpType {
    Hotp = 1,
    Totp = 2,
    Motp = 3,
    Steam = 4,
}

#[derive(Clone, Copy, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
enum Algorithm {
    Sha1 = 0,
    Sha256 = 1,
    Sha512 = 2,
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

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Category {
    id: String,
    name: String,
    ranking: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct AuthenticatorCategory {
    category_id: String,
    #[serde(with = "otti_core::de::base32_string")]
    authenticator_secret: Vec<u8>,
    ranking: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct CustomIcon {
    id: String,
    #[serde(with = "de::base64_string")]
    data: Vec<u8>,
}

/// Fixed header present at the start of an encrypted backup.
const HEADER: &str = "AuthenticatorPro";
/// Amount of rounds for [`pbkdf2`] key derivation.
const PBKDF2_ROUNDS: u32 = 64000;
/// Size of the key for AES en-/decryption.
const KEY_SIZE: usize = 32;
/// Size of the salt used in the key derivation.
const SALT_SIZE: usize = 20;
/// Size of the initialization vector for AES en-/decryption.
const BLOCK_SIZE: usize = 16;

fn decrypt(data: &mut impl Buf, password: impl AsRef<[u8]>) -> Result<Vec<u8>, Error> {
    if data.remaining() <= HEADER.len() + SALT_SIZE + BLOCK_SIZE {
        return Err(Error::InputTooShort);
    }

    let header = data.copy_to_bytes(HEADER.len());
    if header != HEADER.as_bytes() {}

    let pbkdf2_salt = data.copy_to_bytes(SALT_SIZE);
    let aes_iv = data.copy_to_bytes(BLOCK_SIZE);

    let mut key = [0_u8; KEY_SIZE];

    pbkdf2::pbkdf2::<Hmac<Sha1>>(password.as_ref(), &pbkdf2_salt, PBKDF2_ROUNDS, &mut key);

    let key = GenericArray::from_slice(&key);
    let aes_iv = GenericArray::from_slice(&aes_iv);

    let cipher = <cbc::Decryptor<Aes256>>::new(key, aes_iv);

    cipher
        .decrypt_padded_vec_mut::<Pkcs7>(data.chunk())
        .map_err(Into::into)
}

fn encrypt(wr: &mut impl BufMut, data: &[u8], password: impl AsRef<[u8]>) -> Result<(), Error> {
    let pbkdf2_salt = random_salt();
    let aes_iv = random_array();

    let mut key = [0_u8; KEY_SIZE];

    pbkdf2::pbkdf2::<Hmac<Sha1>>(password.as_ref(), &pbkdf2_salt, PBKDF2_ROUNDS, &mut key);

    let key = GenericArray::from_slice(&key);
    let cipher = <cbc::Encryptor<Aes256>>::new(key, &aes_iv);

    let buf = cipher.encrypt_padded_vec_mut::<Pkcs7>(data);

    wr.put(HEADER.as_bytes());
    wr.put(&pbkdf2_salt[..]);
    wr.put(&aes_iv[..]);
    wr.put(&buf[..]);

    Ok(())
}

fn random_salt() -> [u8; SALT_SIZE] {
    if cfg!(test) {
        [0; SALT_SIZE]
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
    let Backup {
        authenticators,
        categories,
        authenticator_categories,
        ..
    } = match password {
        Some(pw) => {
            let buf = decrypt(data, pw)?;
            serde_json::from_slice::<Backup>(&buf)?
        }
        None => serde_json::from_reader::<_, Backup>(data.reader())?,
    };

    authenticators
        .into_iter()
        .map(|auth| {
            let categories = authenticator_categories
                .iter()
                .filter(|ac| ac.authenticator_secret == auth.secret)
                .filter_map(|ac| categories.iter().find(|cat| cat.id == ac.category_id))
                .collect();

            AuthenticatorWithCategories(auth, categories).try_into()
        })
        .collect()
}

pub fn save(
    buf: &mut impl BufMut,
    data: &[otti_core::Account],
    password: Option<impl AsRef<[u8]>>,
) -> Result<(), Error> {
    let json = serde_json::to_vec(&Backup {
        authenticators: data.iter().map(Into::into).collect(),
        categories: vec![],
        authenticator_categories: vec![],
        custom_icons: vec![],
    })?;

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
        let file = include_bytes!("../import/backup.json");
        let accounts = load(&mut &file[..], None::<&str>).unwrap();

        let mut file = Vec::new();
        save(&mut file, &accounts, None::<&str>).unwrap();

        load(&mut file.as_slice(), None::<&str>).unwrap();
    }

    #[test]
    fn roundtrip_encrypted() {
        let file = include_bytes!("../import/backup.authpro");
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
        let expected = json! {{
            "Authenticators": [{
                "Type": 2,
                "Icon": null,
                "Issuer": "Provider 1",
                "Username": "Entry 1",
                "Secret": "AAAAAAAAAAAAAAAA",
                "Algorithm": 0,
                "Digits": 6,
                "Period": 30,
                "Counter": 0,
                "Ranking": 0
            }],
            "Categories": [],
            "AuthenticatorCategories": [],
            "CustomIcons": []
        }};

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
            65, 117, 116, 104, 101, 110, 116, 105, 99, 97, 116, 111, 114, 80, 114, 111, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 155, 189, 28, 124, 174, 147, 211, 183, 46, 183, 109, 25, 58, 172, 146, 42,
            126, 81, 228, 60, 142, 32, 122, 183, 102, 21, 231, 171, 49, 153, 226, 5, 150, 184, 135,
            140, 210, 53, 152, 15, 35, 182, 39, 86, 245, 150, 218, 245, 195, 91, 1, 124, 75, 206,
            163, 81, 207, 108, 39, 84, 41, 9, 106, 59, 247, 42, 220, 229, 72, 172, 81, 162, 227,
            24, 249, 196, 54, 28, 193, 29, 107, 221, 186, 66, 194, 111, 218, 210, 179, 192, 143,
            162, 210, 77, 84, 93, 224, 151, 163, 240, 181, 31, 82, 247, 20, 118, 28, 165, 247, 100,
            168, 180, 111, 123, 111, 151, 72, 175, 109, 165, 5, 151, 6, 44, 126, 207, 36, 251, 227,
            95, 158, 29, 237, 99, 65, 21, 237, 162, 97, 185, 110, 154, 40, 214, 61, 104, 206, 48,
            181, 130, 240, 222, 195, 16, 85, 46, 61, 83, 102, 14, 41, 45, 83, 194, 216, 98, 114,
            113, 107, 213, 224, 67, 23, 2, 174, 134, 211, 206, 255, 149, 58, 148, 131, 163, 150,
            203, 43, 81, 218, 86, 29, 11, 48, 125, 119, 253, 19, 16, 255, 165, 204, 151, 128, 71,
            193, 47, 209, 172, 245, 53, 72, 204, 196, 128, 123, 245, 120, 57, 76, 57, 70, 23, 202,
            216, 108, 182, 246, 35, 177, 164, 211, 26, 200, 136, 226, 90, 55, 199, 173, 233,
        ];

        assert_eq!(expected, export.as_slice());
    }
}
