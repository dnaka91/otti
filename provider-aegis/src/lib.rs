//! # Otti - Provier `Aegis`
//!
//! Import/Export component that allows to transform between the Otti accounts and backups from/to
//! the [`Aegis Authenticator`](https://github.com/beemdevelopment/Aegis).

use std::collections::BTreeMap;

use aes_gcm::{
    aead::generic_array::{ArrayLength, GenericArray},
    AeadInPlace, Aes256Gcm, NewAead,
};
pub use bytes::{Buf, BufMut};
use otti_core::{ExposeSecret, Key};
#[cfg(not(test))]
use rand::prelude::*;
use scrypt::Params as ScryptParams;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

mod de;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("JSON (de-)serialization failed")]
    Json(#[from] serde_json::Error),
    #[error("data en-/decryption failed")]
    Aead(#[from] aes_gcm::Error),
    #[error("the backup file can't be opened with a password")]
    NoPasswordEntry,
    #[error("scrypt output length invalid")]
    ScryptLength(#[from] scrypt::errors::InvalidOutputLen),
    #[error("invalid scrypt parameters")]
    ScryptParams(#[from] scrypt::errors::InvalidParams),
}

#[derive(Debug, Serialize, Deserialize)]
struct Export {
    version: u8,
    header: Header,
    #[serde(with = "de::base64_string")]
    db: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Header {
    slots: Vec<Slot>,
    params: KeyParams,
}

#[derive(Debug, Serialize, Deserialize)]
struct Slot {
    #[serde(rename = "type")]
    ty: u8,
    uuid: String,
    #[serde(with = "de::hex_string")]
    key: Vec<u8>,
    key_params: KeyParams,
    #[serde(flatten)]
    password_slot: Option<PasswordSlot>,
}

const SLOT_TYPE_PASSWORD: u8 = 1;

#[derive(Debug, Serialize, Deserialize)]
struct PasswordSlot {
    n: u32,
    r: u32,
    p: u32,
    #[serde(with = "de::hex_string")]
    salt: Vec<u8>,
    repaired: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct KeyParams {
    #[serde(with = "de::hex_string")]
    nonce: Vec<u8>,
    #[serde(with = "de::hex_string")]
    tag: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Vault {
    version: u8,
    entries: Vec<Entry>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Entry {
    #[serde(flatten, rename = "type")]
    ty: EntryType,
    uuid: String,
    name: String,
    issuer: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    group: Option<String>,
    #[serde(with = "de::base64_string::option")]
    icon: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    icon_mime: Option<String>,
    note: String,
}

const EXTRA_ICON: &str = "aegis/icon";
const EXTRA_ICON_MIME: &str = "aegis/icon_mime";
const EXTRA_NOTE: &str = "aegis/note";

impl From<Entry> for otti_core::Account {
    fn from(e: Entry) -> Self {
        let (info, otp) = match e.ty {
            EntryType::Hotp { info, counter } => (info, otti_core::Otp::Hotp { counter }),
            EntryType::Totp { info, period } => (info, otti_core::Otp::Totp { window: period }),
            EntryType::Steam { info, period } => (info, otti_core::Otp::Steam { period }),
        };

        let mut extras = BTreeMap::new();
        if let Some(icon) = e.icon {
            extras.insert(EXTRA_ICON.to_owned(), icon);
        }
        if let Some(icon_mime) = e.icon_mime {
            extras.insert(EXTRA_ICON_MIME.to_owned(), icon_mime.into_bytes());
        }
        if !e.note.is_empty() {
            extras.insert(EXTRA_NOTE.to_owned(), e.note.into_bytes());
        }

        Self {
            label: e.name,
            secret: Key::new(info.secret),
            digits: info.digits,
            otp,
            algorithm: info.algo.into(),
            issuer: Some(e.issuer),
            meta: otti_core::Metadata {
                tags: match e.group {
                    Some(g) => vec![g],
                    None => vec![],
                },
            },
            extras,
        }
    }
}

impl From<&otti_core::Account> for Entry {
    fn from(a: &otti_core::Account) -> Self {
        let info = OtpInfo {
            secret: a.secret.expose_secret().clone(),
            algo: a.algorithm.into(),
            digits: a.digits,
        };

        Self {
            ty: match a.otp {
                otti_core::Otp::Hotp { counter } => EntryType::Hotp { info, counter },
                otti_core::Otp::Totp { window } => EntryType::Totp {
                    info,
                    period: window,
                },
                otti_core::Otp::Steam { period } => EntryType::Steam { info, period },
            },
            uuid: random_uuid(),
            name: a.label.clone(),
            issuer: a.issuer.clone().unwrap_or_default(),
            group: a.meta.tags.first().cloned(),
            icon: a.extras.get(EXTRA_ICON).cloned(),
            icon_mime: a
                .extras
                .get(EXTRA_ICON_MIME)
                .cloned()
                .and_then(|v| String::from_utf8(v).ok()),
            note: a
                .extras
                .get(EXTRA_NOTE)
                .cloned()
                .and_then(|v| String::from_utf8(v).ok())
                .unwrap_or_default(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[serde(tag = "type", content = "info")]
enum EntryType {
    Hotp {
        #[serde(flatten)]
        info: OtpInfo,
        counter: u64,
    },
    Totp {
        #[serde(flatten)]
        info: OtpInfo,
        period: u64,
    },
    Steam {
        #[serde(flatten)]
        info: OtpInfo,
        period: u64,
    },
}

#[derive(Debug, Serialize, Deserialize)]
struct OtpInfo {
    #[serde(with = "otti_core::de::base32_string")]
    secret: Vec<u8>,
    algo: Algorithm,
    digits: u8,
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

#[derive(Debug, Serialize, Deserialize)]
struct ExportPlain {
    version: u8,
    header: EmptyHeader,
    db: Vault,
}

#[derive(Default, Debug, Serialize, Deserialize)]
struct EmptyHeader {
    slots: Option<()>,
    params: Option<()>,
}

fn decrypt(data: &mut impl Buf, password: impl AsRef<[u8]>) -> Result<Vec<u8>, Error> {
    let mut export = serde_json::from_reader::<_, Export>(data.reader())?;
    let mut slot = export
        .header
        .slots
        .into_iter()
        .find(|s| s.ty == SLOT_TYPE_PASSWORD)
        .ok_or(Error::NoPasswordEntry)?;

    let PasswordSlot { n, r, p, salt, .. } = slot.password_slot.ok_or(Error::NoPasswordEntry)?;

    let mut key = [0u8; 32];

    scrypt::scrypt(
        password.as_ref(),
        &salt,
        &ScryptParams::new(f64::from(n).log2() as u8, r, p)?,
        &mut key,
    )?;

    let key = GenericArray::from_slice(&key);
    let cipher = Aes256Gcm::new(key);

    let nonce = GenericArray::from_slice(&slot.key_params.nonce);
    let tag = GenericArray::from_slice(&slot.key_params.tag);

    cipher.decrypt_in_place_detached(nonce, &[], &mut slot.key, tag)?;

    let key = GenericArray::from_slice(&slot.key);
    let cipher = Aes256Gcm::new(key);

    let nonce = GenericArray::from_slice(&export.header.params.nonce);
    let tag = GenericArray::from_slice(&export.header.params.tag);

    cipher.decrypt_in_place_detached(nonce, &[], &mut export.db, tag)?;

    Ok(export.db)
}

fn encrypt(wr: &mut impl BufMut, data: &[u8], password: impl AsRef<[u8]>) -> Result<(), Error> {
    let mut data = data.to_owned();

    let salt = random_salt();
    let (log_n, r, p) = (15, 8, 1);

    let mut key = [0u8; 32];

    scrypt::scrypt(
        password.as_ref(),
        &salt,
        &ScryptParams::new(log_n, r, p)?,
        &mut key,
    )?;

    let mut data_key = random_array();

    let data_cipher = Aes256Gcm::new(&data_key);
    let data_nonce = random_array();

    let data_tag = data_cipher.encrypt_in_place_detached(&data_nonce, &[], &mut data)?;

    let slot_key = GenericArray::from_slice(&key);
    let slot_cipher = Aes256Gcm::new(slot_key);
    let slot_nonce = random_array();

    let slot_tag = slot_cipher.encrypt_in_place_detached(&slot_nonce, &[], &mut data_key)?;

    let export = Export {
        version: 1,
        header: Header {
            slots: vec![Slot {
                ty: SLOT_TYPE_PASSWORD,
                uuid: random_uuid(),
                key: data_key.to_vec(),
                key_params: KeyParams {
                    nonce: slot_nonce.to_vec(),
                    tag: slot_tag.to_vec(),
                },
                password_slot: Some(PasswordSlot {
                    n: 2_u32.pow(log_n as u32),
                    r,
                    p,
                    salt: salt.to_vec(),
                    repaired: true,
                }),
            }],
            params: KeyParams {
                nonce: data_nonce.to_vec(),
                tag: data_tag.to_vec(),
            },
        },
        db: data,
    };

    serde_json::to_writer(wr.writer(), &export).map_err(Into::into)
}

#[cfg(not(test))]
fn random_uuid() -> String {
    Uuid::new_v4().to_hyphenated().to_string()
}

#[cfg(test)]
fn random_uuid() -> String {
    Uuid::default().to_hyphenated().to_string()
}

#[cfg(not(test))]
fn random_salt() -> [u8; 32] {
    rand::thread_rng().gen::<[u8; 32]>()
}

#[cfg(test)]
fn random_salt() -> [u8; 32] {
    [0; 32]
}

#[cfg(not(test))]
fn random_array<U: ArrayLength<u8>>() -> GenericArray<u8, U> {
    let mut array = GenericArray::default();
    rand::thread_rng().fill_bytes(&mut array);
    array
}

#[cfg(test)]
fn random_array<U: ArrayLength<u8>>() -> GenericArray<u8, U> {
    GenericArray::default()
}

pub fn load(
    data: &mut impl Buf,
    password: Option<impl AsRef<[u8]>>,
) -> Result<Vec<otti_core::Account>, Error> {
    let vault = match password {
        Some(pw) => {
            let buf = decrypt(data, pw)?;
            serde_json::from_slice::<Vault>(&buf)?
        }
        None => serde_json::from_reader::<_, ExportPlain>(data.reader()).map(|e| e.db)?,
    };

    Ok(vault.entries.into_iter().map(Into::into).collect())
}

pub fn save(
    buf: &mut impl BufMut,
    data: &[otti_core::Account],
    password: Option<impl AsRef<[u8]>>,
) -> Result<(), Error> {
    let vault = Vault {
        version: 2,
        entries: data.iter().map(Into::into).collect::<Vec<Entry>>(),
    };

    match password {
        Some(pw) => {
            let json = serde_json::to_vec(&vault)?;
            encrypt(buf, &json, pw)
        }
        None => {
            let json = serde_json::to_vec(&ExportPlain {
                version: 1,
                header: EmptyHeader::default(),
                db: vault,
            })?;

            buf.put(json.as_ref());
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use maplit::btreemap;
    use pretty_assertions::assert_eq;
    use serde_json::json;

    use super::*;

    #[test]
    fn roundtrip_plain() {
        let file = include_bytes!("../import/aegis-export-plain.json");
        let accounts = load(&mut &file[..], None::<&str>).unwrap();

        let mut file = Vec::new();
        save(&mut file, &accounts, None::<&str>).unwrap();

        load(&mut file.as_slice(), None::<&str>).unwrap();
    }

    #[test]
    fn roundtrip_encrypted() {
        let file = include_bytes!("../import/aegis-export.json");
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
            extras: btreemap! {
                "aegis/icon".to_owned() => vec![1, 2, 3, 4],
                "aegis/icon_mime".to_owned() => b"image/png".to_vec(),
                "aegis/note".to_owned() => b"test".to_vec(),
            },
        }];

        save(&mut export, &data, None::<&str>).unwrap();

        let output = serde_json::from_slice::<serde_json::Value>(&export).unwrap();
        let expected = json! {{
            "version": 1,
            "header": {
                "slots": null,
                "params": null
            },
            "db": {
                "version": 2,
                "entries": [{
                    "type": "totp",
                    "uuid": "00000000-0000-0000-0000-000000000000",
                    "name": "Entry 1",
                    "issuer": "Provider 1",
                    "group": "Tag 1",
                    "note": "test",
                    "icon": "AQIDBA==",
                    "icon_mime": "image/png",
                    "info": {
                        "secret": "AAAAAAAAAAAAAAAA",
                        "algo": "SHA1",
                        "digits": 6,
                        "period": 30
                    }
                }]
            }
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
            extras: btreemap! {
                "aegis/icon".to_owned() => vec![1, 2, 3, 4],
                "aegis/icon_mime".to_owned() => b"image/png".to_vec(),
                "aegis/note".to_owned() => b"test".to_vec(),
            },
        }];

        save(&mut export, &data, Some("123")).unwrap();

        let output = serde_json::from_slice::<serde_json::Value>(&export).unwrap();
        let expected = json! {{
            "version": 1,
            "header": {
                "slots": [{
                    "type": 1,
                    "uuid": "00000000-0000-0000-0000-000000000000",
                    "key": "81b1e678128bb925b48d97aa17184fea69dbcef894265623fa796822d229098f",
                    "key_params": {
                        "nonce": "000000000000000000000000",
                        "tag": "4349fe4a53e9bb0a4e1f601fef84be10"
                    },
                    "n": 32768,
                    "r": 8,
                    "p": 1,
                    "salt": "0000000000000000000000000000000000000000000000000000000000000000",
                    "repaired": true
                }],
                "params": {
                    "nonce": "000000000000000000000000",
                    "tag": "9ea0591d234316df9f29325afa94fedf"
                }
            },
            "db": "tYU2WD8TAgFpbP/hltH4dgYSaq9EhBAvqoCB9wVjF7T/Pt5cPWjNWSiGP0tlNk3VNCSok+TPXQpDPVyi6k17XpGFzjJg6Wx2IbeAwiD9AM+elWvjiI+XD8qeeA8zN2neicBB4Uz1v1Y239nn3x/MVJYolN5BU8LJQbeHPqMnUCJzT/KLVujZgQfM2BkcrOO2jCRyptJCWJjVPcUHmCf5W9VAhtjRbc9x0SzH+lFh/+bRC1EtF28SUpZ8pVuUJE0CE/lY8Wl4x3mHlXKVJJl9ktHQMBW+qgSIygW7WhL1/39d1OIbQdNhkcviNYxng2xPI7P9VKCo0qZNPIIjx6fGGF8CPQw1W3qFqpPJ58rL8mM="
        }};

        assert_eq!(expected, output);
    }
}
