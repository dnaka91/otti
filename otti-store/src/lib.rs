//! # Otti Store
//!
//! The storage component for **Otti** manages saving of accounts in a secure manner so that they
//! may only be accessed with the user defined password.

#![deny(rust_2018_idioms, clippy::all, clippy::pedantic)]
#![allow(clippy::missing_errors_doc)]

use std::{
    convert::TryFrom,
    fmt::{self, Display},
    fs::{self, File},
    io::{prelude::*, BufReader, BufWriter},
    path::PathBuf,
};

use directories::ProjectDirs;
use flate2::{
    write::{ZlibDecoder, ZlibEncoder},
    Compression,
};
use orion::{
    aead,
    kdf::{self, Password, Salt},
};
use otti_core::{Account, ExposeSecret};
pub use secrecy::{Secret, SecretString};
use serde::{Deserialize, Serialize};

/// Errors that can occur when sealing or opening an otti store.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Unrecognized version of the store. This can usually only happen if the store was manually
    /// modified by the user.
    #[error("unknown store version {0}")]
    UnknownVersion(u16),
    /// The version of the store is too old and not supported anymore.
    #[error("unsupported store version {0}")]
    UnsupportedVersion(Version),
    /// Failed to find the home directory of the executing user.
    #[error("failed to find the home folder")]
    HomefolderNotFound,
    /// An I/O related error happened.
    #[error("I/O bound error")]
    Io(#[from] std::io::Error),
    /// Encoding of the store data failed.
    #[error("failed to encode content")]
    Encode(#[from] rmp_serde::encode::Error),
    /// Decoding of the store data failed.
    #[error("failed to decode content")]
    Decode(#[from] rmp_serde::decode::Error),
    /// A cryptographic error occurred.
    #[error("cryptographic error")]
    Crypto(#[from] orion::errors::UnknownCryptoError),
    /// The given password to open a store was invalid.
    #[error("password is invalid")]
    InvalidPassword,
}

/// Different versions of the otti store. This enum must be extended and according conversion
/// implemented, whenever the store format has been changed in a breaking manner.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Version {
    /// The current and only format version of the otti store.
    V1,
}

impl Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::V1 => "v1",
        })
    }
}

impl From<Version> for u16 {
    fn from(v: Version) -> Self {
        match v {
            Version::V1 => 1,
        }
    }
}

impl TryFrom<u16> for Version {
    type Error = Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::V1),
            _ => Err(Error::UnknownVersion(value)),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct EncryptedFile {
    salt: Vec<u8>,
    iterations: u32,
    memory: u32,
    data: Vec<u8>,
}

/// Try to open the Otti store with the given password.
pub fn open(password: &SecretString) -> Result<Vec<Account>, Error> {
    let file = File::open(filepath()?)?;
    let mut file = BufReader::new(file);

    let version = read_version(&mut file)?;
    if version != Version::V1 {
        return Err(Error::UnsupportedVersion(version));
    }

    let encrypted = rmp_serde::from_read::<_, EncryptedFile>(&mut file)?;
    let data = decrypt(&encrypted, password)?;
    let data = decompress(&data)?;

    rmp_serde::from_slice(&data).map_err(Into::into)
}

/// Seal the given list of accounts with the provided password.
pub fn seal(accounts: &[Account], password: &SecretString) -> Result<(), Error> {
    let data = rmp_serde::to_vec(accounts)?;
    let data = compress(&data)?;
    let encrypted = encrypt(&data, password)?;
    let path = filepath()?;

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let file = File::create(path)?;
    let mut file = BufWriter::new(file);

    write_version(&mut file, Version::V1)?;
    rmp_serde::encode::write(&mut file, &encrypted)?;

    Ok(())
}

/// Test whether an otti datastore already exists in the current system.
pub fn exists() -> Result<bool, Error> {
    filepath().map(|fp| fp.exists())
}

fn filepath() -> Result<PathBuf, Error> {
    Ok(ProjectDirs::from("rocks", "dnaka91", "otti")
        .ok_or(Error::HomefolderNotFound)?
        .data_dir()
        .join("store.otti"))
}

fn decompress(data: &[u8]) -> Result<Vec<u8>, Error> {
    let mut wr = ZlibDecoder::new(Vec::new());
    wr.write_all(data)?;

    wr.finish().map_err(Into::into)
}

fn compress(data: &[u8]) -> Result<Vec<u8>, Error> {
    let mut wr = ZlibEncoder::new(Vec::new(), Compression::best());
    wr.write_all(data)?;

    wr.finish().map_err(Into::into)
}

fn decrypt(encrypted: &EncryptedFile, password: &SecretString) -> Result<Vec<u8>, Error> {
    let password = Password::from_slice(password.expose_secret().as_bytes())?;
    let salt = Salt::from_slice(&encrypted.salt)?;
    let key = kdf::derive_key(&password, &salt, encrypted.iterations, encrypted.memory, 32)?;

    aead::open(&key, &encrypted.data).map_err(|_e| Error::InvalidPassword)
}

fn encrypt(data: &[u8], password: &SecretString) -> Result<EncryptedFile, Error> {
    let password = Password::from_slice(password.expose_secret().as_bytes())?;
    let salt = Salt::default();
    let key = kdf::derive_key(&password, &salt, 3, 1 << 16, 32)?;

    let data = aead::seal(&key, data)?;

    Ok(EncryptedFile {
        salt: salt.as_ref().to_owned(),
        iterations: 3,
        memory: 1 << 16,
        data,
    })
}

fn read_version(rd: &mut impl Read) -> Result<Version, Error> {
    let mut buf = [0_u8; 2];
    rd.read_exact(&mut buf)?;

    Version::try_from(u16::from_le_bytes(buf))
}

fn write_version(wr: &mut impl Write, version: Version) -> Result<(), Error> {
    wr.write_all(&u16::from(version).to_le_bytes())
        .map_err(Into::into)
}
