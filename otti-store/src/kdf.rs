use argon2::{password_hash::rand_core::RngCore, Argon2};
use chacha20poly1305::aead::OsRng;

pub struct Password<'a>(&'a [u8]);

impl<'a> Password<'a> {
    pub fn from_slice(value: &'a [u8]) -> Self {
        Self(value)
    }
}

pub struct Salt([u8; argon2::RECOMMENDED_SALT_LEN]);

impl Salt {
    pub fn from_slice(value: &[u8]) -> Result<Self, super::Error> {
        if value.len() != argon2::RECOMMENDED_SALT_LEN {
            return Err(super::Error::Crypto);
        }

        let mut salt = [0; argon2::RECOMMENDED_SALT_LEN];
        salt.copy_from_slice(value);

        Ok(Self(salt))
    }
}

impl Default for Salt {
    fn default() -> Self {
        let mut salt = [0; argon2::RECOMMENDED_SALT_LEN];
        OsRng.fill_bytes(&mut salt);

        Self(salt)
    }
}

impl AsRef<[u8]> for Salt {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

pub fn derive_key(
    password: &Password<'_>,
    salt: &Salt,
    iterations: u32,
    memory: u32,
    size: usize,
) -> Result<Vec<u8>, super::Error> {
    let mut key = vec![0; size];

    Argon2::new(
        argon2::Algorithm::Argon2i,
        argon2::Version::V0x13,
        argon2::Params::new(memory, iterations, 1, Some(size))
            .map_err(|_e| super::Error::Crypto)?,
    )
    .hash_password_into(password.0, &salt.0, &mut key)
    .map_err(|_e| super::Error::Crypto)?;

    Ok(key)
}
