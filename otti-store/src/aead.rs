use chacha20poly1305::{
    aead::{Aead, OsRng},
    AeadCore, AeadInPlace, KeyInit, XChaCha20Poly1305, XNonce,
};
use typenum::Unsigned;

const NONCE_SIZE: usize = <XChaCha20Poly1305 as AeadCore>::NonceSize::USIZE;
const TAG_SIZE: usize = <XChaCha20Poly1305 as AeadCore>::TagSize::USIZE;

pub fn seal(key: &[u8], data: &[u8]) -> Result<Vec<u8>, super::Error> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_e| super::Error::Crypto)?;
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);

    let mut buf = vec![0; data.len() + NONCE_SIZE + TAG_SIZE];

    let tag = cipher
        .encrypt_in_place_detached(&nonce, &[], &mut buf[NONCE_SIZE..])
        .map_err(|_e| super::Error::Crypto)?;
    buf[..NONCE_SIZE].copy_from_slice(&nonce);
    buf[NONCE_SIZE + data.len()..].copy_from_slice(&tag);

    Ok(buf)
}

pub fn open(key: &[u8], data: &[u8]) -> Result<Vec<u8>, super::Error> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_e| super::Error::Crypto)?;
    let nonce = XNonce::from_slice(&data[..NONCE_SIZE]);

    cipher
        .decrypt(nonce, &data[NONCE_SIZE..])
        .map_err(|_e| super::Error::Crypto)
}
