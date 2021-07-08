use std::fmt;

use secrecy::{ExposeSecret, Zeroize};
use serde::{
    de::{self, Visitor},
    Deserialize, Deserializer, Serialize,
};

/// The key/secret of an **Otti** account that should be kept private as much as possible.
#[cfg_attr(test, derive(Debug, PartialEq))]
pub struct Key(Vec<u8>);

impl Key {
    #[must_use]
    pub fn new(content: Vec<u8>) -> Self {
        Self(content)
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Zeroize for Key {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl ExposeSecret<Vec<u8>> for Key {
    fn expose_secret(&self) -> &Vec<u8> {
        &self.0
    }
}

#[cfg(test)]
impl secrecy::DebugSecret for Key {}

impl Serialize for Key {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(self.expose_secret())
    }
}

impl<'de> Deserialize<'de> for Key {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_byte_buf(KeyVisitor)
    }
}

struct KeyVisitor;

impl<'de> Visitor<'de> for KeyVisitor {
    type Value = Key;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("protected key represented as raw bytes")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Key(Vec::from(v)))
    }

    fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Key(v))
    }
}
