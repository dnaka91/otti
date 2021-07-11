use std::fmt;

use serde::{
    de::{self, Deserializer, Visitor},
    ser::Serializer,
};

pub mod base64_string {
    use super::*;

    pub fn serialize<S>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&base64::encode(value))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(Base64StringVisitor)
    }

    struct Base64StringVisitor;

    impl<'de> Visitor<'de> for Base64StringVisitor {
        type Value = Vec<u8>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("bytes encoded as Base64 string")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            base64::decode(v).map_err(|e| de::Error::custom(e.to_string()))
        }
    }
}
