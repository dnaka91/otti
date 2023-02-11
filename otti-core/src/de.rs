//! Custom (de-)serialization implementations for [`serde`].

pub mod base32_string {
    //! (De-)serialization support for raw byte data as Base32 string.

    use std::fmt;

    use serde::{
        de::{self, Deserializer, Visitor},
        ser::Serializer,
    };

    /// Serialize a byte slice as Base32 string.
    pub fn serialize<S>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&data_encoding::BASE32_NOPAD.encode(value))
    }

    /// Deserialize a Base32 string back into a byte slice.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(Base32StringVisitor)
    }

    struct Base32StringVisitor;

    impl<'de> Visitor<'de> for Base32StringVisitor {
        type Value = Vec<u8>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("bytes encoded as Base32 string")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            data_encoding::BASE32_NOPAD
                .decode(v.as_bytes())
                .map_err(|e| de::Error::custom(format!("failed decoding `{v}`: {e}")))
        }
    }
}
