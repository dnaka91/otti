use std::fmt;

use serde::{
    de::{self, Deserializer, Visitor},
    ser::Serializer,
};

pub mod base64_string {
    use base64::engine::{general_purpose, Engine};

    use super::*;

    pub fn serialize<S>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&general_purpose::STANDARD.encode(value))
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
            general_purpose::STANDARD
                .decode(v)
                .map_err(|e| de::Error::custom(e.to_string()))
        }
    }

    pub mod option {
        use super::*;

        pub fn serialize<S>(value: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            match value {
                Some(v) => serializer.serialize_some(&general_purpose::STANDARD.encode(v)),
                None => serializer.serialize_none(),
            }
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
        where
            D: Deserializer<'de>,
        {
            deserializer.deserialize_option(OptionVisitor)
        }

        struct OptionVisitor;

        impl<'de> Visitor<'de> for OptionVisitor {
            type Value = Option<Vec<u8>>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("optional bytes encoded as Base64 string")
            }

            fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
            where
                D: Deserializer<'de>,
            {
                super::deserialize(deserializer).map(Some)
            }

            fn visit_none<E>(self) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(None)
            }
        }
    }
}

pub mod hex_string {
    use super::*;

    pub fn serialize<S>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(value))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(HexStringVisitor)
    }

    struct HexStringVisitor;

    impl<'de> Visitor<'de> for HexStringVisitor {
        type Value = Vec<u8>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("bytes encoded as hexadecimal string")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            hex::decode(v).map_err(|e| de::Error::custom(e.to_string()))
        }
    }
}
