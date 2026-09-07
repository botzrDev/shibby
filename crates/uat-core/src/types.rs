//! Wire newtypes that reject at construction, not later.

use crate::error::TypeError;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

/// Maximum `Deadline` value in milliseconds (`600_000`).
pub const MAX_DEADLINE_MS: u32 = 600_000;

/// Maximum `ContentType` length in bytes.
pub const MAX_CONTENT_TYPE_LEN: usize = 64;

/// Maximum decoded `Credential` length in bytes (`2_048`).
pub const MAX_CREDENTIAL_DECODED_LEN: usize = 2_048;

/// Call identity. Hex on the wire, exactly 32 characters. Generated at `Submit`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct TaskId(u128);

impl TaskId {
    /// Construct from the numeric value (e.g. after generating a random u128).
    #[must_use]
    pub const fn from_u128(value: u128) -> Self {
        Self(value)
    }

    /// Borrow the numeric value.
    #[must_use]
    pub const fn as_u128(self) -> u128 {
        self.0
    }

    /// Parse the 32-character hex wire form.
    pub fn from_hex(s: &str) -> Result<Self, TypeError> {
        if s.len() != 32 {
            return Err(TypeError::TaskIdBadHex);
        }
        if !s.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(TypeError::TaskIdBadHex);
        }
        u128::from_str_radix(s, 16)
            .map(Self)
            .map_err(|_| TypeError::TaskIdBadHex)
    }

    /// Format as 32 lowercase hex characters.
    #[must_use]
    pub fn to_hex(self) -> String {
        format!("{:032x}", self.0)
    }
}

impl Serialize for TaskId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for TaskId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

impl fmt::Display for TaskId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// Callee budget for the task, in milliseconds from receipt of `Submit`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize)]
#[serde(transparent)]
pub struct Deadline(u32);

impl Deadline {
    /// Construct, rejecting values above [`MAX_DEADLINE_MS`].
    pub fn new(ms: u32) -> Result<Self, TypeError> {
        if ms > MAX_DEADLINE_MS {
            return Err(TypeError::DeadlineTooLarge {
                got: ms,
                max: MAX_DEADLINE_MS,
            });
        }
        Ok(Self(ms))
    }

    /// Milliseconds.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

impl<'de> Deserialize<'de> for Deadline {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let ms = u32::deserialize(deserializer)?;
        Self::new(ms).map_err(serde::de::Error::custom)
    }
}

/// MIME-ish content type for the task body. At most 64 bytes.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize)]
#[serde(transparent)]
pub struct ContentType(String);

impl ContentType {
    /// Construct, rejecting lengths above [`MAX_CONTENT_TYPE_LEN`].
    pub fn new(value: impl Into<String>) -> Result<Self, TypeError> {
        let value = value.into();
        let got = value.len();
        if got > MAX_CONTENT_TYPE_LEN {
            return Err(TypeError::ContentTypeTooLong {
                got,
                max: MAX_CONTENT_TYPE_LEN,
            });
        }
        Ok(Self(value))
    }

    /// Borrow the string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for ContentType {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::new(s).map_err(serde::de::Error::custom)
    }
}

/// Bearer credential in the JSON header: base64url, no padding (A1.2.2).
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize)]
#[serde(transparent)]
pub struct Credential(String);

impl Credential {
    /// Construct from a base64url (no padding) string; validates encoding and decoded length.
    pub fn new(encoded: impl Into<String>) -> Result<Self, TypeError> {
        let encoded = encoded.into();
        let decoded = URL_SAFE_NO_PAD
            .decode(encoded.as_bytes())
            .map_err(|_| TypeError::CredentialBadEncoding)?;
        let got = decoded.len();
        if got > MAX_CREDENTIAL_DECODED_LEN {
            return Err(TypeError::CredentialTooLong {
                got,
                max: MAX_CREDENTIAL_DECODED_LEN,
            });
        }
        Ok(Self(encoded))
    }

    /// The base64url wire string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Decode the credential bytes.
    pub fn decode(&self) -> Result<Vec<u8>, TypeError> {
        URL_SAFE_NO_PAD
            .decode(self.0.as_bytes())
            .map_err(|_| TypeError::CredentialBadEncoding)
    }
}

impl<'de> Deserialize<'de> for Credential {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::new(s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_id_accepts_32_hex() {
        let id = TaskId::from_hex("0123456789abcdef0123456789abcdef").unwrap();
        assert_eq!(id.to_hex(), "0123456789abcdef0123456789abcdef");
    }

    #[test]
    fn task_id_rejects_31_hex() {
        assert_eq!(
            TaskId::from_hex("0123456789abcdef0123456789abcde"),
            Err(TypeError::TaskIdBadHex)
        );
    }

    #[test]
    fn task_id_rejects_33_hex() {
        assert_eq!(
            TaskId::from_hex("0123456789abcdef0123456789abcdef0"),
            Err(TypeError::TaskIdBadHex)
        );
    }

    #[test]
    fn deadline_accepts_max() {
        assert!(Deadline::new(MAX_DEADLINE_MS).is_ok());
    }

    #[test]
    fn deadline_rejects_past_max() {
        assert_eq!(
            Deadline::new(MAX_DEADLINE_MS + 1),
            Err(TypeError::DeadlineTooLarge {
                got: MAX_DEADLINE_MS + 1,
                max: MAX_DEADLINE_MS
            })
        );
    }

    #[test]
    fn content_type_accepts_64_bytes() {
        let s = "a".repeat(64);
        assert!(ContentType::new(s).is_ok());
    }

    #[test]
    fn content_type_rejects_65_bytes() {
        let s = "a".repeat(65);
        assert_eq!(
            ContentType::new(s),
            Err(TypeError::ContentTypeTooLong {
                got: 65,
                max: MAX_CONTENT_TYPE_LEN
            })
        );
    }

    #[test]
    fn credential_accepts_2048_decoded() {
        let raw = vec![0u8; MAX_CREDENTIAL_DECODED_LEN];
        let enc = URL_SAFE_NO_PAD.encode(&raw);
        assert!(Credential::new(enc).is_ok());
    }

    #[test]
    fn credential_rejects_2049_decoded() {
        let raw = vec![0u8; MAX_CREDENTIAL_DECODED_LEN + 1];
        let enc = URL_SAFE_NO_PAD.encode(&raw);
        assert_eq!(
            Credential::new(enc),
            Err(TypeError::CredentialTooLong {
                got: MAX_CREDENTIAL_DECODED_LEN + 1,
                max: MAX_CREDENTIAL_DECODED_LEN
            })
        );
    }

    #[test]
    fn credential_rejects_bad_encoding() {
        assert_eq!(
            Credential::new("@@@"),
            Err(TypeError::CredentialBadEncoding)
        );
    }
}
