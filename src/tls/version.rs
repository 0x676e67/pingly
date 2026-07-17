use std::fmt;

use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

use super::enums::TlsVersion;

/// A TLS or DTLS protocol version advertised in `supported_versions`.
///
/// The wire identifier is retained alongside the existing [`TlsVersion`] enum representation.
///
/// See [RFC 9846, Section 4.3.1](https://www.rfc-editor.org/rfc/rfc9846.html#section-4.3.1)
/// and [RFC 8701, Section 2](https://www.rfc-editor.org/rfc/rfc8701.html#section-2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Hash)]
pub struct SupportedVersion {
    /// The 16-bit protocol version identifier observed on the wire.
    pub id: u16,

    /// The decoded protocol version enum.
    #[serde(serialize_with = "serialize_version_name")]
    pub name: TlsVersion,
}

fn serialize_version_name<S>(name: &TlsVersion, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match name {
        TlsVersion::Unknown(_) if name.is_grease() => serializer.serialize_str("GREASE"),
        TlsVersion::Unknown(_) => serializer.serialize_str("Unknown"),
        _ => name.serialize(serializer),
    }
}

/// Deserialization form for a version name whose wire ID is stored separately.
#[derive(Deserialize)]
#[serde(untagged)]
enum SupportedVersionNameRepr {
    /// A name whose full value is represented by an existing enum variant.
    Version(TlsVersion),

    /// A generic GREASE or unknown marker resolved from the sibling ID.
    Marker(SupportedVersionMarker),
}

/// Generic names whose numeric value must be recovered from `SupportedVersion::id`.
#[derive(Deserialize)]
enum SupportedVersionMarker {
    /// A GREASE protocol version.
    #[serde(rename = "GREASE")]
    Grease,

    /// An unrecognized non-GREASE protocol version.
    #[serde(rename = "Unknown")]
    Unknown,
}

impl SupportedVersionNameRepr {
    fn matches(self, expected: TlsVersion) -> bool {
        match self {
            Self::Version(version) => version == expected,
            Self::Marker(SupportedVersionMarker::Grease) => expected.is_grease(),
            Self::Marker(SupportedVersionMarker::Unknown) => {
                matches!(expected, TlsVersion::Unknown(_)) && !expected.is_grease()
            }
        }
    }
}

impl SupportedVersion {
    /// Decodes a wire identifier into the existing TLS version enum.
    pub fn from_id(id: u16) -> Self {
        Self {
            id,
            name: TlsVersion::from(id),
        }
    }

    /// Returns the existing TLS version enum for protocol logic and fingerprinting.
    pub fn tls_version(&self) -> TlsVersion {
        TlsVersion::from(self.id)
    }

    /// Returns whether this identifier is reserved for GREASE.
    ///
    /// See [RFC 8701, Section 2](https://www.rfc-editor.org/rfc/rfc8701.html#section-2).
    pub fn is_grease(&self) -> bool {
        self.tls_version().is_grease()
    }

    fn from_serialized_parts(id: u16, name: SupportedVersionNameRepr) -> Result<Self, TlsVersion> {
        let expected = TlsVersion::from(id);
        if name.matches(expected) {
            Ok(Self { id, name: expected })
        } else {
            Err(expected)
        }
    }
}

impl From<u16> for SupportedVersion {
    fn from(id: u16) -> Self {
        Self::from_id(id)
    }
}

impl From<TlsVersion> for SupportedVersion {
    fn from(version: TlsVersion) -> Self {
        Self::from_id(version.value())
    }
}

impl fmt::Display for SupportedVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.name.fmt(formatter)
    }
}

/// Deserialization shape used to validate a saved protocol-version ID and name.
#[derive(Deserialize)]
struct SupportedVersionRepr {
    /// The numeric identifier stored in JSON.
    id: u16,

    /// The protocol version enum stored alongside the identifier.
    name: SupportedVersionNameRepr,
}

impl<'de> Deserialize<'de> for SupportedVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let repr = SupportedVersionRepr::deserialize(deserializer)?;
        let id = repr.id;
        Self::from_serialized_parts(id, repr.name).map_err(|expected| {
            de::Error::custom(format_args!(
                "TLS supported version {id:#06x} must use {expected}, not the saved enum",
            ))
        })
    }
}

/// The client-ordered protocol version list carried by `supported_versions`.
///
/// See [RFC 9846, Section 4.3.1](https://www.rfc-editor.org/rfc/rfc9846.html#section-4.3.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupportedVersions {
    /// Protocol versions in client preference order.
    pub versions: Vec<SupportedVersion>,
}

impl SupportedVersions {
    /// Creates a supported-version list while preserving the supplied order.
    pub fn new(versions: Vec<SupportedVersion>) -> Self {
        Self { versions }
    }

    /// Resolves wire identifiers while preserving their advertised order.
    pub fn from_ids(ids: impl IntoIterator<Item = u16>) -> Self {
        Self::new(ids.into_iter().map(SupportedVersion::from).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::{SupportedVersion, SupportedVersions};
    use crate::tls::TlsVersion;

    #[test]
    fn supported_versions_use_id_and_name_objects() {
        let versions = SupportedVersions::from_ids([0x4a4a, 0x0304, 0x0303]);
        let json = serde_json::to_value(&versions).expect("supported versions serialize");

        assert_eq!(
            json,
            serde_json::json!({
                "versions": [
                    { "id": 19018, "name": "GREASE" },
                    { "id": 772, "name": "TLSv1_3" },
                    { "id": 771, "name": "TLSv1_2" }
                ]
            })
        );
        assert_eq!(
            serde_json::from_value::<SupportedVersions>(json)
                .expect("supported versions deserialize"),
            versions
        );
    }

    #[test]
    fn supported_version_retains_the_enum_and_validates_saved_pairs() {
        let tls13 = SupportedVersion::from(TlsVersion::TLSv1_3);
        assert_eq!(tls13, SupportedVersion::from_id(0x0304));
        assert!(!tls13.is_grease());

        let mismatched = SupportedVersion {
            id: 0x0304,
            name: TlsVersion::TLSv1_2,
        };
        assert_eq!(mismatched.tls_version(), TlsVersion::TLSv1_3);
        assert!(SupportedVersion::from_id(0x2a2a).is_grease());

        let unknown = SupportedVersion::from_id(0xffff);
        let unknown_json = serde_json::to_value(unknown).expect("unknown version should serialize");
        assert_eq!(unknown.name, TlsVersion::Unknown(0xffff));
        assert_eq!(
            unknown_json,
            serde_json::json!({"id": 65535, "name": "Unknown"})
        );
        assert_eq!(
            serde_json::from_value::<SupportedVersion>(unknown_json)
                .expect("unknown version should deserialize"),
            unknown
        );

        for name in ["TLSv1_2", "GREASE", "Unknown"] {
            assert!(
                serde_json::from_value::<SupportedVersion>(serde_json::json!({
                    "id": 772,
                    "name": name
                }))
                .is_err()
            );
        }
    }
}
