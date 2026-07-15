use std::fmt;

use serde::{de, Deserialize, Deserializer, Serialize};

use super::enums::is_grease_value;

macro_rules! named_group_registry {
    ($($id:literal => $name:literal),+ $(,)?) => {
        fn registered_name(id: u16) -> Option<&'static str> {
            match id {
                $($id => Some($name),)+
                _ => None,
            }
        }

        fn registered_id(name: &str) -> Option<u16> {
            match name {
                $($name => Some($id),)+
                _ => None,
            }
        }
    };
}

// Names follow the IANA TLS Supported Groups registry. Historical experimental values that
// pingly already recognized remain here so saved browser captures keep useful labels.
named_group_registry! {
    1 => "sect163k1",
    2 => "sect163r1",
    3 => "sect163r2",
    4 => "sect193r1",
    5 => "sect193r2",
    6 => "sect233k1",
    7 => "sect233r1",
    8 => "sect239k1",
    9 => "sect283k1",
    10 => "sect283r1",
    11 => "sect409k1",
    12 => "sect409r1",
    13 => "sect571k1",
    14 => "sect571r1",
    15 => "secp160k1",
    16 => "secp160r1",
    17 => "secp160r2",
    18 => "secp192k1",
    19 => "secp192r1",
    20 => "secp224k1",
    21 => "secp224r1",
    22 => "secp256k1",
    23 => "secp256r1",
    24 => "secp384r1",
    25 => "secp521r1",
    26 => "brainpoolP256r1",
    27 => "brainpoolP384r1",
    28 => "brainpoolP512r1",
    29 => "x25519",
    30 => "x448",
    31 => "brainpoolP256r1tls13",
    32 => "brainpoolP384r1tls13",
    33 => "brainpoolP512r1tls13",
    34 => "GC256A",
    35 => "GC256B",
    36 => "GC256C",
    37 => "GC256D",
    38 => "GC512A",
    39 => "GC512B",
    40 => "GC512C",
    41 => "curveSM2",
    256 => "ffdhe2048",
    257 => "ffdhe3072",
    258 => "ffdhe4096",
    259 => "ffdhe6144",
    260 => "ffdhe8192",
    512 => "MLKEM512",
    513 => "MLKEM768",
    514 => "MLKEM1024",
    4585 => "SecP256r1MLKEM512",
    4586 => "MLKEM512X25519",
    4587 => "SecP256r1MLKEM768",
    4588 => "X25519MLKEM768",
    4589 => "SecP384r1MLKEM1024",
    4590 => "curveSM2MLKEM768",
    16696 => "CECPQ2",
    25497 => "X25519Kyber768Draft00",
    25498 => "SecP256r1Kyber768Draft00",
    65072 => "X25519Kyber512Draft00",
    65073 => "X25519Kyber768Draft00Old",
    65074 => "P256Kyber768Draft00",
    65281 => "arbitrary_explicit_prime_curves",
    65282 => "arbitrary_explicit_char2_curves",
}

/// A TLS named group advertised for key establishment.
///
/// Every value keeps its wire identifier and a stable display name. Registered identifiers use
/// the name from the IANA TLS Supported Groups registry, GREASE identifiers use `GREASE`, and
/// other values use `Unknown`.
///
/// See the [IANA TLS Supported Groups registry](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8)
/// and [RFC 9846, Section 4.3.7](https://www.rfc-editor.org/rfc/rfc9846.html#section-4.3.7).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Hash)]
pub struct NamedGroup {
    /// The 16-bit named-group identifier observed on the wire.
    pub id: u16,

    /// The registered group name, `GREASE`, or `Unknown`.
    pub name: Box<str>,
}

impl NamedGroup {
    /// Resolves a wire identifier into its canonical display name.
    pub fn from_id(id: u16) -> Self {
        Self {
            id,
            name: Self::name_for_id(id).into(),
        }
    }

    /// Resolves a registered or retained experimental group name.
    ///
    /// `GREASE` and `Unknown` cannot identify a unique wire value and therefore return `None`.
    pub fn from_name(name: &str) -> Option<Self> {
        registered_id(name).map(Self::from_id)
    }

    /// Returns whether this identifier is reserved for GREASE.
    ///
    /// See [RFC 8701, Section 2](https://www.rfc-editor.org/rfc/rfc8701.html#section-2).
    pub fn is_grease(&self) -> bool {
        is_grease_value(self.id)
    }

    pub(super) fn from_serialized_parts(id: u16, name: Box<str>) -> Result<Self, &'static str> {
        let expected = Self::name_for_id(id);
        if name.as_ref() == expected {
            Ok(Self { id, name })
        } else {
            Err(expected)
        }
    }

    fn name_for_id(id: u16) -> &'static str {
        if is_grease_value(id) {
            "GREASE"
        } else {
            registered_name(id).unwrap_or("Unknown")
        }
    }
}

impl From<u16> for NamedGroup {
    fn from(id: u16) -> Self {
        Self::from_id(id)
    }
}

impl fmt::Display for NamedGroup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.name)
    }
}

/// Deserialization shape used to validate a saved named-group ID and name.
#[derive(Deserialize)]
struct NamedGroupRepr {
    /// The numeric identifier stored in JSON.
    id: u16,

    /// The human-readable name stored alongside the identifier.
    name: Box<str>,
}

impl<'de> Deserialize<'de> for NamedGroup {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let repr = NamedGroupRepr::deserialize(deserializer)?;
        let id = repr.id;
        Self::from_serialized_parts(id, repr.name).map_err(|expected| {
            de::Error::custom(format_args!(
                "TLS named group {id:#06x} has name {expected:?}, not the saved name",
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::NamedGroup;

    #[test]
    fn named_groups_use_id_and_iana_name_objects() {
        let groups = [0x8a8a, 4588, 29, 23, 24].map(NamedGroup::from).to_vec();
        let json = serde_json::to_value(&groups).expect("named groups serialize");

        assert_eq!(
            json,
            serde_json::json!([
                { "id": 35466, "name": "GREASE" },
                { "id": 4588, "name": "X25519MLKEM768" },
                { "id": 29, "name": "x25519" },
                { "id": 23, "name": "secp256r1" },
                { "id": 24, "name": "secp384r1" }
            ])
        );
        assert_eq!(
            serde_json::from_value::<Vec<NamedGroup>>(json).expect("named groups deserialize"),
            groups
        );
    }

    #[test]
    fn named_group_resolves_names_and_validates_saved_pairs() {
        let x25519 = NamedGroup::from_name("x25519").expect("x25519 is registered");
        assert_eq!(x25519, NamedGroup::from_id(29));
        assert!(!x25519.is_grease());
        assert!(NamedGroup::from_name("GREASE").is_none());
        assert!(NamedGroup::from_id(0x2a2a).is_grease());
        assert_eq!(NamedGroup::from_id(0xffff).name.as_ref(), "Unknown");

        assert!(serde_json::from_value::<NamedGroup>(serde_json::json!({
            "id": 29,
            "name": "X25519"
        }))
        .is_err());
    }
}
