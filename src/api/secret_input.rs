//! DE: Request-Geheimnisse ab Deserialisierung gesperrt halten, auch bei Abbruch.
//! EN: Keep request secrets locked from deserialization onward, including cancellation.

use crate::security::Passphrase;
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer};
use std::fmt;

// DE: Transport-/Parser-Vorpuffer benötigen zusätzlich die gesicherte Eingangsgrenze.
// EN: Transport/parser staging additionally requires the protected ingress boundary.
pub(super) struct SecretInput(pub Passphrase);

struct SecretVisitor;

impl Visitor<'_> for SecretVisitor {
    type Value = SecretInput;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a bounded passphrase string")
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
        Passphrase::new(value)
            .map(SecretInput)
            .map_err(|_| E::custom("invalid passphrase"))
    }

    fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
        Passphrase::from_string(value)
            .map(SecretInput)
            .map_err(|_| E::custom("invalid passphrase"))
    }
}

impl<'de> Deserialize<'de> for SecretInput {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_str(SecretVisitor)
    }
}
