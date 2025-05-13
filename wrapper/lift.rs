use miniscript::policy::semantic::Policy;
use miniscript::MiniscriptKey;
use serde::ser::{Serialize, SerializeMap, Serializer};

// Newtype wrapper to implement Serde serialization
pub struct PolicyJson<'a, Pk: MiniscriptKey>(&'a Policy<Pk>);

impl<'a, Pk: MiniscriptKey> From<&'a Policy<Pk>> for PolicyJson<'a, Pk> {
    fn from(policy: &'a Policy<Pk>) -> Self {
        PolicyJson(policy)
    }
}

impl<Pk: MiniscriptKey> Serialize for PolicyJson<'_, Pk> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(None)?;

        match self.0 {
            Policy::Unsatisfiable => {
                map.serialize_entry("type", "unsatisfiable")?;
            }
            Policy::Trivial => {
                map.serialize_entry("type", "trivial")?;
            }
            Policy::Key(key) => {
                map.serialize_entry("type", "key")?;
                map.serialize_entry("key", &key.to_string())?;
            }
            Policy::After(time) => {
                map.serialize_entry("type", "after")?;
                map.serialize_entry("lockTime", &time.to_consensus_u32())?;
            }
            Policy::Older(time) => {
                map.serialize_entry("type", "older")?;
                map.serialize_entry("lockTime", &time.to_consensus_u32())?;
            }
            Policy::Sha256(hash) => {
                map.serialize_entry("type", "sha256")?;
                map.serialize_entry("hash", &hash.to_string())?;
            }
            Policy::Hash256(hash) => {
                map.serialize_entry("type", "hash256")?;
                map.serialize_entry("hash", &hash.to_string())?;
            }
            Policy::Ripemd160(hash) => {
                map.serialize_entry("type", "ripemd160")?;
                map.serialize_entry("hash", &hash.to_string())?;
            }
            Policy::Hash160(hash) => {
                map.serialize_entry("type", "hash160")?;
                map.serialize_entry("hash", &hash.to_string())?;
            }
            Policy::Thresh(threshold) => {
                map.serialize_entry("type", "thresh")?;
                map.serialize_entry("threshold", &threshold.k())?;

                // Recursively serialize nested policies
                let policies: Vec<PolicyJson<Pk>> = threshold
                    .data()
                    .iter()
                    .map(|arc_policy| PolicyJson(&**arc_policy))
                    .collect();

                map.serialize_entry("policies", &policies)?;
            }
        }

        map.end()
    }
}
