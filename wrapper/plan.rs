use bitcoin::hashes::{hash160, hex::FromHex, ripemd160, sha256};
use bitcoin::taproot::TapLeafHash;
use bitcoin::{absolute, relative};

use miniscript::plan::AssetProvider;
use miniscript::DefiniteDescriptorKey;
use miniscript::{hash256, Satisfier};

use super::{invoke_callback, json_to_ptr, ptr_to_string, CallbackId, StrPtr};

pub struct Plan(miniscript::plan::Plan);

impl Plan {
    pub fn new(plan: miniscript::plan::Plan) -> Self {
        Plan(plan)
    }
}

// Each function should return u64, serde_json::Value or String, as these can be passed over to
// WASM using u64, json_to_ptr and string_to_ptr.
impl Plan {
    pub fn satisfy(&self, stfr: &impl Satisfier<DefiniteDescriptorKey>) -> serde_json::Value {
        match self.0.satisfy(stfr) {
            Ok((witness, script_sig)) => serde_json::json!({
                "witness": witness,
                "scriptSig": script_sig.as_bytes(),
            }),
            Err(err) => {
                serde_json::json!({
                    "error": err.to_string(),
                })
            }
        }
    }
}

#[derive(Default)]
#[allow(clippy::type_complexity)]
pub struct Assets {
    pub lookup_ecdsa_sig: Option<Box<dyn Fn(&str) -> bool>>,
    pub lookup_tap_key_spend_sig: Option<Box<dyn Fn(&str) -> Option<usize>>>,
    pub lookup_tap_leaf_script_sig: Option<Box<dyn Fn(&str, &str) -> Option<usize>>>,
    pub absolute_timelock: Option<absolute::LockTime>,
    pub relative_timelock: Option<relative::LockTime>,
}

impl AssetProvider<DefiniteDescriptorKey> for Assets {
    fn provider_lookup_ecdsa_sig(&self, pk: &DefiniteDescriptorKey) -> bool {
        if let Some(f) = self.lookup_ecdsa_sig.as_ref() {
            f(&pk.to_string())
        } else {
            false
        }
    }

    fn provider_lookup_tap_key_spend_sig(&self, pk: &DefiniteDescriptorKey) -> Option<usize> {
        if let Some(f) = self.lookup_tap_key_spend_sig.as_ref() {
            f(&pk.to_string())
        } else {
            None
        }
    }

    fn provider_lookup_tap_leaf_script_sig(
        &self,
        pk: &DefiniteDescriptorKey,
        tap_leaf_hash: &TapLeafHash,
    ) -> Option<usize> {
        if let Some(f) = self.lookup_tap_leaf_script_sig.as_ref() {
            f(&pk.to_string(), &tap_leaf_hash.to_string())
        } else {
            None
        }
    }

    fn provider_lookup_sha256(&self, _hash: &sha256::Hash) -> bool {
        false
    }

    fn provider_lookup_hash256(&self, _hash: &hash256::Hash) -> bool {
        false
    }

    fn provider_lookup_ripemd160(&self, _hash: &ripemd160::Hash) -> bool {
        false
    }

    fn provider_lookup_hash160(&self, _hash: &hash160::Hash) -> bool {
        false
    }

    fn check_older(&self, s: relative::LockTime) -> bool {
        if let Some(timelock) = self.relative_timelock {
            s.is_implied_by(timelock)
        } else {
            false
        }
    }

    fn check_after(&self, l: absolute::LockTime) -> bool {
        if let Some(timelock) = self.absolute_timelock {
            l.is_implied_by(timelock)
        } else {
            false
        }
    }
}

#[derive(Default)]
#[allow(clippy::type_complexity)]
pub struct SatisfierImpl {
    pub lookup_ecdsa_sig: Option<Box<dyn Fn(&str) -> Option<bitcoin::ecdsa::Signature>>>,
    pub lookup_tap_key_spend_sig: Option<Box<dyn Fn() -> Option<bitcoin::taproot::Signature>>>,
    pub lookup_tap_leaf_script_sig:
        Option<Box<dyn Fn(&str, &str) -> Option<bitcoin::taproot::Signature>>>,
}

impl Satisfier<DefiniteDescriptorKey> for SatisfierImpl {
    fn lookup_ecdsa_sig(&self, pk: &DefiniteDescriptorKey) -> Option<bitcoin::ecdsa::Signature> {
        if let Some(f) = self.lookup_ecdsa_sig.as_ref() {
            f(&pk.to_string())
        } else {
            None
        }
    }
    fn lookup_tap_key_spend_sig(&self) -> Option<bitcoin::taproot::Signature> {
        if let Some(f) = self.lookup_tap_key_spend_sig.as_ref() {
            f()
        } else {
            None
        }
    }

    fn lookup_tap_leaf_script_sig(
        &self,
        pk: &DefiniteDescriptorKey,
        leaf_hash: &TapLeafHash,
    ) -> Option<bitcoin::taproot::Signature> {
        if let Some(f) = self.lookup_tap_leaf_script_sig.as_ref() {
            f(&pk.to_string(), &leaf_hash.to_string())
        } else {
            None
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn plan_satisfaction_weight(ptr: *const Plan) -> u64 {
    (*ptr).0.satisfaction_weight() as _
}

#[no_mangle]
pub unsafe extern "C" fn plan_scriptsig_size(ptr: *const Plan) -> u64 {
    (*ptr).0.scriptsig_size() as _
}

#[no_mangle]
pub unsafe extern "C" fn plan_witness_size(ptr: *const Plan) -> u64 {
    (*ptr).0.witness_size() as _
}

#[no_mangle]
pub unsafe extern "C" fn plan_satisfy(ptr: *const Plan, satisfier_str_ptr: StrPtr) -> StrPtr {
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct JsonSatisfier {
        lookup_ecdsa_sig: Option<CallbackId>,
        lookup_tap_key_spend_sig: Option<CallbackId>,
        lookup_tap_leaf_script_sig: Option<CallbackId>,
    }

    let json_satisfier: JsonSatisfier =
        serde_json::from_str(&ptr_to_string(satisfier_str_ptr)).unwrap();
    let satisfier = SatisfierImpl {
        lookup_ecdsa_sig: match json_satisfier.lookup_ecdsa_sig {
            Some(callback_id) => Some(Box::new(move |pk| {
                let sig: Option<String> =
                    serde_json::from_str(&invoke_callback(callback_id, pk)).unwrap();
                sig.map(|sig| {
                    bitcoin::ecdsa::Signature::from_slice(&Vec::from_hex(&sig).unwrap()).unwrap()
                })
            })),
            None => None,
        },
        lookup_tap_key_spend_sig: match json_satisfier.lookup_tap_key_spend_sig {
            Some(callback_id) => Some(Box::new(move || {
                let sig: Option<String> =
                    serde_json::from_str(&invoke_callback(callback_id, "")).unwrap();
                sig.map(|sig| {
                    bitcoin::taproot::Signature::from_slice(&Vec::from_hex(&sig).unwrap()).unwrap()
                })
            })),
            None => None,
        },
        lookup_tap_leaf_script_sig: match json_satisfier.lookup_tap_leaf_script_sig {
            Some(callback_id) => Some(Box::new(move |pk, leaf_hash| {
                let sig: Option<String> = serde_json::from_str(&invoke_callback(
                    callback_id,
                    &serde_json::json!({
                        "pk": pk,
                        "leafHash": leaf_hash,
                    })
                    .to_string(),
                ))
                .unwrap();
                sig.map(|sig| {
                    bitcoin::taproot::Signature::from_slice(&Vec::from_hex(&sig).unwrap()).unwrap()
                })
            })),
            None => None,
        },
    };
    json_to_ptr((*ptr).satisfy(&satisfier))
}
