use bitcoin::hashes::{hash160, ripemd160, sha256};
use bitcoin::taproot::TapLeafHash;
use bitcoin::{absolute, relative};
use miniscript::hash256;
use miniscript::plan::AssetProvider;
use miniscript::DefiniteDescriptorKey;

pub struct Plan(miniscript::plan::Plan);

impl Plan {
    pub fn new(plan: miniscript::plan::Plan) -> Self {
        Plan(plan)
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
