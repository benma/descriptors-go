mod lift;

extern crate alloc;
extern crate core;

use alloc::vec::Vec;
use core::fmt;
use miniscript::ForEachKey;
use std::mem::MaybeUninit;
use std::slice;
use std::str::FromStr;

use miniscript::descriptor::DescriptorType;
use miniscript::miniscript::types;
use miniscript::policy::Liftable;

/// Returns a string from WebAssembly compatible numeric types representing
/// its pointer and length.
unsafe fn ptr_to_string(ptr: u64) -> String {
    let len: u32 = ptr as u32;
    let ptr: u32 = (ptr >> 32) as u32;
    let slice = slice::from_raw_parts(ptr as *const u8, len as usize);
    let utf8 = std::str::from_utf8_unchecked(slice);
    String::from(utf8)
}

fn string_to_ptr(s: String) -> u64 {
    let len = s.len();
    let ptr = Box::into_raw(s.into_bytes().into_boxed_slice()) as *const u8 as u32;
    ((ptr as u64) << 32) | len as u64
}

fn json_to_ptr(value: serde_json::Value) -> u64 {
    string_to_ptr(serde_json::to_string(&value).unwrap())
}

#[allow(dead_code)]
fn log(message: &str) {
    unsafe {
        _log(message.as_ptr() as _, message.len() as _);
    }
}

#[link(wasm_import_module = "env")]
extern "C" {
    #[link_name = "log"]
    fn _log(ptr: u32, size: u32);
}

/// Allocates size bytes and leaks the pointer where they start.
fn _allocate(size: usize) -> *mut u8 {
    let vec: Vec<MaybeUninit<u8>> = vec![MaybeUninit::uninit(); size];
    Box::into_raw(vec.into_boxed_slice()) as *mut u8
}

#[no_mangle]
pub extern "C" fn allocate(size: u32) -> *mut u8 {
    _allocate(size as usize)
}

/// Retakes the pointer which allows its memory to be freed.
unsafe fn _deallocate(ptr: *mut [u8]) {
    let _ = Box::from_raw(ptr);
}

#[no_mangle]
pub unsafe extern "C" fn deallocate(ptr: u32, size: u32) {
    _deallocate(core::ptr::slice_from_raw_parts_mut(
        ptr as *mut u8,
        size as usize,
    ));
}

pub struct Descriptor {
    descriptor: miniscript::Descriptor<miniscript::DescriptorPublicKey>,
    single_descriptors: Vec<miniscript::Descriptor<miniscript::DescriptorPublicKey>>,
}

// Each function should return u64, serde_json::Value or String, as these can be passed over to
// WASM using u64, json_to_ptr and string_to_ptr.
impl Descriptor {
    fn multipath_len(&self) -> u64 {
        self.single_descriptors.len() as _
    }

    fn max_weight_to_satisfy(&self) -> serde_json::Value {
        match self.descriptor.max_weight_to_satisfy() {
            Ok(weight) => serde_json::json!({
                "weight": weight.to_wu(),
            }),
            Err(err) => serde_json::json!({
                "error": err.to_string(),
            }),
        }
    }

    fn to_str(&self) -> String {
        self.descriptor.to_string()
    }

    fn address_at(
        &self,
        network: u32,
        multipath_index: u32,
        derivation_index: u32,
    ) -> serde_json::Value {
        let result = || -> Result<String, String> {
            let descriptor = self
                .single_descriptors
                .get(multipath_index as usize)
                .ok_or("multipath index out of bounds".to_string())?;
            let network = match network {
                0 => miniscript::bitcoin::Network::Bitcoin,
                1 => miniscript::bitcoin::Network::Testnet,
                2 => miniscript::bitcoin::Network::Regtest,
                _ => return Err("unknown network".into()),
            };

            let addr = descriptor
                .at_derivation_index(derivation_index)
                .map_err(|e| e.to_string())?
                .address(network)
                .map_err(|e| e.to_string())?;
            Ok(addr.to_string())
        };
        match result() {
            Ok(address) => serde_json::json!({
                "address": address,
            }),
            Err(err) => serde_json::json!({
                "error": err,
            }),
        }
    }

    fn lift(&self) -> serde_json::Value {
        let result = || -> Result<serde_json::Value, String> {
            let policy = self.descriptor.lift().map_err(|err| err.to_string())?;
            serde_json::to_value(lift::PolicyJson::from(&policy)).map_err(|err| err.to_string())
        };
        match result() {
            Ok(policy) => serde_json::json!({
                "policy": policy,
            }),
            Err(err) => serde_json::json!({
                "error": err,
            }),
        }
    }

    fn keys(&self) -> serde_json::Value {
        let keys: Vec<String> = match &self.descriptor {
            miniscript::Descriptor::Bare(_)
            | miniscript::Descriptor::Pkh(_)
            | miniscript::Descriptor::Wpkh(_)
            | miniscript::Descriptor::Sh(_)
            | miniscript::Descriptor::Wsh(_) => {
                let mut keys: Vec<String> = Vec::new();
                self.descriptor.for_each_key(|key| {
                    keys.push(key.to_string());
                    true
                });
                keys
            }
            // Handle separately because ForEachKey iterates the Taproot tree before the internal
            // key, but we want to return the keys in-order from left to right.
            // See https://github.com/rust-bitcoin/rust-miniscript/issues/821
            miniscript::Descriptor::Tr(tr) => core::iter::once(tr.internal_key().clone())
                .chain(tr.iter_scripts().flat_map(|(_, ms)| ms.iter_pk()))
                .map(|key| key.to_string())
                .collect(),
        };

        serde_json::json!(keys)
    }

    fn desc_type(&self) -> String {
        let typ = match self.descriptor.desc_type() {
            DescriptorType::Bare => "Bare",
            DescriptorType::Sh => "Sh",
            DescriptorType::Pkh => "Pkh",
            DescriptorType::Wpkh => "Wpkh",
            DescriptorType::Wsh => "Wsh",
            DescriptorType::ShWsh => "ShWsh",
            DescriptorType::ShWpkh => "ShWpkh",
            DescriptorType::ShSortedMulti => "ShSortedMulti",
            DescriptorType::WshSortedMulti => "WshSortedMulti",
            DescriptorType::ShWshSortedMulti => "ShWshSortedMulti",
            DescriptorType::Tr => "Tr",
        };
        typ.into()
    }
}

fn _descriptor_parse(descriptor: &str) -> Result<Box<Descriptor>, String> {
    let descriptor =
        miniscript::Descriptor::<miniscript::DescriptorPublicKey>::from_str(descriptor)
            .map_err(|e| e.to_string())?;
    Ok(Box::new(Descriptor {
        single_descriptors: descriptor.clone().into_single_descriptors().unwrap(),
        descriptor,
    }))
}

#[no_mangle]
pub unsafe extern "C" fn descriptor_parse(ptr: u64) -> u64 {
    let result = || -> Result<u32, String> {
        let descriptor_string = ptr_to_string(ptr);
        Ok(Box::into_raw(_descriptor_parse(&descriptor_string)?) as u32)
    };

    match result() {
        Ok(ptr) => json_to_ptr(serde_json::json!({
            "ptr": ptr,
        })),
        Err(err) => json_to_ptr(serde_json::json!({
            "error": err,
        })),
    }
}

#[no_mangle]
pub unsafe extern "C" fn descriptor_drop(ptr: *mut Descriptor) {
    let _ = Box::from_raw(ptr);
}

#[no_mangle]
pub unsafe extern "C" fn descriptor_multipath_len(ptr: *const Descriptor) -> u64 {
    (*ptr).multipath_len()
}

#[no_mangle]
pub unsafe extern "C" fn descriptor_max_weight_to_satisfy(ptr: *const Descriptor) -> u64 {
    json_to_ptr((*ptr).max_weight_to_satisfy())
}

#[no_mangle]
pub unsafe extern "C" fn descriptor_to_str(ptr: *const Descriptor) -> u64 {
    string_to_ptr((*ptr).to_str())
}

#[no_mangle]
pub unsafe extern "C" fn descriptor_lift(ptr: *const Descriptor) -> u64 {
    json_to_ptr((*ptr).lift())
}

#[no_mangle]
pub unsafe extern "C" fn descriptor_keys(ptr: *const Descriptor) -> u64 {
    json_to_ptr((*ptr).keys())
}

#[no_mangle]
pub unsafe extern "C" fn descriptor_desc_type(ptr: *const Descriptor) -> u64 {
    string_to_ptr((*ptr).desc_type())
}

#[no_mangle]
pub unsafe extern "C" fn descriptor_address_at(
    ptr: *const Descriptor,
    network: u32,
    multipath_index: u32,
    derivation_index: u32,
) -> u64 {
    json_to_ptr((*ptr).address_at(network, multipath_index, derivation_index))
}

struct TestType(types::Type);

impl fmt::Display for TestType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self.0.corr.base {
            types::Base::B => "B",
            types::Base::K => "K",
            types::Base::V => "V",
            types::Base::W => "W",
        })?;
        f.write_str(match self.0.corr.input {
            types::Input::Zero => "z",
            types::Input::One => "o",
            types::Input::OneNonZero => "on",
            types::Input::Any => "",
            types::Input::AnyNonZero => "n",
        })?;
        if self.0.corr.dissatisfiable {
            fmt::Write::write_char(f, 'd')?;
        }
        if self.0.corr.unit {
            fmt::Write::write_char(f, 'u')?;
        }
        f.write_str(match self.0.mall.dissat {
            types::Dissat::None => "f",
            types::Dissat::Unique => "e",
            types::Dissat::Unknown => "",
        })?;
        if self.0.mall.safe {
            fmt::Write::write_char(f, 's')?;
        }
        if self.0.mall.non_malleable {
            fmt::Write::write_char(f, 'm')?;
        }
        Ok(())
    }
}

pub struct MiniscriptProperties {
    types: String,
    op_codes: usize,
}

/// Parses a miniscript string pointer and returns its properties (parsed types
/// and number of opcodes) as a pointer to a JSON string. The input string must
/// be represented as a numeric pointer that points to a WebAssembly compatible
/// string in memory and the string's length. The returned pointer points to a
/// WebAssembly compatible string that contains the result in JSON format.
/// This function is only used for unit tests.
#[no_mangle]
pub unsafe extern "C" fn miniscript_parse(ptr: u64) -> u64 {
    let result = || -> Result<MiniscriptProperties, String> {
        let miniscript_string = ptr_to_string(ptr);
        let ms = miniscript::Miniscript::<String, miniscript::Segwitv0>::from_str_insane(
            &miniscript_string,
        )
        .map_err(|e| e.to_string())?;

        let ms_types = format!("{}", TestType(ms.ty));
        let mut ms_types = ms_types.chars().collect::<Vec<_>>();
        ms_types.sort_by(|a, b| b.cmp(a));

        Ok(MiniscriptProperties {
            types: ms_types.into_iter().collect(),
            op_codes: ms.ext.ops.count,
        })
    };
    match result() {
        Ok(props) => json_to_ptr(serde_json::json!({
            "types": props.types,
            "op_codes": props.op_codes,
        })),
        Err(err) => json_to_ptr(serde_json::json!({
            "error": err,
        })),
    }
}

/// Compiles a miniscript expression from a string pointer and returns its
/// compiled script as a pointer to a JSON string. The input string must
/// be represented as a numeric pointer that points to a WebAssembly compatible
/// string in memory and the string's length. The returned pointer points to a
/// WebAssembly compatible string that contains the result in JSON format.
/// This function is only used for unit tests.
#[no_mangle]
pub unsafe extern "C" fn miniscript_compile(ptr: u64) -> u64 {
    let result = || -> Result<String, String> {
        let miniscript_string = ptr_to_string(ptr);
        let ms =
            miniscript::Miniscript::<bitcoin::PublicKey, miniscript::Segwitv0>::from_str_insane(
                &miniscript_string,
            )
            .map_err(|e| e.to_string())?;

        let ms_types = format!("{}", TestType(ms.ty));
        let mut ms_types = ms_types.chars().collect::<Vec<_>>();
        ms_types.sort_by(|a, b| b.cmp(a));

        Ok(ms.encode().clone().to_hex_string())
    };
    match result() {
        Ok(script) => json_to_ptr(serde_json::json!({
            "script_hex": script,
        })),
        Err(err) => json_to_ptr(serde_json::json!({
            "error": err,
        })),
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_various() {
        let desc_str = "tr([e81a5744/48'/0'/0'/2']xpub6Duv8Gj9gZeA3sUo5nUMPEv6FZ81GHn3feyaUej5KqcjPKsYLww4xBX4MmYZUPX5NqzaVJWYdYZwGLECtgQruG4FkZMh566RkfUT2pbzsEg/<0;1>/*,and_v(v:pk([3c157b79/48'/0'/0'/2']xpub6DdSN9RNZi3eDjhZWA8PJ5mSuWgfmPdBduXWzSP91Y3GxKWNwkjyc5mF9FcpTFymUh9C4Bar45b6rWv6Y5kSbi9yJDjuJUDzQSWUh3ijzXP/<0;1>/*),older(65535)))#lg9nqqhr";
        let desc = _descriptor_parse(desc_str).unwrap();

        assert_eq!(desc.multipath_len(), 2);
        assert_eq!(
            desc.address_at(0, 0, 0),
            serde_json::json!({
                "address": "bc1pfujezshxnw0jw2m9fn6hz0xr3ljjpjd30gtpqyymgxqquk8rr95qk986dz",
            })
        );
        assert_eq!(
            desc.address_at(1, 0, 0),
            serde_json::json!({
                "address": "tb1pfujezshxnw0jw2m9fn6hz0xr3ljjpjd30gtpqyymgxqquk8rr95qpd34hd",
            })
        );

        assert_eq!(
            desc.address_at(1, 1, 0),
            serde_json::json!({
                "address": "tb1ptd9ngyt09kxtt8mkf832vhxdrn0xhccwp9jv6mz6vv4wqfc8dxjqgzjqnu",
            })
        );
        assert_eq!(
            desc.address_at(1, 0, 1),
            serde_json::json!({
                "address": "tb1pjg74433u7fxtcv72tutjntpvetuwfh79yuf4zptc5a62d5qjes4ss893lw",
            })
        );
        assert_eq!(
            desc.address_at(10, 0, 0),
            serde_json::json!({
                "error": "unknown network",
            })
        );
        assert_eq!(
            desc.max_weight_to_satisfy(),
            serde_json::json!({
                "weight": 140,
            })
        );
        assert_eq!(desc.desc_type(), "Tr".to_string());
    }

    #[test]
    fn test_lift() {
        let desc_str = "tr([e81a5744/48'/0'/0'/2']xpub6Duv8Gj9gZeA3sUo5nUMPEv6FZ81GHn3feyaUej5KqcjPKsYLww4xBX4MmYZUPX5NqzaVJWYdYZwGLECtgQruG4FkZMh566RkfUT2pbzsEg/<0;1>/*,and_v(v:pk([3c157b79/48'/0'/0'/2']xpub6DdSN9RNZi3eDjhZWA8PJ5mSuWgfmPdBduXWzSP91Y3GxKWNwkjyc5mF9FcpTFymUh9C4Bar45b6rWv6Y5kSbi9yJDjuJUDzQSWUh3ijzXP/<0;1>/*),older(65535)))#lg9nqqhr";
        let desc = _descriptor_parse(desc_str).unwrap();
        // println!(serde_json::to_string_pretty(&desc.lift()).unwrap());
        assert_eq!(
            desc.lift(),
            serde_json::json!({
              "policy": {
                "type": "thresh",
                "threshold": 1,
                "policies": [
                  {
                    "type": "key",
                    "key": "[e81a5744/48'/0'/0'/2']xpub6Duv8Gj9gZeA3sUo5nUMPEv6FZ81GHn3feyaUej5KqcjPKsYLww4xBX4MmYZUPX5NqzaVJWYdYZwGLECtgQruG4FkZMh566RkfUT2pbzsEg/<0;1>/*"
                  },
                  {
                    "type": "thresh",
                    "threshold": 2,
                    "policies": [
                      {
                        "type": "key",
                        "key": "[3c157b79/48'/0'/0'/2']xpub6DdSN9RNZi3eDjhZWA8PJ5mSuWgfmPdBduXWzSP91Y3GxKWNwkjyc5mF9FcpTFymUh9C4Bar45b6rWv6Y5kSbi9yJDjuJUDzQSWUh3ijzXP/<0;1>/*"
                      },
                      {
                        "type": "older",
                        "lockTime": 65535
                      }
                    ]
                  }
                ]
              }
            }),
        );
    }

    #[test]
    fn test_keys() {
        struct Test {
            desc: &'static str,
            expected: &'static [&'static str],
        }
        let tests = &[
            Test {
                desc: "tr([e81a5744/48'/0'/0'/2']xpub6Duv8Gj9gZeA3sUo5nUMPEv6FZ81GHn3feyaUej5KqcjPKsYLww4xBX4MmYZUPX5NqzaVJWYdYZwGLECtgQruG4FkZMh566RkfUT2pbzsEg/<0;1>/*,and_v(v:pk([3c157b79/48'/0'/0'/2']xpub6DdSN9RNZi3eDjhZWA8PJ5mSuWgfmPdBduXWzSP91Y3GxKWNwkjyc5mF9FcpTFymUh9C4Bar45b6rWv6Y5kSbi9yJDjuJUDzQSWUh3ijzXP/<0;1>/*),older(65535)))#lg9nqqhr",
                expected: &[
                    "[e81a5744/48'/0'/0'/2']xpub6Duv8Gj9gZeA3sUo5nUMPEv6FZ81GHn3feyaUej5KqcjPKsYLww4xBX4MmYZUPX5NqzaVJWYdYZwGLECtgQruG4FkZMh566RkfUT2pbzsEg/<0;1>/*",
                    "[3c157b79/48'/0'/0'/2']xpub6DdSN9RNZi3eDjhZWA8PJ5mSuWgfmPdBduXWzSP91Y3GxKWNwkjyc5mF9FcpTFymUh9C4Bar45b6rWv6Y5kSbi9yJDjuJUDzQSWUh3ijzXP/<0;1>/*",
                ],
            },
            Test {
                desc: "wpkh(xpub6BzikmgQmvoYG3ShFhXU1LFKaUeU832dHoYL6ka9JpCqKXr7PTHQHaoSMbGU36CZNcoryVPsFBjt9aYyCQHtYi6BQTo6VfRv9xVRuSNNteB)",
                expected: &[
                    "xpub6BzikmgQmvoYG3ShFhXU1LFKaUeU832dHoYL6ka9JpCqKXr7PTHQHaoSMbGU36CZNcoryVPsFBjt9aYyCQHtYi6BQTo6VfRv9xVRuSNNteB",
                ],
            },
        ];
        for test in tests {
            let desc = _descriptor_parse(test.desc).unwrap();
            assert_eq!(desc.keys(), serde_json::json!(test.expected));
        }
    }
}
