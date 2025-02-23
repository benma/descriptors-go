extern crate alloc;
extern crate core;

use alloc::vec::Vec;
use std::mem::MaybeUninit;
use std::slice;
use std::str::FromStr;

/// Returns a string from WebAssembly compatible numeric types representing
/// its pointer and length.
unsafe fn ptr_to_string(ptr: u32, len: u32) -> String {
    let slice = slice::from_raw_parts_mut(ptr as *mut u8, len as usize);
    let utf8 = std::str::from_utf8_unchecked_mut(slice);
    return String::from(utf8);
}

fn string_to_ptr(s: String) -> u64 {
    let len = s.len();
    let ptr = Box::into_raw(s.into_bytes().into_boxed_slice()) as *mut u8 as u32;
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

#[no_mangle]
pub unsafe extern "C" fn descriptor_parse(ptr: u32, len: u32) -> u64 {
    let result = || -> Result<u32, String> {
        let descriptor_string = ptr_to_string(ptr, len);
        let descriptor =
            miniscript::Descriptor::<miniscript::DescriptorPublicKey>::from_str(&descriptor_string)
                .map_err(|e| e.to_string())?;
        let desc = Box::new(Descriptor {
            single_descriptors: descriptor.clone().into_single_descriptors().unwrap(),
            descriptor: descriptor,
        });

        Ok(Box::into_raw(desc) as u32)
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
    let desc = &*ptr;
    desc.single_descriptors.len() as _
}

#[no_mangle]
pub unsafe extern "C" fn descriptor_to_str(ptr: *const Descriptor) -> u64 {
    let desc = &*ptr;
    string_to_ptr(desc.descriptor.to_string())
}

#[no_mangle]
pub unsafe extern "C" fn descriptor_address_at(
    ptr: *const Descriptor,
    network: u32,
    multipath_index: u32,
    derivation_index: u32,
) -> u64 {
    let result = || -> Result<String, String> {
        let desc = &*ptr;
        let descriptor = desc
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
        Ok(address) => json_to_ptr(serde_json::json!({
            "address": address,
        })),
        Err(err) => json_to_ptr(serde_json::json!({
            "error": err,
        })),
    }
}
