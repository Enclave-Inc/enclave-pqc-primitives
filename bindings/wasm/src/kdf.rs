//! `enclave-kdf-v1` wasm bindings.

use enclave_pqc_primitives::kdf;
use wasm_bindgen::prelude::*;

use crate::error::js_error;
use crate::usage::record_usage;

/// Domain-separation prefix for the Enclave labeled KDF.
#[wasm_bindgen(js_name = KDF_LABEL_PREFIX)]
pub fn kdf_label_prefix() -> String {
    kdf::KDF_LABEL_PREFIX.to_string()
}

/// Derive key material with `enclave-kdf-v1` labeled SHAKE256.
///
/// Throws `InvalidParameter` on empty `label` or `length == 0`.
#[wasm_bindgen(js_name = labeledKdf)]
pub fn labeled_kdf(label: &str, ikm: &[u8], length: usize) -> Result<Vec<u8>, JsValue> {
    let out = kdf::labeled_kdf(label, ikm, length).map_err(js_error)?;
    record_usage(out.usage);
    Ok(out.key)
}

/// [`labeled_kdf`] with a 32-byte output.
#[wasm_bindgen(js_name = labeledKdf32)]
pub fn labeled_kdf_32(label: &str, ikm: &[u8]) -> Result<Vec<u8>, JsValue> {
    let out = kdf::labeled_kdf_32(label, ikm).map_err(js_error)?;
    record_usage(out.usage);
    Ok(out.key)
}
