//! SHAKE256 wasm bindings (one-shot).

use enclave_pqc_primitives::hash;
use wasm_bindgen::prelude::*;

use crate::error::js_invalid_parameter;
use crate::usage::record_usage;

/// One-shot SHAKE256 hash of `input` into `output_len` bytes.
#[wasm_bindgen(js_name = shake256)]
pub fn shake256(input: &[u8], output_len: usize) -> Result<Vec<u8>, JsValue> {
    if output_len == 0 {
        return Err(js_invalid_parameter("outputLen must be > 0"));
    }
    let out = hash::shake256(input, output_len);
    record_usage(out.usage);
    Ok(out.digest)
}

/// SHAKE256 over UTF-8 string bytes.
#[wasm_bindgen(js_name = hashUtf8)]
pub fn hash_utf8(value: &str, output_len: usize) -> Result<Vec<u8>, JsValue> {
    if output_len == 0 {
        return Err(js_invalid_parameter("outputLen must be > 0"));
    }
    let out = hash::hash_utf8(value, output_len);
    record_usage(out.usage);
    Ok(out.digest)
}
