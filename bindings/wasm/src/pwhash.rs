//! Argon2id password → key wasm bindings.
//!
//! Deliberately slow and memory-hard — do not weaken parameters for latency
//! without treating that as a security tradeoff. See the Rust `pwhash` module
//! docs.

use enclave_pqc_primitives::pwhash::{
    self, Argon2Params, OUTPUT_BYTES, RECOMMENDED_PARAMS, SALT_BYTES,
};
use js_sys::Object;
use wasm_bindgen::prelude::*;

use crate::error::js_error;
use crate::usage::record_usage;

/// Algorithm identifier (`"Argon2id"`).
#[wasm_bindgen(js_name = PWHASH_ALGORITHM)]
pub fn pwhash_algorithm() -> String {
    pwhash::ALGORITHM.to_string()
}

/// Salt length in bytes produced by [`generate_salt`].
#[wasm_bindgen(js_name = PWHASH_SALT_BYTES)]
pub fn pwhash_salt_bytes() -> usize {
    SALT_BYTES
}

/// Derived key length in bytes (matches AES-256-GCM key size).
#[wasm_bindgen(js_name = PWHASH_OUTPUT_BYTES)]
pub fn pwhash_output_bytes() -> usize {
    OUTPUT_BYTES
}

/// OWASP baseline Argon2id params: `{ memoryCostKib, iterations, parallelism }`.
///
/// Sourced from the OWASP Password Storage Cheat Sheet (19 MiB / t=2 / p=1).
/// Slow and memory-hard by design — lowering these for login latency is a
/// security tradeoff, not a free optimization.
#[wasm_bindgen(js_name = RECOMMENDED_PARAMS)]
pub fn recommended_params() -> Result<JsValue, JsValue> {
    params_to_js(&RECOMMENDED_PARAMS)
}

fn params_to_js(params: &Argon2Params) -> Result<JsValue, JsValue> {
    let obj = Object::new();
    js_sys::Reflect::set(
        &obj,
        &JsValue::from_str("memoryCostKib"),
        &JsValue::from_f64(f64::from(params.memory_cost_kib)),
    )?;
    js_sys::Reflect::set(
        &obj,
        &JsValue::from_str("iterations"),
        &JsValue::from_f64(f64::from(params.iterations)),
    )?;
    js_sys::Reflect::set(
        &obj,
        &JsValue::from_str("parallelism"),
        &JsValue::from_f64(f64::from(params.parallelism)),
    )?;
    Ok(obj.into())
}

fn params_from_js(value: &JsValue) -> Result<Argon2Params, JsValue> {
    let memory = js_sys::Reflect::get(value, &JsValue::from_str("memoryCostKib"))?
        .as_f64()
        .ok_or_else(|| js_error(enclave_pqc_primitives::Error::InvalidParameter))?;
    let iterations = js_sys::Reflect::get(value, &JsValue::from_str("iterations"))?
        .as_f64()
        .ok_or_else(|| js_error(enclave_pqc_primitives::Error::InvalidParameter))?;
    let parallelism = js_sys::Reflect::get(value, &JsValue::from_str("parallelism"))?
        .as_f64()
        .ok_or_else(|| js_error(enclave_pqc_primitives::Error::InvalidParameter))?;
    if !(0.0..(f64::from(u32::MAX)))
        .contains(&memory)
        || !(0.0..(f64::from(u32::MAX))).contains(&iterations)
        || !(0.0..(f64::from(u32::MAX))).contains(&parallelism)
    {
        return Err(js_error(enclave_pqc_primitives::Error::InvalidParameter));
    }
    Ok(Argon2Params {
        memory_cost_kib: memory as u32,
        iterations: iterations as u32,
        parallelism: parallelism as u32,
    })
}

/// Derive a 32-byte key from a password + salt with Argon2id.
///
/// `params` must be `{ memoryCostKib, iterations, parallelism }` (see
/// [`recommended_params`]). Throws on empty password / wrong salt length /
/// invalid costs.
///
/// This call is intentionally slow (~tens–hundreds of ms depending on host).
/// That cost is the offline brute-force defense — do not lower params casually.
#[wasm_bindgen(js_name = pwhashDeriveKey)]
pub fn pwhash_derive_key(
    password: &[u8],
    salt: &[u8],
    params: &JsValue,
) -> Result<Vec<u8>, JsValue> {
    let params = params_from_js(params)?;
    let out = pwhash::pwhash_derive_key(password, salt, &params).map_err(js_error)?;
    record_usage(out.usage);
    // PwhashOutput zeroizes on Drop — take the key before drop.
    let mut out = out;
    let key = core::mem::take(&mut out.key);
    Ok(key)
}

/// Cryptographically random 16-byte salt for Argon2id.
#[wasm_bindgen(js_name = generateSalt)]
pub fn generate_salt() -> Result<Vec<u8>, JsValue> {
    let out = pwhash::generate_salt().map_err(js_error)?;
    record_usage(out.usage);
    Ok(out.salt.to_vec())
}
