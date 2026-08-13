//! ML-KEM-768 wasm bindings (NIST Category 3).

use enclave_pqc_primitives::kem768;
use js_sys::{Object, Reflect, Uint8Array};
use wasm_bindgen::prelude::*;

use crate::error::js_error;
use crate::usage::record_usage;

fn keypair_object(public_key: &[u8], secret_key: &[u8]) -> Result<JsValue, JsValue> {
    let obj = Object::new();
    Reflect::set(
        &obj,
        &JsValue::from_str("publicKey"),
        &Uint8Array::from(public_key),
    )?;
    Reflect::set(
        &obj,
        &JsValue::from_str("secretKey"),
        &Uint8Array::from(secret_key),
    )?;
    Ok(obj.into())
}

fn encapsulation_object(ciphertext: &[u8], shared_secret: &[u8]) -> Result<JsValue, JsValue> {
    let obj = Object::new();
    Reflect::set(
        &obj,
        &JsValue::from_str("ciphertext"),
        &Uint8Array::from(ciphertext),
    )?;
    Reflect::set(
        &obj,
        &JsValue::from_str("sharedSecret"),
        &Uint8Array::from(shared_secret),
    )?;
    Ok(obj.into())
}

/// Generate a fresh ML-KEM-768 keypair (includes PCT).
///
/// Returns `{ publicKey, secretKey }` where `secretKey` is the preferred
/// seed form ([`kem768::SECRET_KEY_SEED_BYTES`] = 64). Expanded size is
/// [`kem768::SECRET_KEY_BYTES`] = 2400 — use [`kem768_expanded_secret_key`].
///
/// Throws `PairwiseConsistencyFailureError` if the PCT fails.
#[wasm_bindgen(js_name = kem768GenerateKeypair)]
pub fn kem768_generate_keypair() -> Result<JsValue, JsValue> {
    let out = kem768::generate_keypair().map_err(js_error)?;
    record_usage(out.usage);
    keypair_object(&out.keypair.public_key, &out.keypair.secret_key)
}

/// Derive an ML-KEM-768 keypair from a 64-byte seed (`d || z`). Includes PCT.
#[wasm_bindgen(js_name = kem768KeypairFromSeed)]
pub fn kem768_keypair_from_seed(seed: &[u8]) -> Result<JsValue, JsValue> {
    let out = kem768::keypair_from_seed(seed).map_err(js_error)?;
    record_usage(out.usage);
    keypair_object(&out.keypair.public_key, &out.keypair.secret_key)
}

/// Expand a 64-byte seed-form secret key to the FIPS expanded encoding
/// ([`kem768::SECRET_KEY_BYTES`] bytes).
#[wasm_bindgen(js_name = kem768ExpandedSecretKey)]
pub fn kem768_expanded_secret_key(secret_key: &[u8]) -> Result<Vec<u8>, JsValue> {
    let (expanded, usage) = kem768::expanded_secret_key(secret_key).map_err(js_error)?;
    record_usage(usage);
    Ok(expanded)
}

/// Encapsulate a shared secret to an ML-KEM-768 public key.
///
/// Returns `{ ciphertext, sharedSecret }` (1088 / 32 bytes).
#[wasm_bindgen(js_name = kem768Encapsulate)]
pub fn kem768_encapsulate(public_key: &[u8]) -> Result<JsValue, JsValue> {
    let out = kem768::encapsulate(public_key).map_err(js_error)?;
    record_usage(out.usage);
    encapsulation_object(
        &out.encapsulation.ciphertext,
        &out.encapsulation.shared_secret,
    )
}

/// Deterministic encapsulation for known-answer / KAT compliance.
///
/// # Hazmat
///
/// **KATs only.** Production code must call [`kem768_encapsulate`].
#[wasm_bindgen(js_name = kem768EncapsulateDeterministic)]
pub fn kem768_encapsulate_deterministic(public_key: &[u8], m: &[u8]) -> Result<JsValue, JsValue> {
    let out = kem768::encapsulate_deterministic(public_key, m).map_err(js_error)?;
    record_usage(out.usage);
    encapsulation_object(
        &out.encapsulation.ciphertext,
        &out.encapsulation.shared_secret,
    )
}

/// Decapsulate an ML-KEM-768 ciphertext.
///
/// `secret_key` may be a 64-byte seed or a 2400-byte expanded key.
#[wasm_bindgen(js_name = kem768Decapsulate)]
pub fn kem768_decapsulate(ciphertext: &[u8], secret_key: &[u8]) -> Result<Vec<u8>, JsValue> {
    let out = kem768::decapsulate(ciphertext, secret_key).map_err(js_error)?;
    record_usage(out.usage);
    Ok(out.shared_secret)
}
