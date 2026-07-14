//! ML-KEM-1024 wasm bindings (NIST Category 5).

use enclave_pqc_primitives::kem;
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

/// Generate a fresh ML-KEM-1024 keypair (includes PCT).
///
/// Returns `{ publicKey, secretKey }` where `secretKey` is the preferred
/// seed form ([`kem::SECRET_KEY_SEED_BYTES`] = 64). Expanded size is
/// [`kem::SECRET_KEY_BYTES`] = 3168 — use [`kem_expanded_secret_key`].
///
/// Throws `PairwiseConsistencyFailureError` if the PCT fails.
#[wasm_bindgen(js_name = kemGenerateKeypair)]
pub fn kem_generate_keypair() -> Result<JsValue, JsValue> {
    let out = kem::generate_keypair().map_err(js_error)?;
    record_usage(out.usage);
    keypair_object(&out.keypair.public_key, &out.keypair.secret_key)
}

/// Derive an ML-KEM-1024 keypair from a 64-byte seed (`d || z`). Includes PCT.
#[wasm_bindgen(js_name = kemKeypairFromSeed)]
pub fn kem_keypair_from_seed(seed: &[u8]) -> Result<JsValue, JsValue> {
    let out = kem::keypair_from_seed(seed).map_err(js_error)?;
    record_usage(out.usage);
    keypair_object(&out.keypair.public_key, &out.keypair.secret_key)
}

/// Expand a 64-byte seed-form secret key to the FIPS expanded encoding
/// ([`kem::SECRET_KEY_BYTES`] bytes).
#[wasm_bindgen(js_name = kemExpandedSecretKey)]
pub fn kem_expanded_secret_key(secret_key: &[u8]) -> Result<Vec<u8>, JsValue> {
    let (expanded, usage) = kem::expanded_secret_key(secret_key).map_err(js_error)?;
    record_usage(usage);
    Ok(expanded)
}

/// Encapsulate a shared secret to an ML-KEM-1024 public key.
///
/// Returns `{ ciphertext, sharedSecret }` (1568 / 32 bytes).
#[wasm_bindgen(js_name = kemEncapsulate)]
pub fn kem_encapsulate(public_key: &[u8]) -> Result<JsValue, JsValue> {
    let out = kem::encapsulate(public_key).map_err(js_error)?;
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
/// **KATs only.** Production code must call [`kem_encapsulate`].
#[wasm_bindgen(js_name = kemEncapsulateDeterministic)]
pub fn kem_encapsulate_deterministic(public_key: &[u8], m: &[u8]) -> Result<JsValue, JsValue> {
    let out = kem::encapsulate_deterministic(public_key, m).map_err(js_error)?;
    record_usage(out.usage);
    encapsulation_object(
        &out.encapsulation.ciphertext,
        &out.encapsulation.shared_secret,
    )
}

/// Decapsulate an ML-KEM-1024 ciphertext.
///
/// `secret_key` may be a 64-byte seed or a 3168-byte expanded key.
#[wasm_bindgen(js_name = kemDecapsulate)]
pub fn kem_decapsulate(ciphertext: &[u8], secret_key: &[u8]) -> Result<Vec<u8>, JsValue> {
    let out = kem::decapsulate(ciphertext, secret_key).map_err(js_error)?;
    record_usage(out.usage);
    Ok(out.shared_secret)
}
