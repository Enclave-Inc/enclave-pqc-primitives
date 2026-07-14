//! ML-DSA-87 wasm bindings (NIST Category 5).

use enclave_pqc_primitives::{sig, Error};
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

/// Generate a fresh ML-DSA-87 keypair (includes PCT).
///
/// Returns `{ publicKey, secretKey }` where `secretKey` is the preferred
/// seed form ([`sig::SECRET_KEY_SEED_BYTES`] = 32). Expanded size is
/// [`sig::SECRET_KEY_BYTES`] = 4896.
///
/// Throws `PairwiseConsistencyFailureError` if the PCT fails.
#[wasm_bindgen(js_name = sigGenerateKeypair)]
pub fn sig_generate_keypair() -> Result<JsValue, JsValue> {
    let out = sig::generate_keypair().map_err(js_error)?;
    record_usage(out.usage);
    keypair_object(&out.keypair.public_key, &out.keypair.secret_key)
}

/// Derive an ML-DSA-87 keypair from a 32-byte seed. Includes PCT.
#[wasm_bindgen(js_name = sigKeypairFromSeed)]
pub fn sig_keypair_from_seed(seed: &[u8]) -> Result<JsValue, JsValue> {
    let out = sig::keypair_from_seed(seed).map_err(js_error)?;
    record_usage(out.usage);
    keypair_object(&out.keypair.public_key, &out.keypair.secret_key)
}

/// Expand a 32-byte seed-form secret key to the FIPS expanded encoding
/// ([`sig::SECRET_KEY_BYTES`] bytes).
#[wasm_bindgen(js_name = sigExpandedSecretKey)]
pub fn sig_expanded_secret_key(secret_key: &[u8]) -> Result<Vec<u8>, JsValue> {
    let (expanded, usage) = sig::expanded_secret_key(secret_key).map_err(js_error)?;
    record_usage(usage);
    Ok(expanded)
}

/// Sign a message with empty context (deterministic ML-DSA-87).
///
/// Empty `message` throws `InvalidLength` (matches Rust).
#[wasm_bindgen(js_name = sigSign)]
pub fn sig_sign(secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>, JsValue> {
    let out = sig::sign(secret_key, message).map_err(js_error)?;
    record_usage(out.usage);
    Ok(out.signature)
}

/// Deterministic ML-DSA.Sign with an explicit context (`context.len() <= 255`).
///
/// Empty `message` or `context.len() > 255` throws (matches Rust).
#[wasm_bindgen(js_name = sigSignWithContext)]
pub fn sig_sign_with_context(
    secret_key: &[u8],
    message: &[u8],
    context: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let out = sig::sign_deterministic(secret_key, message, context).map_err(js_error)?;
    record_usage(out.usage);
    Ok(out.signature)
}

/// Verify an ML-DSA-87 signature (empty context).
///
/// Returns `false` on a cryptographically invalid signature. Throws only for
/// malformed input lengths / encodings.
#[wasm_bindgen(js_name = sigVerify)]
pub fn sig_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, JsValue> {
    match sig::verify(public_key, message, signature) {
        Ok(out) => {
            record_usage(out.usage);
            Ok(true)
        }
        Err(Error::SignatureInvalid) => Ok(false),
        Err(other) => Err(js_error(other)),
    }
}

/// Verify an ML-DSA-87 signature with an explicit context.
///
/// Returns `false` on cryptographic failure; throws on malformed lengths.
#[wasm_bindgen(js_name = sigVerifyWithContext)]
pub fn sig_verify_with_context(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
    context: &[u8],
) -> Result<bool, JsValue> {
    match sig::verify_with_context(public_key, message, signature, context) {
        Ok(out) => {
            record_usage(out.usage);
            Ok(true)
        }
        Err(Error::SignatureInvalid) => Ok(false),
        Err(other) => Err(js_error(other)),
    }
}
