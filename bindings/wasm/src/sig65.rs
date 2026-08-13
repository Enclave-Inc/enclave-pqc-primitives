//! ML-DSA-65 wasm bindings (NIST Category 3).

use enclave_pqc_primitives::{sig65, Error};
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

/// Generate a fresh ML-DSA-65 keypair (includes PCT).
#[wasm_bindgen(js_name = sig65GenerateKeypair)]
pub fn sig65_generate_keypair() -> Result<JsValue, JsValue> {
    let out = sig65::generate_keypair().map_err(js_error)?;
    record_usage(out.usage);
    keypair_object(&out.keypair.public_key, &out.keypair.secret_key)
}

/// Derive an ML-DSA-65 keypair from a 32-byte seed. Includes PCT.
#[wasm_bindgen(js_name = sig65KeypairFromSeed)]
pub fn sig65_keypair_from_seed(seed: &[u8]) -> Result<JsValue, JsValue> {
    let out = sig65::keypair_from_seed(seed).map_err(js_error)?;
    record_usage(out.usage);
    keypair_object(&out.keypair.public_key, &out.keypair.secret_key)
}

/// Expand a 32-byte seed-form secret key to the FIPS expanded encoding (4032 bytes).
#[wasm_bindgen(js_name = sig65ExpandedSecretKey)]
pub fn sig65_expanded_secret_key(secret_key: &[u8]) -> Result<Vec<u8>, JsValue> {
    let (expanded, usage) = sig65::expanded_secret_key(secret_key).map_err(js_error)?;
    record_usage(usage);
    Ok(expanded)
}

/// Sign a message with empty context (deterministic ML-DSA-65).
#[wasm_bindgen(js_name = sig65Sign)]
pub fn sig65_sign(secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>, JsValue> {
    let out = sig65::sign(secret_key, message).map_err(js_error)?;
    record_usage(out.usage);
    Ok(out.signature)
}

/// Deterministic ML-DSA.Sign with an explicit context (`context.len() <= 255`).
#[wasm_bindgen(js_name = sig65SignWithContext)]
pub fn sig65_sign_with_context(
    secret_key: &[u8],
    message: &[u8],
    context: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let out = sig65::sign_deterministic(secret_key, message, context).map_err(js_error)?;
    record_usage(out.usage);
    Ok(out.signature)
}

/// Verify an ML-DSA-65 signature (empty context).
#[wasm_bindgen(js_name = sig65Verify)]
pub fn sig65_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, JsValue> {
    match sig65::verify(public_key, message, signature) {
        Ok(out) => {
            record_usage(out.usage);
            Ok(true)
        }
        Err(Error::SignatureInvalid) => Ok(false),
        Err(other) => Err(js_error(other)),
    }
}

/// Verify an ML-DSA-65 signature with an explicit context.
#[wasm_bindgen(js_name = sig65VerifyWithContext)]
pub fn sig65_verify_with_context(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
    context: &[u8],
) -> Result<bool, JsValue> {
    match sig65::verify_with_context(public_key, message, signature, context) {
        Ok(out) => {
            record_usage(out.usage);
            Ok(true)
        }
        Err(Error::SignatureInvalid) => Ok(false),
        Err(other) => Err(js_error(other)),
    }
}
