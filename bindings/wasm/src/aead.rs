//! AES-256-GCM wasm bindings.

use enclave_pqc_primitives::aead;
use wasm_bindgen::prelude::*;

use crate::error::{js_error, js_invalid_length};
use crate::usage::record_usage;

fn check_aead_key_nonce(key: &[u8], nonce: &[u8]) -> Result<(), JsValue> {
    if key.len() != aead::KEY_BYTES {
        return Err(js_invalid_length(&format!(
            "AES-256-GCM key must be {} bytes, got {}",
            aead::KEY_BYTES,
            key.len()
        )));
    }
    if nonce.len() != aead::NONCE_BYTES {
        return Err(js_invalid_length(&format!(
            "AES-256-GCM nonce must be {} bytes, got {}",
            aead::NONCE_BYTES,
            nonce.len()
        )));
    }
    Ok(())
}

/// Encrypt with AES-256-GCM under an explicit key and nonce.
///
/// Returns `ciphertext || tag` (16-byte tag suffix). Callers must ensure
/// `(key, nonce)` uniqueness.
#[wasm_bindgen(js_name = aeadEncrypt)]
pub fn aead_encrypt(
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, JsValue> {
    check_aead_key_nonce(key, nonce)?;
    let out = aead::encrypt(key, nonce, plaintext, aad).map_err(js_error)?;
    record_usage(out.usage);
    Ok(out.result.ciphertext.clone())
}

/// Decrypt AES-256-GCM ciphertext (including trailing tag).
///
/// Throws on authentication failure (`AeadFailure: ...`).
#[wasm_bindgen(js_name = aeadDecrypt)]
pub fn aead_decrypt(
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, JsValue> {
    check_aead_key_nonce(key, nonce)?;
    let out = aead::decrypt(key, nonce, ciphertext, aad).map_err(js_error)?;
    record_usage(out.usage);
    Ok(out.plaintext)
}
