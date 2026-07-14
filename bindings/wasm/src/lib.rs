//! Generic wasm-bindgen façade over `enclave-pqc-primitives`.
//!
//! Namespaced by **algorithm** only (`kem` / `sig` / `aead` / `hash` / `kdf`).
//! Product concepts (sessions, envelopes, tokens, credentials) must not appear
//! here — they belong in product SDKs that consume this package.
//!
//! Implements NIST Category 5 exclusively (ML-KEM-1024 / ML-DSA-87). There is
//! no suite-selection parameter.

#![deny(missing_docs)]
#![allow(non_snake_case)]

mod aead;
mod error;
mod hash;
mod kdf;
mod kem;
mod self_test;
mod sig;
mod usage;

pub use aead::*;
pub use hash::*;
pub use kdf::*;
pub use kem::*;
pub use self_test::*;
pub use sig::*;
pub use usage::*;

use wasm_bindgen::prelude::*;

/// Canonical suite identifier matching the Rust crate (Category 5 algorithms).
#[wasm_bindgen(js_name = ENCLAVE_PQ_SUITE_ID)]
pub fn enclave_pq_suite_id() -> String {
    enclave_pqc_primitives::ENCLAVE_PQ_SUITE_ID.to_string()
}

/// Overwrite a JS `Uint8Array` in place with zeros.
///
/// # Security note
///
/// Rust-side secret keys are zeroized on `Drop`, but that guarantee **does not**
/// cross the WASM boundary. Once secret material lives in a JS `Uint8Array`, the
/// JS garbage collector will not zero it. Call this when you are finished with
/// long-lived secret buffers.
#[wasm_bindgen(js_name = zeroize)]
pub fn zeroize(buf: &js_sys::Uint8Array) {
    let len = buf.length();
    for i in 0..len {
        buf.set_index(i, 0);
    }
}
