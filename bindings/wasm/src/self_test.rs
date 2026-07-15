//! CAST self-tests exposed to JavaScript.

use enclave_pqc_primitives::run_self_tests;
use wasm_bindgen::prelude::*;

use crate::error::js_self_test_error;

/// Run known-answer CASTs for ML-KEM-1024, ML-DSA-87, and Argon2id.
///
/// Throws `SelfTestFailureError` if any CAST fails. Pair-wise consistency is
/// already enforced inside key generation — this is the power-on / module-entry
/// known-answer path. The Argon2id CAST is slower (memory-hard by design).
#[wasm_bindgen(js_name = runSelfTests)]
pub fn run_self_tests_js() -> Result<(), JsValue> {
    run_self_tests().map_err(js_self_test_error)
}
