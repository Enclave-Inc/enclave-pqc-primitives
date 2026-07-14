//! Map Rust primitive errors to typed, catchable JS `Error` values.
//!
//! Error `name` is set so product SDKs can distinguish:
//! - `PairwiseConsistencyFailureError` — PCT failed inside keygen (entropy /
//!   module integrity concern)
//! - `SelfTestFailureError` — CAST known-answer self-test failed
//! - greppable prefixes (`InvalidLength:`, `AeadFailure:`, …) for other cases

use enclave_pqc_primitives::error::SelfTestError;
use enclave_pqc_primitives::Error;
use js_sys::Reflect;
use wasm_bindgen::JsValue;

fn throw_named(name: &str, message: &str) -> JsValue {
    let err = js_sys::Error::new(message);
    let _ = Reflect::set(&err, &JsValue::from_str("name"), &JsValue::from_str(name));
    JsValue::from(err)
}

/// Convert a primitives [`Error`] into a thrown JS value.
pub(crate) fn js_error(err: Error) -> JsValue {
    match err {
        Error::PairwiseConsistencyFailure => throw_named(
            "PairwiseConsistencyFailureError",
            &format!("PairwiseConsistencyFailure: {}", err.as_str()),
        ),
        Error::InvalidLength => {
            throw_named("Error", &format!("InvalidLength: {}", err.as_str()))
        }
        Error::InvalidEncoding => {
            throw_named("Error", &format!("InvalidEncoding: {}", err.as_str()))
        }
        Error::AeadFailure => throw_named("Error", &format!("AeadFailure: {}", err.as_str())),
        Error::SignatureInvalid => {
            throw_named("Error", &format!("SignatureInvalid: {}", err.as_str()))
        }
        Error::InvalidParameter => {
            throw_named("Error", &format!("InvalidParameter: {}", err.as_str()))
        }
    }
}

/// Convert a [`SelfTestError`] into a thrown JS value.
pub(crate) fn js_self_test_error(err: SelfTestError) -> JsValue {
    throw_named(
        "SelfTestFailureError",
        &format!("SelfTestFailure: {err}"),
    )
}

/// Throw a boundary check failure with a greppable prefix.
pub(crate) fn js_invalid_length(detail: &str) -> JsValue {
    throw_named("Error", &format!("InvalidLength: {detail}"))
}

/// Throw an invalid-parameter boundary failure.
pub(crate) fn js_invalid_parameter(detail: &str) -> JsValue {
    throw_named("Error", &format!("InvalidParameter: {detail}"))
}
