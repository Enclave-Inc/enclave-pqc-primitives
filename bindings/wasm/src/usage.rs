//! Last-operation CBOM usage metadata for JS callers.

use std::cell::RefCell;

use enclave_pqc_primitives::usage::CryptoUsageRecord;
use js_sys::{Object, Reflect};
use wasm_bindgen::prelude::*;

#[derive(Clone, Copy)]
struct UsageSnapshot {
    algorithm: &'static str,
    suite_id: &'static str,
    operation: &'static str,
    crate_version: &'static str,
}

impl From<CryptoUsageRecord> for UsageSnapshot {
    fn from(value: CryptoUsageRecord) -> Self {
        Self {
            algorithm: value.algorithm,
            suite_id: value.suite_id,
            operation: value.operation,
            crate_version: value.crate_version,
        }
    }
}

thread_local! {
    static LAST_USAGE: RefCell<Option<UsageSnapshot>> = const { RefCell::new(None) };
}

/// Record usage from the most recent WASM-bound primitive call.
pub(crate) fn record_usage(usage: CryptoUsageRecord) {
    LAST_USAGE.with(|cell| {
        *cell.borrow_mut() = Some(UsageSnapshot::from(usage));
    });
}

fn usage_to_js(snap: UsageSnapshot) -> Result<JsValue, JsValue> {
    let obj = Object::new();
    Reflect::set(
        &obj,
        &JsValue::from_str("algorithm"),
        &JsValue::from_str(snap.algorithm),
    )?;
    Reflect::set(
        &obj,
        &JsValue::from_str("suiteId"),
        &JsValue::from_str(snap.suite_id),
    )?;
    Reflect::set(
        &obj,
        &JsValue::from_str("operation"),
        &JsValue::from_str(snap.operation),
    )?;
    Reflect::set(
        &obj,
        &JsValue::from_str("crateVersion"),
        &JsValue::from_str(snap.crate_version),
    )?;
    Ok(obj.into())
}

/// Return the [`CryptoUsageRecord`] from the last WASM primitive call.
///
/// Shape: `{ algorithm, suiteId, operation, crateVersion }`.
/// Returns `undefined` if no operation has run yet in this WASM instance.
///
/// This is the CBOM attach point for product layers (Encrypt, etc.). This
/// binding does not persist or transmit the record.
#[wasm_bindgen(js_name = getLastUsageRecord)]
pub fn get_last_usage_record() -> Result<JsValue, JsValue> {
    LAST_USAGE.with(|cell| match *cell.borrow() {
        Some(snap) => usage_to_js(snap),
        None => Ok(JsValue::UNDEFINED),
    })
}
