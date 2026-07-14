//! Shared helpers for NIST ACVP Known-Answer Tests.

#![allow(dead_code)]

use serde::Deserialize;

/// Decode a lowercase/uppercase hex string into bytes.
pub fn unhex(hex: &str) -> Vec<u8> {
    let hex = hex.trim();
    assert!(
        hex.len() % 2 == 0,
        "hex string must have even length (got {})",
        hex.len()
    );
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .unwrap_or_else(|e| panic!("invalid hex at {i}: {e}"))
        })
        .collect()
}

#[derive(Debug, Deserialize)]
pub struct KatFile<T> {
    pub tests: Vec<T>,
}

pub fn load_kat<T: for<'de> Deserialize<'de>>(path: &str) -> KatFile<T> {
    let data =
        std::fs::read_to_string(path).unwrap_or_else(|e| panic!("failed to read {path}: {e}"));
    serde_json::from_str(&data).unwrap_or_else(|e| panic!("failed to parse {path}: {e}"))
}

#[derive(Debug, Deserialize)]
pub struct KemKeygen {
    #[serde(rename = "tcId")]
    pub tc_id: u64,
    pub d: String,
    pub z: String,
    pub ek: String,
    pub dk: String,
}

#[derive(Debug, Deserialize)]
pub struct KemEncap {
    #[serde(rename = "tcId")]
    pub tc_id: u64,
    pub ek: String,
    pub m: String,
    pub c: String,
    pub k: String,
}

#[derive(Debug, Deserialize)]
pub struct KemDecap {
    #[serde(rename = "tcId")]
    pub tc_id: u64,
    pub dk: String,
    pub c: String,
    pub k: String,
}

#[derive(Debug, Deserialize)]
pub struct DsaKeygen {
    #[serde(rename = "tcId")]
    pub tc_id: u64,
    pub seed: String,
    pub pk: String,
    pub sk: String,
}

#[derive(Debug, Deserialize)]
pub struct DsaSigVer {
    #[serde(rename = "tcId")]
    pub tc_id: u64,
    pub pk: String,
    pub message: String,
    pub context: String,
    pub signature: String,
    #[serde(rename = "testPassed")]
    pub test_passed: bool,
}

#[derive(Debug, Deserialize)]
pub struct DsaSigGen {
    #[serde(rename = "tcId")]
    pub tc_id: u64,
    pub sk: String,
    pub message: String,
    pub context: String,
    pub signature: String,
}
