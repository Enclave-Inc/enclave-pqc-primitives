//! Known-answer tests for AES-256-GCM, SHAKE256, and enclave-kdf-v1.
//!
//! AES-GCM vectors are from NIST SP 800-38D (via the classic CAVP-style cases).
//! SHAKE256 vectors are from NIST FIPS 202 short-message KAT material.
//! The KDF vector binds the labeled construction to SHAKE256 output.

use enclave_pqc_primitives::{aead, hash, kdf};

fn unhex(hex: &str) -> Vec<u8> {
    let hex = hex.trim();
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
        .collect()
}

#[test]
fn nist_aes_256_gcm_empty_plaintext() {
    let key = unhex("0000000000000000000000000000000000000000000000000000000000000000");
    let nonce = unhex("000000000000000000000000");
    let sealed = aead::encrypt(&key, &nonce, b"", b"").expect("encrypt");
    assert_eq!(
        sealed.result.ciphertext,
        unhex("530f8afbc74536b9a963b4f1c4cb738b")
    );
    let pt = aead::decrypt(&key, &nonce, &sealed.result.ciphertext, b"").expect("decrypt");
    assert!(pt.plaintext.is_empty());
}

#[test]
fn nist_aes_256_gcm_with_plaintext_and_aad() {
    let key = unhex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
    let nonce = unhex("cafebabefacedbaddecaf888");
    let aad = unhex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
    let plaintext = unhex(
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
         1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
    );
    let expected = unhex(
        "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa\
         8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f66276fc6ece\
         0f4e1768cddf8853bb2d551b",
    );

    let sealed = aead::encrypt(&key, &nonce, &plaintext, &aad).expect("encrypt");
    assert_eq!(sealed.result.ciphertext, expected);
    let opened = aead::decrypt(&key, &nonce, &sealed.result.ciphertext, &aad).expect("decrypt");
    assert_eq!(opened.plaintext, plaintext);
}

#[test]
fn nist_shake256_empty_and_abc() {
    assert_eq!(
        hash::shake256(b"", 32).digest,
        unhex("46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f")
    );
    assert_eq!(
        hash::shake256(b"abc", 32).digest,
        unhex("483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739")
    );
    assert_eq!(
        hash::shake256(b"", 64).digest,
        unhex(
            "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f\
             d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be"
        )
    );
}

#[test]
fn enclave_kdf_v1_known_answer() {
    let expected = hash::shake256(b"enclave-kdf-v1:aes-key:ikm-bytes", 32).digest;
    let got = kdf::labeled_kdf("aes-key", b"ikm-bytes", 32).expect("kdf");
    assert_eq!(got.key, expected);
    assert_ne!(
        got.key,
        kdf::labeled_kdf("other-key", b"ikm-bytes", 32).unwrap().key
    );
}
