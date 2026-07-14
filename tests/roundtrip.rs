//! End-to-end round-trip spanning KEM → KDF → AEAD → signatures.
//!
//! These are complementary to the NIST KAT suites under `tests/nist_*.rs`.

use enclave_pqc_primitives::{aead, hash, kdf, kem, sig, ENCLAVE_PQ_SUITE_ID};

#[test]
fn suite_id_stable() {
    assert_eq!(ENCLAVE_PQ_SUITE_ID, "ENCLAVE_PQ_SUITE_v1");
}

#[test]
fn kem_aead_kdf_pipeline() {
    let kp = kem::generate_keypair();
    let enc = kem::encapsulate(&kp.public_key).expect("encapsulate");
    let shared = kem::decapsulate(&enc.ciphertext, &kp.secret_key).expect("decapsulate");
    assert_eq!(shared, enc.shared_secret);

    let key = kdf::labeled_kdf("aes-256-gcm-key", &shared, aead::KEY_BYTES).expect("kdf");
    let nonce = {
        let digest = hash::shake256(b"test-nonce-context", aead::NONCE_BYTES);
        let mut n = [0u8; aead::NONCE_BYTES];
        n.copy_from_slice(&digest);
        n
    };

    let plaintext = b"pipeline-plaintext";
    let aad = b"pipeline-aad";
    let sealed = aead::encrypt(&key, &nonce, plaintext, aad).expect("encrypt");
    let opened = aead::decrypt(&key, &nonce, &sealed.ciphertext, aad).expect("decrypt");
    assert_eq!(opened, plaintext);
}

#[test]
fn signature_roundtrip_empty_context() {
    let kp = sig::generate_keypair();
    let msg = b"integration-signature";
    let signature = sig::sign(&kp.secret_key, msg).expect("sign");
    // Deterministic: same inputs → same signature.
    let again = sig::sign(&kp.secret_key, msg).expect("sign-again");
    assert_eq!(signature, again);
    sig::verify(&kp.public_key, msg, &signature).expect("verify");
}

#[test]
fn labeled_kdf_domain_separation() {
    let ikm = b"shared-secret-material";
    let a = kdf::labeled_kdf("purpose-a", ikm, 32).unwrap();
    let b = kdf::labeled_kdf("purpose-b", ikm, 32).unwrap();
    assert_ne!(a, b);
}
