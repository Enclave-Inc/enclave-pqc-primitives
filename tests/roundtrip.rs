//! End-to-end round-trip spanning KEM → KDF → AEAD → signatures (Category 5).

use enclave_pqc_primitives::{
    aead, hash, kdf, kem, provider::CryptoProvider, run_self_tests, sig, SoftwareProvider,
    ENCLAVE_PQ_SUITE_ID,
};

#[test]
fn suite_id_stable() {
    assert_eq!(ENCLAVE_PQ_SUITE_ID, "ENCLAVE_PQ_SUITE_v1");
}

#[test]
fn sizes_are_category_5() {
    assert_eq!(kem::PUBLIC_KEY_BYTES, 1568);
    assert_eq!(kem::SECRET_KEY_BYTES, 3168);
    assert_eq!(kem::CIPHERTEXT_BYTES, 1568);
    assert_eq!(sig::PUBLIC_KEY_BYTES, 2592);
    assert_eq!(sig::SECRET_KEY_BYTES, 4896);
    assert_eq!(sig::SIGNATURE_BYTES, 4627);
    assert_eq!(kem::ALGORITHM, "ML-KEM-1024");
    assert_eq!(sig::ALGORITHM, "ML-DSA-87");
}

#[test]
fn kem_aead_kdf_pipeline() {
    let kp = kem::generate_keypair().expect("kem keygen");
    let enc = kem::encapsulate(&kp.keypair.public_key).expect("encapsulate");
    let shared = kem::decapsulate(&enc.encapsulation.ciphertext, &kp.keypair.secret_key)
        .expect("decapsulate");
    assert_eq!(shared.shared_secret, enc.encapsulation.shared_secret);
    assert_eq!(enc.usage.algorithm, "ML-KEM-1024");
    assert_eq!(enc.usage.suite_id, ENCLAVE_PQ_SUITE_ID);

    let key =
        kdf::labeled_kdf("aes-256-gcm-key", &shared.shared_secret, aead::KEY_BYTES).expect("kdf");
    let nonce = {
        let digest = hash::shake256(b"test-nonce-context", aead::NONCE_BYTES);
        let mut n = [0u8; aead::NONCE_BYTES];
        n.copy_from_slice(&digest.digest);
        n
    };

    let plaintext = b"pipeline-plaintext";
    let aad = b"pipeline-aad";
    let sealed = aead::encrypt(&key.key, &nonce, plaintext, aad).expect("encrypt");
    let opened = aead::decrypt(&key.key, &nonce, &sealed.result.ciphertext, aad).expect("decrypt");
    assert_eq!(opened.plaintext, plaintext);
}

#[test]
fn signature_roundtrip_empty_context() {
    let kp = sig::generate_keypair().expect("sig keygen");
    let msg = b"integration-signature";
    let signature = sig::sign(&kp.keypair.secret_key, msg).expect("sign");
    let again = sig::sign(&kp.keypair.secret_key, msg).expect("sign-again");
    assert_eq!(signature.signature, again.signature);
    sig::verify(&kp.keypair.public_key, msg, &signature.signature).expect("verify");
    assert_eq!(signature.usage.algorithm, "ML-DSA-87");
}

#[test]
fn labeled_kdf_domain_separation() {
    let ikm = b"shared-secret-material";
    let a = kdf::labeled_kdf("purpose-a", ikm, 32).unwrap();
    let b = kdf::labeled_kdf("purpose-b", ikm, 32).unwrap();
    assert_ne!(a.key, b.key);
}

#[test]
fn software_provider_matches_free_functions() {
    let provider = SoftwareProvider;
    let kp = provider.kem_generate_keypair().expect("provider kem");
    let enc = provider
        .kem_encapsulate(&kp.keypair.public_key)
        .expect("provider encapsulate");
    let shared = provider
        .kem_decapsulate(&enc.encapsulation.ciphertext, &kp.keypair.secret_key)
        .expect("provider decapsulate");
    assert_eq!(shared.shared_secret, enc.encapsulation.shared_secret);

    let sig_kp = provider.sig_generate_keypair().expect("provider sig");
    let signed = provider
        .sig_sign(&sig_kp.keypair.secret_key, b"provider-msg")
        .expect("provider sign");
    provider
        .sig_verify(
            &sig_kp.keypair.public_key,
            b"provider-msg",
            &signed.signature,
        )
        .expect("provider verify");
}

#[test]
fn cast_self_tests_pass() {
    run_self_tests().expect("CAST self-tests");
}
