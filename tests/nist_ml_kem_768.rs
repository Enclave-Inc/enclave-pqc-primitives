//! NIST ACVP Known-Answer Tests for ML-KEM-768 (FIPS 203).
//!
//! Vectors sourced from `usnistgov/ACVP-Server` gen-val JSON:
//! `ML-KEM-keyGen-FIPS203` and `ML-KEM-encapDecap-FIPS203`.

mod common;

use common::{load_kat, unhex, KemDecap, KemEncap, KemKeygen};
use enclave_pqc_primitives::kem;

#[test]
fn nist_acvp_ml_kem_768_keygen() {
    let cats = load_kat::<KemKeygen>("tests/nist/ml_kem_768_keygen.json");
    assert_eq!(
        cats.tests.len(),
        25,
        "expected 25 ACVP ML-KEM-768 keyGen cases"
    );

    for t in cats.tests {
        let mut seed = unhex(&t.d);
        seed.extend_from_slice(&unhex(&t.z));
        assert_eq!(seed.len(), kem::SECRET_KEY_SEED_BYTES);

        let kp = kem::keypair_from_seed(&seed)
            .unwrap_or_else(|e| panic!("tcId {}: keypair_from_seed: {e}", t.tc_id));
        assert_eq!(kp.public_key, unhex(&t.ek), "tcId {}: ek mismatch", t.tc_id);
        assert_eq!(
            kp.secret_key, seed,
            "tcId {}: seed-form sk mismatch",
            t.tc_id
        );
        assert_eq!(
            kem::expanded_secret_key(&kp.secret_key).unwrap(),
            unhex(&t.dk),
            "tcId {}: expanded dk mismatch",
            t.tc_id
        );
    }
}

#[test]
fn nist_acvp_ml_kem_768_encapsulation() {
    let cats = load_kat::<KemEncap>("tests/nist/ml_kem_768_encapsulation.json");
    assert_eq!(cats.tests.len(), 25);

    for t in cats.tests {
        let ek = unhex(&t.ek);
        let m = unhex(&t.m);
        let enc = kem::encapsulate_deterministic(&ek, &m)
            .unwrap_or_else(|e| panic!("tcId {}: encapsulate_deterministic: {e}", t.tc_id));
        assert_eq!(enc.ciphertext, unhex(&t.c), "tcId {}: c mismatch", t.tc_id);
        assert_eq!(
            enc.shared_secret,
            unhex(&t.k),
            "tcId {}: k mismatch",
            t.tc_id
        );
    }
}

#[test]
fn nist_acvp_ml_kem_768_decapsulation() {
    let cats = load_kat::<KemDecap>("tests/nist/ml_kem_768_decapsulation.json");
    assert_eq!(cats.tests.len(), 10);

    for t in cats.tests {
        let dk = unhex(&t.dk);
        let c = unhex(&t.c);
        assert_eq!(dk.len(), kem::SECRET_KEY_EXPANDED_BYTES);
        let k = kem::decapsulate(&c, &dk)
            .unwrap_or_else(|e| panic!("tcId {}: decapsulate: {e}", t.tc_id));
        assert_eq!(k, unhex(&t.k), "tcId {}: shared secret mismatch", t.tc_id);
    }
}
