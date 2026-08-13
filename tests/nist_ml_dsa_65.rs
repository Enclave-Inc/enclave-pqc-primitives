//! NIST ACVP Known-Answer Tests for ML-DSA-65 (FIPS 204).
//!
//! Vectors sourced from `usnistgov/ACVP-Server` gen-val JSON:
//! `ML-DSA-keyGen-FIPS204`, `ML-DSA-sigGen-FIPS204`, and `ML-DSA-sigVer-FIPS204`
//! (external / pure interface).

mod common;

use common::{load_kat, unhex, DsaKeygen, DsaSigGen, DsaSigVer};
use enclave_pqc_primitives::sig65;

#[test]
fn nist_acvp_ml_dsa_65_keygen() {
    let cats = load_kat::<DsaKeygen>("tests/nist/ml_dsa_65_keygen.json");
    assert_eq!(
        cats.tests.len(),
        25,
        "expected 25 ACVP ML-DSA-65 keyGen cases"
    );

    for t in cats.tests {
        let seed = unhex(&t.seed);
        let out = sig65::keypair_from_seed(&seed)
            .unwrap_or_else(|e| panic!("tcId {}: keypair_from_seed: {e}", t.tc_id));
        assert_eq!(
            out.keypair.public_key,
            unhex(&t.pk),
            "tcId {}: pk mismatch",
            t.tc_id
        );
        assert_eq!(
            out.keypair.secret_key, seed,
            "tcId {}: seed mismatch",
            t.tc_id
        );
        let (expanded, _) = sig65::expanded_secret_key(&out.keypair.secret_key)
            .unwrap_or_else(|e| panic!("tcId {}: expanded_secret_key: {e}", t.tc_id));
        assert_eq!(
            expanded,
            unhex(&t.sk),
            "tcId {}: expanded sk mismatch",
            t.tc_id
        );
    }
}

#[test]
fn nist_acvp_ml_dsa_65_sigver_external_pure() {
    let cats = load_kat::<DsaSigVer>("tests/nist/ml_dsa_65_sigver_external_pure.json");
    assert_eq!(cats.tests.len(), 15);

    for t in cats.tests {
        let pk = unhex(&t.pk);
        let message = unhex(&t.message);
        let context = unhex(&t.context);
        let signature = unhex(&t.signature);
        let result = sig65::verify_with_context(&pk, &message, &signature, &context);
        if t.test_passed {
            result.unwrap_or_else(|e| panic!("tcId {}: expected pass, got {e}", t.tc_id));
        } else {
            assert!(
                result.is_err(),
                "tcId {}: expected signature rejection",
                t.tc_id
            );
        }
    }
}

#[test]
fn nist_acvp_ml_dsa_65_siggen_deterministic_external_pure() {
    let cats =
        load_kat::<DsaSigGen>("tests/nist/ml_dsa_65_siggen_deterministic_external_pure.json");
    assert_eq!(cats.tests.len(), 15);

    for t in cats.tests {
        let sk = unhex(&t.sk);
        let message = unhex(&t.message);
        let context = unhex(&t.context);
        assert_eq!(sk.len(), sig65::SECRET_KEY_EXPANDED_BYTES);
        let out = sig65::sign_deterministic(&sk, &message, &context)
            .unwrap_or_else(|e| panic!("tcId {}: sign_deterministic: {e}", t.tc_id));
        assert_eq!(
            out.signature,
            unhex(&t.signature),
            "tcId {}: signature mismatch",
            t.tc_id
        );
    }
}
