//! Conditional algorithm self-tests (CASTs) per FIPS 140-3 IG 10.3.A style.
//!
//! These are known-answer checks over fixed seeds for ML-KEM-1024 and ML-DSA-87.
//! They are separate from the pair-wise consistency tests (PCTs) that run inside
//! key generation. Call [`run_self_tests`] at process start when a validated
//! boot path is required by a higher layer.
//!
//! Vectors were generated once with this crate's RustCrypto-backed
//! implementation (deterministic seeds) and embedded as golden answers. They
//! are **not** official NIST ACVP fixtures.

use crate::error::SelfTestError;
use crate::kem;
use crate::sig;

/// Fixed 64-byte ML-KEM-1024 seed (`d || z`) for the KEM CAST.
const KEM_SEED: [u8; 64] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
    0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
    0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c,
    0x3d, 0x3e, 0x3f, 0x40,
];

/// Fixed encapsulation randomness `m` for the KEM CAST.
const KEM_M: [u8; 32] = [
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae,
    0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd,
    0xbe, 0xbf,
];

/// Fixed 32-byte ML-DSA-87 seed for the signature CAST.
const SIG_SEED: [u8; 32] = [
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e,
    0x5f, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d,
    0x6e, 0x6f,
];

/// Fixed message for the signature CAST.
const SIG_MESSAGE: &[u8] = b"enclave-pqc-cast-sig-v1";

/// SHAKE256-32 of the CAST public key / shared secret / signature used as the
/// compact known answer (avoids embedding multi-kilobyte blobs in-source while
/// still failing loudly on any algorithmic drift).
mod expected {
    /// `SHAKE256(pk, 32)` for [`super::KEM_SEED`].
    pub const KEM_PK_DIGEST: [u8; 32] = [
        0x3f, 0x74, 0x64, 0x67, 0xc4, 0xe7, 0xd0, 0x0a, 0x8a, 0x31, 0x94, 0x67, 0x73, 0xa2, 0xf0,
        0xcc, 0xdd, 0x9b, 0x03, 0x99, 0x2b, 0x81, 0xd4, 0xa5, 0x5f, 0xfd, 0xdb, 0xfb, 0x4d, 0x5f,
        0x0b, 0xbe,
    ];
    /// Shared secret from encapsulate_deterministic(pk, KEM_M).
    pub const KEM_SHARED_SECRET: [u8; 32] = [
        0x2c, 0x8c, 0xcf, 0xb1, 0xaf, 0xf0, 0x2a, 0x65, 0xc4, 0xd0, 0xd4, 0x9c, 0x3c, 0x94, 0xd2,
        0x14, 0x52, 0x3c, 0x8d, 0xdf, 0xa1, 0xe7, 0xb2, 0x48, 0xb7, 0x14, 0xf0, 0xa0, 0xc5, 0x38,
        0x77, 0x79,
    ];
    /// `SHAKE256(ciphertext, 32)` for the same encapsulation.
    pub const KEM_CT_DIGEST: [u8; 32] = [
        0x11, 0xe4, 0x69, 0xfc, 0x25, 0x2f, 0x2c, 0xdd, 0xde, 0xfd, 0x8f, 0x94, 0x28, 0x53, 0x8d,
        0x88, 0x83, 0x97, 0x66, 0x99, 0xa2, 0x87, 0x6a, 0xe6, 0x57, 0x4e, 0x08, 0x29, 0xf1, 0x60,
        0xd3, 0xdc,
    ];
    /// `SHAKE256(pk, 32)` for [`super::SIG_SEED`].
    pub const SIG_PK_DIGEST: [u8; 32] = [
        0x10, 0x7b, 0x24, 0x98, 0xc6, 0x5a, 0x3f, 0x94, 0xac, 0xa1, 0x60, 0x5e, 0xd9, 0xd4, 0x1e,
        0xc6, 0x83, 0x5e, 0x51, 0xbc, 0x0e, 0xa9, 0x64, 0x31, 0x36, 0x3b, 0x16, 0xb3, 0xea, 0xb1,
        0xe1, 0xf8,
    ];
    /// `SHAKE256(signature, 32)` for (SIG_SEED, SIG_MESSAGE, empty context).
    pub const SIG_DIGEST: [u8; 32] = [
        0x2a, 0xa3, 0xee, 0x21, 0x2e, 0x35, 0x6b, 0x44, 0xbb, 0x90, 0x51, 0x8a, 0xa3, 0xf6, 0x75,
        0x12, 0xb3, 0x14, 0xfb, 0xcc, 0x90, 0x88, 0x49, 0xab, 0xc9, 0xec, 0x9c, 0xd3, 0x33, 0x69,
        0x72, 0x8c,
    ];
}

fn digest32(bytes: &[u8]) -> [u8; 32] {
    let out = crate::hash::shake256_raw(bytes, 32);
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

fn cast_kem() -> core::result::Result<(), SelfTestError> {
    let kp = kem::keypair_from_seed_unchecked(&KEM_SEED)?;
    let pk_digest = digest32(&kp.public_key);
    if pk_digest != expected::KEM_PK_DIGEST {
        return Err(SelfTestError::KnownAnswerMismatch { case: "kem_pk" });
    }

    let enc = kem::encapsulate_deterministic_unchecked(&kp.public_key, &KEM_M)?;
    if enc.shared_secret.as_slice() != expected::KEM_SHARED_SECRET {
        return Err(SelfTestError::KnownAnswerMismatch { case: "kem_ss" });
    }
    let ct_digest = digest32(&enc.ciphertext);
    if ct_digest != expected::KEM_CT_DIGEST {
        return Err(SelfTestError::KnownAnswerMismatch { case: "kem_ct" });
    }

    let recovered = kem::decapsulate(&enc.ciphertext, &kp.secret_key)?.shared_secret;
    if recovered.as_slice() != enc.shared_secret.as_slice() {
        return Err(SelfTestError::KnownAnswerMismatch { case: "kem_decaps" });
    }
    if recovered.as_slice() != expected::KEM_SHARED_SECRET {
        return Err(SelfTestError::KnownAnswerMismatch {
            case: "kem_decaps_kat",
        });
    }
    Ok(())
}

fn cast_sig() -> core::result::Result<(), SelfTestError> {
    let kp = sig::keypair_from_seed_unchecked(&SIG_SEED)?;
    let pk_digest = digest32(&kp.public_key);
    if pk_digest != expected::SIG_PK_DIGEST {
        return Err(SelfTestError::KnownAnswerMismatch { case: "sig_pk" });
    }

    let signature = sig::sign_unchecked(&kp.secret_key, SIG_MESSAGE, &[])?;
    let sig_digest = digest32(&signature);
    if sig_digest != expected::SIG_DIGEST {
        return Err(SelfTestError::KnownAnswerMismatch { case: "sig" });
    }

    sig::verify_unchecked(&kp.public_key, SIG_MESSAGE, &signature, &[])?;

    // Negative: corrupted signature must fail.
    let mut bad = signature;
    bad[0] ^= 0xff;
    match sig::verify_unchecked(&kp.public_key, SIG_MESSAGE, &bad, &[]) {
        Err(crate::Error::SignatureInvalid) => Ok(()),
        Ok(()) => Err(SelfTestError::KnownAnswerMismatch {
            case: "sig_negative",
        }),
        Err(err) => Err(SelfTestError::Primitive(err)),
    }
}

/// Run known-answer CASTs for ML-KEM-1024 and ML-DSA-87.
///
/// Intended for power-on / module-entry self-tests. Pair-wise consistency
/// tests already run inside key generation; this function does not replace them.
pub fn run_self_tests() -> core::result::Result<(), SelfTestError> {
    cast_kem()?;
    cast_sig()?;
    Ok(())
}

/// Emit CAST digests for embedding as expected constants (dev helper).
#[doc(hidden)]
pub fn dump_cast_digests_for_regen() -> String {
    let kp = kem::keypair_from_seed_unchecked(&KEM_SEED).expect("kem seed");
    let enc = kem::encapsulate_deterministic_unchecked(&kp.public_key, &KEM_M).expect("enc");
    let sig_kp = sig::keypair_from_seed_unchecked(&SIG_SEED).expect("sig seed");
    let signature = sig::sign_unchecked(&sig_kp.secret_key, SIG_MESSAGE, &[]).expect("sign");

    format!(
        "KEM_PK_DIGEST={}\nKEM_SHARED_SECRET={}\nKEM_CT_DIGEST={}\nSIG_PK_DIGEST={}\nSIG_DIGEST={}",
        hex::encode(digest32(&kp.public_key)),
        hex::encode(&enc.shared_secret),
        hex::encode(digest32(&enc.ciphertext)),
        hex::encode(digest32(&sig_kp.public_key)),
        hex::encode(digest32(&signature)),
    )
}

// Minimal hex without adding a dependency for the dump helper.
mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let bytes = bytes.as_ref();
        let mut out = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 0xf) as usize] as char);
        }
        out
    }
}
