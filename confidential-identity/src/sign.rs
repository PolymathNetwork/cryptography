//! A modified version of https://github.com/dalek-cryptography/ed25519-dalek which uses
//! custom base point instead of a default base point.

use crate::errors::{ErrorKind, Fallible};
use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use sha3::{digest::FixedOutput, Digest, Sha3_512};
use zeroize::Zeroize;

/// A Schnorr secret key.
///
/// Instances of this secret are automatically overwritten with zeroes when they
/// fall out of scope.
#[derive(Zeroize)]
#[zeroize(drop)] // Overwrite secret key material with null bytes when it goes out of scope.
pub struct SecretKey {
    pub(crate) key: Scalar,
    pub(crate) nonce: [u8; 32],
}

impl SecretKey {
    /// In the original implementation: https://docs.rs/ed25519-dalek/1.0.1/src/ed25519_dalek/secret.rs.html#200
    /// The nonce is obtained by hashing the secret key and using the upper 32 bits of the result.
    /// The secret key is set as lower half of the result with some bit manipulation.
    ///
    /// Here, we do the same for the nonce, but use the secret key as is.
    pub fn new(key: Scalar) -> Self {
        let nonce_from_secret = Sha3_512::default().chain(&key.as_bytes()).fixed_result();

        let mut nonce = [0u8; 32];
        nonce[..].copy_from_slice(&nonce_from_secret[32..]);

        Self { key, nonce }
    }
}

/// A Schnorr public key.
#[derive(Copy, Clone, Default, Eq, PartialEq)]
pub struct PublicKey {
    pub(crate) key: RistrettoPoint,
}

/// Stores the Schnorr signature for verifying the wellformedness of scope_id.
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[allow(non_snake_case)]
pub struct Signature {
    pub(crate) R: CompressedRistretto,
    pub(crate) s: Scalar,
}

impl SecretKey {
    /// Perform a schnorr signature using a custom base point.
    ///
    /// # Return
    ///
    /// Returns the signature.
    #[allow(non_snake_case)]
    pub fn sign(
        &self,
        message: &[u8],
        public_key: &PublicKey,
        base_point: &RistrettoPoint,
    ) -> Signature {
        let mut h = Sha3_512::new();
        let R: CompressedRistretto;
        let r: Scalar;
        let s: Scalar;
        let k: Scalar;

        h.input(&self.nonce);
        h.input(&message);

        r = Scalar::from_hash(h);
        R = (r * base_point).compress();

        h = Sha3_512::new();
        h.input(R.as_bytes());
        h.input(public_key.key.compress().as_bytes());
        h.input(&message);

        k = Scalar::from_hash(h);
        s = (k * self.key) + r;

        Signature { R, s }
    }
}

impl PublicKey {
    /// Verify a signature on a message with this public key.
    ///
    /// # Return
    ///
    /// Returns `Ok(())` if the signature is valid, and `Err` otherwise.
    #[allow(non_snake_case)]
    pub fn verify(
        &self,
        message: &[u8],
        signature: &Signature,
        base_point: &RistrettoPoint,
    ) -> Fallible<()> {
        let mut h = Sha3_512::new();
        let R: RistrettoPoint;
        let k: Scalar;
        let minus_A = -self.key;

        h.input(signature.R.as_bytes());
        h.input(self.key.compress().as_bytes());
        h.input(&message);

        k = Scalar::from_hash(h);
        R = k * minus_A + signature.s * base_point;

        ensure!(R.compress() == signature.R, ErrorKind::SignatureError);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};

    const SEED: [u8; 32] = [42u8; 32];

    #[test]
    fn test_signature_scheme() {
        let mut rng = StdRng::from_seed(SEED);

        let secret = Scalar::random(&mut rng);
        let base_point = RistrettoPoint::random(&mut rng);
        let public = secret * base_point;

        let secret_key = SecretKey::new(secret);
        let public_key = PublicKey { key: public };

        let sig = secret_key.sign("message".as_bytes(), &public_key, &base_point);

        assert!(public_key
            .verify("message".as_bytes(), &sig, &base_point)
            .is_ok());

        assert!(!public_key
            .verify("invalid message".as_bytes(), &sig, &base_point)
            .is_ok());
    }
}
