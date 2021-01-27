//! The `elgamal_encryption` library implements the
//! twisted-Elgamal encryption over the Ristretto 25519 curve.
//! Since Elgamal is a homomorphic encryption it also provides
//! addition and subtraction API over the cipher texts.

use crate::errors::{ErrorKind, Fallible};

use bulletproofs::PedersenGens;
use core::ops::{Add, AddAssign, Sub, SubAssign};
use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use rand::rngs::StdRng;
use rand_core::{CryptoRng, RngCore};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use codec::{Decode, Encode, Error as CodecError, Input, Output};
use sp_std::prelude::*;

/// Prover's representation of the commitment secret.
#[derive(Clone, PartialEq, Zeroize, Debug)]
#[zeroize(drop)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CommitmentWitness {
    /// Depending on how the witness was created this variable stores the
    /// balance value or the asset id in Scalar format.
    value: Scalar,

    /// A random blinding factor.
    blinding: Scalar,
}

impl CommitmentWitness {
    pub fn blinding(&self) -> Scalar {
        self.blinding
    }

    pub fn value(&self) -> Scalar {
        self.value
    }
}

impl CommitmentWitness {
    pub fn new(value: Scalar, blinding: Scalar) -> Self {
        CommitmentWitness { value, blinding }
    }
}

impl From<(Scalar, &mut StdRng)> for CommitmentWitness {
    fn from(v: (Scalar, &mut StdRng)) -> Self {
        CommitmentWitness {
            value: v.0,
            blinding: Scalar::random(v.1),
        }
    }
}

impl Encode for CommitmentWitness {
    #[inline]
    fn size_hint(&self) -> usize {
        64
    }

    fn encode_to<W: Output>(&self, dest: &mut W) {
        let value = self.value.to_bytes();
        let blinding = self.blinding.to_bytes();

        value.encode_to(dest);
        blinding.encode_to(dest);
    }
}

impl Decode for CommitmentWitness {
    fn decode<I: Input>(input: &mut I) -> Result<Self, CodecError> {
        let (value, blinding) = <([u8; 32], [u8; 32])>::decode(input)?;
        let value = Scalar::from_canonical_bytes(value)
            .ok_or_else(|| CodecError::from("CommitmentWitness value point is invalid"))?;
        let blinding = Scalar::from_canonical_bytes(blinding)
            .ok_or_else(|| CodecError::from("CommitmentWitness blinding point is invalid"))?;

        Ok(CommitmentWitness { value, blinding })
    }
}

/// Prover's representation of the encrypted secret.
#[derive(PartialEq, Copy, Clone, Default, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CipherText {
    pub x: RistrettoPoint,
    pub y: RistrettoPoint,
}

impl Encode for CipherText {
    #[inline]
    fn size_hint(&self) -> usize {
        64
    }

    fn encode_to<W: Output>(&self, dest: &mut W) {
        let x = self.x.compress();
        let y = self.y.compress();

        x.as_bytes().encode_to(dest);
        y.as_bytes().encode_to(dest);
    }
}

impl Decode for CipherText {
    fn decode<I: Input>(input: &mut I) -> Result<Self, CodecError> {
        let (x, y) = <([u8; 32], [u8; 32])>::decode(input)?;
        let x = CompressedRistretto(x)
            .decompress()
            .ok_or_else(|| CodecError::from("CipherText X point is invalid"))?;
        let y = CompressedRistretto(y)
            .decompress()
            .ok_or_else(|| CodecError::from("CipherText Y point is invalid"))?;

        Ok(CipherText { x, y })
    }
}

// ------------------------------------------------------------------------
// Arithmetic operations on the ciphertext.
// ------------------------------------------------------------------------

impl<'a, 'b> Add<&'b CipherText> for &'a CipherText {
    type Output = CipherText;

    fn add(self, other: &'b CipherText) -> CipherText {
        CipherText {
            x: self.x + other.x,
            y: self.y + other.y,
        }
    }
}
define_add_variants!(LHS = CipherText, RHS = CipherText, Output = CipherText);

impl<'b> AddAssign<&'b CipherText> for CipherText {
    fn add_assign(&mut self, _rhs: &CipherText) {
        *self = (self as &CipherText) + _rhs;
    }
}
define_add_assign_variants!(LHS = CipherText, RHS = CipherText);

impl<'a, 'b> Sub<&'b CipherText> for &'a CipherText {
    type Output = CipherText;

    fn sub(self, other: &'b CipherText) -> CipherText {
        CipherText {
            x: self.x - other.x,
            y: self.y - other.y,
        }
    }
}
define_sub_variants!(LHS = CipherText, RHS = CipherText, Output = CipherText);

impl<'b> SubAssign<&'b CipherText> for CipherText {
    fn sub_assign(&mut self, _rhs: &CipherText) {
        *self = (self as &CipherText) - _rhs;
    }
}
define_sub_assign_variants!(LHS = CipherText, RHS = CipherText);

// ------------------------------------------------------------------------
// Elgamal Encryption.
// ------------------------------------------------------------------------

/// Elgamal key pair:
/// secret_key := scalar
/// public_key := secret_key * g
///
/// Encryption:
/// plaintext := (value, blinding_factor)
/// cipher_text := (X, Y)
/// X := blinding_factor * public_key
/// Y := blinding_factor * g + value * h
///
/// Decryption:
/// Given (secret_key, X, Y) find value such that:
/// value * h = Y - X / secret_key
///
/// where g and h are 2 orthogonal generators.

/// An Elgamal Secret Key is a random scalar.
#[derive(Clone, Zeroize, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[zeroize(drop)]
pub struct ElgamalSecretKey {
    pub secret: Scalar,
}

impl Encode for ElgamalSecretKey {
    #[inline]
    fn size_hint(&self) -> usize {
        32
    }

    fn encode_to<W: Output>(&self, dest: &mut W) {
        self.secret.as_bytes().encode_to(dest);
    }
}

impl Decode for ElgamalSecretKey {
    fn decode<I: Input>(input: &mut I) -> Result<Self, CodecError> {
        let secret = <[u8; 32]>::decode(input)?;
        let secret = Scalar::from_canonical_bytes(secret)
            .ok_or_else(|| CodecError::from("ElgamalSecretKey.secret is invalid"))?;

        Ok(ElgamalSecretKey { secret })
    }
}

/// The Elgamal Public Key is the secret key multiplied by the blinding generator (g).
#[derive(Copy, Clone, Default, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ElgamalPublicKey {
    pub pub_key: RistrettoPoint,
}

impl ElgamalPublicKey {
    fn encrypt_helper(&self, value: Scalar, blinding: Scalar) -> CipherText {
        let x = blinding * self.pub_key;
        let gens = PedersenGens::default();
        let y = gens.commit(value, blinding);
        CipherText { x, y }
    }

    pub fn encrypt(&self, witness: &CommitmentWitness) -> CipherText {
        self.encrypt_helper(witness.value, witness.blinding)
    }

    /// Generates a blinding factor, and encrypts the value.
    pub fn encrypt_value<R: RngCore + CryptoRng>(
        &self,
        value: Scalar,
        rng: &mut R,
    ) -> (CommitmentWitness, CipherText) {
        let blinding = Scalar::random(rng);
        (
            CommitmentWitness { value, blinding },
            self.encrypt_helper(value, blinding),
        )
    }
}

impl Encode for ElgamalPublicKey {
    #[inline]
    fn size_hint(&self) -> usize {
        32
    }

    fn encode_to<W: Output>(&self, dest: &mut W) {
        let pub_key = self.pub_key.compress();

        pub_key.as_bytes().encode_to(dest);
    }
}

impl Decode for ElgamalPublicKey {
    fn decode<I: Input>(input: &mut I) -> Result<Self, CodecError> {
        let pub_key = <[u8; 32]>::decode(input)?;
        let pub_key = CompressedRistretto(pub_key)
            .decompress()
            .ok_or_else(|| CodecError::from("ElgamalPublicKey.pub_key is invalid"))?;

        Ok(ElgamalPublicKey { pub_key })
    }
}

impl ElgamalSecretKey {
    pub fn new(secret: Scalar) -> Self {
        ElgamalSecretKey { secret }
    }

    pub fn get_public_key(&self) -> ElgamalPublicKey {
        let gens = PedersenGens::default();
        ElgamalPublicKey {
            pub_key: self.secret * gens.B_blinding,
        }
    }

    /// Decrypt a cipher text that is known to encrypt a u32.
    pub fn decrypt(&self, cipher_text: &CipherText) -> Fallible<u32> {
        let gens = PedersenGens::default();
        // value * h = Y - X / secret_key
        let value_h = cipher_text.y - self.secret.invert() * cipher_text.x;
        // Brute force all possible values to find the one that matches value * h.
        let mut result = Scalar::zero() * gens.B;
        for v in 0..u32::max_value() {
            if result == value_h {
                return Ok(v);
            }
            result += gens.B;
        }

        Err(ErrorKind::CipherTextDecryptionError.into())
    }

    /// Verifies that a cipher text encrypts the given witness.
    /// This follows the same logic as decrypt(), except that it uses the `asset_id` as
    /// a hint as to what the message must be in order to avoid searching the entire
    /// message space.
    pub fn verify(&self, cipher_text: &CipherText, hinted_value: &Scalar) -> Fallible<()> {
        let gens = PedersenGens::default();
        // value * h = Y - X / secret_key.
        let value_h = cipher_text.y - self.secret.invert() * cipher_text.x;
        // Try the hinted asset id value and see if it matches value * h.
        let result = hinted_value * gens.B;
        if result == value_h {
            return Ok(());
        }

        Err(ErrorKind::CipherTextDecryptionError.into())
    }
}

pub fn encrypt_using_two_pub_keys(
    witness: &CommitmentWitness,
    pub_key1: ElgamalPublicKey,
    pub_key2: ElgamalPublicKey,
) -> (CipherText, CipherText) {
    let x1 = witness.blinding * pub_key1.pub_key;
    let x2 = witness.blinding * pub_key2.pub_key;
    let gens = PedersenGens::default();
    let y = gens.commit(witness.value, witness.blinding);
    let enc1 = CipherText { x: x1, y };
    let enc2 = CipherText { x: x2, y };

    (enc1, enc2)
}

// ------------------------------------------------------------------------
// CipherText Refreshment Method
// ------------------------------------------------------------------------

impl CipherText {
    pub fn refresh(&self, secret_key: &ElgamalSecretKey, blinding: Scalar) -> Fallible<CipherText> {
        let value: Scalar = secret_key.decrypt(self)?.into();
        let pub_key = secret_key.get_public_key();
        let new_witness = CommitmentWitness { value, blinding };
        let new_ciphertext = pub_key.encrypt(&new_witness);

        Ok(new_ciphertext)
    }

    pub fn refresh_with_hint(
        &self,
        secret_key: &ElgamalSecretKey,
        blinding: Scalar,
        hint: &Scalar,
    ) -> Fallible<CipherText> {
        secret_key.verify(self, hint)?;
        let pub_key = secret_key.get_public_key();
        let new_witness = CommitmentWitness {
            value: *hint,
            blinding,
        };
        let new_ciphertext = pub_key.encrypt(&new_witness);

        Ok(new_ciphertext)
    }
}

// ------------------------------------------------------------------------
// Tests
// ------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    extern crate wasm_bindgen_test;
    use super::*;
    use crate::{AssetId, Balance};
    use rand::{rngs::StdRng, SeedableRng};
    use wasm_bindgen_test::*;

    use sp_std::convert::TryFrom;

    const SEED_1: [u8; 32] = [42u8; 32];
    const SEED_2: [u8; 32] = [56u8; 32];

    #[test]
    #[wasm_bindgen_test]
    fn basic_enc_dec() {
        let mut rng = StdRng::from_seed(SEED_1);
        let elg_secret = ElgamalSecretKey::new(Scalar::random(&mut rng));
        let elg_pub = elg_secret.get_public_key();

        // Test encrypting balance.
        let balance: Balance = 256u32;
        let blinding = Scalar::random(&mut rng);
        let balance_witness = CommitmentWitness {
            value: balance.into(),
            blinding,
        };
        // Test encrypt().
        let cipher = elg_pub.encrypt(&balance_witness);
        let balance1 = elg_secret.decrypt(&cipher).unwrap();
        assert_eq!(balance1, balance);

        // Test encrypt_value().
        let (_, cipher) = elg_pub.encrypt_value(balance_witness.value, &mut rng);
        let balance2 = elg_secret.decrypt(&cipher).unwrap();
        assert_eq!(balance2, balance);

        // Test encrypting asset id.
        let asset_id = AssetId::try_from(20u32).unwrap();
        let blinding = Scalar::random(&mut rng);
        let asset_id_witness = CommitmentWitness {
            value: asset_id.clone().into(),
            blinding,
        };
        // Test encrypt().
        let cipher = elg_pub.encrypt(&asset_id_witness);
        assert!(elg_secret.verify(&cipher, &asset_id.clone().into()).is_ok());

        // Test encrypt_value().
        let (_, cipher) = elg_pub.encrypt_value(asset_id_witness.value, &mut rng);
        assert!(elg_secret.verify(&cipher, &asset_id.into()).is_ok());
    }

    #[test]
    #[wasm_bindgen_test]
    fn homomorphic_encryption() {
        let v1: Scalar = 623u32.into();
        let v2: Scalar = 456u32.into();
        let mut rng = StdRng::from_seed(SEED_2);
        let r1 = Scalar::random(&mut rng);
        let r2 = Scalar::random(&mut rng);

        let elg_secret_key = ElgamalSecretKey::new(Scalar::random(&mut rng));
        let elg_pub = elg_secret_key.get_public_key();

        let cipher1 = elg_pub.encrypt(&CommitmentWitness {
            value: v1,
            blinding: r1,
        });
        let cipher2 = elg_pub.encrypt(&CommitmentWitness {
            value: v2,
            blinding: r2,
        });
        let mut cipher12 = elg_pub.encrypt(&CommitmentWitness {
            value: v1 + v2,
            blinding: r1 + r2,
        });
        assert_eq!(cipher1 + cipher2, cipher12);
        cipher12 -= cipher2;
        assert_eq!(cipher1, cipher12);

        cipher12 = elg_pub.encrypt(&CommitmentWitness {
            value: v1 - v2,
            blinding: r1 - r2,
        });
        assert_eq!(cipher1 - cipher2, cipher12);
        cipher12 += cipher2;
        assert_eq!(cipher1, cipher12);
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_two_encryptions() {
        let mut rng = StdRng::from_seed([17u8; 32]);
        let value = 256u32;
        let blinding = Scalar::random(&mut rng);
        let w = CommitmentWitness {
            value: value.into(),
            blinding,
        };

        let scrt1 = ElgamalSecretKey::new(Scalar::random(&mut rng));
        let pblc1 = scrt1.get_public_key();

        let scrt2 = ElgamalSecretKey::new(Scalar::random(&mut rng));
        let pblc2 = scrt2.get_public_key();

        let (cipher1, cipher2) = encrypt_using_two_pub_keys(&w, pblc1, pblc2);
        let msg1 = scrt1.decrypt(&cipher1).unwrap();
        let msg2 = scrt2.decrypt(&cipher2).unwrap();
        assert_eq!(value, msg1);
        assert_eq!(value, msg2);
    }
}
