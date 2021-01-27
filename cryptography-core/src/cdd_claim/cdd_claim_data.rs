use super::pedersen_commitments::{generate_blinding_factor, generate_pedersen_commit};
use super::{RISTRETTO_POINT_SIZE, SCALAR_SIZE};
use codec::{Decode, Encode, Error as CodecError, Input, Output};
use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Create a scalar from a slice of data.
fn slice_to_scalar(data: &[u8]) -> Scalar {
    use blake2::{Blake2b, Digest};
    let mut hash = [0u8; 64];
    hash.copy_from_slice(Blake2b::digest(data).as_slice());
    Scalar::from_bytes_mod_order_wide(&hash)
}

/// The data needed to generate a CDD ID.
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CddClaimData {
    pub investor_did: Scalar,
    pub investor_unique_id: Scalar,
}

impl CddClaimData {
    /// Create a CDD Claim Data object from slices of data.
    pub fn new(investor_did: &[u8], investor_unique_id: &[u8]) -> Self {
        CddClaimData {
            investor_did: slice_to_scalar(investor_did),
            investor_unique_id: slice_to_scalar(investor_unique_id),
        }
    }
}

impl Encode for CddClaimData {
    #[inline]
    fn size_hint(&self) -> usize {
        SCALAR_SIZE + SCALAR_SIZE
    }

    fn encode_to<W: Output>(&self, dest: &mut W) {
        self.investor_did.as_bytes().encode_to(dest);
        self.investor_unique_id.as_bytes().encode_to(dest);
    }
}

impl Decode for CddClaimData {
    fn decode<I: Input>(input: &mut I) -> Result<Self, CodecError> {
        let investor_did = <[u8; SCALAR_SIZE]>::decode(input)?;
        let investor_did = Scalar::from_bits(investor_did);

        let investor_unique_id = <[u8; SCALAR_SIZE]>::decode(input)?;
        let investor_unique_id = Scalar::from_bits(investor_unique_id);

        Ok(CddClaimData {
            investor_did,
            investor_unique_id,
        })
    }
}

#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CddId(pub RistrettoPoint);

impl Encode for CddId {
    #[inline]
    fn size_hint(&self) -> usize {
        RISTRETTO_POINT_SIZE
    }

    fn encode_to<W: Output>(&self, dest: &mut W) {
        self.0.compress().as_bytes().encode_to(dest);
    }
}

impl Decode for CddId {
    fn decode<I: Input>(input: &mut I) -> Result<Self, CodecError> {
        let id = <[u8; RISTRETTO_POINT_SIZE]>::decode(input)?;
        CompressedRistretto(id)
            .decompress()
            .ok_or_else(|| CodecError::from("Invalid CddId."))
            .map(CddId)
    }
}

/// Compute the CDD_ID. \
/// CDD_ID = PedersenCommitment(INVESTOR_DID, INVESTOR_UNIQUE_ID, [INVESTOR_DID | INVESTOR_UNIQUE_ID]) \
///
/// # Inputs
/// * `cdd_claim` is the CDD claim from which to generate the CDD_ID
///
/// # Output
/// The Pedersen commitment result.
pub fn compute_cdd_id(cdd_claim: &CddClaimData) -> CddId {
    CddId(generate_pedersen_commit(
        cdd_claim.investor_did,
        cdd_claim.investor_unique_id,
    ))
}

pub fn get_blinding_factor(cdd_claim: &CddClaimData) -> Scalar {
    generate_blinding_factor(cdd_claim.investor_did, cdd_claim.investor_unique_id)
}
