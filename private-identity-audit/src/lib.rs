//! PIAL is the library that implements the private identity audit protocol
//! of the PIAL, as defined in the section TODO of the whitepaper TODO.
//!

#![cfg_attr(not(feature = "std"), no_std)]
#![feature(iterator_fold_self)]

#[cfg(not(feature = "std"))]
#[macro_use]
extern crate alloc;

use codec::{Decode, Encode, Error as CodecError, Input, Output};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

mod errors;
#[macro_use]
mod macros;
mod proofs;
mod prover;
mod verifier;
use blake2::{Blake2b, Digest};
use cryptography_core::cdd_claim::{CddClaimData, CddId, RISTRETTO_POINT_SIZE, SCALAR_SIZE};
use cryptography_core::curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use errors::Fallible;
use proofs::{FinalResponse, InitialMessage, Secrets};
use rand_core::{CryptoRng, RngCore};
use sp_std::vec::Vec;
use uuid::Uuid;

/// This is a security parameter. The larger the value, the higher the security guarantees.
/// This value is used to pad the set of private unique ids such that the set,
/// has at least this many element. As a result when a CDD Provider proves that it holds an
/// element of a set, PUIS can guess that element with probability 1/the_size_of_the_padded_set.
pub const SET_SIZE_ANONYMITY_PARAM: usize = 100_000;

pub struct InitialProver;
pub struct FinalProver;

pub struct VerifierSetGenerator;
pub struct Verifier;

/// The initial private set of PUIS.
pub struct PrivateUids(pub Vec<Scalar>);

impl Encode for PrivateUids {
    #[inline]
    fn size_hint(&self) -> usize {
        SCALAR_SIZE * self.0.len()
    }

    fn encode_to<W: Output>(&self, dest: &mut W) {
        let uuids: Vec<[u8; SCALAR_SIZE]> = self.0.iter().map(|u| u.to_bytes()).collect();

        uuids.encode_to(dest);
    }
}

impl Decode for PrivateUids {
    fn decode<I: Input>(input: &mut I) -> Result<Self, CodecError> {
        let uuids = <Vec<[u8; SCALAR_SIZE]>>::decode(input)?;

        let uuids: Vec<Scalar> = uuids.into_iter().map(Scalar::from_bits).collect();

        Ok(PrivateUids(uuids))
    }
}

/// The committed and padded version of the private set of PUIS.
#[derive(Clone, Debug, PartialEq)]
pub struct CommittedUids(pub Vec<RistrettoPoint>);

impl Encode for CommittedUids {
    #[inline]
    fn size_hint(&self) -> usize {
        RISTRETTO_POINT_SIZE * self.0.len()
    }

    fn encode_to<W: Output>(&self, dest: &mut W) {
        let committed_uuids: Vec<[u8; RISTRETTO_POINT_SIZE]> =
            self.0.iter().map(|u| u.compress().to_bytes()).collect();

        committed_uuids.encode_to(dest);
    }
}

impl Decode for CommittedUids {
    fn decode<I: Input>(input: &mut I) -> Result<Self, CodecError> {
        let committed_uuids = <Vec<[u8; RISTRETTO_POINT_SIZE]>>::decode(input)?;

        committed_uuids
            .into_iter()
            .map(|u| {
                CompressedRistretto(u)
                    .decompress()
                    .ok_or_else(|| CodecError::from("Invalid UUID."))
            })
            .collect::<Result<Vec<_>, _>>()
            .map(CommittedUids)
    }
}

/// The Zero-Knowledge challenge.
pub struct Challenge(pub Scalar);

impl Encode for Challenge {
    #[inline]
    fn size_hint(&self) -> usize {
        SCALAR_SIZE
    }

    fn encode_to<W: Output>(&self, dest: &mut W) {
        self.0.to_bytes().encode_to(dest);
    }
}

impl Decode for Challenge {
    fn decode<I: Input>(input: &mut I) -> Result<Self, CodecError> {
        let c = <[u8; SCALAR_SIZE]>::decode(input)?;
        let c = Scalar::from_bits(c);

        Ok(Challenge(c))
    }
}

/// Holds the initial messages in the Zero-Knowledge Proofs sent by CDD Provider.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Proofs {
    cdd_id_proof: InitialMessage,
    cdd_id_second_half_proof: InitialMessage,
    uid_commitment_proof: InitialMessage,
    /// Committed CDD ID. Corresponding to g^uID * h^DID * f^{hash(uID, DID)}`.
    a: RistrettoPoint,
    /// Committed version of the second half CDD ID. Corresponding to (h^DID*f^{hash(uID, DID)})^r.
    b: RistrettoPoint,
}

impl Encode for Proofs {
    #[inline]
    fn size_hint(&self) -> usize {
        self.cdd_id_proof.size_hint()
            + self.cdd_id_second_half_proof.size_hint()
            + self.uid_commitment_proof.size_hint()
            + RISTRETTO_POINT_SIZE
            + RISTRETTO_POINT_SIZE
    }

    fn encode_to<W: Output>(&self, dest: &mut W) {
        self.cdd_id_proof.encode_to(dest);
        self.cdd_id_second_half_proof.encode_to(dest);
        self.uid_commitment_proof.encode_to(dest);

        let a = self.a.compress();
        a.to_bytes().encode_to(dest);

        let b = self.b.compress();
        b.to_bytes().encode_to(dest);
    }
}

impl Decode for Proofs {
    fn decode<I: Input>(input: &mut I) -> Result<Self, CodecError> {
        let (cdd_id_proof, cdd_id_second_half_proof, uid_commitment_proof, a, b) =
            <(
                InitialMessage,
                InitialMessage,
                InitialMessage,
                [u8; RISTRETTO_POINT_SIZE],
                [u8; RISTRETTO_POINT_SIZE],
            )>::decode(input)?;
        let a = CompressedRistretto(a)
            .decompress()
            .ok_or_else(|| CodecError::from("InitialMessage `a` point is invalid"))?;
        let b = CompressedRistretto(b)
            .decompress()
            .ok_or_else(|| CodecError::from("InitialMessage `b` point is invalid"))?;
        Ok(Proofs {
            cdd_id_proof,
            cdd_id_second_half_proof,
            uid_commitment_proof,
            a,
            b,
        })
    }
}

/// Holds the CDD Provider's response to the PUIS challenge.
#[derive(Clone, Encode, Decode, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ProverFinalResponse {
    cdd_id_proof_response: FinalResponse,
    cdd_id_second_half_proof_response: FinalResponse,
    uid_commitment_proof_response: FinalResponse,
}

/// Holds CDD Provider secret data.
#[derive(Clone)]
pub struct ProverSecrets {
    cdd_id_proof_secrets: Secrets,
    cdd_id_second_half_proof_secrets: Secrets,
    uid_commitment_proof_secrets: Secrets,
    rand: Scalar,
}

impl Encode for ProverSecrets {
    #[inline]
    fn size_hint(&self) -> usize {
        self.cdd_id_proof_secrets.size_hint()
            + self.cdd_id_second_half_proof_secrets.size_hint()
            + self.uid_commitment_proof_secrets.size_hint()
            + SCALAR_SIZE
    }

    fn encode_to<W: Output>(&self, dest: &mut W) {
        self.cdd_id_proof_secrets.encode_to(dest);
        self.cdd_id_second_half_proof_secrets.encode_to(dest);
        self.uid_commitment_proof_secrets.encode_to(dest);

        self.rand.to_bytes().encode_to(dest);
    }
}

impl Decode for ProverSecrets {
    fn decode<I: Input>(input: &mut I) -> Result<Self, CodecError> {
        let (
            cdd_id_proof_secrets,
            cdd_id_second_half_proof_secrets,
            uid_commitment_proof_secrets,
            rand,
        ) = <(Secrets, Secrets, Secrets, [u8; SCALAR_SIZE])>::decode(input)?;
        let rand = Scalar::from_bits(rand);

        Ok(ProverSecrets {
            cdd_id_proof_secrets,
            cdd_id_second_half_proof_secrets,
            uid_commitment_proof_secrets,
            rand,
        })
    }
}

/// Holds PUIS secret data.
pub struct VerifierSecrets {
    rand: Scalar,
}

impl Encode for VerifierSecrets {
    #[inline]
    fn size_hint(&self) -> usize {
        SCALAR_SIZE
    }

    fn encode_to<W: Output>(&self, dest: &mut W) {
        self.rand.to_bytes().encode_to(dest);
    }
}

impl Decode for VerifierSecrets {
    fn decode<I: Input>(input: &mut I) -> Result<Self, CodecError> {
        let rand = <[u8; SCALAR_SIZE]>::decode(input)?;
        let rand = Scalar::from_bits(rand);

        Ok(VerifierSecrets { rand })
    }
}

/// Modified version of `slice_to_scalar` of Confidential Identity Library.
/// Creates a scalar from a UUID.
pub fn uuid_to_scalar(uuid: Uuid) -> Scalar {
    let mut hash = [0u8; 64];
    hash.copy_from_slice(Blake2b::digest(uuid.as_bytes()).as_slice());
    Scalar::from_bytes_mod_order_wide(&hash)
}

/// Represents the first leg of the protocol from CDD Provider to PUIS.
pub trait ProofGenerator {
    /// This is called by the CDD Provider in the first step of the protocol to generate
    /// initial ZKP proofs that CDD Provider knows a `uID` and a `DID` such that
    ///
    /// `CDD_ID = g^uID * h^DID * f^{hash(uID, DID)}` for some pre-determined `g, h, and f`.
    ///
    /// # Arguments
    /// * `investor`: Holds the uID and DID of the investor.
    /// * `rng`: Cryptographically secure random number generator.
    ///
    /// # Outputs
    /// * `ProverSecrets`: the secret values of PUIS. These are needed in the later steps of
    ///    the protocol and should be stored locally.
    /// * `Proofs`: The initial messages of ZKPs.
    fn generate_initial_proofs<T: RngCore + CryptoRng>(
        investor: CddClaimData,
        rng: &mut T,
    ) -> Fallible<(ProverSecrets, Proofs)>;
}

/// Represents the second leg of the protocol from PUIS to CDD Provider.
pub trait ChallengeGenerator {
    /// This is called by PUIS to create an committed version of the set of all unique
    /// identity IDs (uID). Moreover, it generates the random ZKP challenge.
    ///
    /// # Arguments
    /// * `private_unique_identifiers`: A list of Scalars that represent the private set of
    ///   unique identifiers. Call `uuid_to_scalar` to convert uIDs to Scalar properly.
    /// * `min_set_size`: An optional parameter to override the default value of
    ///   `SET_SIZE_ANONYMITY_PARAM`.
    /// * `rng`: Cryptographically secure random number generator.
    ///
    /// # Outputs
    /// * `VerifierSecrets`: the secret values of PUIS. These are needed in later steps of
    ///    the protocol and need to be stored locally.
    /// * `CommittedUids`: the padded, committed, and shuffled set of uIDs. These should
    ///    be sent to CDD Provider.
    /// * `Challenge`: the ZKP random challenge.
    fn generate_committed_set_and_challenge<T: RngCore + CryptoRng>(
        private_unique_identifiers: PrivateUids,
        min_set_size: Option<usize>,
        rng: &mut T,
    ) -> Fallible<(VerifierSecrets, CommittedUids, Challenge)>;
}

/// Represents the third leg of the protocol from CDD Provider to PUIS.
pub trait ChallengeResponder {
    /// This is called by CDD Provider to generate the ZKP response of the challenge
    /// and provide the proof of membership.
    ///
    /// # Arguments
    /// * `secrets`: CDD Provider secrets that were generated in the first step of the protocol.
    /// * `committed_uids`: the list of committed uIDs received from PUIS.
    /// * `challenge`: ZKP challenge received from PUIS.
    /// * `rng`: Cryptographically secure random number generator.
    ///
    /// # Outputs
    /// * `ProverFinalResponse`: The ZKP response.
    /// * `CommittedUids`: These re-committed uIDs form part of the proof of membership.
    fn generate_challenge_response<T: RngCore + CryptoRng>(
        secrets: &ProverSecrets,
        committed_uids: &CommittedUids,
        challenge: &Challenge,
        rng: &mut T,
    ) -> Fallible<(ProverFinalResponse, CommittedUids)>;
}

/// Represents the last step of the protocol in which PUIS verifies the proofs.
pub trait ProofVerifier {
    /// PUIS verifies both the ZKP proofs around CDD ID and the proof of membership.
    ///
    /// # Arguments
    /// * `initial_message`: Initial messages of ZKP proofs of CDD ID.
    /// * `final_response`: Final responses of ZKP proofs of CDD ID.
    /// * `challenge`: The ZKP challenge generated by PUIS.
    /// * `cdd_id`: The CDD ID read from the chain.
    /// * `verifier_secrets`: The PUIS secrets generated in the second step of the protocol.
    /// * `rng`: Cryptographically secure random number generator.
    fn verify_proofs(
        initial_message: &Proofs,
        final_response: &ProverFinalResponse,
        challenge: &Challenge,
        cdd_id: &CddId,
        verifier_secrets: &VerifierSecrets,
        re_committed_uids: &CommittedUids,
    ) -> Fallible<()>;
}
