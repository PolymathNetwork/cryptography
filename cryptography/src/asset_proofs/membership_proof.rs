//! Membership proofs are zero-knowledge proofs systems which enables to efficiently prove
//! that the committed secret belongs to the given set of public elements without
//! revealing any other information about the secret.
//! This implementation is based on one-out-of-many proof construction desribed in the following paper
//! <https://eprint.iacr.org/2015/643.pdf>

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};

use crate::asset_proofs::{
    encryption_proofs::{
        AssetProofProver, AssetProofProverAwaitingChallenge, AssetProofVerifier, ZKPChallenge,
    },
    errors::{AssetProofError, Result},
    one_out_of_many_proof::{
        OOONProofFinalResponse, OOONProofInitialMessage, OOONProofVerifier, OOONProver,
        OOONProverAwaitingChallenge, OooNProofGenerators,
    },
    transcript::{TranscriptProtocol, UpdateTranscript},
};

use merlin::{Transcript, TranscriptRng};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const MEMBERSHIP_PROOF_LABEL: &[u8] = b"PolymathMembershipProofLabel";
const MEMBERSHIP_PROOF_CHALLENGE_LABEL: &[u8] = b"PolymathMembershipProofChallengeLabel";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct MembershipProofInitialMessage {
    ooon_proof_initial_message: OOONProofInitialMessage,
    secret_element_comm: RistrettoPoint,
}

impl UpdateTranscript for MembershipProofInitialMessage {
    fn update_transcript(&self, transcript: &mut Transcript) -> Result<()> {
        transcript.append_domain_separator(MEMBERSHIP_PROOF_CHALLENGE_LABEL);
        self.ooon_proof_initial_message
            .update_transcript(transcript)?;

        transcript.append_validated_point(b"Comm", &self.secret_element_comm.compress())?;

        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct MembershipProofFinalResponse {
    ooon_proof_final_response: OOONProofFinalResponse,
}

#[derive(Clone, Debug)]
pub struct MembershipProver {
    ooon_prover: OOONProver,
}
/// The prover awaiting challenge will be initialized by the commitment witness data, which is the
/// committed secret and the blinding factor, and will keep a reference to the public set of elements,
/// to which the committed secret provably belongs to.
pub struct MembershipProverAwaitingChallenge<'a> {
    /// The committed secret element.
    pub secret_element: Zeroizing<Scalar>,
    /// The blinding factor used to commit to the secret_message.
    pub random: Zeroizing<Scalar>,
    /// Generator points used to construct one-out-of-many proofs.
    pub generators: &'a OooNProofGenerators,
    /// The set of elements which the committed secret element belongs to.
    pub elements_set: &'a [Scalar],
    /// The element set size is represented as a power of the given base.
    pub base: usize,
    /// Used to specify the commitment list size for the underlying one-out-of-many proofs.
    pub exp: usize,
}

impl<'a> AssetProofProverAwaitingChallenge for MembershipProverAwaitingChallenge<'a> {
    type ZKInitialMessage = MembershipProofInitialMessage;
    type ZKFinalResponse = MembershipProofFinalResponse;
    type ZKProver = MembershipProver;

    fn create_transcript_rng<T: RngCore + CryptoRng>(
        &self,
        rng: &mut T,
        transcript: &Transcript,
    ) -> TranscriptRng {
        transcript
            .build_rng()
            .rekey_with_witness_bytes(b"secret_element", self.secret_element.as_bytes())
            .rekey_with_witness_bytes(b"random", self.random.as_bytes())
            .finalize(rng)
    }
    /// Given a commitment `C = m*B+r*B_blinding` to a secret element `m`, a membership proof proves that
    /// `m` belongs to the given public set of elements `m_1, m_2, ..., m_N`. Membership proof is comprised
    /// of an one-out-of-many proof generated with respect to an
    /// ad-hoc computed list of commitments. Each commmitment `C_i` in this list is computed by subtracting
    /// the corresponding public set element `m_i` from the user commitment C as follows: `C_i = C - m_i * B`.
    /// If `m` truly belongs to the given set `m_1, m_2, ..., m_N`, then obviously the list of committments
    /// `C_1, C_2, ... C_N` contains a commitment opening to 0.
    fn generate_initial_message(
        &self,
        rng: &mut TranscriptRng,
    ) -> (Self::ZKProver, Self::ZKInitialMessage) {
        let exp = self.exp as u32;
        let n = self.base.pow(exp);

        let pc_gens = self.generators.com_gens;

        let secret_commitment = pc_gens.commit(*self.secret_element, *self.random);

        let initial_size = self.elements_set.len();

        let mut commitments_list: Vec<RistrettoPoint> = (0..initial_size)
            .map(|m| secret_commitment - self.elements_set[m] * pc_gens.B)
            .collect();

        if n != initial_size {
            commitments_list.resize(n, commitments_list[initial_size]);
        }

        let secret_position = self
            .elements_set
            .iter()
            .position(|&r| r == *self.secret_element)
            .unwrap_or_default();

        let ooon_prover = OOONProverAwaitingChallenge {
            secret_index: secret_position,
            random: *self.random,
            generators: self.generators,
            commitments: commitments_list.as_slice(),
            exp: self.exp,
            base: self.base,
        };

        let (ooon_prover, ooon_proof_initial_message) = ooon_prover.generate_initial_message(rng);

        (
            MembershipProver { ooon_prover },
            MembershipProofInitialMessage {
                ooon_proof_initial_message,
                secret_element_comm: secret_commitment,
            },
        )
    }
}

impl AssetProofProver<MembershipProofFinalResponse> for MembershipProver {
    fn apply_challenge(&self, c: &ZKPChallenge) -> MembershipProofFinalResponse {
        let ooon_proof_final_response = self.ooon_prover.apply_challenge(c);

        MembershipProofFinalResponse {
            ooon_proof_final_response,
        }
    }
}

pub struct MembershipProofVerifier<'a> {
    pub secret_element_com: RistrettoPoint,
    pub elements_set: &'a [Scalar],
    pub generators: &'a OooNProofGenerators,
}

impl<'a> AssetProofVerifier for MembershipProofVerifier<'a> {
    type ZKInitialMessage = MembershipProofInitialMessage;
    type ZKFinalResponse = MembershipProofFinalResponse;

    fn verify(
        &self,
        c: &ZKPChallenge,
        initial_message: &Self::ZKInitialMessage,
        final_response: &Self::ZKFinalResponse,
    ) -> Result<()> {
        let n = initial_message
            .ooon_proof_initial_message
            .n
            .pow(initial_message.ooon_proof_initial_message.m as u32);
        let initial_size = self.elements_set.len();

        let mut commitments_list: Vec<RistrettoPoint> = (0..self.elements_set.len())
            .map(|m| self.secret_element_com - self.elements_set[m] * self.generators.com_gens.B)
            .collect();

        // If the elements set size does not match to the system parameter N = n^m, we have to
        // pad the resulted commitment list with its last commitment to make the list size equal to N.
        // Padding has a critical security importance.
        if n != initial_size {
            commitments_list.resize(n, commitments_list[initial_size]);
        }

        let ooon_verifier = OOONProofVerifier {
            generators: self.generators,
            commitments: &commitments_list,
        };

        let result = ooon_verifier.verify(
            c,
            &initial_message.ooon_proof_initial_message,
            &final_response.ooon_proof_final_response,
        );
        ensure!(
            result.is_ok(),
            AssetProofError::MembershipProofVerificationError { check: 1 }
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {

    extern crate wasm_bindgen_test;
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};
    use bincode::{deserialize, serialize};
    use wasm_bindgen_test::*;

    use crate::asset_proofs::encryption_proofs::{
        single_property_prover, single_property_verifier,
    };

    const SEED_1: [u8; 32] = [42u8; 32];
    #[test]
    #[wasm_bindgen_test]
    /// Tests the whole workflow of membership proofs

    fn test_membership_proofs() {
        let mut rng = StdRng::from_seed(SEED_1);
        let mut transcript = Transcript::new(MEMBERSHIP_PROOF_LABEL);

        const BASE: usize = 4;
        const EXPONENT: usize = 3;

        let generators = OooNProofGenerators::new(EXPONENT, BASE);

        let even_elements: Vec<Scalar> = (0..64 as u32).map(|m| Scalar::from(2 * m)).collect();
        let odd_elements: Vec<Scalar> = (0..64 as u32).map(|m| Scalar::from(2 * m + 1)).collect();

        let blinding = Scalar::random(&mut rng);

        let even_member = generators.com_gens.commit(Scalar::from(8u32), blinding);

        let odd_member = generators.com_gens.commit(Scalar::from(75u32), blinding);

        let prover = MembershipProverAwaitingChallenge {
            secret_element: Zeroizing::new(Scalar::from(8u32)),
            random: Zeroizing::new(blinding),
            generators: &generators,
            elements_set: even_elements.as_slice(),
            base: BASE,
            exp: EXPONENT,
        };

        let mut transcript_rng = prover.create_transcript_rng(&mut rng, &transcript);
        let (prover, initial_message) = prover.generate_initial_message(&mut transcript_rng);

        initial_message.update_transcript(&mut transcript).unwrap();
        let challenge = transcript
            .scalar_challenge(MEMBERSHIP_PROOF_CHALLENGE_LABEL)
            .unwrap();

        let final_response = prover.apply_challenge(&challenge);

        // Positive test
        let verifier = MembershipProofVerifier {
            secret_element_com: even_member,
            elements_set: even_elements.as_slice(),
            generators: &generators,
        };

        let result = verifier.verify(&challenge, &initial_message.clone(), &final_response);
        assert!(result.is_ok());

        // Negative test
        let verifier = MembershipProofVerifier {
            secret_element_com: odd_member,
            elements_set: even_elements.as_slice(),
            generators: &generators,
        };
        let result = verifier.verify(&challenge, &initial_message, &final_response);
        assert_err!(
            result,
            AssetProofError::MembershipProofVerificationError { check: 1 }
        );

        // Testing adversarial proof generation where the Prover tries to generate
        // a proof for non-existing set member. 
        let prover = MembershipProverAwaitingChallenge {
            secret_element: Zeroizing::new(Scalar::from(2778u32)),
            random: Zeroizing::new(blinding),
            generators: &generators,
            elements_set: odd_elements.as_slice(),
            base: BASE,
            exp: EXPONENT,
        };
        let non_existing_member = generators.com_gens.commit(Scalar::from(2778u32), blinding);

        let mut transcript_rng = prover.create_transcript_rng(&mut rng, &transcript);
        let (prover, initial_message) = prover.generate_initial_message(&mut transcript_rng);

        initial_message.update_transcript(&mut transcript).unwrap();
        let challenge = transcript
            .scalar_challenge(MEMBERSHIP_PROOF_CHALLENGE_LABEL)
            .unwrap();

        let final_response = prover.apply_challenge(&challenge);

        let verifier = MembershipProofVerifier {
            secret_element_com: non_existing_member,
            elements_set: odd_elements.as_slice(),
            generators: &generators,
        };

        let result = verifier.verify(&challenge, &initial_message.clone(), &final_response);
        assert_err!(
            result,
            AssetProofError::MembershipProofVerificationError { check: 1 }
        );
        
        // Testing the non-interactive API
        let prover = MembershipProverAwaitingChallenge {
            secret_element: Zeroizing::new(Scalar::from(75u32)),
            random: Zeroizing::new(blinding),
            generators: &generators,
            elements_set: odd_elements.as_slice(),
            base: BASE,
            exp: EXPONENT,
        };
        let verifier = MembershipProofVerifier {
            secret_element_com: odd_member,
            elements_set: odd_elements.as_slice(),
            generators: &generators,
        };

        // 1st to 3rd rounds
        let (initial_message_1, final_response_1) =
            single_property_prover::<StdRng, MembershipProverAwaitingChallenge>(prover, &mut rng)
                .unwrap();

        // Positive test
        assert!(
            // 4th round
            single_property_verifier(
                &verifier,
                initial_message_1.clone(),
                final_response_1.clone()
            )
            .is_ok()
        );

        // Negative tests
        let bad_initial_message = initial_message;
        let bad_final_response = final_response;
        assert_err!(
            single_property_verifier(&verifier, bad_initial_message, final_response_1),
            AssetProofError::MembershipProofVerificationError { check: 1 }
        );

        assert_err!(
            single_property_verifier(&verifier, initial_message_1, bad_final_response),
            AssetProofError::MembershipProofVerificationError { check: 1 }
        );
    }

    #[test]
    #[wasm_bindgen_test]
    fn serialize_deserialize_proof() {
        
        let mut rng = StdRng::from_seed(SEED_1);
        let mut transcript = Transcript::new(MEMBERSHIP_PROOF_LABEL);

        const BASE: usize = 4;
        const EXPONENT: usize = 3;
        
        let generators = OooNProofGenerators::new(EXPONENT, BASE);
        let even_elements: Vec<Scalar> = (0..64 as u32).map(|m| Scalar::from(2 * m)).collect();
        let blinding = Scalar::random(&mut rng);

        let even_member = generators.com_gens.commit(Scalar::from(8u32), blinding);
        
        let prover = MembershipProverAwaitingChallenge {
            secret_element: Zeroizing::new(Scalar::from(8u32)),
            random: Zeroizing::new(blinding),
            generators: &generators,
            elements_set: even_elements.as_slice(),
            base: BASE,
            exp: EXPONENT,
        };

        let (initial_message0, final_response0) =
            single_property_prover::<StdRng, MembershipProverAwaitingChallenge>(prover, &mut rng)
                .unwrap();
        
        let initial_message_bytes: Vec<u8> = serialize(&initial_message0).unwrap();
        let final_response_bytes: Vec<u8> = serialize(&final_response0).unwrap();
        let recovered_initial_message: MembershipProofInitialMessage =
            deserialize(&initial_message_bytes).unwrap();
        let recovered_final_response: MembershipProofFinalResponse =
            deserialize(&final_response_bytes).unwrap();
        assert_eq!(recovered_initial_message, initial_message0);
        assert_eq!(recovered_final_response, final_response0);
    }
}
