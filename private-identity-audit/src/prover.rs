//! Given C = g^x * h^y * f^z
//!
//! The goal is to prove the following statements.
//! - a = C^r -> ZKP(a; C)
//! - b = h^{y*r} * f^{z*r} -> ZKP(b; h, f)
//! - a/b = g^{x*r} -> ZKP(a/b; g)

use crate::{
    errors::Fallible,
    proofs::{apply_challenge, generate_initial_message},
    Challenge, ChallengeResponder, CommittedUids, FinalProver, InitialProver, ProofGenerator,
    Proofs, ProverFinalResponse, ProverSecrets,
};
use cryptography_core::cdd_claim::{
    compute_cdd_id, get_blinding_factor, pedersen_commitments::PedersenGenerators, CddClaimData,
};
use cryptography_core::curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use rand::seq::SliceRandom;
use rand_core::{CryptoRng, RngCore};

impl ProofGenerator for InitialProver {
    fn generate_initial_proofs<T: RngCore + CryptoRng>(
        claim: CddClaimData,
        rng: &mut T,
    ) -> Fallible<(ProverSecrets, Proofs)> {
        let blinding_factor = get_blinding_factor(&claim);
        let cdd_id = compute_cdd_id(&claim);

        let r = Scalar::random(rng);

        let pg = PedersenGenerators::default();

        // Corresponds to proving a = C^r, where C is cdd_id.
        let (cdd_id_proof_secrets, cdd_id_proof) =
            generate_initial_message(vec![r], vec![cdd_id.0], rng)?;
        let a = cdd_id.0 * r;

        // Corresponds to proving b = h^{y*r} * f^{z*r}.
        let (cdd_id_second_half_proof_secrets, cdd_id_second_half_proof) =
            generate_initial_message(
                [claim.investor_did * r, blinding_factor * r].to_vec(),
                vec![pg.generators[0], pg.generators[2]],
                rng,
            )?;
        let b = (pg.generators[0] * claim.investor_did + pg.generators[2] * blinding_factor) * r;

        // Corresponds to proving a/b = g^{x*r}.
        let (uid_commitment_proof_secrets, uid_commitment_proof) = generate_initial_message(
            vec![claim.investor_unique_id * r],
            vec![pg.generators[1]],
            rng,
        )?;

        Ok((
            ProverSecrets {
                cdd_id_proof_secrets,
                cdd_id_second_half_proof_secrets,
                uid_commitment_proof_secrets,
                rand: r,
            },
            Proofs {
                cdd_id_proof,
                cdd_id_second_half_proof,
                uid_commitment_proof,
                a,
                b,
            },
        ))
    }
}

impl ChallengeResponder for FinalProver {
    fn generate_challenge_response<T: RngCore + CryptoRng>(
        secrets: &ProverSecrets,
        committed_uids: &CommittedUids,
        challenge: &Challenge,
        rng: &mut T,
    ) -> Fallible<(ProverFinalResponse, CommittedUids)> {
        let r = secrets.rand;
        let mut recommitted_uids: Vec<RistrettoPoint> =
            committed_uids.0.iter().map(|e_uid| e_uid * r).collect();
        // The prover reshuffles the set. Otherwise, once the verifiers searches for the element
        // and finds it, the verifier can tell which element it was based on the position in the
        // set.
        recommitted_uids.shuffle(rng);

        let cdd_id_proof_response = apply_challenge(&secrets.cdd_id_proof_secrets, challenge);
        let cdd_id_second_half_proof_response =
            apply_challenge(&secrets.cdd_id_second_half_proof_secrets, challenge);
        let uid_commitment_proof_response =
            apply_challenge(&secrets.uid_commitment_proof_secrets, challenge);

        Ok((
            ProverFinalResponse {
                cdd_id_proof_response,
                cdd_id_second_half_proof_response,
                uid_commitment_proof_response,
            },
            CommittedUids(recommitted_uids),
        ))
    }
}

// ------------------------------------------------------------------------
// Tests
// ------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use crate::{
        uuid_to_scalar, verifier::gen_random_uuids, ChallengeGenerator, ChallengeResponder,
        FinalProver, InitialProver, PrivateUids, ProofGenerator, ProofVerifier, Verifier,
        VerifierSetGenerator,
    };
    use cryptography_core::cdd_claim::{compute_cdd_id, CddClaimData};
    use cryptography_core::curve25519_dalek::scalar::Scalar;
    use rand::{rngs::StdRng, SeedableRng};
    use rand_core::RngCore;
    use uuid::Uuid;

    #[test]
    fn test_success_end_to_end() {
        let mut rng = StdRng::from_seed([10u8; 32]);

        // Private input of the Verifier.
        let private_uid_set: Vec<Uuid> = gen_random_uuids(100, &mut rng);

        // Make a random did for the investor.
        let mut investor_did = [0u8; 32];
        rng.fill_bytes(&mut investor_did);

        // Verifier shares one of its uids with the Prover.
        let claim = CddClaimData::new(&investor_did, private_uid_set[0].as_bytes());

        // Prover generates cdd_id and places it on the chain.
        let cdd_id = compute_cdd_id(&claim);

        let private_uid_scalar_set: Vec<Scalar> =
            private_uid_set.into_iter().map(uuid_to_scalar).collect();

        // P -> V: Prover generates and sends the initial message.
        let (prover_secrets, proofs) =
            InitialProver::generate_initial_proofs(claim, &mut rng).unwrap();

        // V -> P: Prover sends `proofs` and Verifier returns a list of 10 uids and the challenge.
        let (verifier_secrets, committed_uids, challenge) =
            VerifierSetGenerator::generate_committed_set_and_challenge(
                PrivateUids(private_uid_scalar_set),
                Some(100),
                &mut rng,
            )
            .unwrap();

        // P -> V: Verifier sends the committed_uids and the challenge to the Prover.
        let (prover_response, re_committed_uids) = FinalProver::generate_challenge_response(
            &prover_secrets,
            &committed_uids,
            &challenge,
            &mut rng,
        )
        .unwrap();

        // Only V: Verifier verifies the proofs and check membership.
        assert!(Verifier::verify_proofs(
            &proofs,
            &prover_response,
            &challenge,
            &cdd_id,
            &verifier_secrets,
            &re_committed_uids,
        )
        .is_ok());
    }
}
