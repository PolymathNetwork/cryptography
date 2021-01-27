use crate::{
    errors::{ErrorKind, Fallible},
    proofs::verify,
    uuid_to_scalar, Challenge, ChallengeGenerator, CommittedUids, PrivateUids, ProofVerifier,
    Proofs, ProverFinalResponse, Verifier, VerifierSecrets, VerifierSetGenerator,
    SET_SIZE_ANONYMITY_PARAM,
};
use cryptography_core::cdd_claim::{pedersen_commitments::PedersenGenerators, CddId};
use cryptography_core::curve25519_dalek::scalar::Scalar;
use rand::seq::SliceRandom;
use rand_core::{CryptoRng, RngCore};
use uuid::{Builder, Uuid, Variant, Version};

impl ChallengeGenerator for VerifierSetGenerator {
    fn generate_committed_set_and_challenge<T: RngCore + CryptoRng>(
        private_unique_identifiers: PrivateUids,
        min_set_size: Option<usize>,
        rng: &mut T,
    ) -> Fallible<(VerifierSecrets, CommittedUids, Challenge)> {
        // Pad the input vector with randomly generated uuids.
        let min_size = if let Some(overriden_size) = min_set_size {
            overriden_size
        } else {
            SET_SIZE_ANONYMITY_PARAM
        };

        let padded_vec = if private_unique_identifiers.0.len() >= min_size {
            private_unique_identifiers.0
        } else {
            let padding: Vec<Scalar> =
                gen_random_uuids(min_size - private_unique_identifiers.0.len(), rng)
                    .into_iter()
                    .map(uuid_to_scalar)
                    .collect();
            [&private_unique_identifiers.0[..], &padding[..]].concat()
        };

        // Commit to each element.
        let pg = PedersenGenerators::default();
        let r = Scalar::random(rng);
        let mut commitments = padded_vec
            .into_iter()
            .map(|scalar_uid| pg.generators[1] * scalar_uid * r)
            .collect::<Vec<_>>();
        commitments.shuffle(rng);

        let challenge = Challenge(Scalar::random(rng));

        Ok((
            VerifierSecrets { rand: r },
            CommittedUids(commitments),
            challenge,
        ))
    }
}

impl ProofVerifier for Verifier {
    fn verify_proofs(
        initial_message: &Proofs,
        final_response: &ProverFinalResponse,
        challenge: &Challenge,
        cdd_id: &CddId,
        verifier_secrets: &VerifierSecrets,
        re_committed_uids: &CommittedUids,
    ) -> Fallible<()> {
        let uid_commitment = initial_message.a - initial_message.b;
        ensure!(
            initial_message.cdd_id_proof.generators[0] == cdd_id.0,
            ErrorKind::CDDIdMismatchError
        );

        ensure!(
            verify(
                &initial_message.cdd_id_proof,
                &final_response.cdd_id_proof_response,
                &initial_message.a,
                &challenge,
            ),
            ErrorKind::ZKPVerificationError {
                kind: "CDD ID".into()
            }
        );
        ensure!(
            verify(
                &initial_message.cdd_id_second_half_proof,
                &final_response.cdd_id_second_half_proof_response,
                &initial_message.b,
                &challenge,
            ),
            ErrorKind::ZKPVerificationError {
                kind: "CDD ID Second Half".into()
            }
        );
        ensure!(
            verify(
                &initial_message.uid_commitment_proof,
                &final_response.uid_commitment_proof_response,
                &uid_commitment,
                &challenge,
            ),
            ErrorKind::ZKPVerificationError { kind: "UID".into() }
        );

        let looking_for = uid_commitment * verifier_secrets.rand;

        ensure!(
            re_committed_uids
                .0
                .iter()
                .any(|element| { *element == looking_for }),
            ErrorKind::MembershipProofError
        );
        Ok(())
    }
}

pub fn gen_random_uuids<T: RngCore + CryptoRng>(count: usize, rng: &mut T) -> Vec<Uuid> {
    vec![0; count]
        .into_iter()
        .map(|_| {
            let mut random_bytes: [u8; 16] = [0; 16];
            rng.fill_bytes(&mut random_bytes);
            let rand_uuid = Builder::from_bytes(random_bytes)
                .set_variant(Variant::RFC4122)
                .set_version(Version::Random)
                .build();
            rand_uuid
        })
        .collect()
}

// ------------------------------------------------------------------------------------------------
// -                                            Tests                                             -
// ------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use crate::{
        uuid_to_scalar, verifier::gen_random_uuids, ChallengeGenerator, PrivateUids,
        VerifierSetGenerator, SET_SIZE_ANONYMITY_PARAM,
    };
    use rand::{rngs::StdRng, SeedableRng};
    use rand_core::{CryptoRng, RngCore};

    fn make_random_uuids<T: RngCore + CryptoRng>(count: usize, rng: &mut T) -> PrivateUids {
        PrivateUids(
            gen_random_uuids(count, rng)
                .into_iter()
                .map(uuid_to_scalar)
                .collect(),
        )
    }

    #[test]
    fn test_verifier_set_gen_length() {
        let mut rng = StdRng::from_seed([10u8; 32]);
        let input_len = 10;

        // Test original anonymity param.
        let (_, committed_uids, _) = VerifierSetGenerator::generate_committed_set_and_challenge(
            make_random_uuids(input_len, &mut rng),
            None,
            &mut rng,
        )
        .expect("Success");

        assert_eq!(committed_uids.0.len(), SET_SIZE_ANONYMITY_PARAM);

        // Test overridden anonymity param.
        let different_anonymity_size = 20;
        let (_, committed_uids, _) = VerifierSetGenerator::generate_committed_set_and_challenge(
            make_random_uuids(input_len, &mut rng),
            Some(different_anonymity_size),
            &mut rng,
        )
        .expect("Success");

        assert_eq!(committed_uids.0.len(), different_anonymity_size);

        // Test no padding.
        let different_anonymity_size = 5;
        let (_, committed_uids, _) = VerifierSetGenerator::generate_committed_set_and_challenge(
            make_random_uuids(input_len, &mut rng),
            Some(different_anonymity_size),
            &mut rng,
        )
        .expect("Success");

        assert_eq!(committed_uids.0.len(), input_len);
    }
}
