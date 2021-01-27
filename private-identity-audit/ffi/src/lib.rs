//! The `private_identity_audit_ffi` is the Foreign Function Interface (FFI)
//! for the `private_identity_audit` library. It contains API for generating
//! unique identity membership proofs and verifying them as part of the
//! PIAL project.

extern crate libc;
use libc::size_t;
use rand::{rngs::StdRng, SeedableRng};
use std::{ptr::null_mut, slice};
use uuid::{Builder, Variant, Version};

use private_identity_audit::{
    uuid_to_scalar, ChallengeGenerator, ChallengeResponder, ProofGenerator, ProofVerifier,
    Verifier, VerifierSetGenerator,
};

pub type CddId = cryptography_core::cdd_claim::CddId;
pub type PrivateUids = private_identity_audit::PrivateUids;
pub type CommittedUids = private_identity_audit::CommittedUids;
pub type Challenge = private_identity_audit::Challenge;
pub type Proofs = private_identity_audit::Proofs;
pub type ProverFinalResponse = private_identity_audit::ProverFinalResponse;
pub type ProverSecrets = private_identity_audit::ProverSecrets;
pub type VerifierSecrets = private_identity_audit::VerifierSecrets;
pub type InitialProver = private_identity_audit::InitialProver;
pub type FinalProver = private_identity_audit::FinalProver;
pub type CddClaimData = cryptography_core::cdd_claim::CddClaimData;
pub type RistrettoPoint = cryptography_core::curve25519_dalek::ristretto::RistrettoPoint;
pub type Scalar = cryptography_core::curve25519_dalek::scalar::Scalar;

#[repr(C)]
pub struct InitialProverResults {
    pub prover_secrets: *mut ProverSecrets,
    pub proofs: *mut Proofs,
}

#[repr(C)]
pub struct VerifierSetGeneratorResults {
    pub verifier_secrets: *mut VerifierSecrets,
    pub committed_uids: *mut CommittedUids,
    pub challenge: *mut Challenge,
}

#[repr(C)]
pub struct FinalProverResults {
    pub prover_final_response: *mut ProverFinalResponse,
    pub committed_uids: *mut CommittedUids,
}

fn box_alloc<T>(x: T) -> *mut T {
    Box::into_raw(Box::new(x))
}

// ------------------------------------------------------------------------
// Data Structures
// ------------------------------------------------------------------------

/// Convert a Uuid byte array into a scalar object.
///
/// Caller is responsible for calling `cdd_claim_data_free()` to deallocate this object.
///
/// # Safety
/// Caller is also responsible for making sure `investor_did` and
/// `investor_unique_id` point to allocated blocks of memory of `investor_did_size`
/// and `investor_unique_id_size` bytes respectively.
#[no_mangle]
pub unsafe extern "C" fn uuid_new(unique_id: *const u8, unique_id_size: size_t) -> *mut Scalar {
    assert!(!unique_id.is_null());
    assert!(unique_id_size == 16);

    let mut uuid_bytes = [0u8; 16];
    uuid_bytes.copy_from_slice(slice::from_raw_parts(unique_id, unique_id_size as usize));

    let uuid = Builder::from_bytes(uuid_bytes)
        .set_variant(Variant::RFC4122)
        .set_version(Version::Random)
        .build();

    box_alloc(uuid_to_scalar(uuid))
}

/// Deallocates a `Scalar` object's memory.
///
/// Should only be called on a still-valid pointer to an object returned by
/// `uuid_new()`.
#[no_mangle]
pub unsafe extern "C" fn scalar_free(ptr: *mut Scalar) {
    if ptr.is_null() {
        return;
    }
    Box::from_raw(ptr);
}

/// Create a new `CddClaimData` object.
///
/// Caller is responsible for calling `cdd_claim_data_free()` to deallocate this object.
///
/// # Safety
/// Caller is also responsible for making sure `investor_did` and
/// `investor_unique_id` point to allocated blocks of memory of `investor_did_size`
/// and `investor_unique_id_size` bytes respectively.
#[no_mangle]
pub unsafe extern "C" fn cdd_claim_data_new(
    investor_did: *const u8,
    investor_did_size: size_t,
    investor_unique_id: *const u8,
    investor_unique_id_size: size_t,
) -> *mut CddClaimData {
    assert!(!investor_did.is_null());
    assert!(!investor_unique_id.is_null());
    let investor_did = slice::from_raw_parts(investor_did, investor_did_size as usize);

    let investor_unique_id =
        slice::from_raw_parts(investor_unique_id, investor_unique_id_size as usize);

    box_alloc(CddClaimData::new(investor_did, investor_unique_id))
}

/// Deallocates a `CddClaimData` object's memory.
///
/// Should only be called on a still-valid pointer to an object returned by
/// `cdd_claim_data_new()`.
#[no_mangle]
pub unsafe extern "C" fn cdd_claim_data_free(ptr: *mut CddClaimData) {
    if ptr.is_null() {
        return;
    }
    Box::from_raw(ptr);
}

/// Deallocates a `InitialProverResults` object's memory.
///
/// Should only be called on a still-valid pointer to an object returned by
/// `generate_initial_proofs_wrapper()`.
#[no_mangle]
pub unsafe extern "C" fn initial_prover_results_free(ptr: *mut InitialProverResults) {
    if ptr.is_null() {
        return;
    }
    Box::from_raw(ptr);
}

/// Deallocates a `VerifierSetGeneratorResults` object's memory.
///
/// Should only be called on a still-valid pointer to an object returned by
/// `generate_committed_set_and_challenge_wrapper()`.
#[no_mangle]
pub unsafe extern "C" fn verifier_set_generator_results_free(
    ptr: *mut VerifierSetGeneratorResults,
) {
    if ptr.is_null() {
        return;
    }
    Box::from_raw(ptr);
}

/// Deallocates a `FinalProverResults` object's memory.
///
/// Should only be called on a still-valid pointer to an object returned by
/// `generate_challenge_response_wrapper()`.
#[no_mangle]
pub unsafe extern "C" fn final_prover_results_free(ptr: *mut FinalProverResults) {
    if ptr.is_null() {
        return;
    }
    Box::from_raw(ptr);
}

// ------------------------------------------------------------------------
// InitialProver API
// ------------------------------------------------------------------------

/// Creates a `InitialProverResults` object from a CDD claim and a seed.
///
///
/// # Safety
/// Caller is responsible to make sure `cdd_claim` is a valid
/// pointer to a `CddClaimData` object, and `seed` is a random
/// 32-byte array.
/// Caller is responsible for deallocating memory after use.
#[no_mangle]
pub unsafe extern "C" fn generate_initial_proofs_wrapper(
    cdd_claim: *const CddClaimData,
    seed: *const u8,
    seed_size: size_t,
) -> *mut InitialProverResults {
    assert!(!cdd_claim.is_null());
    assert!(!seed.is_null());
    assert!(seed_size == 32);

    let cdd_claim: CddClaimData = *cdd_claim;

    let mut rng_seed = [0u8; 32];
    rng_seed.copy_from_slice(slice::from_raw_parts(seed, seed_size as usize));
    let mut rng = StdRng::from_seed(rng_seed);

    let result = InitialProver::generate_initial_proofs(cdd_claim, &mut rng);

    // Log the error and return.
    if result.is_err() {
        println!("Step 1) P->V error: {:?}", result.is_err());
        return null_mut();
    }

    let (prover_secrets, proofs) = result.unwrap();

    box_alloc(InitialProverResults {
        prover_secrets: box_alloc(prover_secrets),
        proofs: box_alloc(proofs),
    })
}

// ------------------------------------------------------------------------
// VerifierSetGenerator API
// ------------------------------------------------------------------------

/// Creates a `VerifierSetGeneratorResults` object from a private Uuid (as
/// a Scalar object), a minimum set size, and a seed.
///
/// # Safety
/// Caller is responsible to make sure `private_unique_identifiers`
/// is a valid pointer to a `Scalar` object, and `seed` is a random
/// 32-byte array.
/// Caller is responsible for deallocating memory after use.
#[no_mangle]
pub unsafe extern "C" fn generate_committed_set_and_challenge_wrapper(
    private_unique_identifiers: *mut Scalar,
    private_unique_identifiers_size: size_t,
    min_set_size: *const size_t,
    seed: *const u8,
    seed_size: size_t,
) -> *mut VerifierSetGeneratorResults {
    assert!(!private_unique_identifiers.is_null());
    assert!(private_unique_identifiers_size != 0);
    assert!(!seed.is_null());
    assert!(seed_size == 32);

    let unique_identifiers = private_identity_audit::PrivateUids(
        slice::from_raw_parts_mut(private_unique_identifiers, private_unique_identifiers_size)
            .into(),
    );

    let min_set_size: Option<usize> = match min_set_size.is_null() {
        true => None,
        false => Some(*min_set_size as usize),
    };

    let mut rng_seed = [0u8; 32];
    rng_seed.copy_from_slice(slice::from_raw_parts(seed, seed_size as usize));
    let mut rng = StdRng::from_seed(rng_seed);

    let result = VerifierSetGenerator::generate_committed_set_and_challenge(
        unique_identifiers,
        min_set_size,
        &mut rng,
    );

    // Log the error and return.
    if result.is_err() {
        println!("Step 2) V->P error: {:?}", result.is_err());
        return null_mut();
    }

    let (verifier_secrets, committed_uids, challenge) = result.unwrap();

    box_alloc(VerifierSetGeneratorResults {
        verifier_secrets: box_alloc(verifier_secrets),
        committed_uids: box_alloc(committed_uids),
        challenge: box_alloc(challenge),
    })
}

// ------------------------------------------------------------------------
// FinalProver API
// ------------------------------------------------------------------------

/// Creates a `FinalProverResults` object from a prover's secret, a
/// committed set of Uids, a challenge, and a seed.
///
/// # Safety
/// Caller is responsible to make sure `secrets`
/// is a valid pointer to a `ProverSecrets` object, `challenge` is
/// a valid pointer to a `Challenge` object, and `seed` is a random
/// 32-byte array.
/// Caller is responsible for deallocating memory after use.
#[no_mangle]
pub unsafe extern "C" fn generate_challenge_response_wrapper(
    secrets: *const ProverSecrets,
    committed_uids: *const CommittedUids,
    challenge: *const Challenge,
    seed: *const u8,
    seed_size: size_t,
) -> *mut FinalProverResults {
    assert!(!secrets.is_null());
    assert!(!committed_uids.is_null());
    assert!(!seed.is_null());
    assert!(seed_size == 32);

    let secrets: &ProverSecrets = &*secrets;

    let committed_uids_vec: &CommittedUids = &*committed_uids;

    let challenge: &Challenge = &*challenge;

    let mut rng_seed = [0u8; 32];
    rng_seed.copy_from_slice(slice::from_raw_parts(seed, seed_size as usize));
    let mut rng = StdRng::from_seed(rng_seed);

    let result =
        FinalProver::generate_challenge_response(secrets, committed_uids_vec, challenge, &mut rng);

    // Log the error and return.
    if result.is_err() {
        println!("Step 3) P->V error: {:?}", result.is_err());
        return null_mut();
    }

    let (prover_final_response, re_committed_uids) = result.unwrap();
    box_alloc(FinalProverResults {
        prover_final_response: box_alloc(prover_final_response),
        committed_uids: box_alloc(re_committed_uids),
    })
}

// ------------------------------------------------------------------------
// Verifier API
// ------------------------------------------------------------------------

/// Verifies the proof of a Uuid's membership in a set of Uuids.
///
/// # Safety
/// Caller is responsible to make sure `initial_message`,
/// `final_response`, `challenge`, `cdd_id`, `verifier_secrets`,
/// and `re_committed_uids` pointers are valid objects, created by
/// this API.
/// Caller is responsible for deallocating memory after use.
#[no_mangle]
pub unsafe extern "C" fn verify_proofs(
    initial_message: *const Proofs,
    final_response: *const ProverFinalResponse,
    challenge: *const Challenge,
    cdd_id: *const CddId,
    verifier_secrets: *const VerifierSecrets,
    re_committed_uids: *const CommittedUids,
) -> bool {
    assert!(!initial_message.is_null());
    assert!(!final_response.is_null());
    assert!(!challenge.is_null());
    assert!(!cdd_id.is_null());
    assert!(!verifier_secrets.is_null());
    assert!(!re_committed_uids.is_null());

    let initial_message: &Proofs = &*initial_message;
    let final_response: &ProverFinalResponse = &*final_response;
    let challenge: &Challenge = &*challenge;
    let cdd_id: &CddId = &*cdd_id;
    let verifier_secrets: &VerifierSecrets = &*verifier_secrets;
    let re_committed_uids: &CommittedUids = &*re_committed_uids;

    let result = Verifier::verify_proofs(
        initial_message,
        final_response,
        challenge,
        cdd_id,
        verifier_secrets,
        re_committed_uids,
    );

    // Log the error.
    if result.is_err() {
        println!("Step 4) Verifier error: {:?}", result.is_err());
    }

    result.is_ok()
}
