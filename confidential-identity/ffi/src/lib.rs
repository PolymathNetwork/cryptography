//! The `confidential_identity_ffi` is the Foreign Function Interface (FFI)
//! for the `confidential_identity` library. It contains API for generating
//! claim proofs and verifying them as part of the
//! Asset Granularity Unique Identity project.

extern crate libc;
use libc::size_t;
use std::slice;

use confidential_identity::{build_scope_claim_proof_data, compute_cdd_id, compute_scope_id};

pub type ScopeClaimData = confidential_identity::ScopeClaimData;
pub type ScopeClaimProofData = confidential_identity::ScopeClaimProofData;
pub type ProofPublicKey = confidential_identity::ProofPublicKey;
pub type ProofKeyPair = confidential_identity::ProofKeyPair;
pub type CddClaimData = confidential_identity::CddClaimData;
pub type CddId = confidential_identity::CddId;
pub type Signature = schnorrkel::Signature;
pub type RistrettoPoint = curve25519_dalek::ristretto::RistrettoPoint;

fn box_alloc<T>(x: T) -> *mut T {
    Box::into_raw(Box::new(x))
}

// ------------------------------------------------------------------------
// Data Structures
// ------------------------------------------------------------------------

/// Create a new `CddClaimData` object.
///
/// Caller is responsible for calling `cdd_claim_data_free()` to deallocate this object.
///
/// # Safety
///
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

/// Create a new `ScopeClaimData` object.
///
/// Caller is responsible for calling `scope_claim_data_free()` to deallocate this object.
///
/// # Safety
///
/// Caller is also responsible for making sure `scope_did` and
/// `investor_unique_id` point to allocated blocks of memory of `scope_did_size`
/// and `investor_unique_id_size` bytes respectively.
#[no_mangle]
pub unsafe extern "C" fn scope_claim_data_new(
    scope_did: *const u8,
    scope_did_size: size_t,
    investor_unique_id: *const u8,
    investor_unique_id_size: size_t,
) -> *mut ScopeClaimData {
    assert!(!scope_did.is_null());
    assert!(!investor_unique_id.is_null());

    let scope_did = slice::from_raw_parts(scope_did, scope_did_size as usize);
    let investor_unique_id =
        slice::from_raw_parts(investor_unique_id, investor_unique_id_size as usize);

    box_alloc(ScopeClaimData::new(scope_did, investor_unique_id))
}

/// Deallocates a `ScopeClaimData` object's memory.
///
/// Should only be called on a still-valid pointer to an object returned by
/// `scope_claim_data_new()`.
#[no_mangle]
pub unsafe extern "C" fn scope_claim_data_free(ptr: *mut ScopeClaimData) {
    if ptr.is_null() {
        return;
    }
    Box::from_raw(ptr);
}

/// Deallocates a `ScopeClaimProofData` object's memory.
///
/// Should only be called on a still-valid pointer to an object returned by
/// `build_scope_claim_proof_data_wrapper()`.
#[no_mangle]
pub unsafe extern "C" fn scope_claim_proof_data_free(ptr: *mut ScopeClaimProofData) {
    if ptr.is_null() {
        return;
    }
    Box::from_raw(ptr);
}

/// Create a new `ProofPublicKey` object.
///
/// Caller is responsible for calling `cdd_claim_data_free()` to deallocate this object.
///
/// # Safety
///
/// Caller is responsible for making sure `investor_did` and
/// `scope_did` point to allocated blocks of memory of `investor_did_size`
/// and `scope_did_size` bytes respectively. Caller is also responsible
/// for making sure the `cdd_id` and `scope_id` are valid pointers, created using
/// `compute_cdd_id_wrapper()` and `compute_scope_id_wrapper()` API.
#[no_mangle]
pub unsafe extern "C" fn proof_public_key_new(
    cdd_id: *mut CddId,
    investor_did: *const u8,
    investor_did_size: size_t,
    scope_id: *mut RistrettoPoint,
    scope_did: *const u8,
    scope_did_size: size_t,
) -> *mut ProofPublicKey {
    assert!(!cdd_id.is_null());
    assert!(!investor_did.is_null());
    assert!(!scope_id.is_null());
    assert!(!scope_did.is_null());

    let cdd_id: CddId = *cdd_id;
    let investor_did = slice::from_raw_parts(investor_did, investor_did_size as usize);
    let scope_id: RistrettoPoint = *scope_id;
    let scope_did = slice::from_raw_parts(scope_did, scope_did_size as usize);

    let proof_public_key = ProofPublicKey::new(cdd_id, investor_did, scope_id, scope_did);

    box_alloc(proof_public_key)
}

/// Deallocates a `ProofPublicKey` object's memory.
///
/// Should only be called on a still-valid pointer to an object returned by
/// `proof_public_key_new()`.
#[no_mangle]
pub unsafe extern "C" fn proof_public_key_free(ptr: *mut ProofPublicKey) {
    if ptr.is_null() {
        return;
    }

    Box::from_raw(ptr);
}

/// Deallocates a `Signature` object's memory.
///
/// Should only be called on a still-valid pointer to an object returned by
/// `generate_id_match_proof_wrapper()`.
#[no_mangle]
pub unsafe extern "C" fn signature_free(ptr: *mut Signature) {
    if ptr.is_null() {
        return;
    }
    Box::from_raw(ptr);
}

// ------------------------------------------------------------------------
// Prover API
// ------------------------------------------------------------------------

/// Creates a `ScopeClaimProofData` object from a CDD claim and an scope claim.
///
/// # Safety
///
/// Caller is responsible to make sure `cdd_claim` and `scope_claim`
/// pointers are valid pointers to `CddClaimData` and `ScopeClaimData`
/// objects, created by this API.
/// Caller is responsible for deallocating memory after use.
#[no_mangle]
pub unsafe extern "C" fn build_scope_claim_proof_data_wrapper(
    cdd_claim: *const CddClaimData,
    scope_claim: *const ScopeClaimData,
) -> *mut ScopeClaimProofData {
    assert!(!cdd_claim.is_null());
    assert!(!scope_claim.is_null());

    let cdd_claim: CddClaimData = *cdd_claim;
    let scope_claim: ScopeClaimData = *scope_claim;
    box_alloc(build_scope_claim_proof_data(&cdd_claim, &scope_claim))
}

/// Creates a CDD ID from a CDD claim.
///
/// # Safety
///
/// Caller is responsible to make sure `cdd_claim` pointer is a valid
/// `CddClaimData` object, created by this API.
/// Caller is responsible for deallocating memory after use.
#[no_mangle]
pub unsafe extern "C" fn compute_cdd_id_wrapper(cdd_claim: *const CddClaimData) -> *mut CddId {
    assert!(!cdd_claim.is_null());

    let cdd_claim: CddClaimData = *cdd_claim;
    box_alloc(compute_cdd_id(&cdd_claim))
}

/// Creates a scope ID from a scope claim.
///
/// # Safety
///
/// Caller is responsible to make sure the `scope_claim` pointer is a valid
/// `ScopeClaimData` object, created by this API.
/// Caller is responsible for deallocating memory after use.
#[no_mangle]
pub unsafe extern "C" fn compute_scope_id_wrapper(
    scope_claim: *const ScopeClaimData,
) -> *mut RistrettoPoint {
    assert!(!scope_claim.is_null());

    let scope_claim: ScopeClaimData = *scope_claim;
    box_alloc(compute_scope_id(&scope_claim))
}

/// Creates a `Signature` from a scope claim proof data and a message.
///
/// # Safety
///
/// Caller is responsible to make sure `scope_claim_proof_data` and `message`
/// pointers are valid objects, created by this API, and `message` points to
/// a block of memory that has at least `message_size` bytes.
/// Caller is responsible for deallocating memory after use.
#[no_mangle]
pub unsafe extern "C" fn generate_id_match_proof_wrapper(
    scope_claim_proof_data: *mut ScopeClaimProofData,
    message: *const u8,
    message_size: size_t,
) -> *mut Signature {
    assert!(!scope_claim_proof_data.is_null());
    assert!(!message.is_null());
    // We allow zero size messages.

    let message_slice = slice::from_raw_parts(message, message_size as usize);
    let scope_claim_proof_data: ScopeClaimProofData = *scope_claim_proof_data;
    let pair = ProofKeyPair::from(scope_claim_proof_data);
    let proof = pair.generate_id_match_proof(message_slice);

    box_alloc(proof)
}

// ------------------------------------------------------------------------
// Verifier API
// ------------------------------------------------------------------------

/// Verifies the signature on a message.
///
/// # Safety
///
/// Caller is responsible to make sure `proof_public_key`, `message`, and `signature`
/// pointers are valid objects, created by this API, and `message` points to a block
/// of memory that has at least `message_size` bytes.
/// Caller is responsible for deallocating memory after use.
#[no_mangle]
pub unsafe extern "C" fn verify_id_match_proof_wrapper(
    proof_public_key: *const ProofPublicKey,
    message: *const u8,
    message_size: size_t,
    signature: *const Signature,
) -> bool {
    assert!(!proof_public_key.is_null());
    assert!(!message.is_null());
    // We allow zero size messages.

    let message_slice = slice::from_raw_parts(message, message_size as usize);
    let proof_public_key: ProofPublicKey = *proof_public_key;
    let signature: Signature = *signature;

    proof_public_key.verify_id_match_proof(message_slice, &signature)
}
