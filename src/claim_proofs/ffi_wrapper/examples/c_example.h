#ifndef claim_proofs_ffi_h
#define claim_proofs_ffi_h

/* Warning, this file is autogenerated by cbindgen. Don't modify this manually. */

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct ScopeClaimProofData ScopeClaimProofData;

typedef struct CddClaimData CddClaimData;

typedef struct ScopeClaimData ScopeClaimData;

typedef struct RistrettoPoint RistrettoPoint;

typedef struct Signature Signature;

typedef struct ProofPublicKey ProofPublicKey;

/**
 * Creates a `ScopeClaimProofData` object from a CDD claim and an scope claim.
 *
 * SAFETY: Caller is responsible to make sure `cdd_claim` and `scope_claim`
 *         pointers are valid pointers to `CddClaimData` and `ScopeClaimData`
 *         objects, created by this API.
 * Caller is responsible for deallocating memory after use.
 */
ScopeClaimProofData *build_scope_claim_proof_data_wrapper(const CddClaimData *cdd_claim,
                                                          const ScopeClaimData *scope_claim);

/**
 * Deallocates a `CddClaimData` object's memory.
 *
 * Should only be called on a still-valid pointer to an object returned by
 * `cdd_claim_data_new()`.
 */
void cdd_claim_data_free(CddClaimData *ptr);

/**
 * Create a new `CddClaimData` object.
 *
 * Caller is responsible for calling `cdd_claim_data_free()` to deallocate this object.
 * SAFETY: Caller is also responsible for making sure `investor_did` and
 *         `investor_unique_id` point to allocated blocks of memory of `investor_did_size`
 *         and `investor_unique_id_size` bytes respectively.
 */
CddClaimData *cdd_claim_data_new(const uint8_t *investor_did,
                                 size_t investor_did_size,
                                 const uint8_t *investor_unique_id,
                                 size_t investor_unique_id_size);

/**
 * Creates a CDD ID from a CDD claim.
 *
 * SAFETY: Caller is responsible to make sure `cdd_claim` pointer is a valid
 *         `CddClaimData` object, created by this API.
 * Caller is responsible for deallocating memory after use.
 */
RistrettoPoint *compute_cdd_id_wrapper(const CddClaimData *cdd_claim);

/**
 * Creates a scope ID from a scope claim.
 *
 * SAFETY: Caller is responsible to make sure the `scope_claim` pointer is a valid
 *         `ScopeClaimData` object, created by this API.
 * Caller is responsible for deallocating memory after use.
 */
RistrettoPoint *compute_scope_id_wrapper(const ScopeClaimData *scope_claim);

/**
 * Creates a `Signature` from a scope claim proof data and a message.
 *
 * SAFETY: Caller is responsible to make sure `scope_claim_proof_data` and `message`
 *         pointers are valid objects, created by this API, and `message` points to
 *         a block of memory that has at least `message_size` bytes.
 * Caller is responsible for deallocating memory after use.
 */
Signature *generate_id_match_proof_wrapper(ScopeClaimProofData *scope_claim_proof_data,
                                           const uint8_t *message,
                                           size_t message_size);

/**
 * Deallocates a `ProofPublicKey` object's memory.
 *
 * Should only be called on a still-valid pointer to an object returned by
 * `proof_public_key_new()`.
 */
void proof_public_key_free(ProofPublicKey *ptr);

/**
 * Create a new `ProofPublicKey` object.
 *
 * Caller is responsible for calling `cdd_claim_data_free()` to deallocate this object.
 * SAFETY: Caller is responsible for making sure `investor_did` and
 *         `scope_did` point to allocated blocks of memory of `investor_did_size`
 *         and `scope_did_size` bytes respectively. Caller is also responsible
 *         for making sure the `cdd_id` and `scope_id` are valid pointers, created using
 *         `compute_cdd_id_wrapper()` and `compute_scope_id_wrapper()` API.
 */
ProofPublicKey *proof_public_key_new(RistrettoPoint *cdd_id,
                                     const uint8_t *investor_did,
                                     size_t investor_did_size,
                                     RistrettoPoint *scope_id,
                                     const uint8_t *scope_did,
                                     size_t scope_did_size);

/**
 * Deallocates a `ScopeClaimData` object's memory.
 *
 * Should only be called on a still-valid pointer to an object returned by
 * `scope_claim_data_new()`.
 */
void scope_claim_data_free(ScopeClaimData *ptr);

/**
 * Create a new `ScopeClaimData` object.
 *
 * Caller is responsible for calling `scope_claim_data_free()` to deallocate this object.
 * SAFETY: Caller is also responsible for making sure `scope_did` and
 *         `investor_unique_id` point to allocated blocks of memory of `scope_did_size`
 *         and `investor_unique_id_size` bytes respectively.
 */
ScopeClaimData *scope_claim_data_new(const uint8_t *scope_did,
                                     size_t scope_did_size,
                                     const uint8_t *investor_unique_id,
                                     size_t investor_unique_id_size);

/**
 * Deallocates a `ScopeClaimProofData` object's memory.
 *
 * Should only be called on a still-valid pointer to an object returned by
 * `build_scope_claim_proof_data_wrapper()`.
 */
void scope_claim_proof_data_free(ScopeClaimProofData *ptr);

/**
 * Deallocates a `Signature` object's memory.
 *
 * Should only be called on a still-valid pointer to an object returned by
 * `generate_id_match_proof_wrapper()`.
 */
void signature_free(Signature *ptr);

/**
 * Verifies the signature on a message.
 *
 * SAFETY: Caller is responsible to make sure `proof_public_key`, `message`, and `signature`
 *         pointers are valid objects, created by this API, and `message` points to a block
 *         of memory that has at least `message_size` bytes.
 * Caller is responsible for deallocating memory after use.
 */
bool verify_id_match_proof_wrapper(const ProofPublicKey *proof_public_key,
                                   const uint8_t *message,
                                   size_t message_size,
                                   const Signature *signature);

#endif /* claim_proofs_ffi_h */
