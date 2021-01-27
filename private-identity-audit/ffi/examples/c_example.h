#ifndef private_identity_audit_ffi_h
#define private_identity_audit_ffi_h

/* Warning, this file is autogenerated by cbindgen. Don't modify this manually. */

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * The Zero-Knowledge challenge.
 */
typedef struct Challenge Challenge;

/**
 * The committed and padded version of the private set of PUIS.
 */
typedef struct CommittedUids CommittedUids;

/**
 * Holds the initial messages in the Zero-Knowledge Proofs sent by CDD Provider.
 */
typedef struct Proofs Proofs;

/**
 * Holds the CDD Provider's response to the PUIS challenge.
 */
typedef struct ProverFinalResponse ProverFinalResponse;

/**
 * Holds CDD Provider secret data.
 */
typedef struct ProverSecrets ProverSecrets;

/**
 * Holds PUIS secret data.
 */
typedef struct VerifierSecrets VerifierSecrets;

typedef struct Scalar Scalar;

typedef struct CddClaimData CddClaimData;

typedef struct {
  ProverSecrets *prover_secrets;
  Proofs *proofs;
} InitialProverResults;

typedef struct {
  VerifierSecrets *verifier_secrets;
  CommittedUids *committed_uids;
  Challenge *challenge;
} VerifierSetGeneratorResults;

typedef struct {
  ProverFinalResponse *prover_final_response;
  CommittedUids *committed_uids;
} FinalProverResults;

typedef struct CddId CddId;

/**
 * Convert a Uuid byte array into a scalar object.
 *
 * Caller is responsible for calling `cdd_claim_data_free()` to deallocate this object.
 *
 * # Safety
 * Caller is also responsible for making sure `investor_did` and
 * `investor_unique_id` point to allocated blocks of memory of `investor_did_size`
 * and `investor_unique_id_size` bytes respectively.
 */
Scalar *uuid_new(const uint8_t *unique_id, size_t unique_id_size);

/**
 * Deallocates a `Scalar` object's memory.
 *
 * Should only be called on a still-valid pointer to an object returned by
 * `uuid_new()`.
 */
void scalar_free(Scalar *ptr);

/**
 * Create a new `CddClaimData` object.
 *
 * Caller is responsible for calling `cdd_claim_data_free()` to deallocate this object.
 *
 * # Safety
 * Caller is also responsible for making sure `investor_did` and
 * `investor_unique_id` point to allocated blocks of memory of `investor_did_size`
 * and `investor_unique_id_size` bytes respectively.
 */
CddClaimData *cdd_claim_data_new(const uint8_t *investor_did,
                                 size_t investor_did_size,
                                 const uint8_t *investor_unique_id,
                                 size_t investor_unique_id_size);

/**
 * Deallocates a `CddClaimData` object's memory.
 *
 * Should only be called on a still-valid pointer to an object returned by
 * `cdd_claim_data_new()`.
 */
void cdd_claim_data_free(CddClaimData *ptr);

/**
 * Deallocates a `InitialProverResults` object's memory.
 *
 * Should only be called on a still-valid pointer to an object returned by
 * `generate_initial_proofs_wrapper()`.
 */
void initial_prover_results_free(InitialProverResults *ptr);

/**
 * Deallocates a `VerifierSetGeneratorResults` object's memory.
 *
 * Should only be called on a still-valid pointer to an object returned by
 * `generate_committed_set_and_challenge_wrapper()`.
 */
void verifier_set_generator_results_free(VerifierSetGeneratorResults *ptr);

/**
 * Deallocates a `FinalProverResults` object's memory.
 *
 * Should only be called on a still-valid pointer to an object returned by
 * `generate_challenge_response_wrapper()`.
 */
void final_prover_results_free(FinalProverResults *ptr);

/**
 * Creates a `InitialProverResults` object from a CDD claim and a seed.
 *
 *
 * # Safety
 * Caller is responsible to make sure `cdd_claim` is a valid
 * pointer to a `CddClaimData` object, and `seed` is a random
 * 32-byte array.
 * Caller is responsible for deallocating memory after use.
 */
InitialProverResults *generate_initial_proofs_wrapper(const CddClaimData *cdd_claim,
                                                      const uint8_t *seed,
                                                      size_t seed_size);

/**
 * Creates a `VerifierSetGeneratorResults` object from a private Uuid (as
 * a Scalar object), a minimum set size, and a seed.
 *
 * # Safety
 * Caller is responsible to make sure `private_unique_identifiers`
 * is a valid pointer to a `Scalar` object, and `seed` is a random
 * 32-byte array.
 * Caller is responsible for deallocating memory after use.
 */
VerifierSetGeneratorResults *generate_committed_set_and_challenge_wrapper(Scalar *private_unique_identifiers,
                                                                          size_t private_unique_identifiers_size,
                                                                          const size_t *min_set_size,
                                                                          const uint8_t *seed,
                                                                          size_t seed_size);

/**
 * Creates a `FinalProverResults` object from a prover's secret, a
 * committed set of Uids, a challenge, and a seed.
 *
 * # Safety
 * Caller is responsible to make sure `secrets`
 * is a valid pointer to a `ProverSecrets` object, `challenge` is
 * a valid pointer to a `Challenge` object, and `seed` is a random
 * 32-byte array.
 * Caller is responsible for deallocating memory after use.
 */
FinalProverResults *generate_challenge_response_wrapper(const ProverSecrets *secrets,
                                                        const CommittedUids *committed_uids,
                                                        const Challenge *challenge,
                                                        const uint8_t *seed,
                                                        size_t seed_size);

/**
 * Verifies the proof of a Uuid's membership in a set of Uuids.
 *
 * # Safety
 * Caller is responsible to make sure `initial_message`,
 * `final_response`, `challenge`, `cdd_id`, `verifier_secrets`,
 * and `re_committed_uids` pointers are valid objects, created by
 * this API.
 * Caller is responsible for deallocating memory after use.
 */
bool verify_proofs(const Proofs *initial_message,
                   const ProverFinalResponse *final_response,
                   const Challenge *challenge,
                   const CddId *cdd_id,
                   const VerifierSecrets *verifier_secrets,
                   const CommittedUids *re_committed_uids);

#endif /* private_identity_audit_ffi_h */
