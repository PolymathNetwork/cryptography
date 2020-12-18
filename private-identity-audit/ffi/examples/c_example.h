#ifndef private_identity_audit_ffi_h
#define private_identity_audit_ffi_h

/* Warning, this file is autogenerated by cbindgen. Don't modify this manually. */

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * Holds the initial messages in the Zero-Knowledge Proofs sent by CDD Provider.
 */
typedef struct Proofs Proofs;

/**
 * Holds CDD Provider secret data.
 */
typedef struct ProverSecrets ProverSecrets;

struct InitialProverResults {
    ProverSecrets *prover_secrets;
    Proofs *proofs;
};
typedef struct InitialProverResults InitialProverResults;

typedef struct CommittedUids CommittedUids;
typedef struct ProverFinalResponse ProverFinalResponse;
/**
 * Holds the CDD Provider's response to the PUIS challenge.
 */
struct FinalProverResults {
    ProverFinalResponse *prover_final_response;
    CommittedUids *committed_uids;
};
typedef struct FinalProverResults FinalProverResults;

/**
 * Holds PUIS secret data.
 */
typedef struct VerifierSecrets VerifierSecrets;

typedef struct  Challenge Challenge;
typedef struct  VerifierSecrets VerifierSecrets;

struct VerifierSetGeneratorResults {
    // (VerifierSecrets, CommittedUids, Challenge)
    VerifierSecrets *verifier_secrets;
    CommittedUids *committed_uids;
    size_t committed_uids_size;
    Challenge *challenge;
};
typedef struct VerifierSetGeneratorResults VerifierSetGeneratorResults;

typedef struct Scalar Scalar;

typedef struct CddClaimData CddClaimData;

typedef struct RistrettoPoint RistrettoPoint;

typedef struct CommittedUids CommittedUids;

/**
 * Creates a CDD ID from a CDD claim.
 *
 * SAFETY: Caller is responsible to make sure `cdd_claim` pointer is a valid
 *         `CddClaimData` object, created by this API.
 * Caller is responsible for deallocating memory after use.
 */
RistrettoPoint *compute_cdd_id_wrapper(const CddClaimData *cdd_claim);

Scalar *uuid_new(const uint8_t *unique_id, size_t unique_id_size);

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
                                 const Scalar *investor_unique_id);

/**
 * Deallocates a `CddClaimData` object's memory.
 *
 * Should only be called on a still-valid pointer to an object returned by
 * `cdd_claim_data_new()`.
 */
void cdd_claim_data_free(CddClaimData *ptr);

void initial_prover_results_free(InitialProverResults *ptr);

void verifier_set_generator_results_free(VerifierSetGeneratorResults *ptr);

void final_prover_results_free(FinalProverResults *ptr);

InitialProverResults *generate_initial_proofs_wrapper(const CddClaimData *cdd_claim,
                                                      const uint8_t *seed,
                                                      size_t seed_size);

VerifierSetGeneratorResults *generate_committed_set_and_challenge_wrapper(Scalar *private_unique_identifiers,
                                                                          size_t private_unique_identifiers_size,
                                                                          const size_t *min_set_size,
                                                                          const uint8_t *seed,
                                                                          size_t seed_size);

FinalProverResults *generate_challenge_response_wrapper(ProverSecrets *secrets,
                                                        CommittedUids *committed_uids,
                                                        size_t committed_uids_size,
                                                        Challenge *challenge,
                                                        const uint8_t *seed,
                                                        size_t seed_size);

bool verify_proofs(const Proofs *initial_message,
                   const ProverFinalResponse *final_response,
                   Challenge *challenge,
                   RistrettoPoint *cdd_id,
                   const VerifierSecrets *verifier_secrets,
                   const CommittedUids *re_committed_uids);

#endif /* private_identity_audit_ffi_h */
