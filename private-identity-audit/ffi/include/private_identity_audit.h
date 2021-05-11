#ifndef private_identity_audit_ffi_h
#define private_identity_audit_ffi_h

/* Warning, this file is autogenerated by cbindgen. Don't modify this manually. */

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * The data needed to generate a CDD ID.
 */
typedef struct CddClaimData CddClaimData;

typedef struct VecEncoding {
  uint8_t *arr;
  uintptr_t n;
} VecEncoding;

typedef struct VerifierSetGeneratorResults {
  struct VecEncoding *verifier_secrets;
  struct VecEncoding *committed_uids;
} VerifierSetGeneratorResults;

typedef struct MatrixEncoding {
  uint8_t *arr;
  uintptr_t rows;
  uintptr_t cols;
} MatrixEncoding;

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
struct CddClaimData *cdd_claim_data_new(const uint8_t *investor_did,
                                        size_t investor_did_size,
                                        const uint8_t *investor_unique_id,
                                        size_t investor_unique_id_size);

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
struct VerifierSetGeneratorResults *generate_committed_set(struct MatrixEncoding *private_unique_identifiers,
                                                           const size_t *min_set_size,
                                                           const uint8_t *seed,
                                                           size_t seed_size);

#endif /* private_identity_audit_ffi_h */
