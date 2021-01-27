//! The `claim_proofs` library contains API for generating
//! claim proofs and verifying them as part of the
//! Asset Granularity Unique Identity project.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
#[macro_use]
extern crate alloc;

pub use claim_proofs::{
    build_scope_claim_proof_data, compute_cdd_id, compute_scope_id, CddClaimData, CddId,
    ProofKeyPair, ProofPublicKey, ScopeClaimData, ScopeClaimProofData,
};
pub use curve25519_dalek::{self, ristretto::CompressedRistretto, scalar::Scalar};
use rand_core::{CryptoRng, RngCore};
pub use schnorrkel;

pub fn random_claim<R: RngCore + CryptoRng>(rng: &mut R) -> (CddClaimData, ScopeClaimData) {
    let investor_unique_id = Scalar::random(rng);
    (
        CddClaimData {
            investor_did: Scalar::random(rng),
            investor_unique_id,
        },
        ScopeClaimData {
            scope_did: Scalar::random(rng),
            investor_unique_id,
        },
    )
}

/// That `ensure` does not transform into a string representation like `failure::ensure` is doing.
#[allow(unused_macros)]
macro_rules! ensure {
    ($predicate:expr, $context_selector:expr) => {
        if !$predicate {
            return Err($context_selector.into());
        }
    };
}

/// Helper macro to assert that `predicate` is an `Error::from( $err)`.
#[allow(unused_macros)]
macro_rules! assert_err {
    ($predicate:expr, $err:expr) => {
        assert_eq!($predicate.expect_err("Error expected").kind(), &$err);
    };
}

mod claim_proofs;
pub mod mocked;
pub mod uuid;
