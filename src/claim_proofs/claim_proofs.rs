//! The `claim_proofs` library contains API for generating
//! claim proofs and verifying them as part of the
//! Asset Granularity Unique Identity project.
//!
//! The investor would use the `ProofKeyPair` API to generate
//! the proofs.
//!
//! The verifier would use the `ProofPublicKey` API to verify
//! the proofs, and conclude that an investor's identity matches
//! its claims.
//!
//! ```
//! use cryptography::claim_proofs::{compute_cdd_id, compute_scope_id, build_scope_claim_proof_data,
//!     CddClaimData, ScopeClaimData, ProofKeyPair};
//! use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
//!
//! // Investor side:
//! let message = b"some asset ownership claims!";
//!
//! let investor_did = [1u8; 32];
//! let investor_unique_id = [2u8; 32];
//! let cdd_claim = CddClaimData::new(&investor_did, &investor_unique_id);
//!
//! let scope_did = [4u8; 32];
//! let scope_claim = ScopeClaimData::new(&scope_did, &investor_unique_id);
//!
//! let scope_claim_proof_data = build_scope_claim_proof_data(&cdd_claim, &scope_claim);
//! let pair = ProofKeyPair::from(scope_claim_proof_data);
//!
//! let proof = pair.generate_id_match_proof(message);
//! let cdd_id = compute_cdd_id(&cdd_claim);
//! let scope_id = compute_scope_id(&scope_claim);
//!
//! // Verifier side:
//! use cryptography::claim_proofs::ProofPublicKey;
//!
//! let verifier_pub = ProofPublicKey::new(cdd_id, &investor_did, scope_id, &scope_did);
//! let result = verifier_pub.verify_id_match_proof(message, &proof);
//!
//! assert!(result);
//! ```
//!

use super::pedersen_commitments::PedersenGenerators;
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use lazy_static::lazy_static;
#[cfg(feature = "runtime-benchmarks")]
use merlin::Transcript;
#[cfg(feature = "runtime-benchmarks")]
use rand_chacha::ChaChaRng;
#[cfg(feature = "runtime-benchmarks")]
use schnorrkel::context::SigningTranscriptWithRng;
use schnorrkel::{context::SigningContext, signing_context, Keypair, PublicKey, Signature};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use sp_std::prelude::*;

/// Signing context.
const SIGNING_CTX: &[u8] = b"PolymathClaimProofs";
lazy_static! {
    static ref SIG_CTXT: SigningContext = signing_context(SIGNING_CTX);
}

#[cfg(feature = "runtime-benchmarks")]
const MESSAGE_LABEL: &[u8] = b"PolymathMessageBytes";

#[cfg(feature = "runtime-benchmarks")]
/// Make a signing transcript from the message.
/// Use ChaCha20 as the PRNG instead of defaulting to the OS RNG. This has to be done
/// to support platforms that do not provide an OS RNG, e.g. WASM.
fn make_signing_transcript(message: &[u8]) -> SigningTranscriptWithRng<Transcript, ChaChaRng> {
    use rand_core::SeedableRng;
    let mut t = Transcript::new(SIGNING_CTX);
    t.append_message(MESSAGE_LABEL, message);
    let csprng = ChaChaRng::from_seed([0u8; 32]); // DANGER
    schnorrkel::context::attach_rng(t, csprng)
}

/// Create a scalar from a slice of data.
fn slice_to_scalar(data: &[u8]) -> Scalar {
    use blake2::{Blake2b, Digest};
    let mut hash = [0u8; 64];
    hash.copy_from_slice(Blake2b::digest(data).as_slice());
    Scalar::from_bytes_mod_order_wide(&hash)
}

/// The data needed to generate a CDD ID.
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CddClaimData {
    pub investor_did: Scalar,
    pub investor_unique_id: Scalar,
}

impl CddClaimData {
    /// Create a CDD Claim Data object from slices of data.
    pub fn new(investor_did: &[u8], investor_unique_id: &[u8]) -> Self {
        CddClaimData {
            investor_did: slice_to_scalar(investor_did),
            investor_unique_id: slice_to_scalar(investor_unique_id),
        }
    }
}

/// The data needed to generate a SCOPE ID.
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ScopeClaimData {
    pub scope_did: Scalar,
    pub investor_unique_id: Scalar,
}

impl ScopeClaimData {
    /// Create a Scope Claim Data object from slices of data.
    pub fn new(scope_did: &[u8], investor_unique_id: &[u8]) -> Self {
        ScopeClaimData {
            scope_did: slice_to_scalar(scope_did),
            investor_unique_id: slice_to_scalar(investor_unique_id),
        }
    }
}

/// The data needed to generate a proof that a SCOPE ID matches a CDD ID
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ScopeClaimProofData {
    pub scope_did: Scalar,
    pub investor_did: Scalar,
    pub investor_unique_id: Scalar,
}

/// An Schnorrkel/Ristretto x25519 ("sr25519") key pair.
/// This is the construct that the investors will use to generate
/// claim proofs.
#[derive(Debug)]
pub struct ProofKeyPair {
    keypair: Keypair,
}

/// An Schnorrkel/Ristretto x25519 ("sr25519") public key.
/// This is the construct that the blockchain validator will use for
/// claim proof validation.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProofPublicKey {
    pub_key: PublicKey,
}

fn generate_pedersen_commit(a: Scalar, b: Scalar) -> RistrettoPoint {
    use sha3::{Digest, Sha3_512};
    // 0. Generate the blind factor as concatenation of `a` and `b`.
    let hash = Sha3_512::default().chain(a.as_bytes()).chain(b.as_bytes());
    let blind = Scalar::from_hash(hash);

    // Calculate the output commit.
    let pg = PedersenGenerators::default();
    pg.commit(&[a, b, blind])
}

/// Compute the CDD_ID. \
/// CDD_ID = PedersenCommitment(INVESTOR_DID, INVESTOR_UNIQUE_ID, [INVESTOR_DID | INVESTOR_UNIQUE_ID]) \
///
/// # Inputs
/// * `cdd_claim` is the CDD claim from which to generate the CDD_ID
///
/// # Output
/// The Pedersen commitment result.
pub fn compute_cdd_id(cdd_claim: &CddClaimData) -> RistrettoPoint {
    generate_pedersen_commit(cdd_claim.investor_did, cdd_claim.investor_unique_id)
}

/// Compute the SCOPE_ID \
/// SCOPE_ID = PedersenCommitment(SCOPE_DID, INVESTOR_UNIQUE_ID, [SCOPE_DID | INVESTOR_UNIQUE_ID])
///
/// # Inputs
/// * `scope_claim` is the scope claim from which to generate the SCOPE_ID
/// * `id1` is the second value to commit.
///
/// # Output
/// The Pedersen commitment result.
pub fn compute_scope_id(scope_claim: &ScopeClaimData) -> RistrettoPoint {
    generate_pedersen_commit(scope_claim.scope_did, scope_claim.investor_unique_id)
}

pub fn build_scope_claim_proof_data(
    cdd_claim: &CddClaimData,
    scope_claim: &ScopeClaimData,
) -> ScopeClaimProofData {
    ScopeClaimProofData {
        scope_did: scope_claim.scope_did,
        investor_unique_id: cdd_claim.investor_unique_id,
        investor_did: cdd_claim.investor_did,
    }
}

pub type Seed = [u8; 32];

impl From<ScopeClaimProofData> for ProofKeyPair {
    /// Create a key pair object for the investor from a claim data.
    ///
    /// # Input:
    /// `d`: the data required to prove that a SCOPE_ID matches a CDD_ID.
    fn from(d: ScopeClaimProofData) -> Self {
        use sha3::{digest::FixedOutput, Digest, Sha3_256, Sha3_512};
        // Investor's secret key is:
        // Hash([INVESTOR_DID | INVESTOR_UNIQUE_ID]) - Hash([SCOPE_DID | INVESTOR_UNIQUE_ID])
        let first_term = Scalar::from_hash(
            Sha3_512::default()
                .chain(d.investor_did.as_bytes())
                .chain(d.investor_unique_id.as_bytes()),
        );

        let second_term = Scalar::from_hash(
            Sha3_512::default()
                .chain(d.scope_did.as_bytes())
                .chain(d.investor_unique_id.as_bytes()),
        );

        let secret_key_scalar = first_term - second_term;

        // Set the secret key's nonce to : ["nonce" | secret_key]
        let nonce = Sha3_256::default()
            .chain("nonce")
            .chain(&secret_key_scalar.as_bytes())
            .fixed_result();

        let mut exported_private_key = [0u8; 64];
        exported_private_key[..32].copy_from_slice(secret_key_scalar.as_bytes());
        exported_private_key[32..].copy_from_slice(&nonce);

        let secret = schnorrkel::SecretKey::from_bytes(&exported_private_key)
            .expect("key is always the correct size");
        let public = secret.to_public();

        ProofKeyPair {
            keypair: schnorrkel::Keypair { public, secret },
        }
    }
}

impl ProofKeyPair {
    /// Generate an Id match proof.
    ///
    /// # Input
    /// * `message`: the message to generate a proof for.
    ///
    /// # Output
    /// A proof in the form of an Schnorrkel/Ristretto x25519 signature.
    pub fn generate_id_match_proof(&self, message: &[u8]) -> Signature {
        #[cfg(not(feature = "runtime-benchmarks"))]
        return self.keypair.sign(SIG_CTXT.bytes(message));
        #[cfg(feature = "runtime-benchmarks")]
        self.keypair.sign(make_signing_transcript(message))
    }
}

impl ProofPublicKey {
    /// Create a public key object for the blockchain validator.
    ///
    /// # Inputs
    /// * `cdd_id`: the investor's CDD_ID.
    /// * `investor_did`: the investor's DID.
    /// * `scope_id`: the investor's SCOPE_ID.
    /// * `scope_did`: the scope DID
    pub fn new(
        cdd_id: RistrettoPoint,
        investor_did: &[u8],
        scope_id: RistrettoPoint,
        scope_did: &[u8],
    ) -> Self {
        let investor_did = slice_to_scalar(investor_did);
        let scope_did = slice_to_scalar(scope_did);
        let pg = PedersenGenerators::default();

        let cdd_label_prime = pg.label_prime(cdd_id, investor_did);
        let scope_label_prime = pg.label_prime(scope_id, scope_did);
        let diff = cdd_label_prime - scope_label_prime;

        let pub_key = PublicKey::from_point(diff);
        ProofPublicKey { pub_key }
    }

    /// Verify an Id match proof.
    ///
    /// # Inputs
    /// * `message`: the message to verify the proof for.
    /// * `sig`: the proof.
    ///
    /// # Output
    /// `true` on a successful verification, `false` otherwise.
    pub fn verify_id_match_proof(&self, message: &[u8], sig: &Signature) -> bool {
        self.pub_key
            .verify_simple(SIGNING_CTX, message, sig)
            .is_ok()
    }
}

// ------------------------------------------------------------------------
// Tests
// ------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};
    use rand_core::RngCore;

    const SEED_1: [u8; 32] = [42u8; 32];
    const SEED_2: [u8; 32] = [43u8; 32];

    #[test]
    fn match_pub_key_both_sides() {
        let expected_public_key = [
            102, 132, 8, 112, 82, 12, 133, 155, 7, 47, 56, 166, 4, 178, 144, 27, 78, 252, 169, 28,
            30, 215, 62, 126, 248, 158, 208, 35, 9, 210, 148, 49,
        ];

        let mut rng = StdRng::from_seed(SEED_1);

        // Generate random IDs.
        // Use random slices to make claims.
        // Don't make any assumptions about these slices' sizes.
        let mut unique_id_bytes = [0u8; 256];
        rng.fill_bytes(&mut unique_id_bytes);
        let mut did_bytes = [0u8; 32];
        rng.fill_bytes(&mut did_bytes);
        let mut scope_id_bytes = [0u8; 128];
        rng.fill_bytes(&mut scope_id_bytes);
        let cdd_claim = CddClaimData::new(&did_bytes, &unique_id_bytes);
        let scope_claim = ScopeClaimData::new(&scope_id_bytes, &unique_id_bytes);

        let scope_claim_proof_data = build_scope_claim_proof_data(&cdd_claim, &scope_claim);

        // Investor side.
        let pair = ProofKeyPair::from(scope_claim_proof_data);
        let cdd_id = compute_cdd_id(&cdd_claim);
        let scope_id = compute_scope_id(&scope_claim);

        // Verifier side.
        let verifier_pub = ProofPublicKey::new(cdd_id, &did_bytes, scope_id, &scope_id_bytes);

        // Make sure both sides get the same public key.
        assert_eq!(pair.keypair.public, verifier_pub.pub_key);

        assert_eq!(verifier_pub.pub_key.to_bytes(), expected_public_key);
    }

    #[test]
    fn verify_proofs() {
        let mut rng = StdRng::from_seed(SEED_2);

        // Use random slices to make claims.
        // Don't make any assumptions about these slices' sizes.
        let mut unique_id_bytes = [0u8; 72];
        rng.fill_bytes(&mut unique_id_bytes);
        let mut did_bytes = [0u8; 32];
        rng.fill_bytes(&mut did_bytes);
        let mut scope_id_bytes = [0u8; 128];
        rng.fill_bytes(&mut scope_id_bytes);
        let cdd_claim = CddClaimData::new(&did_bytes, &unique_id_bytes);
        let scope_claim = ScopeClaimData::new(&scope_id_bytes, &unique_id_bytes);

        let message = &b"I didn't claim anything!".to_vec();
        let bad_message = &b"I claim everything!".to_vec();

        // Investor side.
        let scope_claim_proof_data = build_scope_claim_proof_data(&cdd_claim, &scope_claim);

        let pair = ProofKeyPair::from(scope_claim_proof_data);
        let proof = pair.generate_id_match_proof(message);

        // Note: the SR 255-19 randomizes the signing process, therefore
        // we can't check the `proof` against a  test vector here.

        let cdd_id = compute_cdd_id(&cdd_claim);
        let scope_id = compute_scope_id(&scope_claim);

        // => Investor makes {cdd_id, scope_id, investor_did, scope_did, message, proof} public knowledge.

        // Verifier side.
        let verifier_pub = ProofPublicKey::new(cdd_id, &did_bytes, scope_id, &scope_id_bytes);

        // Positive tests.
        let result = verifier_pub.verify_id_match_proof(message, &proof);
        assert!(result);

        // Negative tests.
        let bad_result = verifier_pub.verify_id_match_proof(bad_message, &proof);
        assert!(!bad_result);
    }
}
