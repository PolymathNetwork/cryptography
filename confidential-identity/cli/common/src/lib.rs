use blake2::{Blake2s, Digest};
use confidential_identity::CddId;
use curve25519_dalek::ristretto::RistrettoPoint;
use serde::{Deserialize, Serialize};

// IdentityId is the investor's DID.
pub type InvestorDID = [u8; 32];
pub const INVESTORDID_LEN: usize = 32;

// Ticker, a 12 bytes slice, is the scope DID.
pub type ScopeDID = [u8; 12];
pub const SCOPEDID_LEN: usize = 12;

// Unique ID is a UUIDv4.
pub type UniqueID = [u8; 16];
pub const UNIQUEID_LEN: usize = 16;

#[derive(Debug, Serialize, Deserialize)]
pub struct Proof {
    pub cdd_id: CddId,
    pub investor_did: InvestorDID,
    pub scope_id: RistrettoPoint,
    pub scope_did: ScopeDID,
    #[serde(with = "serde_bytes")]
    pub proof: Vec<u8>,
}

/// Returns the message used for checking the proof.
pub fn make_message(investor_did: &InvestorDID, scope_did: &ScopeDID) -> [u8; 32] {
    Blake2s::default()
        .chain(investor_did)
        .chain(scope_did)
        .finalize()
        .into()
}
