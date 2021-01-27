use blake2::{Blake2s, Digest};
use confidential_identity::{
    build_scope_claim_proof_data, compute_cdd_id, compute_scope_id, mocked, CddClaimData, CddId,
    ProofKeyPair, ScopeClaimData,
};
use curve25519_dalek::ristretto::RistrettoPoint;
use serde::{Deserialize, Serialize};

use wasm_bindgen::prelude::*;

type InvestorDID = [u8; 32];

// Ticker, a 12 bytes slice, is the scope DID.
pub type ScopeDID = [u8; 12];

// Unique ID is a UUIDv4.
type UniqueID = [u8; 16];

#[derive(Debug, Serialize, Deserialize)]
pub struct RawCddClaimData {
    pub investor_did: InvestorDID,
    pub investor_unique_id: UniqueID,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RawScopeClaimData {
    pub scope_did: ScopeDID,
    pub investor_unique_id: UniqueID,
}

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

/// Creates a CDD_ID from investor did and investor uid
///
/// # Arguments
/// * `cdd_claim` a stringified json with the following format:
///   { "investor_did": [32_bytes_array], "investor_unique_id": [16_bytes_array] }
///
/// # Errors
/// * Failure to deserialize the cdd claim.
/// * Failure to serialize the cdd id.
#[wasm_bindgen]
pub fn process_create_cdd_id(cdd_claim: String) -> Result<String, JsValue> {
    let raw_cdd_data: RawCddClaimData = serde_json::from_str(&cdd_claim)
        .map_err(|error| format!("Failed to deserialize the cdd claim: {}", error))?;

    let cdd_claim = CddClaimData::new(&raw_cdd_data.investor_did, &raw_cdd_data.investor_unique_id);

    let cdd_id = compute_cdd_id(&cdd_claim);

    let cdd_id_str = serde_json::to_string(&cdd_id)
        .map_err(|error| format!("Failed to serialize the CDD Id: {}", error))?;

    Ok(cdd_id_str)
}

/// Creates a scope claim proof for an investor from investor did, investor uid, and scope did.
///
/// # Arguments
/// * `cdd_claim` a stringified json with the following format:
///   { "investor_did": [32_bytes_array], "investor_unique_id": [16_bytes_array] }
/// * `scoped_claim` a stringified json with the following format:
///   { "scope_did":[12_bytes_array], "investor_unique_id":[16_bytes_array] }
///
/// # Errors
/// * Failure to deserialize the cdd claim.
/// * Failure to deserialize the scope claim.
/// * Failure to serialize the proof.
#[wasm_bindgen]
pub fn process_create_claim_proof(
    cdd_claim: String,
    scoped_claim: String,
) -> Result<String, JsValue> {
    let raw_cdd_claim: RawCddClaimData = serde_json::from_str(&cdd_claim)
        .map_err(|error| format!("Failed to deserialize the cdd claim: {}", error))?;

    let raw_scope_claim: RawScopeClaimData = serde_json::from_str(&scoped_claim)
        .map_err(|error| format!("Failed to deserialize the scope claim: {}", error))?;

    let message = make_message(&raw_cdd_claim.investor_did, &raw_scope_claim.scope_did);

    let cdd_claim = CddClaimData::new(
        &raw_cdd_claim.investor_did,
        &raw_cdd_claim.investor_unique_id,
    );
    let scope_claim = ScopeClaimData::new(
        &raw_scope_claim.scope_did,
        &raw_scope_claim.investor_unique_id,
    );
    let scope_claim_proof_data = build_scope_claim_proof_data(&cdd_claim, &scope_claim);

    let pair = ProofKeyPair::from(scope_claim_proof_data);
    let proof = pair.generate_id_match_proof(&message).to_bytes().to_vec();

    let cdd_id = compute_cdd_id(&cdd_claim);
    let scope_id = compute_scope_id(&scope_claim);

    // => Investor makes {cdd_id, investor_did, scope_id, scope_did, proof} public knowledge.
    let packaged_proof = Proof {
        cdd_id,
        investor_did: raw_cdd_claim.investor_did,
        scope_id,
        scope_did: raw_scope_claim.scope_did,
        proof,
    };
    let proof_str = serde_json::to_string(&packaged_proof)
        .map_err(|error| format!("Failed to serialize the proof: {}", error))?;

    Ok(proof_str)
}

#[wasm_bindgen]
pub fn process_create_mocked_investor_uid(did: String) -> String {
    // Sanitize Did input.
    let did = did.strip_prefix("0x").unwrap_or(&did);
    let did = did.chars().filter(|c| *c != '-').collect::<String>();
    let raw_did = hex::decode(did).expect("Invalid input DID, please use hex format");
    assert!(
        raw_did.len() == 32,
        "Invalid input DID, len should be 64 hex characters"
    );

    // Generate the mocked InvestorUid
    let investor_uid = mocked::make_investor_uid(&raw_did);

    hex::encode(investor_uid)
}
