use codec::{Decode, Encode};
use confidential_identity::{CddClaimData, CddId};
use private_identity_audit::{
    Challenge, ChallengeGenerator, ChallengeResponder, CommittedUids, FinalProver, InitialProver,
    PrivateUids, ProofGenerator, ProofVerifier, Proofs, ProverFinalResponse, ProverSecrets,
    Verifier, VerifierSecrets, VerifierSetGenerator,
};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use std::convert::Into;

use wasm_bindgen::prelude::*;
use wasm_bindgen::JsValue;

// ------------------------------------------------------------------------------------
// -                                  Type Definitions                                -
// ------------------------------------------------------------------------------------

/// A base64 encoded string.
pub type Base64 = String;

/// Investor's DID.
type InvestorDID = [u8; 32];

/// Unique ID in UUIDv4 format.
type UniqueID = [u8; 16];

#[derive(Debug, Serialize, Deserialize)]
pub struct RawCddClaimData {
    pub investor_did: InvestorDID,
    pub investor_unique_id: UniqueID,
}

#[wasm_bindgen]
pub struct InitialProofsOutput {
    prover_secrets: Base64,
    proofs: Base64,
}

#[wasm_bindgen]
impl InitialProofsOutput {
    #[wasm_bindgen(getter)]
    pub fn initial_proofs_secrets(&self) -> Base64 {
        self.prover_secrets.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn initial_proofs_proofs(&self) -> Base64 {
        self.proofs.clone()
    }
}

#[wasm_bindgen]
pub struct CommittedSetOutput {
    verifier_secrets: Base64,
    committed_uids: Base64,
    challenge: Base64,
}

#[wasm_bindgen]
impl CommittedSetOutput {
    /// The committed set results.
    #[wasm_bindgen(getter)]
    pub fn verifier_secrets(&self) -> Base64 {
        self.verifier_secrets.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn committed_uids(&self) -> Base64 {
        self.committed_uids.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn challenge(&self) -> Base64 {
        self.challenge.clone()
    }
}

#[wasm_bindgen]
pub struct ChallengeResponseOutput {
    response: Base64,
    committed_uids: Base64,
}

#[wasm_bindgen]
impl ChallengeResponseOutput {
    /// The initial proof results.
    #[wasm_bindgen(getter)]
    pub fn response(&self) -> Base64 {
        self.response.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn committed_uids(&self) -> Base64 {
        self.committed_uids.clone()
    }
}

// ------------------------------------------------------------------------------------
// -                                     Error Types                                  -
// ------------------------------------------------------------------------------------

#[wasm_bindgen]
#[derive(Serialize)]
pub enum WasmError {
    GenerateInitialMessageError,
    GenerateCommittedSetError,
    GenerateChallengeResponseError,
    ProofVerificationError,
    DeserializationError,
    Base64DecodingError,
    DecryptionError,
}

impl From<WasmError> for JsValue {
    fn from(e: WasmError) -> JsValue {
        if let Ok(msg) = serde_json::to_string(&e) {
            msg.into()
        } else {
            "Failed to serialized the error to string!".into()
        }
    }
}

type Fallible<T> = Result<T, JsValue>;

// ------------------------------------------------------------------------------------
// -                                     Public API                                   -
// ------------------------------------------------------------------------------------

/// Helper function to convert a Uid from Uuid to Scalar format.
#[wasm_bindgen]
pub fn convert_uuid_to_scalar(uuid: Base64) -> Fallible<Base64> {
    match base64::decode(uuid) {
        Ok(uuid) => {
            let mut uuid_slice = [0u8; 16];
            uuid_slice.copy_from_slice(uuid.as_slice());
            Ok(base64::encode(
                private_identity_audit::uuid_to_scalar(Uuid::from_bytes(uuid_slice)).as_bytes(),
            ))
        }
        Err(_) => return Err(WasmError::DeserializationError.into()),
    }
}

/// The first leg of the protocol from CDD Provider to PUIS.
#[wasm_bindgen]
pub fn generate_initial_proofs(cdd_claim: Base64) -> Fallible<InitialProofsOutput> {
    let cdd_claim = decode_base64::<CddClaimData>(cdd_claim)?;

    let mut rng = OsRng;
    let results = InitialProver::generate_initial_proofs(cdd_claim, &mut rng)
        .map_err(|_| WasmError::GenerateInitialMessageError)?;

    Ok(InitialProofsOutput {
        prover_secrets: base64::encode(results.0.encode()),
        proofs: base64::encode(results.1.encode()),
    })
}

/// The second leg of the protocol from PUIS to CDD Provider.
#[wasm_bindgen]
pub fn generate_committed_set_and_challenge(
    private_uuids: Base64,
    min_set_size: Option<usize>,
) -> Fallible<CommittedSetOutput> {
    let uuids: PrivateUids = decode_base64(private_uuids)?;

    let mut rng = OsRng;
    let results =
        VerifierSetGenerator::generate_committed_set_and_challenge(uuids, min_set_size, &mut rng)
            .map_err(|_| WasmError::GenerateCommittedSetError)?;

    Ok(CommittedSetOutput {
        verifier_secrets: base64::encode(results.0.encode()),
        committed_uids: base64::encode(results.1.encode()),
        challenge: base64::encode(results.2.encode()),
    })
}

/// The third leg of the protocol from CDD Provider to PUIS.
#[wasm_bindgen]
pub fn generate_challenge_response(
    secrets: Base64,
    committed_uids: Base64,
    challenge: Base64,
) -> Fallible<ChallengeResponseOutput> {
    let secrets: ProverSecrets = decode_base64(secrets)?;
    let committed_uids: CommittedUids = decode_base64(committed_uids)?;
    let challenge: Challenge = decode_base64(challenge)?;

    let mut rng = OsRng;
    let results =
        FinalProver::generate_challenge_response(&secrets, &committed_uids, &challenge, &mut rng)
            .map_err(|_| WasmError::GenerateChallengeResponseError)?;

    Ok(ChallengeResponseOutput {
        response: base64::encode(results.0.encode()),
        committed_uids: base64::encode(results.1.encode()),
    })
}

/// The last step of the protocol in which PUIS verifies the proofs.
#[wasm_bindgen]
pub fn verify_proofs(
    initial_message: Base64,
    final_response: Base64,
    challenge: Base64,
    cdd_id: Base64,
    verifier_secrets: Base64,
    re_committed_uids: Base64,
) -> Fallible<()> {
    let initial_message: Proofs = decode_base64(initial_message)?;
    let final_response: ProverFinalResponse = decode_base64(final_response)?;
    let challenge: Challenge = decode_base64(challenge)?;
    let cdd_id: CddId = decode_base64(cdd_id)?;
    let verifier_secrets: VerifierSecrets = decode_base64(verifier_secrets)?;
    let re_committed_uids: CommittedUids = decode_base64(re_committed_uids)?;

    Verifier::verify_proofs(
        &initial_message,
        &final_response,
        &challenge,
        &cdd_id,
        &verifier_secrets,
        &re_committed_uids,
    )
    .map_err(|_| WasmError::ProofVerificationError)?;

    Ok(())
}

// ------------------------------------------------------------------------------------
// -                               Internal Functions                                 -
// ------------------------------------------------------------------------------------

fn decode_base64<T: Decode>(data: Base64) -> Fallible<T> {
    let decoded = base64::decode(data).map_err(|_| WasmError::Base64DecodingError)?;
    T::decode(&mut &decoded[..]).map_err(|_| WasmError::DeserializationError.into())
}

// ------------------------------------------------------------------------------------
// -                               A Minimal Test Case                                -
// ------------------------------------------------------------------------------------

#[wasm_bindgen]
extern "C" {
    fn alert(s: &str);
}

#[wasm_bindgen]
pub fn test_pial_wrapper() {
    let claim = String::from(
        "AhX7FWIhH5tEO575NvwLqBL+QVGU+q0jnv1zkKScSQJhVpx4tYh7ljbvAO7/YljA9svW+PCh5batFRkg+We5DA==",
    );
    let cdd_id = String::from("mJBkHvwUSRPH26xM0yCICu7kiOXWNGrC3Ad19Hez7Ao=");
    let uuids = String::from("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");

    let result1 = match generate_initial_proofs(claim) {
        Ok(r) => r,
        Err(err) => {
            let str = err.as_string().unwrap_or(String::from("nothing!"));
            alert(&str);
            return;
        }
    };

    let result2 = generate_committed_set_and_challenge(uuids, Some(100)).unwrap();
    let challenge = result2.challenge;
    let result3 = generate_challenge_response(
        result1.prover_secrets,
        result2.committed_uids,
        challenge.clone(),
    )
    .unwrap();

    let result = verify_proofs(
        result1.proofs,
        result3.response,
        challenge,
        cdd_id,
        result2.verifier_secrets,
        result3.committed_uids,
    )
    .is_ok();

    if result {
        alert("CDD provider's proof of identity membership has been successfully verified!");
    } else {
        alert("Failed to verify CDD provider's proof of identity membership!");
    }
}
