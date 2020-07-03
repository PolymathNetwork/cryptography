//! The MERCAT's asset issuance implementation.
//!
use crate::{
    asset_proofs::{
        correctness_proof::{
            CorrectnessProof, CorrectnessProverAwaitingChallenge, CorrectnessVerifier,
        },
        encrypting_same_value_proof::{
            EncryptingSameValueProverAwaitingChallenge, EncryptingSameValueVerifier,
        },
        encryption_proofs::single_property_prover,
        encryption_proofs::single_property_verifier,
        wellformedness_proof::{
            WellformednessProof, WellformednessProverAwaitingChallenge, WellformednessVerifier,
        },
    },
    errors::{ErrorKind, Fallible},
    mercat::{
        AssetMemo, AssetTransactionIssuer, AssetTransactionMediator, AssetTransactionVerifier,
        AssetTxContent, AssetTxState, CipherEqualDifferentPubKeyProof, EncryptionKeys,
        EncryptionPubKey, InitializedAssetTx, JustifiedAssetTx, PubAccount, SecAccount,
        SigningKeys, SigningPubKey, TxSubstate,
    },
    Balance,
};

use bulletproofs::PedersenGens;
use codec::Encode;
use lazy_static::lazy_static;
use rand_core::{CryptoRng, RngCore};
use schnorrkel::{context::SigningContext, signing_context};
use zeroize::Zeroizing;

lazy_static! {
    static ref SIG_CTXT: SigningContext = signing_context(b"mercat/assert");
}

/// Helper function to verify the proofs on an asset initialization transaction.
fn asset_issuance_init_verify(
    asset_tx: &InitializedAssetTx,
    issr_pub_account: &PubAccount,
    mdtr_enc_pub_key: &EncryptionPubKey,
) -> Fallible<()> {
    let gens = PedersenGens::default();

    // Verify the signature on the transaction.
    let message = asset_tx.content.encode();
    issr_pub_account
        .content
        .memo
        .owner_sign_pub_key
        .verify(SIG_CTXT.bytes(&message), &asset_tx.sig)?;

    // Verify the proof of encrypting the same asset type as the account type.
    single_property_verifier(
        &EncryptingSameValueVerifier {
            pub_key1: issr_pub_account.content.memo.owner_enc_pub_key,
            pub_key2: mdtr_enc_pub_key.clone(),
            cipher1: issr_pub_account.content.enc_asset_id,
            cipher2: asset_tx.content.enc_asset_id,
            pc_gens: &gens,
        },
        asset_tx.content.asset_id_equal_cipher_proof.init,
        asset_tx.content.asset_id_equal_cipher_proof.response,
    )?;

    // Verify the proof of memo's wellformedness.
    single_property_verifier(
        &WellformednessVerifier {
            pub_key: issr_pub_account.content.memo.owner_enc_pub_key,
            cipher: asset_tx.content.memo,
            pc_gens: &gens,
        },
        asset_tx.content.balance_wellformedness_proof.init,
        asset_tx.content.balance_wellformedness_proof.response,
    )?;

    Ok(())
}

// -------------------------------------------------------------------------------------
// -                                    Issuer                                         -
// -------------------------------------------------------------------------------------

/// The confidential transaction issuer issues an asset for an issuer account, and
/// encrypts the metadata to the mediator's public key.
pub struct CtxIssuer {}

impl AssetTransactionIssuer for CtxIssuer {
    fn initialize<T: RngCore + CryptoRng>(
        &self,
        issr_account_id: u32,
        issr_account: &SecAccount,
        mdtr_pub_key: &EncryptionPubKey,
        amount: Balance,
        rng: &mut T,
    ) -> Fallible<(InitializedAssetTx, AssetTxState)> {
        let gens = PedersenGens::default();

        // Encrypt the asset_id with mediator's public key.
        let mdtr_enc_asset_id = mdtr_pub_key.encrypt(&issr_account.asset_id_witness);

        // Encrypt the balance issued to mediator's public key.
        let (_, mdtr_enc_amount) = mdtr_pub_key.encrypt_value(amount.into(), rng);

        // Encrypt the balance to issuer's public key (memo).
        let (issr_amount_witness, issr_enc_amount) =
            issr_account.enc_keys.pblc.encrypt_value(amount.into(), rng);
        let memo = AssetMemo::from(issr_enc_amount);

        // Proof of encrypting the same asset type as the account type.
        let same_asset_id_cipher_proof =
            CipherEqualDifferentPubKeyProof::from(single_property_prover(
                EncryptingSameValueProverAwaitingChallenge {
                    pub_key1: issr_account.enc_keys.pblc,
                    pub_key2: mdtr_pub_key.clone(),
                    w: Zeroizing::new(issr_account.asset_id_witness.clone()),
                    pc_gens: &gens,
                },
                rng,
            )?);

        // Proof of memo's wellformedness.
        let memo_wellformedness_proof = WellformednessProof::from(single_property_prover(
            WellformednessProverAwaitingChallenge {
                pub_key: issr_account.enc_keys.pblc,
                w: Zeroizing::new(issr_amount_witness.clone()),
                pc_gens: &gens,
            },
            rng,
        )?);

        // Proof of memo's correctness.
        let memo_correctness_proof = CorrectnessProof::from(single_property_prover(
            CorrectnessProverAwaitingChallenge {
                pub_key: issr_account.enc_keys.pblc,
                w: issr_amount_witness,
                pc_gens: &gens,
            },
            rng,
        )?);

        // Bundle the issuance data.
        let content = AssetTxContent {
            account_id: issr_account_id,
            enc_asset_id: mdtr_enc_asset_id.into(),
            enc_amount: mdtr_enc_amount.into(),
            memo: memo,
            asset_id_equal_cipher_proof: same_asset_id_cipher_proof,
            balance_wellformedness_proof: memo_wellformedness_proof,
            balance_correctness_proof: memo_correctness_proof,
        };

        // Sign the issuance content.
        let message = content.encode();
        let sig = issr_account.sign_keys.sign(SIG_CTXT.bytes(&message));

        Ok((
            InitializedAssetTx { content, sig },
            AssetTxState::Initialization(TxSubstate::Started),
        ))
    }
}

// -------------------------------------------------------------------------------------
// -                                    Validator                                      -
// -------------------------------------------------------------------------------------

pub struct AssetTxIssueValidator {}

/// Called by validators to verify the ZKP of the wellformedness of encrypted balance
/// and to verify the signature.
fn verify_initialization(
    asset_tx: &InitializedAssetTx,
    state: AssetTxState,
    issr_pub_account: &PubAccount,
    mdtr_enc_pub_key: &EncryptionPubKey,
) -> Fallible<AssetTxState> {
    // Validate the state.
    ensure!(
        state == AssetTxState::Initialization(TxSubstate::Started),
        ErrorKind::InvalidPreviousAssetTransactionState { state }
    );

    asset_issuance_init_verify(asset_tx, issr_pub_account, mdtr_enc_pub_key)?;

    Ok(AssetTxState::Initialization(TxSubstate::Validated))
}

impl AssetTransactionVerifier for AssetTxIssueValidator {
    /// Called by validators to verify the justification and processing of the transaction.
    fn verify(
        &self,
        asset_tx: &JustifiedAssetTx,
        issr_account: &PubAccount,
        mdtr_enc_pub_key: &EncryptionPubKey,
        mdtr_sign_pub_key: &SigningPubKey,
    ) -> Fallible<AssetTxState> {
        // Verify mediator's signature on the transaction.
        let message = asset_tx.content.encode();
        let _ = mdtr_sign_pub_key.verify(SIG_CTXT.bytes(&message), &asset_tx.sig)?;

        // Verify issuer's initialization proofs and signature.
        let asset_tx = asset_tx.content.clone();
        verify_initialization(
            &asset_tx,
            AssetTxState::Initialization(TxSubstate::Started),
            issr_account,
            mdtr_enc_pub_key,
        )?;

        Ok(AssetTxState::Justification(TxSubstate::Validated))
    }
}

// -------------------------------------------------------------------------------------
// -                                    Mediator                                       -
// -------------------------------------------------------------------------------------

pub struct AssetTxIssueMediator {}

impl AssetTransactionMediator for AssetTxIssueMediator {
    /// Justifies and processes a confidential asset issue transaction. This method is called
    /// by mediator. Corresponds to `JustifyAssetTx` and `ProcessCTx` of MERCAT paper.
    /// If the trasaction is justified, it will be processed immediately.
    fn justify(
        &self,
        asset_tx: InitializedAssetTx,
        issr_pub_account: &PubAccount,
        state: AssetTxState,
        mdtr_enc_keys: &EncryptionKeys,
        mdtr_sign_keys: &SigningKeys,
    ) -> Fallible<(JustifiedAssetTx, PubAccount)> {
        let gens = PedersenGens::default();

        // Validate the state.
        ensure!(
            state == AssetTxState::Initialization(TxSubstate::Started),
            ErrorKind::InvalidPreviousAssetTransactionState { state }
        );

        // Mediator revalidates all proofs.
        asset_issuance_init_verify(&asset_tx, issr_pub_account, &mdtr_enc_keys.pblc)?;

        // Mediator decrypts the encrypted amount and uses it to verify the correctness proof.
        let amount = mdtr_enc_keys.scrt.decrypt(&asset_tx.content.enc_amount)?;

        single_property_verifier(
            &CorrectnessVerifier {
                value: amount.into(),
                pub_key: issr_pub_account.content.memo.owner_enc_pub_key,
                cipher: asset_tx.content.memo,
                pc_gens: &gens,
            },
            asset_tx.content.balance_correctness_proof.init,
            asset_tx.content.balance_correctness_proof.response,
        )?;

        // After successfully justifying the transaction, mediator deposits the amount
        // to issuer's account (aka processing phase).
        let mut updated_issr_account = issr_pub_account.clone();
        updated_issr_account.content.enc_balance += asset_tx.content.memo;

        // On successful justification, mediator transitions the state.
        let message = asset_tx.encode();
        let sig = mdtr_sign_keys.sign(SIG_CTXT.bytes(&message));

        Ok((
            JustifiedAssetTx {
                content: asset_tx,
                sig,
            },
            updated_issr_account,
        ))
    }
}

// ------------------------------------------------------------------------
// Tests
// ------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    extern crate wasm_bindgen_test;
    use super::*;
    use crate::{
        asset_proofs::{
            correctness_proof::CorrectnessProof, membership_proof::MembershipProof,
            CommitmentWitness, ElgamalSecretKey,
        },
        mercat::{
            AccountMemo, EncryptedAmount, EncryptedAssetId, EncryptionKeys, PubAccountContent,
            SecAccount, Signature,
        },
        AssetId,
    };
    use curve25519_dalek::scalar::Scalar;
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use schnorrkel::{ExpansionMode, MiniSecretKey};
    use wasm_bindgen_test::*;

    #[test]
    #[wasm_bindgen_test]
    fn asset_issuance_and_validation() {
        // ----------------------- Setup
        let mut rng = StdRng::from_seed([10u8; 32]);
        let issued_amount: Balance = 20u32.into();

        // Generate keys for the issuer.
        let issuer_elg_secret_key = ElgamalSecretKey::new(Scalar::random(&mut rng));
        let issuer_enc_key = EncryptionKeys {
            pblc: issuer_elg_secret_key.get_public_key().into(),
            scrt: issuer_elg_secret_key.into(),
        };
        let sign_keys = schnorrkel::Keypair::generate_with(&mut rng);
        let asset_id = AssetId::from(1);

        let issuer_secret_account = SecAccount {
            enc_keys: issuer_enc_key.clone(),
            sign_keys: sign_keys.clone(),
            asset_id: asset_id.clone(),
            asset_id_witness: CommitmentWitness::from((asset_id.clone().into(), &mut rng)),
        };

        let pub_account_enc_asset_id = EncryptedAssetId::from(
            issuer_enc_key
                .pblc
                .encrypt(&issuer_secret_account.asset_id_witness),
        );

        // Note that we use default proof values since we don't reverify these proofs during asset issuance.
        let issuer_public_account = PubAccount {
            content: PubAccountContent {
                id: 1,
                enc_asset_id: pub_account_enc_asset_id,
                // Set the initial encrypted balance to 0.
                enc_balance: EncryptedAmount::default(),
                asset_wellformedness_proof: WellformednessProof::default(),
                asset_membership_proof: MembershipProof::default(),
                initial_balance_correctness_proof: CorrectnessProof::default(),
                memo: AccountMemo::new(issuer_enc_key.pblc, sign_keys.public.into()),
            },
            initial_sig: Signature::from_bytes(&[128u8; 64]).expect("Invalid Schnorrkel signature"),
        };

        // Generate keys for the mediator.
        let mediator_elg_secret_key = ElgamalSecretKey::new(Scalar::random(&mut rng));
        let mediator_enc_key = EncryptionKeys {
            pblc: mediator_elg_secret_key.get_public_key().into(),
            scrt: mediator_elg_secret_key.into(),
        };

        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let mediator_signing_pair = MiniSecretKey::from_bytes(&seed)
            .expect("Invalid seed")
            .expand_to_keypair(ExpansionMode::Ed25519);

        // ----------------------- Initialization
        let issuer = CtxIssuer {};
        let (asset_tx, state) = issuer
            .initialize(
                1234u32,
                &issuer_secret_account,
                &mediator_enc_key.pblc,
                issued_amount,
                &mut rng,
            )
            .unwrap();

        // ----------------------- Justification
        let mediator = AssetTxIssueMediator {};
        let (justified_tx, updated_issuer_account) = mediator
            .justify(
                asset_tx.clone(),
                &issuer_public_account,
                state,
                &mediator_enc_key,
                &mediator_signing_pair,
            )
            .unwrap();

        // Positive test.
        let validator = AssetTxIssueValidator {};
        let state = validator
            .verify(
                &justified_tx,
                &updated_issuer_account,
                &mediator_enc_key.pblc,
                &mediator_signing_pair.public.into(),
            )
            .unwrap();
        assert_eq!(state, AssetTxState::Justification(TxSubstate::Validated));

        // Negative tests.
        // Invalid issuer signature.
        let mut invalid_tx = asset_tx.clone();
        invalid_tx.sig = Signature::from_bytes(&[128u8; 64]).expect("Invalid Schnorrkel signature");

        let result = mediator.justify(
            invalid_tx,
            &issuer_public_account,
            AssetTxState::Initialization(TxSubstate::Started),
            &mediator_enc_key,
            &mediator_signing_pair,
        );
        assert_err!(result, ErrorKind::SignatureValidationFailure);

        // Negative test.
        // Invalid mediator signature.
        let mut invalid_justified_tx = justified_tx.clone();
        invalid_justified_tx.sig =
            Signature::from_bytes(&[128u8; 64]).expect("Invalid Schnorrkel signature");

        let result = validator.verify(
            &invalid_justified_tx,
            &updated_issuer_account,
            &mediator_enc_key.pblc,
            &mediator_signing_pair.public.into(),
        );
        assert_err!(result, ErrorKind::SignatureValidationFailure);

        // Invalid issuer signature.
        let mut invalid_justified_tx = justified_tx.clone();
        invalid_justified_tx.content.sig =
            Signature::from_bytes(&[128u8; 64]).expect("Invalid Schnorrkel signature");

        let result = validator.verify(
            &invalid_justified_tx,
            &updated_issuer_account,
            &mediator_enc_key.pblc,
            &mediator_signing_pair.public.into(),
        );
        assert_err!(result, ErrorKind::SignatureValidationFailure);

        // ----------------------- Processing
        // Check that the issued amount is added to the account balance.
        assert!(issuer_enc_key
            .scrt
            .verify(
                &updated_issuer_account.content.enc_balance,
                &Scalar::from(issued_amount)
            )
            .is_ok());

        // Check that the asset_id is still the same.
        assert_eq!(
            updated_issuer_account.content.enc_asset_id,
            pub_account_enc_asset_id
        );
    }
}
