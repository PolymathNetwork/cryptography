use crate::{
    asset_proofs::{
        ciphertext_refreshment_proof::CipherTextRefreshmentProverAwaitingChallenge,
        ciphertext_refreshment_proof::CipherTextRefreshmentVerifier,
        encrypt_using_two_pub_keys,
        encrypting_same_value_proof::EncryptingSameValueProverAwaitingChallenge,
        encrypting_same_value_proof::EncryptingSameValueVerifier,
        encryption_proofs::single_property_prover,
        encryption_proofs::single_property_verifier,
        range_proof::{prove_within_range, verify_within_range, RangeProofInitialMessage},
        CommitmentWitness,
    },
    errors::{ErrorKind, Fallible},
    mercat::{
        CipherEqualDifferentPubKeyProof, CipherEqualSamePubKeyProof,
        ConfidentialTransactionInitVerifier, ConfidentialTransactionReceiver,
        ConfidentialTransactionSender, ConfidentialTxMemo, ConfidentialTxState, EncryptedAssetId,
        EncryptionKeys, EncryptionPubKey, EncryptionSecKey, InRangeProof, PubAccount,
        PubFinalConfidentialTxData, PubFinalConfidentialTxDataContent, PubInitConfidentialTxData,
        PubInitConfidentialTxDataContent, SignatureKeys, SignaturePubKey, TxSubstate,
    },
};
use curve25519_dalek::scalar::Scalar;
use rand::rngs::StdRng;
use sp_application_crypto::sr25519;
use sp_core::crypto::Pair;
use std::convert::TryFrom;
use zeroize::Zeroizing;

// -------------------------------------------------------------------------------------
// -                                    Sender                                         -
// -------------------------------------------------------------------------------------

/// The sender of a confidential transaction. Sender creates a transaction
/// and performs initial proofs.
pub struct CtxSender {}

impl ConfidentialTransactionSender for CtxSender {
    fn create(
        &self,
        sndr_enc_keys: EncryptionKeys,
        sndr_sign_keys: SignatureKeys,
        sndr_account: PubAccount,
        rcvr_pub_key: EncryptionPubKey,
        rcvr_account: PubAccount,
        asset_id: u32,
        amount: u32,
        rng: &mut StdRng,
    ) -> Fallible<(PubInitConfidentialTxData, ConfidentialTxState)> {
        // NOTE: If this decryption ends up being too slow, we can pass in the balance
        // as input.
        let balance = sndr_enc_keys.scrt.key.decrypt(&sndr_account.enc_balance)?;
        ensure!(
            balance >= amount,
            ErrorKind::NotEnoughFund {
                balance,
                transaction_amount: amount
            }
        );

        let range = 32;
        // Prove that the amount encrypted under different public keys are the same
        let witness = CommitmentWitness::try_from((amount, Scalar::random(rng)))?;
        let amount_enc_blinding = *witness.blinding();
        let (sndr_new_enc_amount, rcvr_new_enc_amount) =
            encrypt_using_two_pub_keys(&witness, sndr_enc_keys.pblc.key, rcvr_pub_key.key);

        let amount_equal_cipher_proof =
            CipherEqualDifferentPubKeyProof::from(single_property_prover(
                EncryptingSameValueProverAwaitingChallenge {
                    pub_key1: sndr_enc_keys.pblc.key,
                    pub_key2: rcvr_pub_key.key,
                    w: Zeroizing::new(witness.clone()),
                },
                rng,
            )?);

        // Prove that committed amount is not negative
        let non_neg_amount_proof = InRangeProof {
            init: RangeProofInitialMessage(sndr_new_enc_amount.y.compress()),
            response: prove_within_range(amount.into(), amount_enc_blinding, range)?.1,
            range,
        };

        // Refresh the encrypted balance and prove that the refreshment was done
        // correctly
        let balance_refresh_enc_blinding = Scalar::random(rng);
        let refreshed_enc_balance = sndr_account
            .enc_balance
            .refresh(&sndr_enc_keys.scrt.key, balance_refresh_enc_blinding)?;
        let balance_refreshed_same_proof =
            CipherEqualSamePubKeyProof::from(single_property_prover(
                CipherTextRefreshmentProverAwaitingChallenge::new(
                    sndr_enc_keys.scrt.key.clone(),
                    sndr_account.enc_balance,
                    refreshed_enc_balance,
                ),
                rng,
            )?);

        // Prove that sender has enough funds
        let blinding = balance_refresh_enc_blinding - amount_enc_blinding;
        let enough_fund_proof = InRangeProof::from(prove_within_range(
            (balance - amount).into(),
            blinding,
            range,
        )?);

        // Refresh the encrypted asset id of the sender account and prove that the
        // refreshment was done correctly
        let asset_id_refresh_enc_blinding = Scalar::random(rng);
        let refreshed_enc_asset_id = sndr_account
            .enc_asset_id
            .refresh(&sndr_enc_keys.scrt.key, asset_id_refresh_enc_blinding)?;
        let asset_id_refreshed_same_proof =
            CipherEqualSamePubKeyProof::from(single_property_prover(
                CipherTextRefreshmentProverAwaitingChallenge::new(
                    sndr_enc_keys.scrt.key.clone(),
                    sndr_account.enc_asset_id,
                    refreshed_enc_asset_id,
                ),
                rng,
            )?);

        // Prove the new refreshed encrytped asset id is the same as the one
        // encrypted by the receiver's pub key
        let asset_id_witness =
            CommitmentWitness::try_from((asset_id, asset_id_refresh_enc_blinding))?;
        let enc_asset_id_using_rcvr = rcvr_pub_key.key.encrypt(&asset_id_witness);
        let asset_id_equal_cipher_proof =
            CipherEqualDifferentPubKeyProof::from(single_property_prover(
                EncryptingSameValueProverAwaitingChallenge {
                    pub_key1: sndr_enc_keys.pblc.key,
                    pub_key2: rcvr_pub_key.key,
                    w: Zeroizing::new(asset_id_witness),
                },
                rng,
            )?);

        // ------- gather the content and sign it
        let content = PubInitConfidentialTxDataContent {
            amount_equal_cipher_proof,
            non_neg_amount_proof,
            enough_fund_proof,
            asset_id_equal_cipher_proof,
            balance_refreshed_same_proof,
            asset_id_refreshed_same_proof,
            memo: ConfidentialTxMemo {
                sndr_account_id: sndr_account.id,
                rcvr_account_id: rcvr_account.id,
                enc_amount_using_sndr: sndr_new_enc_amount,
                enc_amount_using_rcvr: rcvr_new_enc_amount,
                sndr_pub_key: sndr_enc_keys.pblc,
                rcvr_pub_key: rcvr_pub_key,
                refreshed_enc_balance,
                refreshed_enc_asset_id,
                enc_asset_id_using_rcvr,
            },
        };

        let sig = sndr_sign_keys.pair.sign(&content.to_bytes()?);

        Ok((
            PubInitConfidentialTxData { content, sig },
            ConfidentialTxState::Initialization(TxSubstate::Started),
        ))
    }
}

// ------------------------------------------------------------------------------------------------
// -                                          Receiver                                            -
// ------------------------------------------------------------------------------------------------

/// The receiver of a confidential transaction. Receiver finalizes and processes
/// transaction.
pub struct CtxReceiver {}

impl ConfidentialTransactionReceiver for CtxReceiver {
    fn finalize_and_process(
        &self,
        conf_tx_init_data: PubInitConfidentialTxData,
        rcvr_enc_keys: (EncryptionPubKey, EncryptionSecKey),
        rcvr_sign_keys: SignatureKeys,
        sndr_pub_key: EncryptionPubKey,
        sndr_account: PubAccount,
        rcvr_account: PubAccount,
        enc_asset_id: EncryptedAssetId,
        amount: u32,
        state: ConfidentialTxState,
        rng: &mut StdRng,
    ) -> Fallible<(PubFinalConfidentialTxData, ConfidentialTxState)> {
        self.finalize_by_receiver(
            conf_tx_init_data,
            rcvr_enc_keys.1,
            rcvr_sign_keys,
            rcvr_account,
            state,
            amount,
            rng,
        )?;

        // TODO: will complete this in the ctx processing story
        //ensure!(false, ErrorKind::NotImplemented)
        Err(ErrorKind::NotImplemented.into())
    }
}

impl CtxReceiver {
    /// This function is called by the receiver of the transaction to finalize the
    /// transaction. It corresponds to `FinalizeCTX` function of the MERCAT paper.
    pub fn finalize_by_receiver(
        &self,
        conf_tx_init_data: PubInitConfidentialTxData,
        rcvr_enc_sec: EncryptionSecKey,
        rcvr_sign_keys: SignatureKeys,
        rcvr_account: PubAccount,
        state: ConfidentialTxState,
        expected_amount: u32,
        rng: &mut StdRng,
    ) -> Fallible<(PubFinalConfidentialTxData, ConfidentialTxState)> {
        ensure!(
            state == ConfidentialTxState::InitilaziationJustification(TxSubstate::Verified),
            ErrorKind::InvalidPreviousState { state }
        );

        // Check that amount is correct
        let received_amount = rcvr_enc_sec
            .key
            .decrypt(&conf_tx_init_data.content.memo.enc_amount_using_rcvr)?;

        ensure!(
            received_amount == expected_amount,
            ErrorKind::TransactionAmountMismatch {
                expected_amount,
                received_amount
            }
        );

        // Check rcvc public keys match
        let acc_key = conf_tx_init_data.content.memo.rcvr_pub_key.key;
        let memo_key = rcvr_account.memo.owner_enc_pub_key.key;
        ensure!(acc_key == memo_key, ErrorKind::InputPubKeyMismatch);

        // Generate proof of equality of asset ids
        let enc_asset_id_from_sndr = conf_tx_init_data.content.memo.enc_asset_id_using_rcvr;
        let enc_asset_id_from_rcvr_acc = rcvr_account.enc_asset_id;
        let prover = CipherTextRefreshmentProverAwaitingChallenge::new(
            rcvr_enc_sec.key,
            enc_asset_id_from_rcvr_acc,
            enc_asset_id_from_sndr,
        );

        let (init, response) = single_property_prover(prover, rng)?;

        // gather the content and sign it
        let content = PubFinalConfidentialTxDataContent {
            init_data: conf_tx_init_data,
            asset_id_equal_cipher_proof: CipherEqualSamePubKeyProof { init, response },
        };

        let sig = rcvr_sign_keys.pair.sign(&content.to_bytes()?);
        Ok((
            PubFinalConfidentialTxData { content, sig },
            ConfidentialTxState::Finalization(TxSubstate::Started),
        ))
    }
}

// ------------------------------------------------------------------------------------------------
// -                                          Validator                                           -
// ------------------------------------------------------------------------------------------------

fn verify_initital_transaction_proofs(
    transaction: PubInitConfidentialTxData,
    sndr_account: PubAccount,
) -> Fallible<()> {
    let memo = &transaction.content.memo;
    let init_data = &transaction.content;

    ensure!(
        sndr_account.id == memo.sndr_account_id,
        ErrorKind::AccountIdMismatch
    );

    // Verify encrypted amounts are equal
    single_property_verifier(
        &EncryptingSameValueVerifier {
            pub_key1: memo.sndr_pub_key.key,
            pub_key2: memo.rcvr_pub_key.key,
            cipher1: memo.enc_amount_using_sndr,
            cipher2: memo.enc_amount_using_rcvr,
        },
        init_data.amount_equal_cipher_proof.init,
        init_data.amount_equal_cipher_proof.response,
    )?;

    // Verify that amount is not negative
    verify_within_range(
        init_data.non_neg_amount_proof.clone().init,
        init_data.non_neg_amount_proof.clone().response,
        init_data.non_neg_amount_proof.range,
    )?;

    // verify the balance refreshment was done correctly
    single_property_verifier(
        &CipherTextRefreshmentVerifier::new(
            memo.sndr_pub_key.key,
            sndr_account.enc_balance,
            memo.refreshed_enc_balance,
        ),
        init_data.balance_refreshed_same_proof.init,
        init_data.balance_refreshed_same_proof.response,
    )?;

    // Verify that balance has enough fund
    verify_within_range(
        init_data.enough_fund_proof.clone().init,
        init_data.enough_fund_proof.clone().response,
        init_data.enough_fund_proof.range,
    )?;

    // verify the asset id refreshment was done correctly
    single_property_verifier(
        &CipherTextRefreshmentVerifier::new(
            memo.sndr_pub_key.key,
            sndr_account.enc_asset_id,
            memo.refreshed_enc_asset_id,
        ),
        init_data.asset_id_refreshed_same_proof.init,
        init_data.asset_id_refreshed_same_proof.response,
    )?;

    // In the inital transaction, sender has encrypted the sset id
    // using receiver pub key. We verify that this encrypted asset id
    // is the same as the one in the sender account.
    single_property_verifier(
        &EncryptingSameValueVerifier {
            pub_key1: memo.sndr_pub_key.key,
            pub_key2: memo.rcvr_pub_key.key,
            cipher1: memo.refreshed_enc_asset_id,
            cipher2: memo.enc_asset_id_using_rcvr,
        },
        init_data.asset_id_equal_cipher_proof.init,
        init_data.asset_id_equal_cipher_proof.response,
    )?;
    Ok(())
}

/// Verifies the initial transaction.
pub struct CtxSenderValidator {}

impl ConfidentialTransactionInitVerifier for CtxSenderValidator {
    fn verify(
        &self,
        transaction: PubInitConfidentialTxData,
        sndr_account: PubAccount,
        sndr_sign_pub_key: SignaturePubKey,
        state: ConfidentialTxState,
    ) -> Fallible<ConfidentialTxState> {
        ensure!(
            state == ConfidentialTxState::Initialization(TxSubstate::Started),
            ErrorKind::InvalidPreviousState { state }
        );
        ensure!(
            sr25519::Pair::verify(
                &transaction.sig,
                &transaction.content.to_bytes()?,
                &sndr_sign_pub_key.key
            ),
            ErrorKind::SignatureValidationFailure
        );
        verify_initital_transaction_proofs(transaction, sndr_account)?;
        Ok(ConfidentialTxState::Initialization(TxSubstate::Verified))
    }
}

/// Verifies the proofs that are performed by both the Sender and the Receiver of a
/// confidential transaction.
pub struct CtxReceiverValidator {}

impl CtxReceiverValidator {
    pub fn verify_finalize_by_receiver(
        &self,
        sndr_account: PubAccount,
        rcvr_account: PubAccount,
        conf_tx_final_data: PubFinalConfidentialTxData,
        state: ConfidentialTxState,
    ) -> Fallible<()> {
        ensure!(
            state == ConfidentialTxState::Finalization(TxSubstate::Started),
            ErrorKind::InvalidPreviousState { state }
        );

        let memo = &conf_tx_final_data.content.init_data.content.memo;
        let init_data = conf_tx_final_data.content.init_data.clone();
        let final_content = &conf_tx_final_data.content;

        verify_initital_transaction_proofs(init_data, sndr_account)?;

        // In the inital transaction, sender has encrypted the asset id
        // using receiver pub key.We verify that this encrypted asset id
        // is the same as the one in the receiver account
        single_property_verifier(
            &CipherTextRefreshmentVerifier::new(
                memo.rcvr_pub_key.key,
                rcvr_account.enc_asset_id,
                memo.enc_asset_id_using_rcvr,
            ),
            final_content.asset_id_equal_cipher_proof.init,
            final_content.asset_id_equal_cipher_proof.response,
        )?;

        ensure!(
            sr25519::Pair::verify(
                &conf_tx_final_data.sig,
                &conf_tx_final_data.content.to_bytes()?,
                &rcvr_account.memo.owner_sign_pub_key.key,
            ),
            ErrorKind::SignatureValidationFailure
        );

        Ok(())
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
        asset_proofs::{CipherText, ElgamalSecretKey},
        mercat::{
            AccountMemo, ConfidentialTxMemo, CorrectnessProof, EncryptionKeys, EncryptionPubKey,
            MembershipProof, Signature, SignatureKeys, WellformednessProof,
        },
    };
    use curve25519_dalek::scalar::Scalar;
    use rand::SeedableRng;
    use wasm_bindgen_test::*;

    // -------------------------- mock helper methods -----------------------

    fn mock_gen_enc_key_pair(seed: u8) -> EncryptionKeys {
        let mut rng = StdRng::from_seed([seed; 32]);
        let elg_secret = ElgamalSecretKey::new(Scalar::random(&mut rng));
        let elg_pub = elg_secret.get_public_key();
        EncryptionKeys {
            pblc: elg_pub.into(),
            scrt: elg_secret.into(),
        }
    }

    fn mock_gen_sign_key_pair(seed: u8) -> (SignatureKeys, SignaturePubKey) {
        let pair = sr25519::Pair::from_seed(&[seed; 32]);
        (
            SignatureKeys { pair: pair.clone() },
            SignaturePubKey::from(pair.public()),
        )
    }

    fn mock_ctx_init_memo(
        rcvr_pub_key: EncryptionPubKey,
        amount: u32,
        asset_id: u32,
    ) -> ConfidentialTxMemo {
        let enc_amount_using_rcvr = rcvr_pub_key.key.encrypt_value(amount).unwrap();
        let enc_asset_id_using_rcvr = rcvr_pub_key.key.encrypt_value(asset_id).unwrap();

        ConfidentialTxMemo {
            sndr_account_id: 0,
            rcvr_account_id: 0,
            enc_amount_using_sndr: CipherText::default(),
            enc_amount_using_rcvr,
            sndr_pub_key: EncryptionPubKey::default(),
            rcvr_pub_key,
            refreshed_enc_balance: CipherText::default(),
            refreshed_enc_asset_id: CipherText::default(),
            enc_asset_id_using_rcvr,
        }
    }

    fn mock_gen_account(
        rcvr_enc_pub_key: EncryptionPubKey,
        rcvr_sign_pub_key: SignaturePubKey,
        asset_id: u32,
        balance: u32,
    ) -> Fallible<PubAccount> {
        let enc_asset_id = rcvr_enc_pub_key.key.encrypt_value(asset_id)?;
        let enc_balance = rcvr_enc_pub_key.key.encrypt_value(balance)?;

        Ok(PubAccount {
            id: 1,
            enc_asset_id,
            enc_balance: enc_balance,
            asset_wellformedness_proof: WellformednessProof::default(),
            asset_membership_proof: MembershipProof::default(),
            balance_correctness_proof: CorrectnessProof::default(),
            memo: AccountMemo::from((rcvr_enc_pub_key, rcvr_sign_pub_key)),
            sign: Signature::default(),
        })
    }

    fn copy_mock_account(
        acc: &PubAccount,
        rcvr_enc_pub_key: EncryptionPubKey,
        rcvr_sign_pub_key: SignaturePubKey,
    ) -> PubAccount {
        PubAccount {
            id: acc.id,
            enc_asset_id: acc.enc_asset_id,
            enc_balance: acc.enc_balance,
            asset_wellformedness_proof: WellformednessProof::default(),
            asset_membership_proof: MembershipProof::default(),
            balance_correctness_proof: CorrectnessProof::default(),
            memo: AccountMemo::from((rcvr_enc_pub_key, rcvr_sign_pub_key)),
            sign: Signature::default(),
        }
    }

    fn mock_ctx_init_data(
        rcvr_pub_key: EncryptionPubKey,
        expected_amount: u32,
        asset_id: u32,
    ) -> PubInitConfidentialTxData {
        PubInitConfidentialTxData {
            content: PubInitConfidentialTxDataContent {
                memo: mock_ctx_init_memo(rcvr_pub_key, expected_amount, asset_id),
                asset_id_equal_cipher_proof: CipherEqualDifferentPubKeyProof::default(),
                amount_equal_cipher_proof: CipherEqualDifferentPubKeyProof::default(),
                non_neg_amount_proof: InRangeProof::default(),
                enough_fund_proof: InRangeProof::default(),
                balance_refreshed_same_proof: CipherEqualSamePubKeyProof::default(),
                asset_id_refreshed_same_proof: CipherEqualSamePubKeyProof::default(),
            },
            sig: Signature::default(),
        }
    }

    // -------------------------- tests -----------------------

    #[test]
    #[wasm_bindgen_test]
    fn test_finalize_ctx_success() {
        let ctx_rcvr = CtxReceiver {};
        let expected_amount = 10;
        let asset_id = 20;
        let balance = 0;

        let rcvr_enc_keys = mock_gen_enc_key_pair(17u8);
        let (rcvr_sign_keys, rcvr_sign_pub_key) = mock_gen_sign_key_pair(18u8);

        let ctx_init_data = mock_ctx_init_data(rcvr_enc_keys.pblc, expected_amount, asset_id);
        let rcvr_account =
            mock_gen_account(rcvr_enc_keys.pblc, rcvr_sign_pub_key, asset_id, balance).unwrap();
        let valid_state = ConfidentialTxState::InitilaziationJustification(TxSubstate::Verified);

        let result = ctx_rcvr.finalize_by_receiver(
            ctx_init_data,
            rcvr_enc_keys.scrt,
            rcvr_sign_keys,
            rcvr_account,
            valid_state,
            expected_amount,
            &mut StdRng::from_seed([17u8; 32]),
        );

        match result {
            Err(e) => assert!(false, "{:?}", e),
            _ => (),
        }
        // Correctness of the proof will be verified in the verify function
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_finalize_ctx_prev_state_error() {
        let ctx_rcvr = CtxReceiver {};
        let expected_amount = 10;
        let asset_id = 20;
        let balance = 0;

        let rcvr_enc_keys = mock_gen_enc_key_pair(17u8);
        let (rcvr_sign_keys, rcvr_sign_pub_key) = mock_gen_sign_key_pair(18u8);

        let ctx_init_data = mock_ctx_init_data(rcvr_enc_keys.pblc, expected_amount, asset_id);
        let rcvr_account =
            mock_gen_account(rcvr_enc_keys.pblc, rcvr_sign_pub_key, asset_id, balance).unwrap();
        let invalid_state = ConfidentialTxState::InitilaziationJustification(TxSubstate::Started);

        let result = ctx_rcvr.finalize_by_receiver(
            ctx_init_data,
            rcvr_enc_keys.scrt,
            rcvr_sign_keys,
            rcvr_account,
            invalid_state,
            expected_amount,
            &mut StdRng::from_seed([17u8; 32]),
        );

        assert_err!(
            result,
            ErrorKind::InvalidPreviousState {
                state: invalid_state,
            }
        );
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_finalize_ctx_amount_mismatch_error() {
        let ctx_rcvr = CtxReceiver {};
        let expected_amount = 10;
        let received_amount = 20;
        let asset_id = 20;
        let balance = 0;

        let rcvr_enc_keys = mock_gen_enc_key_pair(17u8);
        let (rcvr_sign_keys, rcvr_sign_pub_key) = mock_gen_sign_key_pair(18u8);

        let ctx_init_data = mock_ctx_init_data(rcvr_enc_keys.pblc, received_amount, asset_id);
        let rcvr_account =
            mock_gen_account(rcvr_enc_keys.pblc, rcvr_sign_pub_key, asset_id, balance).unwrap();
        let valid_state = ConfidentialTxState::InitilaziationJustification(TxSubstate::Verified);

        let result = ctx_rcvr.finalize_by_receiver(
            ctx_init_data,
            rcvr_enc_keys.scrt,
            rcvr_sign_keys,
            rcvr_account,
            valid_state,
            expected_amount,
            &mut StdRng::from_seed([17u8; 32]),
        );

        assert_err!(
            result,
            ErrorKind::TransactionAmountMismatch {
                expected_amount,
                received_amount
            }
        );
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_finalize_ctx_pub_key_mismatch_error() {
        let ctx_rcvr = CtxReceiver {};
        let expected_amount = 10;
        let asset_id = 20;
        let balance = 0;

        let rcvr_enc_keys = mock_gen_enc_key_pair(17u8);
        let wrong_enc_keys = mock_gen_enc_key_pair(18u8);
        let (rcvr_sign_keys, rcvr_sign_pub_key) = mock_gen_sign_key_pair(18u8);

        let ctx_init_data = mock_ctx_init_data(rcvr_enc_keys.pblc, expected_amount, asset_id);
        let rcvr_account =
            mock_gen_account(wrong_enc_keys.pblc, rcvr_sign_pub_key, asset_id, balance).unwrap();
        let valid_state = ConfidentialTxState::InitilaziationJustification(TxSubstate::Verified);

        let result = ctx_rcvr.finalize_by_receiver(
            ctx_init_data,
            rcvr_enc_keys.scrt,
            rcvr_sign_keys,
            rcvr_account,
            valid_state,
            expected_amount,
            &mut StdRng::from_seed([17u8; 32]),
        );

        assert_err!(result, ErrorKind::InputPubKeyMismatch);
    }

    // ------------------------------ Test simple scenarios

    #[test]
    #[wasm_bindgen_test]
    fn test_ctx_create_finalize_validate_success() {
        let sndr = CtxSender {};
        let rcvr = CtxReceiver {};
        let sndr_vldtr = CtxSenderValidator {};
        let rcvr_vldtr = CtxReceiverValidator {};
        let asset_id = 20;
        let sndr_balance = 40;
        let rcvr_balance = 0;
        let amount = 30;

        let mut rng = StdRng::from_seed([17u8; 32]);

        let sndr_enc_keys = mock_gen_enc_key_pair(10u8);
        let (sndr_sign_keys, sndr_sign_pub_key) = mock_gen_sign_key_pair(11u8);

        let rcvr_enc_keys = mock_gen_enc_key_pair(12u8);
        let (rcvr_sign_keys, rcvr_sign_pub_key) = mock_gen_sign_key_pair(13u8);

        let rcvr_account = mock_gen_account(
            rcvr_enc_keys.pblc,
            rcvr_sign_pub_key.clone(),
            asset_id,
            rcvr_balance,
        )
        .unwrap();
        let rcvr_account_for_initialize =
            copy_mock_account(&rcvr_account, rcvr_enc_keys.pblc, rcvr_sign_pub_key.clone());
        let rcvr_account_for_finalize =
            copy_mock_account(&rcvr_account, rcvr_enc_keys.pblc, rcvr_sign_pub_key.clone());
        let rcvr_account_for_validation =
            copy_mock_account(&rcvr_account, rcvr_enc_keys.pblc, rcvr_sign_pub_key);

        let sndr_account = mock_gen_account(
            sndr_enc_keys.pblc,
            sndr_sign_pub_key.clone(),
            asset_id,
            sndr_balance,
        )
        .unwrap();
        let sndr_account_for_initialize =
            copy_mock_account(&sndr_account, sndr_enc_keys.pblc, sndr_sign_pub_key.clone());
        let sndr_account_for_validation =
            copy_mock_account(&sndr_account, sndr_enc_keys.pblc, sndr_sign_pub_key);

        // Create the trasaction and check its result and state
        let result = sndr.create(
            sndr_enc_keys,
            sndr_sign_keys.clone(),
            sndr_account_for_initialize,
            rcvr_enc_keys.pblc,
            rcvr_account_for_initialize,
            asset_id,
            amount,
            &mut rng,
        );
        let (ctx_init_data, state) = result.unwrap();
        assert_eq!(
            state,
            ConfidentialTxState::Initialization(TxSubstate::Started)
        );

        // Verify the initialization step
        let result = sndr_vldtr.verify(
            ctx_init_data.clone(),
            sndr_account,
            SignaturePubKey {
                key: sndr_sign_keys.pair.public(),
            },
            state,
        );
        let state = result.unwrap();
        assert_eq!(
            state,
            ConfidentialTxState::Initialization(TxSubstate::Verified)
        );

        // TODO: skipping the mediator step. Therefore assuming that it has passed.
        let state = ConfidentialTxState::InitilaziationJustification(TxSubstate::Verified);

        // Finalize the transaction and check its state
        let result = rcvr.finalize_by_receiver(
            ctx_init_data,
            rcvr_enc_keys.scrt,
            rcvr_sign_keys,
            rcvr_account_for_finalize,
            state,
            amount,
            &mut rng,
        );
        let (ctx_finalized_data, finalized_state) = result.unwrap();
        assert_eq!(
            finalized_state,
            ConfidentialTxState::Finalization(TxSubstate::Started)
        );

        // verify the finalization step
        let result = rcvr_vldtr.verify_finalize_by_receiver(
            sndr_account_for_validation,
            rcvr_account_for_validation,
            ctx_finalized_data,
            finalized_state,
        );
        result.unwrap();
    }

    // TODO other test cases
    // 1. balance less than amount
}
