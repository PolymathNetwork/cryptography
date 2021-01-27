use codec::{Decode, Encode};
use mercat::{
    account::{convert_asset_ids, AccountCreator},
    asset::AssetIssuer,
    cryptography_core::{
        asset_proofs::{CipherText, CommitmentWitness, ElgamalPublicKey, ElgamalSecretKey},
        curve25519_dalek::scalar::Scalar,
        AssetId,
    },
    transaction::{CtxMediator, CtxReceiver, CtxSender},
    Account as MercatAccount, AccountCreatorInitializer, AssetTransactionIssuer, EncryptedAmount,
    EncryptionKeys, FinalizedTransferTx, InitializedAssetTx, InitializedTransferTx,
    MediatorAccount as MercatMediatorAccount, PubAccount as MercatPubAccount, PubAccountTx,
    SecAccount, TransferTransactionMediator, TransferTransactionReceiver,
    TransferTransactionSender,
};
use rand_core::OsRng;
use serde::Serialize;
use serde_json;
use std::convert::Into;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsValue;

// ------------------------------------------------------------------------------------
// -                                  Type Definitions                                -
// ------------------------------------------------------------------------------------

/// A base64 encoded string.
pub type Base64 = String;

/// Contains the secret and public account information of a party.
#[wasm_bindgen]
pub struct CreateAccountOutput {
    secret_account: Base64,
    public_key: Base64,
    account_id: Base64,
    account_tx: Base64,
}

#[wasm_bindgen]
impl CreateAccountOutput {
    /// The secret account must be kept confidential and not shared with anyone else.
    #[wasm_bindgen(getter)]
    pub fn secret_account(&self) -> Base64 {
        self.secret_account.clone()
    }

    /// The public cryptographic key of the account.
    #[wasm_bindgen(getter)]
    pub fn public_key(&self) -> Base64 {
        self.public_key.clone()
    }

    /// The account id. The account id is the same as the encrypted ticker id.
    #[wasm_bindgen(getter)]
    pub fn account_id(&self) -> Base64 {
        self.account_id.clone()
    }

    /// The Zero Knowledge proofs of the account creation.
    #[wasm_bindgen(getter)]
    pub fn account_tx(&self) -> Base64 {
        self.account_tx.clone()
    }

    pub fn account(&self) -> Account {
        Account::new(
            self.secret_account(),
            PubAccount::new(self.account_id(), self.public_key()),
        )
    }
}

/// Contains the secret and public account information of a mediator.
#[wasm_bindgen]
pub struct CreateMediatorAccountOutput {
    secret_account: MediatorAccount,
    public_key: Base64,
}

#[wasm_bindgen]
impl CreateMediatorAccountOutput {
    /// The secret account must be kept confidential and not shared with anyone else.
    #[wasm_bindgen(getter)]
    pub fn secret_account(&self) -> MediatorAccount {
        MediatorAccount {
            secret: self.secret_account.secret.clone(),
        }
    }

    /// The public cryptographic key of the account.
    #[wasm_bindgen(getter)]
    pub fn public_key(&self) -> Base64 {
        self.public_key.clone()
    }
}

/// Contains the Zero Knowledge Proof of minting an asset by the issuer.
#[wasm_bindgen]
pub struct MintAssetOutput {
    asset_tx: Base64,
}

#[wasm_bindgen]
impl MintAssetOutput {
    /// The Zero Knowledge proofs of the asset minting.
    #[wasm_bindgen(getter)]
    pub fn asset_tx(&self) -> Base64 {
        self.asset_tx.clone()
    }
}

/// Contains the Zero Knowledge Proof of initializing a confidential transaction by the sender.
#[wasm_bindgen]
pub struct CreateTransactionOutput {
    init_tx: Base64,
}

#[wasm_bindgen]
impl CreateTransactionOutput {
    /// The Zero Knowledge proofs of the initialized confidential transaction.
    #[wasm_bindgen(getter)]
    pub fn init_tx(&self) -> Base64 {
        self.init_tx.clone()
    }
}

/// Contains the Zero Knowledge Proof of finalizing a confidential transaction by the receiver.
#[wasm_bindgen]
pub struct FinalizedTransactionOutput {
    finalized_tx: Base64,
}

#[wasm_bindgen]
impl FinalizedTransactionOutput {
    /// The Zero Knowledge proofs of the finalized confidential transaction.
    #[wasm_bindgen(getter)]
    pub fn finalized_tx(&self) -> Base64 {
        self.finalized_tx.clone()
    }
}

/// Contains the Zero Knowledge Proof of justifying a confidential transaction by the mediator.
#[wasm_bindgen]
pub struct JustifiedTransactionOutput {
    justified_tx: Base64,
}

#[wasm_bindgen]
impl JustifiedTransactionOutput {
    /// The Zero Knowledge proofs of the justified confidential transaction.
    #[wasm_bindgen(getter)]
    pub fn justified_tx(&self) -> Base64 {
        self.justified_tx.clone()
    }
}

/// A wrapper around base64 encoding of mediator secret account.
#[wasm_bindgen]
pub struct MediatorAccount {
    secret: Base64,
}

#[wasm_bindgen]
impl MediatorAccount {
    #[wasm_bindgen(constructor)]
    pub fn new(secret: Base64) -> Self {
        Self { secret }
    }

    fn to_mercat(&self) -> Fallible<MercatMediatorAccount> {
        decode::<MercatMediatorAccount>(self.secret.clone())
    }
}

/// A wrapper around base64 encoding of a mercat account.
#[wasm_bindgen]
pub struct Account {
    secret_account: Base64,
    public_account: PubAccount,
}

#[wasm_bindgen]
impl Account {
    #[wasm_bindgen(constructor)]
    pub fn new(secret_account: Base64, public_account: PubAccount) -> Self {
        Self {
            secret_account,
            public_account,
        }
    }

    fn to_mercat(&self) -> Fallible<MercatAccount> {
        Ok(MercatAccount {
            secret: decode::<SecAccount>(self.secret_account.clone())?,
            public: self.public_account.to_mercat()?,
        })
    }
}

/// A wrapper around base64 encoding of mercat public account.
#[wasm_bindgen]
pub struct PubAccount {
    account_id: Base64,
    public_key: Base64,
}

#[wasm_bindgen]
impl PubAccount {
    #[wasm_bindgen(constructor)]
    pub fn new(account_id: Base64, public_key: Base64) -> Self {
        Self {
            account_id,
            public_key,
        }
    }

    fn to_mercat(&self) -> Fallible<MercatPubAccount> {
        Ok(MercatPubAccount {
            owner_enc_pub_key: decode::<ElgamalPublicKey>(self.public_key.clone())?,
            enc_asset_id: decode::<CipherText>(self.account_id.clone())?,
        })
    }
}

// ------------------------------------------------------------------------------------
// -                                     Error Types                                  -
// ------------------------------------------------------------------------------------

#[wasm_bindgen]
#[derive(Serialize)]
pub enum WasmError {
    AccountCreationError,
    AssetIssuanceError,
    TransactionCreationError,
    TransactionFinalizationError,
    TransactionJustificationError,
    DeserializationError,
    Base64DecodingError,
    HexDecodingError,
    PlainTickerIdsError,
    DecryptionError,
}

impl From<WasmError> for JsValue {
    fn from(e: WasmError) -> Self {
        serde_json::to_string(&e)
            .map(|msg| msg.into())
            .unwrap_or_else(|_| "Failed to serialized the error to string!".into())
    }
}

type Fallible<T> = Result<T, JsValue>;

// ------------------------------------------------------------------------------------
// -                                     Public API                                   -
// ------------------------------------------------------------------------------------

/// Creates a mercat account for a given `ticker_id`. It is the responsibility of the caller
/// to properly store and safeguard the secret values returned by this function.
///
/// # Arguments
/// * `valid_ticker_ids`: The list of all valid confidential ticker ids. These values can be
///                       obtained from the chain. The values are expected to be a list of
///                       hex strings (without the 0x).
///
/// * `ticker_id`: The ticker id of this account.
///
/// # Outputs
/// * `CreateAccountOutput`: Contains both the public and secret account information.
///
/// # Errors
/// * `PlainTickerIdsError`: If the `valid_ticker_ids` is not a list of hex strings (without the
/// 0x)
/// * `HexDecodingError`: If `ticker_id` or `valid_ticker_ids`s are not a proper Hex values.
/// * `AccountCreationError`: If mercat library throws an error while creating the account.
#[wasm_bindgen]
pub fn create_account(
    valid_ticker_ids: JsValue,
    ticker_id: String,
) -> Fallible<CreateAccountOutput> {
    let mut rng = OsRng;
    let valid_ticker_ids: Vec<String> = valid_ticker_ids
        .into_serde()
        .map_err(|_| WasmError::PlainTickerIdsError)?;

    let secret_account = create_secret_account(&mut rng, ticker_id)?;
    let valid_asset_ids: Vec<AssetId> = valid_ticker_ids
        .into_iter()
        .map(ticker_id_to_asset_id)
        .collect::<Fallible<Vec<AssetId>>>()?;
    let valid_asset_ids = convert_asset_ids(valid_asset_ids);
    let account_tx: PubAccountTx = AccountCreator
        .create(&secret_account, &valid_asset_ids, &mut rng)
        .map_err(|_| WasmError::AccountCreationError)?;
    let account_id = account_tx.pub_account.enc_asset_id;

    Ok(CreateAccountOutput {
        secret_account: base64::encode(secret_account.encode()),
        public_key: base64::encode(secret_account.enc_keys.public.encode()),
        account_id: base64::encode(account_id.encode()),
        account_tx: base64::encode(account_tx.encode()),
    })
}

/// Creates a mercat mediator account. It is the responsibility of the caller
/// to properly store and safeguard the secret values returned by this function.
///
/// # Arguments
///
/// # Outputs
/// * `CreateMediatorAccountOutput`: Contains the public and secret mediator account.
///
/// # Errors
#[wasm_bindgen]
pub fn create_mediator_account() -> CreateMediatorAccountOutput {
    let mut rng = OsRng;

    let mediator_elg_secret_key = ElgamalSecretKey::new(Scalar::random(&mut rng));
    let mediator_enc_key = EncryptionKeys {
        public: mediator_elg_secret_key.get_public_key(),
        secret: mediator_elg_secret_key,
    };

    CreateMediatorAccountOutput {
        public_key: base64::encode(mediator_enc_key.public.encode()),
        secret_account: MediatorAccount {
            secret: base64::encode(
                MercatMediatorAccount {
                    encryption_key: mediator_enc_key,
                }
                .encode(),
            ),
        },
    }
}

/// Creates a Zero Knowledge Proof of minting a confidential asset.
///
/// # Arguments
/// * `amount`: An integer with a max value of `2^32` representing the mint amount.
/// * `issuer_account`: The mercat account. Can be obtained from `CreateAccountOutput.account`.
///
/// # Outputs
/// * `MintAssetOutput`: The ZKP of minting the asset.
///
/// # Errors
/// * `Base64DecodingError`: If the `issuer_account` cannot be decoded from base64.
/// * `DeserializationError`: If the `issuer_account` cannot be deserialized to a mercat account.
#[wasm_bindgen]
pub fn mint_asset(amount: u32, issuer_account: Account) -> Fallible<MintAssetOutput> {
    let mut rng = OsRng;
    let asset_tx: InitializedAssetTx = AssetIssuer
        .initialize_asset_transaction(&issuer_account.to_mercat()?, &[], amount, &mut rng)
        .map_err(|_| WasmError::AssetIssuanceError)?;

    Ok(MintAssetOutput {
        asset_tx: base64::encode(asset_tx.encode()),
    })
}

/// Creates the ZKP for the initial phase of creating a confidential transaction. This function
/// is called by the sender and depends on secret information from the sender and public
/// information of the receiver and the mediator.
///
/// # Arguments
/// * `amount`: An integer with a max value of `2^32` representing the mint amount.
/// * `sender_account`: The mercat account. Can be obtained from `CreateAccountOutput.account`.
/// * `encrypted_pending_balance`: Sender's encrypted pending balance. Can be obtained from the
///                                chain.
/// * `receiver_public_account`: Receiver's public account. Can be obtained from the chain.
/// * `mediator_public_key`: Mediator's public key. Can be obtained from the chain.
///
/// # Outputs
/// * `CreateAccountOutput`: The ZKP of the initialized transaction.
///
/// # Errors
/// * `Base64DecodingError`: If either of the inputs cannot be decoded from base64.
/// * `DeserializationError`: If either of the inputs cannot be deserialized to a mercat account.
/// * `TransactionCreationError`: If the mercat library throws an error when creating the proof.
#[wasm_bindgen]
pub fn create_transaction(
    amount: u32,
    sender_account: Account,
    encrypted_pending_balance: Base64,
    receiver_public_account: PubAccount,
    mediator_public_key: Base64,
) -> Fallible<CreateTransactionOutput> {
    let mut rng = OsRng;

    let init_tx = CtxSender
        .create_transaction(
            &sender_account.to_mercat()?,
            &decode::<CipherText>(encrypted_pending_balance)?,
            &receiver_public_account.to_mercat()?,
            &decode::<ElgamalPublicKey>(mediator_public_key)?,
            &[],
            amount,
            &mut rng,
        )
        .map_err(|_| WasmError::TransactionCreationError)?;

    Ok(CreateTransactionOutput {
        init_tx: base64::encode(init_tx.encode()),
    })
}

/// Creates the ZKP for the finalized phase of creating a confidential transaction. This function
/// is called by the receiver and depends on secret information from the receiver and public
/// information of the sender.
///
/// # Arguments
/// * `amount`: An integer with a max value of `2^32` representing the mint amount.
/// * `init_tx`: The initialized transaction proof. Can be obtained from the chain.
/// * `receiver_account`: The mercat account. Can be obtained from `CreateAccountOutput.account`.
///
/// # Outputs
/// * `FinalizedTransactionOutput`: The ZKP of the finalized transaction.
///
/// # Errors
/// * `Base64DecodingError`: If either of the inputs cannot be decoded from base64.
/// * `DeserializationError`: If either of the inputs cannot be deserialized to a mercat account.
/// * `TransactionFinalizationError`: If the mercat library throws an error when creating the proof.
#[wasm_bindgen]
pub fn finalize_transaction(
    amount: u32,
    init_tx: Base64,
    receiver_account: Account,
) -> Fallible<FinalizedTransactionOutput> {
    let mut rng = OsRng;

    let finalized_tx = CtxReceiver
        .finalize_transaction(
            decode::<InitializedTransferTx>(init_tx)?,
            receiver_account.to_mercat()?,
            amount,
            &mut rng,
        )
        .map_err(|_| WasmError::TransactionFinalizationError)?;

    Ok(FinalizedTransactionOutput {
        finalized_tx: base64::encode(finalized_tx.encode()),
    })
}

/// Creates the ZKP for the justification phase of creating a confidential transaction.
/// This function is called by the mediator and depends on secret information from the
/// mediator and public information of the sender and the receiver. Moreover, this function
/// expects the plain ticker id which should be communicated to the mediator off-chain.
///
/// # Arguments
/// * `finalized_tx`: The finalized transaction proof. Can be obtained from the chain.
/// * `mediator_account`: The secret portion of the mediator's account. Can be obtained from
///                       `CreateMediatorAccountOutput.secret_account`.
/// * `sender_public_account`: Sender's public account. Can be obtained from the chain.
/// * `sender_encrypted_pending_balance`: Sender's encrypted pending balance.
///                                       Can be obtained from the chain.
/// * `receiver_public_account`: Receiver's public account. Can be obtained from the chain.
/// * `ticker_id`: The plain ticker id. Should be communicated off-chain.
///
/// # Outputs
/// * `JustifiedTransactionOutput`: The ZKP of the justify_transaction transaction.
///
/// # Errors
/// * `Base64DecodingError`: If either of the inputs cannot be decoded from base64.
/// * `DeserializationError`: If either of the inputs cannot be deserialized to a mercat account.
/// * `TransactionJustificationError`: If the mercat library throws an error when creating the proof.
#[wasm_bindgen]
pub fn justify_transaction(
    finalized_tx: Base64,
    mediator_account: MediatorAccount,
    sender_public_account: PubAccount,
    sender_encrypted_pending_balance: Base64,
    receiver_public_account: PubAccount,
    ticker_id: String,
) -> Fallible<JustifiedTransactionOutput> {
    let mut rng = OsRng;

    let justified_tx = CtxMediator
        .justify_transaction(
            decode::<FinalizedTransferTx>(finalized_tx)?,
            &mediator_account.to_mercat()?.encryption_key,
            &sender_public_account.to_mercat()?,
            &decode::<EncryptedAmount>(sender_encrypted_pending_balance)?,
            &receiver_public_account.to_mercat()?,
            &[],
            ticker_id_to_asset_id(ticker_id)?,
            &mut rng,
        )
        .map_err(|_| WasmError::TransactionJustificationError)?;

    Ok(JustifiedTransactionOutput {
        justified_tx: base64::encode(justified_tx.encode()),
    })
}

/// Decrypts an `encrypted_value` given the secret account information.
///
/// # Arguments
/// * `encrypted_value`: The encrypted value.
/// * `account`: The mercat account. Can be obtained from `CreateAccountOutput.account`.
///
/// # Outputs
/// * `u32`: The decrypted value.
///
/// # Errors
/// * `Base64DecodingError`: If either of the inputs cannot be decoded from base64.
/// * `DeserializationError`: If either of the inputs cannot be deserialized to a mercat account.
/// * `DecryptionError`: If the mercat library throws an error while decrypting the value.
#[wasm_bindgen]
pub fn decrypt(encrypted_value: Base64, account: Account) -> Fallible<u32> {
    let enc_balance = decode::<EncryptedAmount>(encrypted_value)?;
    let account = account.to_mercat()?;

    let decrypted_value = account
        .secret
        .enc_keys
        .secret
        .decrypt(&enc_balance)
        .map_err(|_| WasmError::DecryptionError)?;

    Ok(decrypted_value)
}

// ------------------------------------------------------------------------------------
// -                               Internal Functions                                 -
// ------------------------------------------------------------------------------------

fn decode<T: Decode>(data: Base64) -> Fallible<T> {
    let decoded = base64::decode(data).map_err(|_| WasmError::Base64DecodingError)?;
    T::decode(&mut &decoded[..]).map_err(|_| WasmError::DeserializationError.into())
}

fn ticker_id_to_asset_id(ticker_id: String) -> Fallible<AssetId> {
    let mut asset_id = [0u8; 12];
    let decoded = hex::decode(ticker_id).map_err(|_| WasmError::HexDecodingError)?;
    asset_id[..decoded.len()].copy_from_slice(&decoded);
    Ok(AssetId { id: asset_id })
}

fn create_secret_account(rng: &mut OsRng, ticker_id: String) -> Fallible<SecAccount> {
    let elg_secret = ElgamalSecretKey::new(Scalar::random(rng));
    let elg_pub = elg_secret.get_public_key();
    let enc_keys = EncryptionKeys {
        public: elg_pub,
        secret: elg_secret,
    };

    let mut asset_id = [0u8; 12];
    let decoded = hex::decode(ticker_id).map_err(|_| WasmError::HexDecodingError)?;
    asset_id[..decoded.len()].copy_from_slice(&decoded);

    let asset_id = AssetId { id: asset_id };
    let asset_id_witness = CommitmentWitness::new(asset_id.into(), Scalar::random(rng));

    Ok(SecAccount {
        enc_keys,
        asset_id_witness,
    })
}
