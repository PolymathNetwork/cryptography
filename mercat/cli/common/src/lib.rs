//! A common library for utility functions.

pub mod account_create;
pub mod account_issue;
pub mod account_transfer;
pub mod chain_setup;
pub mod errors;
mod harness;
pub mod justify;
pub mod validate;

use codec::{Decode, Encode};
use cryptography_core::asset_proofs::CipherText;
use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT, scalar::Scalar};
use errors::Error;
use log::{debug, error, info};
use mercat::{
    Account, AssetTxState, EncryptedAmount, EncryptedAssetId, FinalizedTransferTx,
    InitializedAssetTx, InitializedTransferTx, JustifiedTransferTx, PubAccount, PubAccountTx,
    SecAccount, TransferTxState, TxSubstate,
};
use metrics::Recorder;
use metrics_core::Key;
use rand::{rngs::StdRng, Rng, SeedableRng};
use rand::{CryptoRng, RngCore};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    convert::TryInto,
    fmt,
    fs::{create_dir_all, File},
    hash::Hash,
    io::BufReader,
    path::{Path, PathBuf},
};

pub const ON_CHAIN_DIR: &str = "on-chain";
pub const OFF_CHAIN_DIR: &str = "off-chain";
pub const MEDIATOR_PUBLIC_ACCOUNT_FILE: &str = "mediator_public_account";
pub const VALIDATED_PUBLIC_ACCOUNT_FILE: &str = "validated_public_account";
pub const VALIDATED_PUBLIC_ACCOUNT_BALANCE_FILE: &str = "validated_public_account_balance";
pub const SECRET_ACCOUNT_FILE: &str = "secret_account";
pub const ASSET_ID_LIST_FILE: &str = "valid_asset_ids.json";
pub const COMMON_OBJECTS_DIR: &str = "common";
pub const USER_ACCOUNT_MAP: &str = "user_ticker_to_account_id.json";
pub const LAST_VALIDATED_TX_ID_FILE: &str = "last_validated_tx_id_file.json";

/// A wrapper around MERCAT api which holds the transaction data, the transaction id,
/// and the user who initiated the transaction. Some transactions also hold the
/// ordering state.
#[derive(Debug)]
pub enum CoreTransaction {
    Account {
        account_tx: PubAccountTx,
        ordering_state: OrderingState,
        tx_id: u32,
    },
    IssueInit {
        issue_tx: InitializedAssetTx,
        issuer: String,
        ordering_state: OrderingState,
        tx_id: u32,
        amount: u32,
    },
    TransferInit {
        tx: InitializedTransferTx,
        sender: String,
        ordering_state: OrderingState,
        tx_id: u32,
    },
    TransferFinalize {
        tx: FinalizedTransferTx,
        receiver: String,
        ordering_state: OrderingState,
        tx_id: u32,
    },
    TransferJustify {
        tx: JustifiedTransferTx,
        mediator: String,
        tx_id: u32,
    },
    Invalid,
}

impl CoreTransaction {
    /// Returns true for transactions that can be verified by the network validators.
    fn is_ready_for_validation(&self) -> bool {
        match self {
            CoreTransaction::Account {
                account_tx: _,
                ordering_state: _,
                tx_id: _,
            } => true,
            CoreTransaction::IssueInit {
                issue_tx: _,
                issuer: _,
                tx_id: _,
                ordering_state: _,
                amount: _,
            } => true,
            CoreTransaction::TransferJustify {
                tx: _,
                mediator: _,
                tx_id: _,
            } => true,
            _ => false,
        }
    }

    /// Returns true for outgoing transactions.
    fn decreases_account_balance(&self) -> bool {
        matches!(
            self,
            CoreTransaction::TransferInit {
                tx: _,
                sender: _,
                ordering_state: _,
                tx_id: _,
            }
        )
    }

    pub fn ordering_state(&self) -> OrderingState {
        match self {
            CoreTransaction::Account {
                account_tx: _,
                tx_id: _,
                ordering_state,
            } => ordering_state.clone(),
            CoreTransaction::IssueInit {
                issue_tx: _,
                issuer: _,
                ordering_state,
                tx_id: _,
                amount: _,
            } => ordering_state.clone(),
            CoreTransaction::TransferInit {
                tx: _,
                sender: _,
                ordering_state,
                tx_id: _,
            } => ordering_state.clone(),
            CoreTransaction::TransferFinalize {
                tx: _,
                receiver: _,
                ordering_state,
                tx_id: _,
            } => ordering_state.clone(),
            _ => OrderingState::new(0),
        }
    }
}

#[derive(Clone, Debug)]
pub enum Direction {
    Incoming,
    Outgoing,
}

/// A wrapper that hides the validation error and only keeps the result of the validation.
#[derive(Clone)]
pub struct ValidationResult {
    user: String,
    ticker: String,
    direction: Direction,
    amount: Option<EncryptedAmount>,
}

impl ValidationResult {
    /// Creates the error value. An amount of None, indicates that an error has occurred.
    fn error(user: &str, ticker: &str) -> Self {
        Self {
            user: user.to_string(),
            ticker: ticker.to_string(),
            direction: Direction::Incoming,
            amount: None,
        }
    }
}

/// Used in processing of pending transactions.
#[derive(Debug, Serialize, Deserialize, Encode, Decode, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct OrderingState {
    pub last_processed_tx_counter: Option<u32>,
    pub last_pending_tx_counter: u32,
    pub tx_id: u32,
}

impl OrderingState {
    pub fn new(tx_id: u32) -> Self {
        Self {
            last_processed_tx_counter: None,
            last_pending_tx_counter: 0,
            tx_id,
        }
    }
}

/// A wrapper around the MERCAT PubAccount that stores the last processed transaction counter
/// of the owner of the account, at the time of updating the account.
#[derive(Debug, Serialize, Deserialize, Encode, Decode, Clone)]
pub struct OrderedPubAccount {
    pub last_processed_tx_counter: Option<u32>,
    pub pub_account: PubAccount,
}

/// A wrapper around the MERCAT PubAccount that stores the ordering state of this transaction.
#[derive(Debug, Serialize, Deserialize, Encode, Decode, Clone)]
pub struct OrderedPubAccountTx {
    pub ordering_state: OrderingState,
    pub account_tx: PubAccountTx,
}

/// Used for issue asset transaction.
#[derive(Debug, Serialize, Deserialize, Encode, Decode, Clone)]
pub struct OrderedAssetInstruction {
    pub state: AssetTxState,
    pub amount: u32,
    pub ordering_state: OrderingState,
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
}

/// Used for justification and verification of issue asset transaction.
#[derive(Debug, Serialize, Deserialize, Encode, Decode, Clone)]
pub struct AssetInstruction {
    pub state: AssetTxState,
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
}

/// Used for creating and finalizing a transfer transaction.
#[derive(Debug, Serialize, Deserialize, Encode, Decode, Clone)]
pub struct OrderedTransferInstruction {
    pub state: TransferTxState,
    pub ordering_state: OrderingState,
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
}

/// Used for justifying and validating a transfer transaction.
#[derive(Debug, Serialize, Deserialize, Encode, Decode, Clone)]
pub struct TransferInstruction {
    pub state: TransferTxState,
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
}

#[derive(PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PrintableAccountId(pub Vec<u8>);

impl fmt::Display for PrintableAccountId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

impl PrintableAccountId {
    fn to_string(&self) -> String {
        base64::encode(self.0.clone())
    }
}

#[inline]
pub fn asset_transaction_file(tx_id: u32, user: &str, state: AssetTxState) -> String {
    format!("tx_{}_{}_{}.json", tx_id, user, state)
}

#[inline]
pub fn confidential_transaction_file(tx_id: u32, user: &str, state: TransferTxState) -> String {
    format!("tx_{}_{}_{}.json", tx_id, user, state)
}

#[inline]
pub fn account_create_transaction_file(tx_id: u32, user: &str, ticker: &str) -> String {
    format!("tx_{}_{}_ticker#{}.json", tx_id, user, ticker)
}

#[inline]
pub fn user_public_account_file(ticker: &str) -> String {
    format!("{}_{}", ticker, VALIDATED_PUBLIC_ACCOUNT_FILE)
}

#[inline]
pub fn user_public_account_balance_file(ticker: &str) -> String {
    format!("{}_{}", ticker, VALIDATED_PUBLIC_ACCOUNT_BALANCE_FILE)
}

#[inline]
pub fn user_secret_account_file(ticker: &str) -> String {
    format!("{}_{}", ticker, SECRET_ACCOUNT_FILE)
}

/// This is used for simulating cheating by increasing the account id.
#[inline]
pub fn non_empty_account_id() -> EncryptedAssetId {
    CipherText {
        x: RISTRETTO_BASEPOINT_POINT,
        y: RISTRETTO_BASEPOINT_POINT,
    }
}

/// Parses the transaction file name and returns: (tx_id, user_name, state, the_input_file_path).
#[inline]
pub fn parse_tx_name(tx_file_path: String) -> Result<(u32, String, String, String), Error> {
    let re = Regex::new(r"^tx_([0-9]+)_([a-z]+)_([a-zA-Z-#0-9]+).json$").map_err(|_| {
        Error::RegexError {
            reason: String::from("Failed to compile the transaction file name regex"),
        }
    })?;
    let file_name = Path::new(&tx_file_path)
        .file_name()
        .expect("It is a file and therefore, this should never fail!")
        .to_str()
        .ok_or(Error::PathBufConversionError)?;
    let caps = re.captures(&file_name).ok_or(Error::RegexError {
        reason: format!("Transaction info pattern did not match {}", file_name),
    })?;
    let tx_id = caps[1]
        .to_string()
        .parse::<u32>()
        .map_err(|_| Error::RegexError {
            reason: String::from("failed to convert amount to u32."),
        })?;
    let user = caps[2].to_string();
    let state = caps[3].to_string();
    Ok((tx_id, user, state, tx_file_path))
}

// -------------------------------------- Metric recording ------------------------------------------------
#[allow(dead_code)]
static RECORDER: PrintRecorder = PrintRecorder;

#[derive(Default)]
pub struct PrintRecorder;

impl Recorder for PrintRecorder {
    fn increment_counter(&self, key: Key, value: u64) {
        info!(
            "metrics: {{ \"counter\": {{ \"name\": \"{}\", \"value\": {} }} }}",
            key, value
        );
    }

    fn update_gauge(&self, key: Key, value: i64) {
        info!(
            "gauge: {{ \"counter\": {{ \"name\": \"{}\", \"value\": {} }} }}",
            key, value
        );
    }

    fn record_histogram(&self, key: Key, value: u64) {
        info!(
            "histogram: {{ \"counter\": {{ \"name\": \"{}\", \"value\": {} }} }}",
            key, value
        );
    }
}

#[cfg(feature = "std")]
pub fn init_print_logger() {
    let recorder = PrintRecorder::default();
    metrics::set_boxed_recorder(Box::new(recorder)).unwrap()
}

#[cfg(not(feature = "std"))]
pub fn init_print_logger() {
    metrics::set_recorder(&RECORDER).unwrap()
}

// -------------------------------------- Metric recording ------------------------------------------------

/// Utility function to construct the path based user name, file name, and whether the file
/// should be stored on or off chain.
#[inline]
pub fn construct_path(db_dir: PathBuf, on_off_chain: &str, user: &str, file_name: &str) -> PathBuf {
    let mut file_path = db_dir;
    file_path.push(on_off_chain);
    file_path.push(user);
    file_path.push(file_name);
    file_path
}

/// Utility function to save a serializable data to a location inside the database directory,
/// for a particular user.
#[inline]
pub fn save_to_file<T>(
    db_dir: PathBuf,
    on_off_chain: &str,
    user: &str,
    file_name: &str,
    data: &T,
) -> Result<(), Error>
where
    T: ?Sized + serde::Serialize,
{
    let mut file_path = db_dir;
    file_path.push(on_off_chain);
    file_path.push(user);

    // The file_path is now the path to the user directory. Create it if it does not exist.
    create_dir_all(file_path.clone()).map_err(|error| Error::FileCreationError {
        error,
        path: file_path.clone(),
    })?;

    file_path.push(file_name);
    let file = File::create(file_path.clone()).map_err(|error| Error::FileCreationError {
        error,
        path: file_path.clone(),
    })?;
    serde_json::to_writer_pretty(file, &data).map_err(|error| Error::FileWriteError {
        error,
        path: file_path,
    })?;

    Ok(())
}

/// Utility function to read and deserializable data from a location inside the database directory,
/// for a particular user.
#[inline]
pub fn load_from_file<T: serde::de::DeserializeOwned>(
    db_dir: PathBuf,
    on_off_chain: &str,
    user: &str,
    file_name: &str,
) -> Result<T, Error> {
    let file_path = construct_path(db_dir, on_off_chain, user, file_name);
    let file = File::open(file_path.clone()).map_err(|error| Error::FileReadError {
        error,
        path: file_path.clone(),
    })?;

    let data = BufReader::new(file);

    serde_json::from_reader(data).map_err(|error| Error::ObjectDeserializationError {
        error,
        path: file_path.clone(),
    })
}

/// Utility function to remove a file from the database directory for a particular user.
#[inline]
pub fn remove_file(
    db_dir: PathBuf,
    on_off_chain: &str,
    user: &str,
    file_name: &str,
) -> Result<(), Error> {
    let file_path = construct_path(db_dir, on_off_chain, user, file_name);
    std::fs::remove_file(file_path.clone()).map_err(|error| Error::FileRemovalError {
        error,
        path: file_path,
    })?;
    Ok(())
}

/// A data structure that various CLIs can share to serialize and deserialize asset ids.
#[derive(Serialize, Deserialize)]
pub struct AssetIdList(pub Vec<Scalar>);

/// Utility function to read the asset ids from the database directory.
#[inline]
pub fn get_asset_ids(db_dir: PathBuf) -> Result<Vec<Scalar>, Error> {
    let file_path = construct_path(db_dir, ON_CHAIN_DIR, COMMON_OBJECTS_DIR, ASSET_ID_LIST_FILE);
    let file = File::open(file_path).map_err(|error| Error::FileReadError {
        error,
        path: ASSET_ID_LIST_FILE.into(),
    })?;
    let mut de = serde_json::Deserializer::from_reader(file);

    let valid_asset_ids =
        AssetIdList::deserialize(&mut de).map_err(|_| Error::AssetIdListDeserializeError {
            path: ASSET_ID_LIST_FILE.into(),
        })?;
    Ok(valid_asset_ids.0)
}

/// Utility function to save an object that implements the Decode trait to file.
#[inline]
pub fn save_object<T: Encode>(
    db_dir: PathBuf,
    on_off_chain: &str,
    user: &str,
    file_name: &str,
    data: &T,
) -> Result<(), Error> {
    let mut file_path = db_dir;
    file_path.push(on_off_chain);
    file_path.push(user);

    // The file_path is now the path to the user directory. Create it if it does not exist.
    create_dir_all(file_path.clone()).map_err(|error| Error::FileCreationError {
        error,
        path: file_path.clone(),
    })?;

    file_path.push(file_name);

    std::fs::write(file_path.clone(), data.encode()).map_err(|error| Error::ObjectSaveError {
        error,
        path: file_path,
    })?;

    Ok(())
}

/// Utility function to read an object that implements the Encode trait from file.
#[inline]
pub fn load_object<T: Decode>(
    db_dir: PathBuf,
    on_off_chain: &str,
    user: &str,
    file_name: &str,
) -> Result<T, Error> {
    let file_path = construct_path(db_dir, on_off_chain, user, file_name);
    load_object_from(file_path)
}

/// Utility function to read an object that implements the Encode trait from file.
#[inline]
pub fn load_object_from<T: Decode>(file_path: PathBuf) -> Result<T, Error> {
    let data = std::fs::read(file_path.clone()).map_err(|error| Error::FileReadError {
        error,
        path: file_path.clone(),
    })?;

    T::decode(&mut &data[..]).map_err(|error| Error::ObjectLoadError {
        error,
        path: file_path,
    })
}

/// Helper function to save a config file to `cfg_path`.
pub fn save_config<T>(cfg_path: Option<PathBuf>, cfg: &T)
where
    T: ?Sized + serde::Serialize,
{
    if let Some(path) = &cfg_path {
        std::fs::write(
            path,
            serde_json::to_string_pretty(cfg).unwrap_or_else(|error| {
                panic!("Failed to serialize configuration file: {}", error)
            }),
        )
        .unwrap_or_else(|_| panic!("Failed to write the configuration to the file {:?}.", path));
    }
}

/// Helper function to generate a random seed using the thread RNG.
#[inline]
pub fn gen_seed() -> String {
    let mut rng = rand::thread_rng();
    let mut seed = [0u8; 32];
    rng.fill(&mut seed);
    base64::encode(seed)
}

/// Helper function to generate a random seed using the thread RNG.
#[inline]
pub fn gen_seed_from<T: RngCore + CryptoRng>(rng: &mut T) -> String {
    let mut seed = [0u8; 32];
    rng.fill(&mut seed);
    base64::encode(seed)
}

/// Helper function to create an RNG from seed.
#[inline]
pub fn create_rng_from_seed(seed: Option<String>) -> Result<StdRng, Error> {
    let seed = seed.ok_or(Error::EmptySeed)?;
    let seed: &[u8] = &base64::decode(seed).map_err(|error| Error::SeedDecodeError { error })?;
    let seed = seed
        .try_into()
        .map_err(|_| Error::SeedLengthError { length: seed.len() })?;

    Ok(StdRng::from_seed(seed))
}

/// Reads the account mapping from disk. Returns a map of account id to (user_name, ticker, tx_id).
#[inline]
pub fn load_account_map(db_dir: PathBuf) -> HashMap<String, (String, String, u32)> {
    let mapping: Result<HashMap<String, (String, String, u32)>, Error> =
        load_from_file(db_dir, OFF_CHAIN_DIR, COMMON_OBJECTS_DIR, USER_ACCOUNT_MAP);
    match mapping {
        Err(_error) => HashMap::new(),
        Ok(mapping) => mapping,
    }
}

/// Updates the account mapping file with a new record.
#[inline]
pub fn update_account_map(
    db_dir: PathBuf,
    user: String,
    ticker: String,
    account_id: EncryptedAssetId,
    tx_id: u32,
) -> Result<(), Error> {
    let mut mapping = load_account_map(db_dir.clone());
    mapping.insert(
        PrintableAccountId(account_id.encode()).to_string(),
        (user, ticker, tx_id),
    );
    save_to_file(
        db_dir,
        OFF_CHAIN_DIR,
        COMMON_OBJECTS_DIR,
        USER_ACCOUNT_MAP,
        &mapping,
    )
}

/// Reads the account mapping file and returns (user_name, ticker, tx_id) of the given account id.
#[inline]
pub fn get_user_ticker_from(
    account_id: EncryptedAssetId,
    db_dir: PathBuf,
) -> Result<(String, String, u32), Error> {
    let mapping = load_account_map(db_dir);
    let (user, ticker, tx_id) = mapping
        .get(&PrintableAccountId(account_id.encode()).to_string())
        .ok_or(Error::AccountIdNotFound {
            account_id: PrintableAccountId(account_id.encode()).to_string(),
        })?;
    Ok((user.clone(), ticker.clone(), *tx_id))
}

/// Searches the on-chain transactions to find the last transaction that the give user has submitted
/// before `current_tx_id`. If such a transaction is found, its ordering state is returned.
#[inline]
pub fn last_ordering_state(
    user: String,
    last_processed_tx_counter_from_account: Option<u32>,
    current_tx_id: u32,
    db_dir: PathBuf,
) -> Result<OrderingState, Error> {
    let all_tx_files = all_unverified_tx_files(db_dir)?;

    let parsed: (Option<Error>, Option<u32>, Option<u32>, CoreTransaction) = all_tx_files
        .into_iter()
        .map(parse_tx_name) // Extract info from file name.
        .filter(|res| {
            // Keep only the files that are created for the current user.
            res.as_ref().map_or_else(
                |_| false,
                |(tx_id, tx_user, _, _)| tx_user == &user && tx_id < &current_tx_id,
            )
        })
        .map(|res| {
            // Convert the files into tx objects.
            res.map(|(tx_id, user, state, tx_file_path)| {
                load_tx_file(tx_id, user, state, tx_file_path)
                    .map_or_else(|_| CoreTransaction::Invalid, |tx| tx) // Remove Result.
            })
        })
        .fold(
            (None, None, None, CoreTransaction::Invalid),
            // Closure of the fold operator.
            |acc, tx| {
                // Find the last transaction by comparing the last pending transaction value of each tx.
                let (prev_error, last_processed, max_pending, last_tx) = acc;
                match tx {
                    Err(error) => {
                        error!("Error while finding the last transaction: {:?}", error);
                        (Some(error), None, None, CoreTransaction::Invalid)
                    }
                    Ok(tx) => {
                        let ordering_state = tx.ordering_state();
                        match prev_error {
                            Some(error) => (Some(error), None, None, CoreTransaction::Invalid),
                            None => {
                                if ordering_state.last_pending_tx_counter
                                    > max_pending.unwrap_or_default()
                                {
                                    (
                                        None,
                                        ordering_state.last_processed_tx_counter,
                                        Some(ordering_state.last_pending_tx_counter),
                                        tx,
                                    )
                                } else {
                                    (prev_error, last_processed, max_pending, last_tx)
                                }
                            }
                        }
                    }
                }
            },
        );
    let (prev_error, last_processed_tx_counter, last_pending_tx_counter, _) = parsed;
    if prev_error.is_some() {
        return Err(Error::LastTransactionNotFound { user });
    }
    if last_pending_tx_counter == None {
        // No pending transactions found, return the ordering state from the account.
        return Ok(OrderingState {
            last_processed_tx_counter: last_processed_tx_counter_from_account,
            last_pending_tx_counter: last_processed_tx_counter_from_account.unwrap_or_default(),
            tx_id: current_tx_id,
        });
    }
    Ok(OrderingState {
        last_processed_tx_counter,
        last_pending_tx_counter: last_pending_tx_counter.unwrap_or_default(),
        tx_id: current_tx_id,
    })
}

/// Searches the chain for the transactions of the given user, whose pending transaction counter is
/// between `start` and `end`.
#[inline]
pub fn load_tx_between_counters(
    user: &str,
    db_dir: PathBuf,
    start: u32,
    end: u32,
) -> Result<Vec<CoreTransaction>, Error> {
    all_unverified_tx_files(db_dir)?
        .into_iter()
        .map(parse_tx_name)
        .filter(|res| {
            // keep only the files that are created for the current user.
            res.as_ref()
                .map_or_else(|_| false, |(_, tx_user, _, _)| tx_user == user)
        })
        .map(|res| {
            // Convert the files into tx objects.
            res.map(|(tx_id, user, state, tx_file_path)| {
                load_tx_file(tx_id, user, state, tx_file_path)
                    .map_or_else(|_| CoreTransaction::Invalid, |tx| tx) // Remove Result.
            })
        })
        .filter(|res| {
            // Keep only the transactions that are created between `start` and `end`.
            res.as_ref().map_or_else(
                |_| false,
                |tx| {
                    tx.ordering_state().last_pending_tx_counter >= start
                        && tx.ordering_state().last_pending_tx_counter <= end
                },
            )
        })
        .collect()
}

/// Searches the on-chain data for all pending transactions that decreased the balance of the
/// given user and computes the pending balance.
#[inline]
pub fn compute_enc_pending_balance(
    sender: &str,
    ordering_state: OrderingState, // The state at the time of creating the last transaction.
    last_processed_tx_counter: Option<u32>, // The current last processed tx counter.
    enc_balance_in_account: EncryptedAmount,
    db_dir: PathBuf,
) -> Result<EncryptedAmount, Error> {
    if last_processed_tx_counter < ordering_state.last_processed_tx_counter {
        return Err(Error::MismatchInProcessedCounter {
            current: last_processed_tx_counter,
            earliest: ordering_state.last_processed_tx_counter,
        });
    }
    let mut start = 1;
    if let Some(counter) = ordering_state.last_processed_tx_counter {
        start = counter + 1;
    }
    let transfer_inits = load_tx_between_counters(
        sender,
        db_dir.clone(),
        start,
        ordering_state.last_pending_tx_counter,
    )?
    .into_iter()
    .filter(|tx| tx.decreases_account_balance())
    .collect::<Vec<CoreTransaction>>();

    debug!(
        "------------> found {} outgoing transactions",
        transfer_inits.len()
    );
    if transfer_inits.is_empty() {
        // There are no pending transactions.
        return Ok(enc_balance_in_account);
    }

    // last_processed_tx_counter > ordering_state.last_processed_tx_counter &&  last_processed_tx_counter > pending -> pending has been skipped
    // last_processed_tx_counter > ordering_state.last_processed_tx_counter &&  last_processed_tx_counter == pending -> error
    // last_processed_tx_counter > ordering_state.last_processed_tx_counter &&  last_processed_tx_counter < pending
    // last_processed_tx_counter == ordering_state.last_processed_tx_counter
    // TODO: implementing the simple case for now where the last processed transaction inside the account
    //       is the same as the last processed transaction inside the last transaction.
    // The rest of the cases will be handled in CRYP-130
    if last_processed_tx_counter != ordering_state.last_processed_tx_counter {
        return Err(Error::NotImplemented {
            story: "CRYP-130".to_string(),
        });
    }

    let mut pending_balance = enc_balance_in_account;
    for core_tx in transfer_inits {
        if let CoreTransaction::TransferInit {
            tx,
            sender: _,
            ordering_state: _,
            tx_id: _,
        } = core_tx
        {
            pending_balance -= tx.memo.enc_amount_using_sender;
            let account_id = tx.memo.sender_account_id;
            debug!(
                "------> decremented by {}.",
                debug_decrypt(account_id, tx.memo.enc_amount_using_sender, db_dir.clone())?
            );
        }
    }
    Ok(pending_balance)
}

/// Searches the on-chain data and returns all the transactions since the last verification.
pub fn all_unverified_tx_files(db_dir: PathBuf) -> Result<Vec<String>, Error> {
    let start = last_verified_tx_id(db_dir.clone());
    let mut dir = db_dir;
    dir.push(ON_CHAIN_DIR);
    dir.push(COMMON_OBJECTS_DIR);

    let mut files = vec![];
    for entry in std::fs::read_dir(dir.clone()).map_err(|error| Error::FileReadError {
        error,
        path: dir.clone(),
    })? {
        let entry = entry.map_err(|error| Error::FileReadError {
            error,
            path: dir.clone(),
        })?;
        let path = entry.path();
        if !path.is_dir() {
            let file_name: &str = path
                .file_name()
                .expect("It is a file and therefore, this should never fail!")
                .to_str()
                .ok_or(Error::PathBufConversionError)?;
            if file_name.starts_with("tx_") {
                let re = Regex::new(r"^tx_([0-9]+)_.*$").map_err(|_| Error::RegexError {
                    reason: String::from("Failed to compile the transaction id regex"),
                })?;
                let caps = re.captures(&file_name).ok_or(Error::RegexError {
                    reason: format!("Pattern did not match {}", file_name),
                })?;
                let tx_id = caps[1]
                    .to_string()
                    .parse::<u32>()
                    .map_err(|_| Error::RegexError {
                        reason: String::from("failed to convert amount to u32."),
                    })?;
                if tx_id as i32 > start {
                    files.push(String::from(
                        path.to_str().ok_or(Error::PathBufConversionError)?,
                    ));
                }
            }
        }
    }
    Ok(files)
}

/// Loads the tx_id of the last verified transaction from an off-chain file.
#[inline]
pub fn last_verified_tx_id(db_dir: PathBuf) -> i32 {
    // The file and updated after verification is done.
    let last_verified: Result<i32, Error> = load_from_file(
        db_dir,
        OFF_CHAIN_DIR,
        COMMON_OBJECTS_DIR,
        LAST_VALIDATED_TX_ID_FILE,
    );
    match last_verified {
        Err(_) => -1,
        Ok(tx_id) => tx_id,
    }
}

/// Reads a transaction file and returns the corresponding object.
#[inline]
pub fn load_tx_file(
    tx_id: u32,
    user: String,
    state: String,
    tx_file_path: String,
) -> Result<CoreTransaction, Error> {
    let tx = if state == AssetTxState::Initialization(TxSubstate::Started).to_string() {
        let instruction: OrderedAssetInstruction = load_object_from(PathBuf::from(tx_file_path))?;
        CoreTransaction::IssueInit {
            issue_tx: InitializedAssetTx::decode(&mut &instruction.data[..])
                .map_err(|_| Error::DecodeError)?,
            issuer: user,
            ordering_state: instruction.ordering_state,
            tx_id,
            amount: instruction.amount,
        }
    } else if state == TransferTxState::Initialization(TxSubstate::Started).to_string() {
        let instruction: OrderedTransferInstruction =
            load_object_from(PathBuf::from(tx_file_path))?;
        CoreTransaction::TransferInit {
            tx: InitializedTransferTx::decode(&mut &instruction.data[..])
                .map_err(|_| Error::DecodeError)?,
            sender: user,
            ordering_state: instruction.ordering_state,
            tx_id,
        }
    } else if state == TransferTxState::Finalization(TxSubstate::Started).to_string() {
        let instruction: OrderedTransferInstruction =
            load_object_from(PathBuf::from(tx_file_path))?;
        CoreTransaction::TransferFinalize {
            tx: FinalizedTransferTx::decode(&mut &instruction.data[..])
                .map_err(|_| Error::DecodeError)?,
            receiver: user,
            ordering_state: instruction.ordering_state,
            tx_id,
        }
    } else if state == TransferTxState::Justification(TxSubstate::Started).to_string() {
        let instruction: TransferInstruction = load_object_from(PathBuf::from(tx_file_path))?;
        CoreTransaction::TransferJustify {
            tx: JustifiedTransferTx::decode(&mut &instruction.data[..])
                .map_err(|_| Error::DecodeError)?,
            mediator: user,
            tx_id,
        }
    } else if state.starts_with("ticker#") {
        let ordered_account_tx: OrderedPubAccountTx =
            load_object_from(PathBuf::from(tx_file_path))?;
        CoreTransaction::Account {
            account_tx: ordered_account_tx.account_tx,
            tx_id,
            ordering_state: ordered_account_tx.ordering_state,
        }
    } else {
        return Err(Error::InvalidTransactionFile { path: tx_file_path });
    };
    Ok(tx)
}

/// Use only for debugging purposes.
#[inline]
fn debug_decrypt(
    account_id: EncryptedAssetId,
    enc_balance: EncryptedAmount,
    db_dir: PathBuf,
) -> Result<u32, Error> {
    let (user, ticker, _) = get_user_ticker_from(account_id, db_dir.clone())?;
    let ordered_pub_account: OrderedPubAccount = load_object(
        db_dir.clone(),
        ON_CHAIN_DIR,
        &user,
        &user_public_account_file(&ticker),
    )?;
    let account = Account {
        secret: load_object(
            db_dir,
            OFF_CHAIN_DIR,
            &user,
            &user_secret_account_file(&ticker),
        )?,
        public: ordered_pub_account.pub_account,
    };
    account
        .secret
        .enc_keys
        .secret
        .decrypt(&enc_balance)
        .map_err(|error| Error::LibraryError { error })
}

/// Use only for debugging purposes.
#[inline]
pub fn debug_decrypt_account_balance(
    user: String,
    ticker: String,
    db_dir: PathBuf,
) -> Result<u32, Error> {
    let enc_balance: EncryptedAmount = load_object(
        db_dir.clone(),
        ON_CHAIN_DIR,
        &user,
        &user_public_account_balance_file(&ticker),
    )?;
    let secret: SecAccount = load_object(
        db_dir,
        OFF_CHAIN_DIR,
        &user,
        &user_secret_account_file(&ticker),
    )?;
    secret
        .enc_keys
        .secret
        .decrypt(&enc_balance)
        .map_err(|error| Error::LibraryError { error })
}

/// Use only for debugging purposes.
#[inline]
pub fn debug_decrypt_base64_account_balance(
    user: String,
    encrypted_value: String,
    ticker: String,
    db_dir: PathBuf,
) -> Result<u32, Error> {
    let mut data: &[u8] = &base64::decode(encrypted_value).unwrap();
    let enc_balance = EncryptedAmount::decode(&mut data).unwrap();
    let scrt: SecAccount = load_object(
        db_dir,
        OFF_CHAIN_DIR,
        &user,
        &user_secret_account_file(&ticker),
    )?;
    scrt.enc_keys
        .secret
        .decrypt(&enc_balance)
        .map_err(|error| Error::LibraryError { error })
}
