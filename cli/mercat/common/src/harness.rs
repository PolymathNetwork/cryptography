use crate::{
    chain_setup::process_asset_id_creation, create_account::process_create_account, errors::Error,
    load_object, COMMON_OBJECTS_DIR, OFF_CHAIN_DIR, ON_CHAIN_DIR, PUBLIC_ACCOUNT_FILE,
    SECRET_ACCOUNT_FILE,
};
use cryptography::mercat::{PubAccount, SecAccount};
use linked_hash_map::LinkedHashMap;
use log::info;
use rand::Rng;
use rand::{rngs::StdRng, SeedableRng};
use regex::Regex;
use std::path::PathBuf;
use std::{
    collections::HashSet,
    convert::{From, TryFrom},
    fs, io,
    time::Instant,
};
use yaml_rust::{Yaml, YamlLoader};

// --------------------------------------------------------------------------------------------------
// -                                       data types                                                -
// ---------------------------------------------------------------------------------------------------

/// The signature fo the function for a generic step in a transaction. This function performs
/// the action (e.g., initializing a transaction, finalizing a transaction, or creating an account),
/// and returns the corresponding CLI command that can be run to reproduce this step manually.
type StepFunc = Box<dyn Fn() -> String + 'static>;

/// The trait which prescribes the order of functions needed for a transaction. For example, for a
/// confidential transaction, the order is initiate, finalize, mediate, and finally validate.
trait TransactionOrder {
    fn order(&self) -> Vec<StepFunc>;
}

/// Represents the three types of mercat transactions.
#[derive(Debug)]
pub enum Transaction {
    /// Transfer a balance from Alice to Bob, with some mediator and validator.
    Transfer(Transfer),
    /// Create an account for Alice for a ticker, with balance of zero.
    Create(Create),
    /// Issue tokens for an account (effectively funding an account).
    Issue(Issue),
}

/// A generic party, can be sender, receiver, or mediator.
#[derive(Debug)]
pub struct Party {
    pub name: String,
    pub cheater: bool,
}

impl From<&str> for Party {
    fn from(segment: &str) -> Self {
        // Example: alice or alice(cheat)
        let re = Regex::new(r"([a-zA-Z0-9]+)(\(cheat\))?").unwrap();
        let caps = re.captures(segment).unwrap(); // TODO: convert to try_from
        let name = String::from(caps.get(1).unwrap().as_str());
        let cheater = caps.get(2).is_some();
        Self { name, cheater }
    }
}

/// Data type of the transaction of transferring balance.
#[derive(Debug)]
pub struct Transfer {
    pub id: u32,
    pub sender: Party,
    pub receiver: Party,
    pub receiver_approves: bool,
    pub mediator: Party,
    pub mediator_approves: bool,
    pub amount: u32,
    pub ticker: String,
}

impl TryFrom<(u32, String)> for Transfer {
    type Error = Error;
    fn try_from(pair: (u32, String)) -> Result<Self, Error> {
        let (id, segment) = pair;
        // Example: Bob(cheat) 40 ACME Carol approve Marry reject
        let re = Regex::new(
            r"^([a-zA-Z0-9()]+) ([0-9]+) ([a-zA-Z0-9]+) ([a-zA-Z0-9()]+) (approve|reject) ([a-zA-Z0-9()]+) (approve|reject)$",
        )
        .map_err(|_| Error::RegexError {
            reason: String::from("Failed to compile the Transfer regex"),
        })?;
        let caps = re.captures(&segment).ok_or(Error::RegexError {
            reason: format!("Pattern did not match {}", segment),
        })?;
        Ok(Self {
            id,
            sender: Party::from(caps.get(1).unwrap().as_str()),
            receiver: Party::from(caps.get(4).unwrap().as_str()),
            receiver_approves: caps.get(5).unwrap().as_str() == "approve",
            mediator: Party::from(caps.get(6).unwrap().as_str()),
            mediator_approves: caps.get(7).unwrap().as_str() == "approve",
            amount: caps.get(2).unwrap().as_str().parse::<u32>().unwrap(),
            ticker: String::from(caps.get(3).unwrap().as_str()),
        })
    }
}

/// Data type of the transaction of creating empty account.
#[derive(Debug)]
pub struct Create {
    pub id: u32,
    pub seed: String,
    pub chain_db_dir: PathBuf,
    pub account_id: u32,
    pub owner: Party,
    pub ticker: String,
}

/// Data type of the transaction of funding an account by issuer.
#[derive(Debug)]
pub struct Issue {
    pub id: u32,
    pub owner: Party,
    pub mediator: Party,
    pub mediator_approves: bool,
    pub ticker: String,
    pub amount: u32,
}

impl TryFrom<(u32, String)> for Issue {
    type Error = Error;
    fn try_from(pair: (u32, String)) -> Result<Self, Error> {
        let (id, segment) = pair;
        // Example: Bob(cheat) 40 ACME Carol approve Marry reject
        let re = Regex::new(
            r"^([a-zA-Z0-9()]+) ([0-9]+) ([a-zA-Z0-9]+) ([a-zA-Z0-9()]+) (approve|reject)$",
        )
        .map_err(|_| Error::RegexError {
            reason: String::from("Failed to compile the Issue regex"),
        })?;
        let caps = re.captures(&segment).ok_or(Error::RegexError {
            reason: format!("Pattern did not match {}", segment),
        })?;
        Ok(Self {
            id,
            owner: Party::from(caps.get(1).unwrap().as_str()),
            mediator: Party::from(caps.get(4).unwrap().as_str()),
            mediator_approves: caps.get(5).unwrap().as_str() == "approve",
            ticker: String::from(caps.get(3).unwrap().as_str()),
            amount: caps.get(2).unwrap().as_str().parse::<u32>().unwrap(),
        })
    }
}
/// Human readable form of a mercat account.
#[derive(PartialEq, Eq, Hash, Debug)]
pub struct Account {
    owner: String,
    ticker: String,
    balance: u32,
}

/// Represents the various combinations of the transactions.
#[derive(Debug)]
pub enum TransactionMode {
    /// The transactions are run `repeat` number of times, and in each iteration, the
    /// steps of one transaction are done before the steps of the next transaction.
    Sequence {
        repeat: u32,
        steps: Vec<TransactionMode>,
    },
    /// The transactions are run `repeat` number of times, and in each iteration, the
    /// steps of the transactions are interleaved randomly.
    Concurrent {
        repeat: u32,
        steps: Vec<TransactionMode>,
    },
    Transaction(Transaction),
}

/// Represents a testcase that is read from the config file.
pub struct TestCase {
    /// Human readable description of the testcase. Will be printed to the log.
    title: String,
    /// The list of valid ticker names. This names will be converted to asset ids for meract.
    ticker_names: Vec<String>,
    ///// The initial list of accounts for each party.
    //accounts: Vec<Account>,
    /// The transactions of this testcase.
    transactions: TransactionMode,
    /// The expected value of the accounts at the end of the scenario.
    accounts_outcome: HashSet<Account>,
    /// Maximum allowable time in Milliseconds
    timing_limit: u128,
    /// the directory that will act as the chain datastore.
    chain_db_dir: PathBuf,
}

// --------------------------------------------------------------------------------------------------
// -                                  data type methods                                             -
// --------------------------------------------------------------------------------------------------

impl TransactionOrder for Transaction {
    fn order(&self) -> Vec<StepFunc> {
        match self {
            Transaction::Issue(fund) => fund.order(),
            Transaction::Transfer(transfer) => transfer.order(),
            Transaction::Create(create) => create.order(),
        }
    }
}

impl Transfer {
    pub fn send(&self) -> StepFunc {
        let value = format!("todo-send-transaction {}", self.id);
        // TODO: run the initialize transfer function, and return its CLI + args
        //       sea "create_account" function for an example of how it will look like.
        return Box::new(move || value.clone());
    }

    pub fn receive(&self) -> StepFunc {
        let value = format!("todo-receive-transaction {}", self.id);
        return Box::new(move || value.clone());
    }

    pub fn mediate(&self) -> StepFunc {
        let value = format!("todo-mediate-transaction {}", self.id);
        return Box::new(move || value.clone());
    }

    pub fn validate(&self) -> StepFunc {
        let value = format!("todo-validate-transaction {}", self.id);
        return Box::new(move || value.clone());
    }

    pub fn order(&self) -> Vec<StepFunc> {
        vec![self.send(), self.receive(), self.mediate(), self.validate()]
    }
}

impl Create {
    pub fn create_account(&self) -> StepFunc {
        let value = format!(
            "mercat-account create --account-id {} --ticker {} --user {} {}",
            self.account_id,
            self.ticker,
            self.owner.name,
            cheater_flag(self.owner.cheater)
        );
        let seed = self.seed.clone();
        let chain_db_dir = self.chain_db_dir.clone();
        let ticker = self.ticker.clone();
        let account_id = self.account_id;
        let owner = self.owner.name.clone();
        return Box::new(move || {
            process_create_account(
                Some(seed.clone()),
                chain_db_dir.clone(),
                ticker.clone(),
                account_id,
                owner.clone(),
            )
            .unwrap();
            value.clone()
        });
    }

    pub fn validate(&self) -> StepFunc {
        let value = format!("todo-validate-account --account-id={}", self.account_id);
        return Box::new(move || value.clone());
    }

    pub fn order(&self) -> Vec<StepFunc> {
        vec![self.create_account(), self.validate()]
    }
}

impl Issue {
    pub fn issue(&self) -> StepFunc {
        let value = format!("todo-issue-transaction {}", self.id);
        return Box::new(move || value.clone());
    }

    pub fn mediate(&self) -> StepFunc {
        let value = format!("todo-mediate-issue-transaction {}", self.id);
        return Box::new(move || value.clone());
    }

    pub fn validate(&self) -> StepFunc {
        let value = format!("todo-validate-issue-transaction {}", self.id);
        return Box::new(move || value.clone());
    }

    pub fn order(&self) -> Vec<StepFunc> {
        vec![self.issue(), self.mediate(), self.validate()]
    }
}

impl TransactionMode {
    fn sequence(&self) -> Vec<StepFunc> {
        match self {
            TransactionMode::Transaction(transaction) => transaction.order(),
            TransactionMode::Sequence { repeat, steps } => {
                let mut seq: Vec<StepFunc> = vec![];
                for _ in 0..*repeat {
                    for transaction in steps {
                        seq.extend(transaction.sequence());
                    }
                }
                seq
            }
            TransactionMode::Concurrent { repeat, steps } => {
                let mut seqs: Vec<Vec<StepFunc>> = vec![];
                for _ in 0..*repeat {
                    for transaction in steps {
                        seqs.push(transaction.sequence());
                    }
                }
                // TODO Tie this rng to a global rng whose seed can be set for reproduceablity
                let mut rng = rand::thread_rng();
                let mut seed = [0u8; 32];
                rng.fill(&mut seed);
                info!(
                    "Using seed {:?} for interleaving the transactions.",
                    base64::encode(seed)
                );

                let mut rng = StdRng::from_seed(seed);
                let mut seq: Vec<StepFunc> = vec![];

                while seqs.len() != 0 {
                    let next = rng.gen_range(0, seqs.len());
                    if seqs[next].len() == 0 {
                        seqs.remove(next);
                        continue;
                    }
                    seq.push(seqs[next].remove(0));
                }
                seq
            }
        }
    }
}

impl TestCase {
    fn run(&self) -> Result<HashSet<Account>, Error> {
        self.chain_setup()?;
        let start = Instant::now();
        for transaction in self.transactions.sequence() {
            info!("Running {}", transaction());
        }
        let duration = Instant::now() - start;
        if duration.as_millis() > self.timing_limit {
            return Err(Error::TimeLimitExceeded {
                want: self.timing_limit,
                got: duration.as_millis(),
            });
        }
        self.resulting_accounts()
    }

    fn chain_setup(&self) -> Result<(), Error> {
        process_asset_id_creation(self.chain_db_dir.clone(), self.ticker_names.clone())
    }

    /// Reads the contents of all the accounts from the on-chain directory and decrypts
    /// the balance with the secret account from the off-chain directory.
    fn resulting_accounts(&self) -> Result<HashSet<Account>, Error> {
        let mut accounts: HashSet<Account> = HashSet::new();
        let mut path = self.chain_db_dir.clone();
        path.push(ON_CHAIN_DIR);

        for dir in all_dirs_in_dir(path)? {
            if let Some(user) = dir.file_name().and_then(|user| user.to_str()) {
                if user != COMMON_OBJECTS_DIR {
                    for ticker in self.ticker_names.clone() {
                        let pub_file_name = format!("{}_{}", ticker, PUBLIC_ACCOUNT_FILE);
                        let sec_file_name = format!("{}_{}", ticker, SECRET_ACCOUNT_FILE);

                        let mut path = dir.clone();
                        path.push(pub_file_name.clone());
                        if !path.exists() {
                            continue;
                        }
                        let pub_account: PubAccount = load_object(
                            self.chain_db_dir.clone(),
                            ON_CHAIN_DIR,
                            user,
                            &pub_file_name,
                        )?;
                        let sec_account: SecAccount = load_object(
                            self.chain_db_dir.clone(),
                            OFF_CHAIN_DIR,
                            user,
                            &sec_file_name,
                        )?;
                        let account = cryptography::mercat::Account {
                            pblc: pub_account,
                            scrt: sec_account,
                        };
                        let balance = account.decrypt_balance().unwrap();
                        accounts.insert(Account {
                            owner: String::from(user),
                            ticker,
                            balance,
                        });
                    }
                }
            }
        }
        Ok(accounts)
    }
}

// ------------------------------------------------------------------------------------------
// -                                  Utility functions                                     -
// ------------------------------------------------------------------------------------------
fn cheater_flag(is_cheater: bool) -> String {
    if is_cheater {
        String::from("--cheater")
    } else {
        String::from("")
    }
}

fn all_files_in_dir(dir: PathBuf) -> io::Result<Vec<PathBuf>> {
    let mut files = vec![];
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_dir() {
            files.push(path);
        }
    }
    Ok(files)
}

fn all_dirs_in_dir(dir: PathBuf) -> Result<Vec<PathBuf>, Error> {
    let mut files = vec![];
    for entry in fs::read_dir(dir.clone()).map_err(|error| Error::FileReadError {
        error,
        path: dir.clone(),
    })? {
        let entry = entry.map_err(|error| Error::FileReadError {
            error,
            path: dir.clone(),
        })?;
        let path = entry.path();
        if path.is_dir() {
            files.push(path);
        }
    }
    Ok(files)
}
fn make_empty_accounts(
    accounts: &Vec<Account>,
    chain_db_dir: PathBuf,
) -> Result<(u32, TransactionMode), Error> {
    let mut account_id = 0;
    let mut transaction_counter = 0;
    let mut seq: Vec<TransactionMode> = vec![];
    for account in accounts {
        let mut rng = rand::thread_rng();
        let mut seed = [0u8; 32];
        rng.fill(&mut seed);
        let seed = base64::encode(seed); // TODO consolidate all the rngs and seeds into one place instead of littering the code
        seq.push(TransactionMode::Transaction(Transaction::Create(Create {
            id: transaction_counter,
            seed: seed,
            chain_db_dir: chain_db_dir.clone(),
            account_id: account_id,
            owner: Party {
                name: account.owner.clone(),
                cheater: false, // TODO: test harness does not support cheating for account creation yet.
            },
            ticker: account.ticker.clone(),
        })));
        account_id += 1;
        transaction_counter += 1;
    }
    Ok((
        transaction_counter,
        TransactionMode::Sequence {
            repeat: 1,
            steps: seq,
        },
    ))
}

fn to_string(value: &Yaml, path: PathBuf, attribute: &str) -> Result<String, Error> {
    Ok(value
        .as_str()
        .ok_or(Error::ErrorParsingTestHarnessConfig {
            path: path,
            reason: format!("Failed to read {}", attribute),
        })?
        .to_string())
}

fn to_hash<'a>(
    value: &'a Yaml,
    path: PathBuf,
    attribute: &str,
) -> Result<&'a LinkedHashMap<Yaml, Yaml>, Error> {
    if let Yaml::Hash(hash) = value {
        Ok(hash)
    } else {
        Err(Error::ErrorParsingTestHarnessConfig {
            path,
            reason: format!("Failed to parse {} as hash", attribute),
        })
    }
}

fn to_array<'a>(value: &'a Yaml, path: PathBuf, attribute: &str) -> Result<&'a Vec<Yaml>, Error> {
    if let Yaml::Array(array) = value {
        Ok(array)
    } else {
        Err(Error::ErrorParsingTestHarnessConfig {
            path,
            reason: format!("Failed to parse {} as array", attribute),
        })
    }
}

fn parse_transactions(
    value: &Yaml,
    path: PathBuf,
    attribute: &str,
    transaction_id: u32,
) -> Result<(u32, Vec<TransactionMode>), Error> {
    let mut transaction_list: Vec<TransactionMode> = vec![];
    let mut transaction_id = transaction_id;
    let transactions = to_array(value, path.clone(), attribute)?;
    for transaction in transactions.into_iter() {
        match &transaction {
            Yaml::Hash(transaction) => {
                for (key, value) in transaction {
                    let key = to_string(key, path.clone(), "todo")?;
                    let (new_transaction_id, steps) =
                        parse_transactions(value, path.clone(), "todo", transaction_id)?;
                    transaction_id = new_transaction_id;
                    if key == "sequence" {
                        // TODO add repeat to the config. Create new story for it.
                        transaction_list.push(TransactionMode::Sequence { repeat: 1, steps });
                    } else if key == "concurrent" {
                        transaction_list.push(TransactionMode::Concurrent { repeat: 1, steps });
                    } else {
                        // raise key error
                    }
                }
            }
            Yaml::String(transaction) => {
                if let Some(issue) = Issue::try_from((transaction_id, transaction.to_string()))
                    .map_err(|_| Error::ErrorParsingTestHarnessConfig {
                        path: path.clone(),
                        reason: String::from("todo"),
                    })
                    .ok()
                {
                    transaction_id += 1;
                    transaction_list.push(TransactionMode::Transaction(Transaction::Issue(issue)));
                } else if let Some(transfer) =
                    Transfer::try_from((transaction_id, transaction.to_string()))
                        .map_err(|_| Error::ErrorParsingTestHarnessConfig {
                            path: path.clone(),
                            reason: String::from("todo"),
                        })
                        .ok()
                {
                    transaction_id += 1;
                    transaction_list.push(TransactionMode::Transaction(Transaction::Transfer(
                        transfer,
                    )));
                }
            }
            _ => {

                // TODO raise error
            }
        }
    }

    Ok((transaction_id, transaction_list))
}

fn parse_config(path: PathBuf) -> Result<TestCase, Error> {
    let config = fs::read_to_string(path.clone()).map_err(|error| Error::FileReadError {
        error,
        path: path.clone(),
    })?;
    let config = YamlLoader::load_from_str(&config).unwrap();
    let config = &config[0];

    let title: String = to_string(&config["title"], path.clone(), "title")?;
    let mut ticker_names: Vec<String> = vec![];
    if let Yaml::Array(tickers_yaml) = &config["tickers"] {
        for ticker in tickers_yaml {
            ticker_names.push(to_string(&ticker, path.clone(), "ticker")?)
        }
    }

    let mut all_accounts: Vec<Account> = vec![];
    let accounts = to_array(&config["accounts"], path.clone(), "accounts")?;
    for user in accounts {
        let user = to_hash(&user, path.clone(), "accounts.user")?;
        for (user, tickers) in user {
            let user = to_string(&user, path.clone(), "accounts.user")?;
            let tickers = to_array(&tickers, path.clone(), "accounts.tickers")?;
            for ticker in tickers {
                let ticker = to_string(
                    &ticker,
                    path.clone(),
                    &format!("accounts.{}.ticker", user.clone()),
                )?;
                all_accounts.push(Account {
                    balance: 0,
                    owner: user.clone(),
                    ticker,
                });
            }
        }
    }

    let mut accounts_outcome: HashSet<Account> = HashSet::new();
    let outcomes = to_array(&config["outcome"], path.clone(), "outcome")?;
    let mut timing_limit: u128 = 0;
    for outcome in outcomes {
        let outcome_type = to_hash(&outcome, path.clone(), "outcome.key")?;
        for (key, value) in outcome_type {
            let key = to_string(key, path.clone(), "outcome.key")?;
            if key == "time-limit" {
                if let Some(expected_time_limit) = value.as_i64() {
                    // TODO generalize error
                    timing_limit =
                        u128::try_from(expected_time_limit).map_err(|_| Error::BalanceTooBig)?;
                }
            } else {
                let accounts_for_user =
                    to_array(&value, path.clone(), &format!("outcome.{}.ticker", key))?;
                let owner = key.clone();
                for accounts in accounts_for_user {
                    let accounts =
                        to_hash(&accounts, path.clone(), &format!("outcome.{}.ticker", key))?;
                    for (ticker, amount) in accounts {
                        let ticker = to_string(
                            &ticker,
                            path.clone(),
                            &format!("outcome.{}.ticker", owner.clone()),
                        )?;
                        let balance =
                            amount
                                .as_i64()
                                .ok_or(Error::ErrorParsingTestHarnessConfig {
                                    path: path.clone(),
                                    reason: format!(
                                        "failed to convert expect amount for outcome.{}.{}",
                                        owner.clone(),
                                        ticker.clone()
                                    ),
                                })?;
                        let balance = u32::try_from(balance).map_err(|_| Error::BalanceTooBig)?;
                        accounts_outcome.insert(Account {
                            owner: owner.clone(),
                            ticker: ticker.clone(),
                            balance,
                        });
                    }
                }
            }
        }
    }

    let mut chain_db_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    chain_db_dir.push("chain_dir/unittest/node/simple"); // TODO change
    let (next_transaction_id, create_account_transactions) =
        make_empty_accounts(&all_accounts, chain_db_dir.clone())?;

    // TODO declared mutable since later I want to consume a single element of it
    let (_, mut transactions) = parse_transactions(
        &config["transactions"],
        path.clone(),
        "transactions",
        next_transaction_id,
    )?;

    if transactions.len() != 1 {
        return Err(Error::TopLevelTransaction);
    }
    let transactions = TransactionMode::Sequence {
        repeat: 1,
        steps: vec![create_account_transactions, transactions.remove(0)],
    };
    Ok(TestCase {
        title,
        ticker_names,
        transactions,
        accounts_outcome,
        timing_limit,
        chain_db_dir,
    })
}

fn accounts_are_equal(want: &HashSet<Account>, got: &HashSet<Account>) -> bool {
    let intersection: HashSet<_> = want.intersection(&got).collect();
    intersection.len() == want.len() && want.len() == got.len()
}

// This is called from the test and benchmark. Allowing it be unused to silence compiler warnings.
#[allow(unused)]
fn run_from(relative: &str) {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push(relative);
    let configs = all_files_in_dir(path).unwrap();
    for config in configs {
        let testcase = &parse_config(config).unwrap();
        info!("Running test case: {}.", testcase.title);
        let want = &testcase.accounts_outcome;
        let got = &testcase.run().unwrap();
        assert!(
            accounts_are_equal(want, got),
            format!("want: {:?}, got: {:?}", want, got)
        );
    }
}

// ------------------------------------------------------------------------------------------------
// -                                            Tests                                             -
// ------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use env_logger;
    //use sp_std::prelude::*;

    #[test]
    fn test_on_slow_pc() {
        env_logger::init();
        run_from("scenarios/unittest/pc");
    }

    #[test]
    fn test_on_fast_node() {
        run_from("scenarios/unittest/node");
    }

    #[test] // TODO change this to wasm-test
    fn test_on_wasm() {
        run_from("scenarios/unittest/wasm");
    }
}