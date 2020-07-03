use confy;
use log::info;
use mercat_common::{gen_seed, save_config};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use structopt::StructOpt;

#[derive(Clone, Debug, Serialize, Deserialize, StructOpt)]
pub struct CreateMediatorAccountInfo {
    /// The name of the mediator.
    /// It is the responsibility of the caller to ensure this name is unique.
    /// If it is not unique the artifacts will be overwritten.
    #[structopt(
        short,
        long,
        help = "The name of the mediator. This name must be unique."
    )]
    pub user: String,

    /// The directory that will serve as the database of the on/off-chain data and will be used
    /// to save and load the data that in a real execution would be written to the on/off the
    /// blockchain. Defaults to the current directory. This directory will have two main
    /// sub-directories: `on-chain` and `off-chain`.
    #[structopt(
        parse(from_os_str),
        help = "The directory to load and save the input and output files. Defaults to current directory.",
        short,
        long
    )]
    pub db_dir: Option<PathBuf>,

    /// An optional seed, to feed to the RNG, that can be passed to reproduce a previous run of this CLI.
    /// The seed can be found inside the logs.
    #[structopt(
        short,
        long,
        help = "Base64 encoding of an initial seed for the RNG. If not provided, the seed will be chosen at random."
    )]
    pub seed: Option<String>,

    /// An optional path to save the config used for this experiment.
    #[structopt(
        parse(from_os_str),
        long,
        help = "Path to save the input command line arguments as a config file."
    )]
    pub save_config: Option<PathBuf>,
}

#[derive(Clone, Debug, Serialize, Deserialize, StructOpt)]
pub struct JustifyIssuanceInfo {
    /// The directory that will serve as the database of the on/off-chain data and will be used
    /// to save and load the data that in a real execution would be written to the on/off the
    /// blockchain. Defaults to the current directory. This directory will have two main
    /// sub-directories: `on-chain` and `off-chain`.
    #[structopt(
        parse(from_os_str),
        help = "The directory to load and save the input and output files. Defaults to current directory.",
        short,
        long
    )]
    pub db_dir: Option<PathBuf>,

    /// The transaction ID for the asset issuance transaction.
    /// This ID must be the same as the one used to initialize the asset issuance,
    /// using the `mercat-account` CLI.
    #[structopt(long, help = "The id of the transaction. This value must be unique.")]
    pub tx_id: u32,

    /// The name of the issuer.
    /// An account must have already been created for this user, using `mercat-account`
    /// CLI.
    #[structopt(short, long, help = "The name of the issuer.")]
    pub issuer: String,

    /// The name of the mediator.
    #[structopt(short, long, help = "The name of the mediator.")]
    pub mediator: String,

    /// An optional seed, to feed to the RNG, that can be passed to reproduce a previous run of this CLI.
    /// The seed can be found inside the logs.
    #[structopt(
        long,
        help = "Base64 encoding of an initial seed for the RNG. If not provided, the seed will be chosen at random."
    )]
    pub seed: Option<String>,

    /// Whether to reject an issuance transaction.
    #[structopt(
        short,
        long,
        help = "If present the mediator will reject the transaction."
    )]
    pub reject: bool,

    /// An optional path to save the config used for this experiment.
    #[structopt(
        parse(from_os_str),
        long,
        help = "Path to save the input command line arguments as a config file."
    )]
    pub save_config: Option<PathBuf>,
}

#[derive(Clone, Debug, Serialize, Deserialize, StructOpt)]
pub struct JustifyTransactionInfo {
    /// The directory that will serve as the database of the on/off-chain data and will be used
    /// to save and load the data that in a real execution would be written to the on/off the
    /// blockchain. Defaults to the current directory. This directory will have two main
    /// sub-directories: `on-chain` and `off-chain`.
    #[structopt(
        parse(from_os_str),
        help = "The directory to load and save the input and output files. Defaults to current directory.",
        short,
        long
    )]
    pub db_dir: Option<PathBuf>,

    /// The transaction ID for the asset transaction.
    /// This ID must be the same as the one used to create the transaction,
    /// using the `mercat-account` CLI.
    #[structopt(long, help = "The id of the transaction. This value must be unique.")]
    pub tx_id: u32,

    /// Asset id that is transferred.
    /// An asset ticker name which is a string of at most 12 characters.
    #[structopt(
        short,
        long,
        help = "The asset ticker id. String of at most 12 characters."
    )]
    pub ticker_id: String,

    /// The name of the sender.
    /// An account must have already been created for this user, using `mercat-account`
    /// CLI.
    #[structopt(long, help = "The name of the sender.")]
    pub sender: String,

    /// An account must have already been created for this user, using `mercat-account`
    /// CLI.
    #[structopt(long, help = "The name of the receiver.")]
    pub receiver: String,

    /// The name of the mediator.
    #[structopt(short, long, help = "The name of the mediator.")]
    pub mediator: String,

    /// Whether to reject a transaction.
    #[structopt(
        short,
        long,
        help = "If present the mediator will reject the transaction."
    )]
    pub reject: bool,

    /// An optional path to save the config used for this experiment.
    #[structopt(
        parse(from_os_str),
        long,
        help = "Path to save the input command line arguments as a config file."
    )]
    pub save_config: Option<PathBuf>,
}

#[derive(Clone, Debug, Serialize, Deserialize, StructOpt)]
pub enum CLI {
    /// Create a MERCAT mediator account.
    Create(CreateMediatorAccountInfo),

    /// Justify a MERCAT asset issuance transaction.
    JustifyIssuance(JustifyIssuanceInfo),

    /// Justify a MERCAT transaction.
    JustifyTransaction(JustifyTransactionInfo),
}

pub fn parse_input() -> Result<CLI, confy::ConfyError> {
    info!("Parsing input configuration.");
    let args: CLI = CLI::from_args();

    match args {
        CLI::Create(cfg) => {
            // Set the default seed and db_dir if needed.
            let db_dir = cfg.db_dir.clone().or_else(|| std::env::current_dir().ok());

            let seed: Option<String> = cfg.seed.clone().or_else(|| Some(gen_seed()));
            info!("Seed: {:?}", seed.clone().unwrap());

            let cfg = CreateMediatorAccountInfo {
                save_config: cfg.save_config.clone(),
                seed,
                db_dir,
                user: cfg.user.clone(),
            };

            info!(
                "Parsed the following config from the command line:\n{:#?}",
                cfg
            );

            // Save the config if the argument is passed.
            save_config(cfg.save_config.clone(), &cfg);

            return Ok(CLI::Create(cfg));
        }

        CLI::JustifyIssuance(cfg) => {
            // Set the default seed and db_dir if needed.
            let db_dir = cfg.db_dir.clone().or_else(|| std::env::current_dir().ok());

            let seed: Option<String> = cfg.seed.clone().or_else(|| Some(gen_seed()));
            info!("Seed: {:?}", seed.clone().unwrap());
            let cfg = JustifyIssuanceInfo {
                db_dir,
                tx_id: cfg.tx_id,
                issuer: cfg.issuer,
                mediator: cfg.mediator,
                seed,
                reject: cfg.reject,
                save_config: cfg.save_config.clone(),
            };

            info!(
                "Parsed the following config from the command line:\n{:#?}",
                cfg.clone()
            );

            // Save the config if the argument is passed.
            save_config(cfg.save_config.clone(), &cfg);

            return Ok(CLI::JustifyIssuance(cfg));
        }

        CLI::JustifyTransaction(cfg) => {
            // Set the default seed and db_dir if needed.
            let db_dir = cfg.db_dir.clone().or_else(|| std::env::current_dir().ok());

            let cfg = JustifyTransactionInfo {
                db_dir,
                tx_id: cfg.tx_id,
                ticker_id: cfg.ticker_id,
                sender: cfg.sender,
                receiver: cfg.receiver,
                mediator: cfg.mediator,
                reject: cfg.reject,
                save_config: cfg.save_config.clone(),
            };

            info!(
                "Parsed the following config from the command line:\n{:#?}",
                cfg.clone()
            );

            // Save the config if the argument is passed.
            save_config(cfg.save_config.clone(), &cfg);

            return Ok(CLI::JustifyTransaction(cfg));
        }
    }
}
