//! A simple commandline application to demonstrate a claim prover's (AKA an investor)
//! steps to create proofs for their claims.
//! Use `scp --help` to see the usage.
//!

use cli_common::Proof;

use cryptography::claim_proofs::{
    build_scope_claim_proof_data, compute_cdd_id, compute_scope_id, random_claim, ProofKeyPair,
};
use rand::{rngs::StdRng, SeedableRng};
use serde::{Deserialize, Serialize};
use structopt::StructOpt;

/// scp -- a simple claim prover.{n}
/// The scp utility (optionally) creates a random claim and proves it.
#[derive(StructOpt, Debug, Serialize, Deserialize)]
struct Cli {
    /// Generate and use a random claim.
    #[structopt(short, long)]
    rand: bool,

    /// Message to prove.
    #[structopt(short, long, default_value = "A very important claim.")]
    message: String,

    /// Get the Json formatted claim from file.
    /// If this option is provided along with `rand`,
    /// it will save the randomly generated claim to file.
    #[structopt(short, long, parse(from_os_str))]
    cdd_claim: Option<std::path::PathBuf>,

    #[structopt(short, long, parse(from_os_str))]
    scope_claim: Option<std::path::PathBuf>,

    /// Write the proof to file in Json format.
    #[structopt(short, long, parse(from_os_str))]
    proof: Option<std::path::PathBuf>,

    /// Be verbose.
    #[structopt(short, long)]
    verbose: bool,
}

fn main() {
    let args = Cli::from_args();

    let (cdd_claim, scope_claim) = if args.rand {
        let mut rng = StdRng::from_seed([42u8; 32]);
        let (rand_cdd_claim, rand_scope_claim) = random_claim(&mut rng);

        // If user provided the `claim` option, save this to file.
        if let Some(c) = args.cdd_claim {
            std::fs::write(
                c,
                serde_json::to_string(&rand_cdd_claim)
                    .unwrap_or_else(|error| panic!("Failed to serialize the cdd claim: {}", error)),
            )
            .expect("Failed to write the cdd claim to file.");
            if args.verbose {
                println!("Successfully wrote the cdd claim to file.");
            }
        }

        if let Some(c) = args.scope_claim {
            std::fs::write(
                c,
                serde_json::to_string(&rand_scope_claim).unwrap_or_else(|error| {
                    panic!("Failed to serialize the scope claim: {}", error)
                }),
            )
            .expect("Failed to write the scope claim to file.");
            if args.verbose {
                println!("Successfully wrote the scope claim to file.");
            }
        }

        (rand_cdd_claim, rand_scope_claim)
    } else {
        let file_cdd_claim = match args.cdd_claim {
            Some(c) => {
                let json_file_content =
                    std::fs::read_to_string(&c).expect("Failed to read the cdd claim from file.");
                serde_json::from_str(&json_file_content).unwrap_or_else(|error| {
                    panic!("Failed to deserialize the cdd claim: {}", error)
                })
            }
            None => panic!("You must either pass in a claim file or generate it randomly."),
        };
        let file_scope_claim = match args.scope_claim {
            Some(c) => {
                let json_file_content =
                    std::fs::read_to_string(&c).expect("Failed to read the scope claim from file.");
                serde_json::from_str(&json_file_content).unwrap_or_else(|error| {
                    panic!("Failed to deserialize the scope claim: {}", error)
                })
            }
            None => panic!("You must either pass in a claim file or generate it randomly."),
        };
        (file_cdd_claim, file_scope_claim)
    };

    if args.verbose {
        println!(
            "CDD Claim: {:?}",
            serde_json::to_string(&cdd_claim).unwrap()
        );
        println!(
            "Scope Claim: {:?}",
            serde_json::to_string(&scope_claim).unwrap()
        );
        println!("Message: {:?}", args.message);
    }

    let message: &[u8] = args.message.as_bytes();
    let scope_claim_proof_data = build_scope_claim_proof_data(&cdd_claim, &scope_claim);

    let pair = ProofKeyPair::from(scope_claim_proof_data);
    let proof = pair.generate_id_match_proof(message).to_bytes().to_vec();

    let cdd_id = compute_cdd_id(&cdd_claim);
    let scope_id = compute_scope_id(&scope_claim);

    // => Investor makes {did_label, claim_label, inv_id_0, iss_id, message, proof} public knowledge.
    let packaged_proof = Proof {
        cdd_id: cdd_id,
        investor_did: cdd_claim.investor_did,
        scope_id: scope_id,
        scope_did: scope_claim.scope_did,
        proof,
    };
    let proof_str = serde_json::to_string(&packaged_proof)
        .unwrap_or_else(|error| panic!("Failed to serialize the proof: {}", error));

    if args.verbose {
        println!("Proof Package: {:?}", proof_str);
    }

    if let Some(p) = args.proof {
        std::fs::write(p, proof_str.as_bytes()).expect("Failed to write the proof to file.");
        println!("Successfully wrote the proof.");
    }
}
