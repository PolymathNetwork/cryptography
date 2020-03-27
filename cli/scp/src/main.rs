//! A simple commandline application to demonstrate a claim prover's (AKA an investor)
//! steps to create proofs for their claims.
//! Use `scp --help` to see the usage.
//!

use cli_common::{ Proof, random_claim };

use cryptography::claim_proofs::{compute_label, ClaimData, ProofKeyPair };
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
    claim: Option<std::path::PathBuf>,

    /// Write the proof to file in Json format.
    #[structopt(short, long, parse(from_os_str))]
    proof: Option<std::path::PathBuf>,

    /// Be verbose.
    #[structopt(short, long)]
    verbose: bool,
}



fn main() {
    let args = Cli::from_args();

    let claim_data: ClaimData = if args.rand {
        let mut rng = StdRng::from_seed([42u8; 32]);
        let rand_claim = random_claim(&mut rng);

        // If user provided the `claim` option, save this to file.
        if let Some(c) = args.claim {
            std::fs::write(
                c,
                serde_json::to_string(&rand_claim)
                    .unwrap_or_else(|error| panic!("Failed to serialize the claim: {}", error)),
            )
            .expect("Failed to write the claim to file.");
            if args.verbose {
                println!("Successfully wrote the claim to file.");
            }
        }

        rand_claim
    } else {
        match args.claim {
            Some(c) => {
                let json_file_content =
                    std::fs::read_to_string(&c).expect("Failed to read the claim from file.");
                serde_json::from_str(&json_file_content)
                    .unwrap_or_else(|error| panic!("Failed to deserialize the claim: {}", error))
            }
            None => panic!("You must either pass in a claim file or generate it randomly."),
        }
    };

    if args.verbose {
        println!("Claim: {:?}", serde_json::to_string(&claim_data).unwrap());
        println!("Message: {:?}", args.message);
    }

    let message: &[u8] = args.message.as_bytes();
    let pair = ProofKeyPair::from(claim_data);
    let proof = pair.generate_id_match_proof(message).to_bytes().to_vec();

    let did_label = compute_label(
        &claim_data.inv_id_0,
        &claim_data.inv_id_1,
        Some(&claim_data.inv_blind),
    );
    let claim_label = compute_label(&claim_data.iss_id, &claim_data.inv_id_1, None);

    // => Investor makes {did_label, claim_label, inv_id_0, iss_id, message, proof} public knowledge.
    let packaged_proof = Proof {
        did_label,
        inv_id_0: claim_data.inv_id_0,
        claim_label,
        iss_id: claim_data.iss_id,
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
