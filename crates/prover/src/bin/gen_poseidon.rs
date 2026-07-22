//! Generate `contracts/src/PoseidonT5.sol` and `contracts/generated/poseidon_t5_fixture.json`
//! from arkworks' canonical Poseidon constants.
//!
//! Run: `cargo run -p prover --bin gen_poseidon`

use std::fs;
use std::path::PathBuf;

use prover::poseidon_codegen::{generate_fixture, generate_solidity};

fn repo_root() -> PathBuf {
    // crates/prover -> repo root
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().unwrap()
}

fn main() -> anyhow::Result<()> {
    let root = repo_root();
    let sol_path = root.join("contracts/src/PoseidonT5.sol");
    let fixture_path = root.join("contracts/generated/poseidon_t5_fixture.json");

    fs::create_dir_all(sol_path.parent().unwrap())?;
    fs::create_dir_all(fixture_path.parent().unwrap())?;

    fs::write(&sol_path, generate_solidity())?;
    fs::write(&fixture_path, serde_json::to_string_pretty(&generate_fixture())?)?;

    println!("wrote {}", sol_path.display());
    println!("wrote {}", fixture_path.display());
    Ok(())
}
