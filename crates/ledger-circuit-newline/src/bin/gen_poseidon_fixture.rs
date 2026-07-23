//! Emits a cross-check fixture for the on-chain Poseidon used by the new-line contracts.
//!
//! Computes arkworks-0.6 `CRH` (the exact hash the circuit uses, via `poseidon_circom_config`) over
//! arities 2 (Merkle node), 4 (opsAcc / netsAcc folds) and 6 (the arity-6 interval account leaf),
//! and writes `contracts/generated/newline/poseidon_fixture.json`. A Foundry test pins
//! `PoseidonT5.{hash2,hash4,hash6}` to these values. Run:
//!   cargo run -p ledger-circuit-newline --bin gen_poseidon_fixture

use ark_bn254::Fr;
use ark_crypto_primitives::crh::{poseidon::CRH, CRHScheme};
use ark_ff::{BigInteger, PrimeField};
use sonobe_primitives::transcripts::poseidon::poseidon_circom_config;

fn hex_of(f: Fr) -> String {
    let hex: String = f
        .into_bigint()
        .to_bytes_be()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let trimmed = hex.trim_start_matches('0');
    format!("0x{}", if trimmed.is_empty() { "0" } else { trimmed })
}

fn eval(inputs: &[u64]) -> String {
    let cfg = poseidon_circom_config();
    let fr: Vec<Fr> = inputs.iter().map(|x| Fr::from(*x)).collect();
    hex_of(CRH::<Fr>::evaluate(&cfg, fr).expect("poseidon"))
}

fn block(name: &str, cases: &[Vec<u64>]) -> String {
    let items: Vec<String> = cases
        .iter()
        .map(|c| {
            let ins: Vec<String> = c.iter().map(|x| format!("\"{x}\"")).collect();
            format!(
                "    {{ \"inputs\": [{}], \"output\": \"{}\" }}",
                ins.join(", "),
                eval(c)
            )
        })
        .collect();
    format!(
        "  \"{name}\": [\n{}\n  ],\n  \"{name}Count\": {}",
        items.join(",\n"),
        cases.len()
    )
}

fn main() {
    let hash2 = vec![vec![1u64, 2], vec![7, 0], vec![0, 0], vec![123456, 789]];
    let hash4 = vec![
        vec![1u64, 2, 3, 4],
        vec![0, 0, 0, 0],
        vec![1000, 1, 500, 0],
    ];
    // arity-6 interval leaf: (key, next_key, token, balance, nonce, pk_hash)
    let hash6 = vec![
        vec![2001u64, 900, 1, 0, 0, 0],
        vec![1000, 0, 1, 999500, 1, 0],
        vec![0, 0, 0, 0, 0, 0],
        vec![5, 9, 1, 42, 3, 123456],
    ];
    println!(
        "{{\n  \"config\": \"poseidon_circom_config (t=5, rate=4)\",\n{},\n{},\n{}\n}}",
        block("hash2", &hash2),
        block("hash4", &hash4),
        block("hash6", &hash6),
    );
}
