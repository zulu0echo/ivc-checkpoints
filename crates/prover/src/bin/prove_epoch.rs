//! Drive one epoch: build a synthetic workload, fold it, produce the DeciderEth proof,
//! and emit the generated verifier + settlement calldata into `contracts/generated/`.
//!
//! Run (small path, needs `light-test` on modest hardware):
//!   cargo run -p prover --bin prove_epoch --release --features light-test -- --scale small
//! Full path (real verifier, ~64 GB RAM):
//!   cargo run -p prover --bin prove_epoch --release -- --scale large

use std::fs;
use std::path::PathBuf;

use clap::Parser;
use prover::workload::{self, WorkloadSpec};
use prover::{fr_to_hex, prove_epoch};

#[derive(Parser)]
#[command(about = "Fold an epoch and emit the on-chain verifier + calldata")]
struct Args {
    /// Workload scale: "small" (few-hundred ops, CI) or "large" (~42,705 ops).
    #[arg(long, default_value = "small")]
    scale: String,
    /// Epoch number.
    #[arg(long, default_value_t = 1)]
    epoch: u64,
    /// Pad to a fixed number of fold steps (constant public `i`) — privacy mode; see
    /// docs/TRUST_MODEL.md §Privacy. Must be >= the epoch's real step count.
    #[arg(long)]
    pad_steps: Option<usize>,
    /// Output directory for artifacts (default: <repo>/contracts/generated).
    #[arg(long)]
    out: Option<PathBuf>,
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().unwrap()
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let spec = match args.scale.as_str() {
        "small" => WorkloadSpec::small(),
        "large" => WorkloadSpec::large_daily(),
        other => anyhow::bail!("unknown scale '{other}' (use 'small' or 'large')"),
    }
    .with_pad_to_steps(args.pad_steps);
    let out_dir = args.out.unwrap_or_else(|| repo_root().join("contracts/generated"));
    fs::create_dir_all(&out_dir)?;

    eprintln!(
        "building workload scale={} ({} ops, {} accounts, {} payees)",
        args.scale,
        spec.total_ops(),
        spec.n_accounts,
        spec.n_payees
    );
    let wl = workload::build(spec, args.epoch);

    eprintln!("folding {} steps + decider prove (this is the slow part)...", wl.batches.len());
    let art = prove_epoch(
        args.epoch,
        wl.token_id,
        wl.z0.clone(),
        wl.batches,
        wl.nets,
        wl.transfers_root,
    )?;

    // Cross-check Nova's z_n against the native executor.
    anyhow::ensure!(
        art.zn == wl.native_zn,
        "Nova z_n != native z_n (circuit/native mismatch)"
    );

    // --- write artifacts -----------------------------------------------------
    let decider_path = out_dir.join("NovaDecider.sol");
    fs::write(&decider_path, &art.decider_sol)?;

    let nets_json: Vec<serde_json::Value> = art
        .nets
        .iter()
        .map(|n| {
            serde_json::json!({
                "addr": format!("0x{}", hex::encode(n.addr)),
                "key": fr_to_hex(&n.key),
                "amount": n.amount.to_string(),
            })
        })
        .collect();

    // Parallel arrays for easy Foundry parsing (vm.parseJsonAddressArray / UintArray).
    let net_addrs: Vec<String> = art.nets.iter().map(|n| format!("0x{}", hex::encode(n.addr))).collect();
    let net_amounts: Vec<String> = art.nets.iter().map(|n| n.amount.to_string()).collect();

    // Escape-hatch witness (for exercising ProvenCheckpoint.exit against the last proven root).
    let ex = &wl.exit;
    let exit_json = serde_json::json!({
        "owner": format!("0x{}", hex::encode(ex.owner)),
        "tokenId": ex.token_id,
        "balance": ex.balance.to_string(),
        "nonce": ex.nonce,
        "key": fr_to_hex(&ex.key),
        "siblings": ex.siblings.iter().map(|s| format!("{s}")).collect::<Vec<_>>(),
        "isRight": ex.is_right,
    });

    let proof_json = serde_json::json!({
        "epoch": art.epoch,
        "tokenId": art.token_id,
        "steps": art.steps,
        "prevStateRoot": fr_to_hex(&art.z0[0]),
        "newStateRoot": fr_to_hex(&art.zn[0]),
        "opsAcc": fr_to_hex(&art.zn[1]),
        "netsAcc": fr_to_hex(&art.zn[2]),
        "transfersRoot": format!("0x{}", hex::encode(art.transfers_root)),
        "proof": art.proof_words,
        "netAddrs": net_addrs,
        "netAmounts": net_amounts,
        "nets": nets_json,
        "exit": exit_json,
        "calldataBytes": art.calldata_bytes,
        "evmVerifyGasRevm": art.evm_verify_gas,
    });
    fs::write(out_dir.join("proof.json"), serde_json::to_string_pretty(&proof_json)?)?;
    fs::write(
        out_dir.join("calldata_explicit.hex"),
        format!("0x{}", hex::encode(&art.calldata_explicit)),
    )?;

    eprintln!("--- measurements (this run) ---");
    eprintln!("steps: {}", art.steps);
    let fold_total: u128 = art.fold_times_ms.iter().sum();
    eprintln!(
        "fold: {} ms total, {} ms/step avg",
        fold_total,
        if art.steps > 0 { fold_total / art.steps as u128 } else { 0 }
    );
    eprintln!("decider prove: {} ms", art.decider_prove_ms);
    eprintln!("verifyNovaProof gas (revm): {}", art.evm_verify_gas);
    eprintln!("calldata: {} bytes", art.calldata_bytes);
    eprintln!("wrote artifacts to {}", out_dir.display());
    Ok(())
}
