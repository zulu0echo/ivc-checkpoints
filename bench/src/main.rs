//! End-to-end prover-side measurement. Folds a synthetic epoch, produces the decider
//! proof, and records the measured [M] numbers: per-step fold time, decider prove time,
//! peak RSS, calldata bytes, and the revm-metered verifyNovaProof gas. Writes
//! `results/prover.json`, which `script/compare_to_model.py` merges with the Foundry
//! tx-level gas into `results/measured.json`.
//!
//! The default (small) path is CI-sized. `--features full-bench` runs the large daily
//! epoch. Wrap with `/usr/bin/time -v` (GNU) on the prover box for authoritative peak RSS.

use std::fs;
use std::path::PathBuf;

use clap::Parser;
use prover::workload::{self, WorkloadSpec};
use prover::prove_epoch;

#[derive(Parser)]
struct Args {
    /// "small" or "large". Defaults to large iff built with --features full-bench.
    #[arg(long)]
    scale: Option<String>,
    #[arg(long, default_value_t = 1)]
    epoch: u64,
    /// Pad to a fixed number of fold steps (constant public `i`) — privacy mode.
    #[arg(long)]
    pad_steps: Option<usize>,
    /// Override peak RSS (KB) — e.g. fed from an outer `/usr/bin/time -v` wrapper.
    #[arg(long)]
    rss_kb: Option<u64>,
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..").canonicalize().unwrap()
}

fn peak_rss_bytes() -> u64 {
    unsafe {
        let mut ru: libc::rusage = std::mem::zeroed();
        libc::getrusage(libc::RUSAGE_SELF, &mut ru);
        let m = ru.ru_maxrss as u64;
        // macOS reports bytes; Linux reports KB.
        if cfg!(target_os = "macos") {
            m
        } else {
            m.saturating_mul(1024)
        }
    }
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let default_scale = if cfg!(feature = "full-bench") { "large" } else { "small" };
    let scale = args.scale.unwrap_or_else(|| default_scale.to_string());
    let spec = match scale.as_str() {
        "small" => WorkloadSpec::small(),
        "large" => WorkloadSpec::large_daily(),
        other => anyhow::bail!("unknown scale '{other}'"),
    }
    .with_pad_to_steps(args.pad_steps);

    eprintln!("[bench] scale={scale} ops={}", spec.total_ops());
    let wl = workload::build(spec, args.epoch);
    let n_steps = wl.batches.len();

    let art = prove_epoch(args.epoch, wl.token_id, wl.z0.clone(), wl.batches, wl.nets, wl.transfers_root)?;
    anyhow::ensure!(art.zn == wl.native_zn, "Nova z_n != native z_n");

    let peak_rss = args.rss_kb.map(|kb| kb * 1024).unwrap_or_else(peak_rss_bytes);
    let fold_total: u128 = art.fold_times_ms.iter().sum();
    let fold_avg = if n_steps > 0 { fold_total / n_steps as u128 } else { 0 };

    let out = serde_json::json!({
        "scale": scale,
        "op_count": spec.total_ops(),
        "steps": art.steps,
        "batch_size": ledger_circuit::BATCH,
        "tree_depth": ledger_circuit::DEPTH,
        "z_len": ledger_circuit::STATE_LEN,
        "fold_ms_total": fold_total,
        "fold_ms_per_step_avg": fold_avg,
        "fold_ms_per_step": art.fold_times_ms,
        "decider_prove_ms": art.decider_prove_ms,
        "peak_rss_bytes": peak_rss,
        "calldata_bytes": art.calldata_bytes,
        "verify_gas_revm": art.evm_verify_gas,
        "light_test": cfg!(feature = "light-test"),
        "platform": std::env::consts::OS,
    });

    let results_dir = repo_root().join("results");
    fs::create_dir_all(&results_dir)?;
    let path = results_dir.join("prover.json");
    fs::write(&path, serde_json::to_string_pretty(&out)?)?;

    println!("[bench] steps={} fold_avg={fold_avg}ms decider={}ms revm_gas={} calldata={}B rss={}MB",
        art.steps, art.decider_prove_ms, art.evm_verify_gas, art.calldata_bytes, peak_rss / (1024 * 1024));
    println!("[bench] wrote {}", path.display());
    if cfg!(feature = "light-test") {
        println!("[bench] NOTE: light-test build — prover time/RSS are NOT production figures; verifier gas IS representative.");
    }
    Ok(())
}
