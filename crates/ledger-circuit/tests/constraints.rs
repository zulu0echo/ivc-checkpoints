//! Measures and prints the F-circuit's per-op and per-step R1CS/GR1CS constraint counts
//! from arkworks `ConstraintSystem` stats. These feed the decider circuit-size relation
//! (`10,543,489 + 3x` for an x-constraint step circuit, from sonobe's docs), turning the
//! analytical estimate into a measured [M] figure.
//!
//! Run with: `cargo test -p ledger-circuit --release constraint_counts -- --nocapture`

use ark_bn254::Fr;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar};
use ark_relations::gr1cs::ConstraintSystem;
use folding_schemes::frontend::FCircuit;
use ledger_circuit::native::EpochExecutor;
use ledger_circuit::{EpochStepInput, EpochStepInputVar, LedgerCircuit};

/// Build one fold step of `B` active ops over a depth-`D` tree and return the number of
/// constraints in the resulting system.
fn step_constraints<const B: usize, const D: usize>() -> usize {
    let mut exec = EpochExecutor::<Fr, D>::new();
    let token = Fr::from(1u64);
    let pool = Fr::from(1u64 << 20);
    exec.register(pool, token, 1_000_000_000, 0);
    for j in 0..B {
        exec.register(Fr::from(10_000u64 + j as u64), token, 0, 0);
    }
    // z_0 = state before this batch (all accounts registered, no ops yet).
    let z0 = exec.initial_state();

    let mut ops = Vec::with_capacity(B);
    for j in 0..B {
        let ben = Fr::from(10_000u64 + j as u64);
        ops.push(exec.load(pool, ben, token, 1));
    }

    let circuit = LedgerCircuit::<Fr, B, D>::new(()).unwrap();
    let cs = ConstraintSystem::<Fr>::new_ref();
    let z_var = Vec::<FpVar<Fr>>::new_witness(cs.clone(), || Ok(z0.to_vec())).unwrap();
    let batch = EpochStepInput::<Fr, B, D> { ops: ops.try_into().unwrap() };
    let ext = EpochStepInputVar::new_witness(cs.clone(), || Ok(batch)).unwrap();
    circuit.generate_step_constraints(cs.clone(), 0, z_var, ext).unwrap();

    assert!(cs.is_satisfied().unwrap(), "step circuit must be satisfiable");
    cs.num_constraints()
}

#[test]
fn constraint_counts() {
    // Production depth (22). Two batch sizes to isolate marginal per-op from step overhead.
    let c8 = step_constraints::<8, 22>();
    let c16 = step_constraints::<16, 22>();

    // marginal per-op = slope; step overhead = intercept.
    let per_op = (c16 - c8) / 8;
    let overhead = c16 - per_op * 16;

    println!("[M] ledger F-circuit constraint counts (depth D=22):");
    println!("[M]   B=8  step: {c8} constraints");
    println!("[M]   B=16 step: {c16} constraints");
    println!("[M]   marginal per-op: {per_op} constraints");
    println!("[M]   per-step overhead (intercept): {overhead} constraints");
    println!("[M]   => decider circuit size at B=16 ~= 10,543,489 + 3 * {c16} = {}", 10_543_489 + 3 * c16);

    // Loose sanity bounds — the point is to record the measured value, not to pin it.
    assert!(per_op > 1_000, "per-op suspiciously low: {per_op}");
    assert!(c16 > 10_000, "per-step suspiciously low: {c16}");
}
