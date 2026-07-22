//! Epoch-ledger F-circuit, implemented directly against sonobe's arkworks `FCircuit`
//! trait (no Circom/Noir frontend).
//!
//! IVC state `z = [stateRoot, opsAcc, netsAcc]` (`STATE_LEN = 3`). Each fold step
//! consumes a batch of `B` operations (a const generic — a pure prover-side knob, no
//! on-chain effect) and, per active op, enforces:
//!
//! 1. **Inclusion** — `from`/`to` leaves open against the running `stateRoot`
//!    (Poseidon IMT, depth `D` = 22).
//! 2. **Solvency** — `balance(from) ≥ amount`, with `amount`/balances range-checked to
//!    96 bits (so field wraparound cannot forge solvency).
//! 3. **Replay protection** — witnessed `nonce == leaf.nonce`; the leaf nonce increments
//!    on the debit write.
//! 4. **Conservation** — `from` debited and `to` credited by exactly `amount` (structural).
//! 5. **Accumulation** — `opsAcc` folds every op hash; `netsAcc` folds `(payeeKey,
//!    tokenId, amount)` for `withdraw` ops only. `netsAcc` uses a **fixed 4-input**
//!    Poseidon so the contract can recompute it on-chain (`withdrawalsAcc`).
//!
//! Padding ops (`active = false`, for the final partial batch) compute the same hashes
//! but are conditionally excluded from every enforcement and state update, so per-step
//! cost is uniform and padding is a true no-op.

pub mod imt;
pub mod native;
pub mod ops;
pub mod poseidon;

use ark_crypto_primitives::sponge::{poseidon::PoseidonConfig, Absorb};
use ark_ff::PrimeField;
use ark_r1cs_std::{
    boolean::Boolean,
    convert::ToBitsGadget,
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
    select::CondSelectGadget,
};
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};
use folding_schemes::{frontend::FCircuit, Error};

pub use ops::{EpochStepInput, EpochStepInputVar, OpKind, OpWitness};
pub use poseidon::{canonical_config, PoseidonGadget, PoseidonNative};

use imt::merkle_root_from_leaf;
use poseidon::PoseidonGadget as PG;

/// IVC state length: [stateRoot, opsAcc, netsAcc].
pub const STATE_LEN: usize = 3;
/// Production tree depth (spec §Data Structures: ~4.2M leaves).
pub const DEPTH: usize = 22;
/// Production batch size (spec §F-circuit semantics: B = 16).
pub const BATCH: usize = 16;

/// Withdraw op kind code, matched against `kind` in-circuit to gate `netsAcc`.
const WITHDRAW_CODE: u64 = OpKind::Withdraw as u64;
/// Balances/amounts are 96-bit (spec §F-circuit semantics, solvency).
const VALUE_BITS: usize = 96;

/// The epoch-ledger step circuit. `B` ops per step, tree depth `D`.
#[derive(Clone, Debug)]
pub struct LedgerCircuit<F: PrimeField + Absorb, const B: usize, const D: usize> {
    poseidon_config: PoseidonConfig<F>,
}

/// The production instantiation: batch 16, depth 22.
pub type LedgerStep<F> = LedgerCircuit<F, BATCH, DEPTH>;

impl<F: PrimeField + Absorb, const B: usize, const D: usize> LedgerCircuit<F, B, D> {
    pub fn config(&self) -> &PoseidonConfig<F> {
        &self.poseidon_config
    }
}

impl<F: PrimeField + Absorb, const B: usize, const D: usize> FCircuit<F> for LedgerCircuit<F, B, D> {
    type Params = ();
    type ExternalInputs = EpochStepInput<F, B, D>;
    type ExternalInputsVar = EpochStepInputVar<F>;

    fn new(_params: Self::Params) -> Result<Self, Error> {
        Ok(Self { poseidon_config: canonical_config::<F>() })
    }

    fn state_len(&self) -> usize {
        STATE_LEN
    }

    fn generate_step_constraints(
        &self,
        cs: ConstraintSystemRef<F>,
        _i: usize,
        z_i: Vec<FpVar<F>>,
        external_inputs: Self::ExternalInputsVar,
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        assert_eq!(z_i.len(), STATE_LEN, "state must be [stateRoot, opsAcc, netsAcc]");
        assert_eq!(external_inputs.ops.len(), B, "batch must carry exactly B ops");

        let poseidon = PG::<F>::new(cs.clone(), &self.poseidon_config)?;
        let withdraw_code = FpVar::constant(F::from(WITHDRAW_CODE));
        let one = FpVar::<F>::one();

        let mut state_root = z_i[0].clone();
        let mut ops_acc = z_i[1].clone();
        let mut nets_acc = z_i[2].clone();

        for op in external_inputs.ops.iter() {
            // --- (1) inclusion of the `from` leaf against the current stateRoot ------
            let from_old_leaf =
                poseidon.h4(&op.from_key, &op.token_id, &op.from_old_balance, &op.from_old_nonce)?;
            let from_old_root =
                merkle_root_from_leaf(&poseidon, &from_old_leaf, &op.from_siblings, &op.from_index_bits)?;
            from_old_root.conditional_enforce_equal(&state_root, &op.active)?;

            // --- (2) solvency + 96-bit range on amount, balance, and the debit --------
            enforce_bit_width(&op.amount, VALUE_BITS)?;
            enforce_bit_width(&op.from_old_balance, VALUE_BITS)?;
            let from_new_balance = &op.from_old_balance - &op.amount;
            enforce_bit_width(&from_new_balance, VALUE_BITS)?; // fails iff balance < amount

            // --- (3) replay protection: witnessed nonce == leaf nonce -----------------
            op.nonce.conditional_enforce_equal(&op.from_old_nonce, &op.active)?;

            // --- (4a) debit `from`: balance -= amount, nonce += 1; derive intermediate root
            let from_new_nonce = &op.from_old_nonce + &one;
            let from_new_leaf =
                poseidon.h4(&op.from_key, &op.token_id, &from_new_balance, &from_new_nonce)?;
            let inter_root_active =
                merkle_root_from_leaf(&poseidon, &from_new_leaf, &op.from_siblings, &op.from_index_bits)?;
            let inter_root = FpVar::conditionally_select(&op.active, &inter_root_active, &state_root)?;

            // --- inclusion of the `to` leaf against the intermediate root -------------
            let to_old_leaf =
                poseidon.h4(&op.to_key, &op.token_id, &op.to_old_balance, &op.to_old_nonce)?;
            let to_old_root =
                merkle_root_from_leaf(&poseidon, &to_old_leaf, &op.to_siblings, &op.to_index_bits)?;
            to_old_root.conditional_enforce_equal(&inter_root, &op.active)?;

            // --- (4b) credit `to`: balance += amount (nonce unchanged) ----------------
            let to_new_balance = &op.to_old_balance + &op.amount;
            enforce_bit_width(&to_new_balance, VALUE_BITS)?; // no credit-side overflow
            let to_new_leaf =
                poseidon.h4(&op.to_key, &op.token_id, &to_new_balance, &op.to_old_nonce)?;
            let new_root_active =
                merkle_root_from_leaf(&poseidon, &to_new_leaf, &op.to_siblings, &op.to_index_bits)?;
            state_root = FpVar::conditionally_select(&op.active, &new_root_active, &inter_root)?;

            // --- (5a) opsAcc: fold every active op's hash -----------------------------
            let op_hash = poseidon.hn(&[
                op.kind.clone(),
                op.from_key.clone(),
                op.to_key.clone(),
                op.token_id.clone(),
                op.amount.clone(),
                op.nonce.clone(),
            ])?;
            let ops_acc_next = poseidon.h2(&ops_acc, &op_hash)?;
            ops_acc = FpVar::conditionally_select(&op.active, &ops_acc_next, &ops_acc)?;

            // --- (5b) netsAcc: fold (payeeKey, tokenId, amount) for withdraws only --
            // payeeKey is the settling party = the `from` account of a withdraw op.
            let is_withdraw = op.kind.is_eq(&withdraw_code)?;
            // This r1cs-std fork exposes Boolean AND via the `&` (BitAnd) operator.
            let do_nets = op.active.clone() & is_withdraw;
            let nets_acc_next = poseidon.h4(&nets_acc, &op.from_key, &op.token_id, &op.amount)?;
            nets_acc = FpVar::conditionally_select(&do_nets, &nets_acc_next, &nets_acc)?;
        }

        Ok(vec![state_root, ops_acc, nets_acc])
    }
}

/// Enforce `0 <= x < 2^bits` by proving `x` has a `bits`-wide little-endian
/// decomposition (all higher bits zero). Since `2^96 < p`, this is a real range proof.
fn enforce_bit_width<F: PrimeField>(x: &FpVar<F>, bits: usize) -> Result<(), SynthesisError> {
    let le = x.to_bits_le()?;
    for b in le.iter().skip(bits) {
        b.enforce_equal(&Boolean::FALSE)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_r1cs_std::{alloc::AllocVar, GR1CSVar};
    use ark_relations::gr1cs::ConstraintSystem;
    use native::EpochExecutor;

    // A tiny end-to-end native+circuit agreement check on one batch (small depth).
    #[test]
    fn single_batch_native_matches_circuit() {
        const B: usize = 4;
        const D: usize = 10;

        let mut exec = EpochExecutor::<Fr, D>::new();
        // genesis: pool funded, two accounts, one payee.
        let pool = Fr::from(1000u64);
        let ben_a = Fr::from(2001u64);
        let ben_b = Fr::from(2002u64);
        let ret = Fr::from(3001u64);
        let token = Fr::from(1u64);
        let sink = exec.sink_key();
        exec.register(sink, token, 0, 0);
        exec.register(pool, token, 1_000_000, 0);
        exec.register(ben_a, token, 0, 0);
        exec.register(ben_b, token, 0, 0);
        exec.register(ret, token, 0, 0);

        let z0 = exec.initial_state();

        // one batch of 4 ops: two loads, one spend, one withdraw.
        let ops = vec![
            exec.load(pool, ben_a, token, 500),
            exec.load(pool, ben_b, token, 300),
            exec.spend(ben_a, ret, token, 200),
            exec.withdraw(ret, token, 200),
        ];
        let z_expected = exec.state();

        // circuit
        let circuit = LedgerCircuit::<Fr, B, D>::new(()).unwrap();
        let cs = ConstraintSystem::<Fr>::new_ref();
        let z_var = Vec::<FpVar<Fr>>::new_witness(cs.clone(), || Ok(z0.to_vec())).unwrap();
        let batch = EpochStepInput::<Fr, B, D> { ops: ops.try_into().unwrap() };
        let ext = EpochStepInputVar::new_witness(cs.clone(), || Ok(batch)).unwrap();

        let z_next = circuit.generate_step_constraints(cs.clone(), 0, z_var, ext).unwrap();
        assert!(cs.is_satisfied().unwrap(), "circuit must be satisfied");
        let z_next_val: Vec<Fr> = z_next.iter().map(|v| v.value().unwrap()).collect();
        assert_eq!(z_next_val, z_expected.to_vec(), "circuit z_next must equal native");
    }

    /// Constant-`i` padding soundness: an all-inactive batch must leave z untouched, for an
    /// arbitrary z_0 (inclusion is not enforced for inactive ops). This is what lets the
    /// prover pad every epoch to a fixed step count without changing the transition.
    #[test]
    fn inactive_batch_is_noop() {
        const B: usize = 4;
        const D: usize = 10;
        let z0 = vec![Fr::from(123u64), Fr::from(456u64), Fr::from(789u64)];

        let circuit = LedgerCircuit::<Fr, B, D>::new(()).unwrap();
        let cs = ConstraintSystem::<Fr>::new_ref();
        let z_var = Vec::<FpVar<Fr>>::new_witness(cs.clone(), || Ok(z0.clone())).unwrap();
        let batch = EpochStepInput::<Fr, B, D>::default(); // all ops inactive
        let ext = EpochStepInputVar::new_witness(cs.clone(), || Ok(batch)).unwrap();

        let z_next = circuit.generate_step_constraints(cs.clone(), 0, z_var, ext).unwrap();
        assert!(cs.is_satisfied().unwrap(), "inactive batch must be satisfiable for any z_0");
        let z_next_val: Vec<Fr> = z_next.iter().map(|v| v.value().unwrap()).collect();
        assert_eq!(z_next_val, z0, "an all-inactive batch must leave z unchanged");
    }
}
