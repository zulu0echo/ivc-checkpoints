//! Per-step external inputs: a batch of `B` ledger operations, each carrying the
//! witness data needed to apply it to a depth-`D` tree.
//!
//! Shape discipline: the sonobe `FCircuit` trait (this pin) has no `external_inputs_len`,
//! so the in-circuit variable must have a fixed shape known without a concrete value
//! (Nova allocates it during key generation with the witness absent). We get that by
//! making the *value* type carry `B` and `D` as const generics and by driving the
//! `AllocVar` impl with those constants — every allocation loops exactly `B`×`D` times,
//! so the constraint shape is identical in setup and proving.

use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    boolean::Boolean,
    fields::fp::FpVar,
};
use ark_relations::gr1cs::{Namespace, SynthesisError};
use core::borrow::Borrow;

/// Operation kind. `code()` is bound into `opHash`, so kinds are non-malleable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpKind {
    Load = 0,
    Spend = 1,
    Withdraw = 2,
}

impl OpKind {
    pub fn code(self) -> u64 {
        self as u64
    }
}

/// Native operation witness. All balances/amounts/nonces are field-encoded; amounts and
/// balances are constrained to 96 bits in-circuit.
#[derive(Clone, Debug)]
pub struct OpWitness<F: PrimeField, const D: usize> {
    /// Inactive ops are padding for the final (partial) batch: fully skipped in-circuit.
    pub active: bool,
    pub kind: u64,
    pub from_key: F,
    pub to_key: F,
    pub token_id: F,
    pub amount: F,
    /// Spender's expected nonce (replay protection): must equal `from_old_nonce`.
    pub nonce: F,

    // `from` leaf pre-image, and its path against the *current* stateRoot.
    pub from_old_balance: F,
    pub from_old_nonce: F,
    pub from_index_bits: [bool; D],
    pub from_siblings: [F; D],

    // `to` leaf pre-image, and its path against the *intermediate* root (post from-write).
    pub to_old_balance: F,
    pub to_old_nonce: F,
    pub to_index_bits: [bool; D],
    pub to_siblings: [F; D],
}

impl<F: PrimeField, const D: usize> OpWitness<F, D> {
    /// An inactive padding op (skipped in-circuit).
    pub fn padding() -> Self {
        Self {
            active: false,
            kind: OpKind::Load.code(),
            from_key: F::zero(),
            to_key: F::zero(),
            token_id: F::zero(),
            amount: F::zero(),
            nonce: F::zero(),
            from_old_balance: F::zero(),
            from_old_nonce: F::zero(),
            from_index_bits: [false; D],
            from_siblings: [F::zero(); D],
            to_old_balance: F::zero(),
            to_old_nonce: F::zero(),
            to_index_bits: [false; D],
            to_siblings: [F::zero(); D],
        }
    }
}

impl<F: PrimeField, const D: usize> Default for OpWitness<F, D> {
    fn default() -> Self {
        Self::padding()
    }
}

/// A full step's external input: exactly `B` ops.
#[derive(Clone, Debug)]
pub struct EpochStepInput<F: PrimeField, const B: usize, const D: usize> {
    pub ops: [OpWitness<F, D>; B],
}

impl<F: PrimeField, const B: usize, const D: usize> Default for EpochStepInput<F, B, D> {
    fn default() -> Self {
        Self { ops: core::array::from_fn(|_| OpWitness::padding()) }
    }
}

// ---- in-circuit variables ---------------------------------------------------

#[derive(Clone, Debug)]
pub struct OpWitnessVar<F: PrimeField> {
    pub active: Boolean<F>,
    pub kind: FpVar<F>,
    pub from_key: FpVar<F>,
    pub to_key: FpVar<F>,
    pub token_id: FpVar<F>,
    pub amount: FpVar<F>,
    pub nonce: FpVar<F>,
    pub from_old_balance: FpVar<F>,
    pub from_old_nonce: FpVar<F>,
    pub from_index_bits: Vec<Boolean<F>>,
    pub from_siblings: Vec<FpVar<F>>,
    pub to_old_balance: FpVar<F>,
    pub to_old_nonce: FpVar<F>,
    pub to_index_bits: Vec<Boolean<F>>,
    pub to_siblings: Vec<FpVar<F>>,
}

#[derive(Clone, Debug)]
pub struct EpochStepInputVar<F: PrimeField> {
    pub ops: Vec<OpWitnessVar<F>>,
}

impl<F: PrimeField, const B: usize, const D: usize> AllocVar<EpochStepInput<F, B, D>, F>
    for EpochStepInputVar<F>
{
    fn new_variable<T: Borrow<EpochStepInput<F, B, D>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        // Present when proving; absent (Err) during key generation. Either way the shape
        // below is fixed by the const generics B and D.
        let value: Option<EpochStepInput<F, B, D>> = f().ok().map(|v| v.borrow().clone());

        let mut ops = Vec::with_capacity(B);
        for i in 0..B {
            let op: Option<OpWitness<F, D>> = value.as_ref().map(|v| v.ops[i].clone());
            let get = |sel: fn(&OpWitness<F, D>) -> F| -> Result<F, SynthesisError> {
                op.as_ref().map(sel).ok_or(SynthesisError::AssignmentMissing)
            };

            let active = Boolean::new_variable(
                cs.clone(),
                || op.as_ref().map(|o| o.active).ok_or(SynthesisError::AssignmentMissing),
                mode,
            )?;
            let kind = FpVar::new_variable(
                cs.clone(),
                || op.as_ref().map(|o| F::from(o.kind)).ok_or(SynthesisError::AssignmentMissing),
                mode,
            )?;
            let from_key = FpVar::new_variable(cs.clone(), || get(|o| o.from_key), mode)?;
            let to_key = FpVar::new_variable(cs.clone(), || get(|o| o.to_key), mode)?;
            let token_id = FpVar::new_variable(cs.clone(), || get(|o| o.token_id), mode)?;
            let amount = FpVar::new_variable(cs.clone(), || get(|o| o.amount), mode)?;
            let nonce = FpVar::new_variable(cs.clone(), || get(|o| o.nonce), mode)?;
            let from_old_balance =
                FpVar::new_variable(cs.clone(), || get(|o| o.from_old_balance), mode)?;
            let from_old_nonce =
                FpVar::new_variable(cs.clone(), || get(|o| o.from_old_nonce), mode)?;
            let to_old_balance =
                FpVar::new_variable(cs.clone(), || get(|o| o.to_old_balance), mode)?;
            let to_old_nonce = FpVar::new_variable(cs.clone(), || get(|o| o.to_old_nonce), mode)?;

            let mut from_index_bits = Vec::with_capacity(D);
            let mut from_siblings = Vec::with_capacity(D);
            let mut to_index_bits = Vec::with_capacity(D);
            let mut to_siblings = Vec::with_capacity(D);
            for d in 0..D {
                from_index_bits.push(Boolean::new_variable(
                    cs.clone(),
                    || op.as_ref().map(|o| o.from_index_bits[d]).ok_or(SynthesisError::AssignmentMissing),
                    mode,
                )?);
                from_siblings.push(FpVar::new_variable(
                    cs.clone(),
                    || op.as_ref().map(|o| o.from_siblings[d]).ok_or(SynthesisError::AssignmentMissing),
                    mode,
                )?);
                to_index_bits.push(Boolean::new_variable(
                    cs.clone(),
                    || op.as_ref().map(|o| o.to_index_bits[d]).ok_or(SynthesisError::AssignmentMissing),
                    mode,
                )?);
                to_siblings.push(FpVar::new_variable(
                    cs.clone(),
                    || op.as_ref().map(|o| o.to_siblings[d]).ok_or(SynthesisError::AssignmentMissing),
                    mode,
                )?);
            }

            ops.push(OpWitnessVar {
                active,
                kind,
                from_key,
                to_key,
                token_id,
                amount,
                nonce,
                from_old_balance,
                from_old_nonce,
                from_index_bits,
                from_siblings,
                to_old_balance,
                to_old_nonce,
                to_index_bits,
                to_siblings,
            });
        }

        Ok(EpochStepInputVar { ops })
    }
}
