//! Phase-1 port of the S5+V ledger F-circuit to the NEW sonobe line
//! (sonobe-primitives, arkworks 0.6, gr1cs). Concrete over BN254 Fr.
//!
//! Same semantics as the classic prototype (per-op inclusion / 96-bit solvency / replay /
//! conservation / accumulation over a Poseidon IMT), rewritten against the new `FCircuit`
//! trait: `synthesize_step(i, state, external_inputs) -> (StateVar, ExternalOutputs)`, with
//! external inputs passed by value and allocated inside the step. State z = [root, opsAcc,
//! netsAcc]. Poseidon uses `poseidon_circom_config`.

use ark_bn254::Fr;
use ark_crypto_primitives::{
    crh::{
        poseidon::{
            constraints::{CRHGadget, CRHParametersVar},
            CRH,
        },
        CRHScheme, CRHSchemeGadget,
    },
    sponge::poseidon::PoseidonConfig,
};
use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::AllocVar,
    boolean::Boolean,
    convert::ToBitsGadget,
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
    select::CondSelectGadget,
    GR1CSVar,
};
use ark_relations::gr1cs::SynthesisError;
use sonobe_primitives::{circuits::FCircuit, transcripts::poseidon::poseidon_circom_config};
use std::collections::HashMap;

pub mod config;
pub mod sparsemt;

use crate::config::{LedgerConfig, LedgerConfigGadget, TREE_H};
use crate::sparsemt::{constraints::MerkleSparseTreeGadget, MerkleSparseTree};

pub const STATE_LEN: usize = 3;
pub const VALUE_BITS: usize = 96;
const WITHDRAW: u64 = 2;

fn cfg() -> PoseidonConfig<Fr> {
    poseidon_circom_config()
}

// ---- native Poseidon ----
fn h_native(c: &PoseidonConfig<Fr>, input: Vec<Fr>) -> Fr {
    CRH::<Fr>::evaluate(c, input).expect("poseidon native")
}
fn h4n(c: &PoseidonConfig<Fr>, a: Fr, b: Fr, cc: Fr, d: Fr) -> Fr {
    h_native(c, vec![a, b, cc, d])
}
fn h2n(c: &PoseidonConfig<Fr>, a: Fr, b: Fr) -> Fr {
    h_native(c, vec![a, b])
}

// ---- in-circuit Poseidon ----
fn h_gadget(p: &CRHParametersVar<Fr>, input: &[FpVar<Fr>]) -> Result<FpVar<Fr>, SynthesisError> {
    CRHGadget::<Fr>::evaluate(p, input)
}

// ============================ tree index bits ============================

// LSB-first path bits for a leaf at assigned position `index` in a `depth`-level tree.
// Matches plasma-blind `sparsemt`'s convention (bit i = "node at level i is a right child"),
// so these bits drive `MerkleSparseTreeGadget::recover_root` against `MerkleSparseTree::siblings`.
fn index_bits(index: u64, depth: usize) -> Vec<bool> {
    (0..depth).map(|i| (index >> i) & 1 == 1).collect()
}

// ============================ ops (plain data) ============================

#[derive(Clone, Debug)]
pub struct OpWitness {
    pub active: bool,
    pub kind: u64,
    pub from_key: Fr,
    pub to_key: Fr,
    pub token_id: Fr,
    pub amount: Fr,
    pub nonce: Fr,
    pub from_next_key: Fr,
    pub from_old_balance: Fr,
    pub from_old_nonce: Fr,
    pub from_index_bits: Vec<bool>,
    pub from_siblings: Vec<Fr>,
    pub to_next_key: Fr,
    pub to_old_balance: Fr,
    pub to_old_nonce: Fr,
    pub to_index_bits: Vec<bool>,
    pub to_siblings: Vec<Fr>,
}

impl OpWitness {
    pub fn padding(depth: usize) -> Self {
        Self {
            active: false,
            kind: 0,
            from_key: Fr::from(0u64),
            to_key: Fr::from(0u64),
            token_id: Fr::from(0u64),
            amount: Fr::from(0u64),
            nonce: Fr::from(0u64),
            from_next_key: Fr::from(0u64),
            from_old_balance: Fr::from(0u64),
            from_old_nonce: Fr::from(0u64),
            from_index_bits: vec![false; depth],
            from_siblings: vec![Fr::from(0u64); depth],
            to_next_key: Fr::from(0u64),
            to_old_balance: Fr::from(0u64),
            to_old_nonce: Fr::from(0u64),
            to_index_bits: vec![false; depth],
            to_siblings: vec![Fr::from(0u64); depth],
        }
    }
}

#[derive(Clone, Debug)]
pub struct EpochStepInput {
    pub ops: Vec<OpWitness>,
}

// ============================ the F-circuit ============================

#[derive(Clone)]
pub struct LedgerCircuit {
    pub c: PoseidonConfig<Fr>,
    pub batch: usize,
    pub depth: usize,
}

impl LedgerCircuit {
    pub fn new(batch: usize, depth: usize) -> Self {
        Self { c: cfg(), batch, depth }
    }
}

fn enforce_bit_width(x: &FpVar<Fr>, bits: usize) -> Result<(), SynthesisError> {
    let le = x.to_bits_le()?;
    for b in le.iter().skip(bits) {
        b.enforce_equal(&Boolean::FALSE)?;
    }
    Ok(())
}

/// Bit-width bound for interval keys: keys are treated as `KEY_BITS`-bounded integers so the
/// `<` comparison below is well-defined (no field wraparound). 160 bits covers Ethereum
/// address-sized keys and is well under BN254's ~254-bit modulus.
pub const KEY_BITS: usize = 160;

/// Conditionally enforce strict `a < b` (as `KEY_BITS`-bounded integers) when `should` is true.
/// When `should` is false the check is neutralised (it compares `0 < 1`, always valid), so it is
/// safe to call on padding / inactive ops. Soundness relies on bounding both operands to
/// `KEY_BITS` bits, which rules out a wraparound where a large `b - a` masquerades as small.
fn enforce_lt_when(
    a: &FpVar<Fr>,
    b: &FpVar<Fr>,
    should: &Boolean<Fr>,
) -> Result<(), SynthesisError> {
    let zero = FpVar::<Fr>::zero();
    let one = FpVar::<Fr>::one();
    let a_eff = should.select(a, &zero)?;
    let b_eff = should.select(b, &one)?;
    enforce_bit_width(&a_eff, KEY_BITS)?;
    enforce_bit_width(&b_eff, KEY_BITS)?;
    // a < b  <=>  (b - a - 1) fits in KEY_BITS bits, given a, b < 2^KEY_BITS.
    let diff_m1 = &b_eff - &a_eff - &one;
    enforce_bit_width(&diff_m1, KEY_BITS)?;
    Ok(())
}

impl FCircuit for LedgerCircuit {
    type Field = Fr;
    type State = [Fr; STATE_LEN];
    type StateVar = [FpVar<Fr>; STATE_LEN];
    type ExternalInputs = EpochStepInput;
    type ExternalOutputs = ();

    fn dummy_state(&self) -> Self::State {
        [Fr::from(0u64); STATE_LEN]
    }

    fn same_state_shape(_a: &Self::State, _b: &Self::State) -> bool {
        true
    }

    fn dummy_external_inputs(&self) -> Self::ExternalInputs {
        EpochStepInput { ops: (0..self.batch).map(|_| OpWitness::padding(self.depth)).collect() }
    }

    fn synthesize_step(
        &self,
        _i: FpVar<Fr>,
        state: Self::StateVar,
        ext: Self::ExternalInputs,
    ) -> Result<(Self::StateVar, Self::ExternalOutputs), SynthesisError> {
        assert_eq!(ext.ops.len(), self.batch, "batch size mismatch");
        assert_eq!(self.depth, TREE_H - 1, "depth must equal TREE_H - 1");
        let cs = state[0].cs();
        let p = CRHParametersVar::<Fr>::new_constant(cs.clone(), self.c.clone())?;
        // plasma-blind sparse-Merkle-tree gadget; both hash params are the (constant) Poseidon config.
        let mt = MerkleSparseTreeGadget::<LedgerConfig<TREE_H>, Fr, LedgerConfigGadget<TREE_H>>::new(
            p.clone(),
            p.clone(),
        );
        let withdraw_code = FpVar::constant(Fr::from(WITHDRAW));
        let one = FpVar::<Fr>::one();

        let mut state_root = state[0].clone();
        let mut ops_acc = state[1].clone();
        let mut nets_acc = state[2].clone();

        for op in ext.ops.iter() {
            // allocate witnesses from the value
            let active = Boolean::new_witness(cs.clone(), || Ok(op.active))?;
            let kind = FpVar::new_witness(cs.clone(), || Ok(Fr::from(op.kind)))?;
            let from_key = FpVar::new_witness(cs.clone(), || Ok(op.from_key))?;
            let to_key = FpVar::new_witness(cs.clone(), || Ok(op.to_key))?;
            let token_id = FpVar::new_witness(cs.clone(), || Ok(op.token_id))?;
            let amount = FpVar::new_witness(cs.clone(), || Ok(op.amount))?;
            let nonce = FpVar::new_witness(cs.clone(), || Ok(op.nonce))?;
            let from_next_key = FpVar::new_witness(cs.clone(), || Ok(op.from_next_key))?;
            let from_old_balance = FpVar::new_witness(cs.clone(), || Ok(op.from_old_balance))?;
            let from_old_nonce = FpVar::new_witness(cs.clone(), || Ok(op.from_old_nonce))?;
            let to_next_key = FpVar::new_witness(cs.clone(), || Ok(op.to_next_key))?;
            let to_old_balance = FpVar::new_witness(cs.clone(), || Ok(op.to_old_balance))?;
            let to_old_nonce = FpVar::new_witness(cs.clone(), || Ok(op.to_old_nonce))?;
            let mut from_sibs = Vec::with_capacity(self.depth);
            let mut from_bits = Vec::with_capacity(self.depth);
            let mut to_sibs = Vec::with_capacity(self.depth);
            let mut to_bits = Vec::with_capacity(self.depth);
            for d in 0..self.depth {
                from_sibs.push(FpVar::new_witness(cs.clone(), || Ok(op.from_siblings[d]))?);
                from_bits.push(Boolean::new_witness(cs.clone(), || Ok(op.from_index_bits[d]))?);
                to_sibs.push(FpVar::new_witness(cs.clone(), || Ok(op.to_siblings[d]))?);
                to_bits.push(Boolean::new_witness(cs.clone(), || Ok(op.to_index_bits[d]))?);
            }

            // (1) inclusion of `from` against current root (leaf preimage hashed inside recover_root)
            let from_old_leaf = [
                from_key.clone(),
                from_next_key.clone(),
                token_id.clone(),
                from_old_balance.clone(),
                from_old_nonce.clone(),
            ];
            let from_old_root = mt.recover_root(&from_old_leaf, &from_bits, &from_sibs)?;
            from_old_root.conditional_enforce_equal(&state_root, &active)?;

            // (2) solvency + 96-bit range
            enforce_bit_width(&amount, VALUE_BITS)?;
            enforce_bit_width(&from_old_balance, VALUE_BITS)?;
            let from_new_balance = &from_old_balance - &amount;
            enforce_bit_width(&from_new_balance, VALUE_BITS)?;

            // (3) replay
            nonce.conditional_enforce_equal(&from_old_nonce, &active)?;

            // (4a) debit -> intermediate root
            let from_new_nonce = &from_old_nonce + &one;
            let from_new_leaf = [
                from_key.clone(),
                from_next_key.clone(),
                token_id.clone(),
                from_new_balance.clone(),
                from_new_nonce,
            ];
            let inter_active = mt.recover_root(&from_new_leaf, &from_bits, &from_sibs)?;
            let inter_root = FpVar::conditionally_select(&active, &inter_active, &state_root)?;

            // to inclusion vs intermediate
            let to_old_leaf = [
                to_key.clone(),
                to_next_key.clone(),
                token_id.clone(),
                to_old_balance.clone(),
                to_old_nonce.clone(),
            ];
            let to_old_root = mt.recover_root(&to_old_leaf, &to_bits, &to_sibs)?;
            to_old_root.conditional_enforce_equal(&inter_root, &active)?;

            // (4b) credit
            let to_new_balance = &to_old_balance + &amount;
            enforce_bit_width(&to_new_balance, VALUE_BITS)?;
            let to_new_leaf = [
                to_key.clone(),
                to_next_key.clone(),
                token_id.clone(),
                to_new_balance,
                to_old_nonce.clone(),
            ];
            let new_active = mt.recover_root(&to_new_leaf, &to_bits, &to_sibs)?;
            state_root = FpVar::conditionally_select(&active, &new_active, &inter_root)?;

            // (5a) opsAcc
            let op_hash = h_gadget(&p, &[kind.clone(), from_key.clone(), to_key.clone(), token_id.clone(), amount.clone(), nonce.clone()])?;
            let ops_next = h_gadget(&p, &[ops_acc.clone(), op_hash])?;
            ops_acc = FpVar::conditionally_select(&active, &ops_next, &ops_acc)?;

            // (5b) netsAcc (withdraws only)
            let is_withdraw = kind.is_eq(&withdraw_code)?;
            let do_nets = active.clone() & is_withdraw;
            let nets_next = h_gadget(&p, &[nets_acc.clone(), from_key.clone(), token_id.clone(), amount.clone()])?;
            nets_acc = FpVar::conditionally_select(&do_nets, &nets_next, &nets_acc)?;
        }

        Ok(([state_root, ops_acc, nets_acc], ()))
    }
}

// ============================ native executor ============================

pub struct EpochExecutor {
    tree: MerkleSparseTree<LedgerConfig<TREE_H>>,
    c: PoseidonConfig<Fr>,
    slots: HashMap<Vec<u8>, u64>,
    balances: HashMap<Vec<u8>, u128>,
    nonces: HashMap<Vec<u8>, u64>,
    next_keys: HashMap<Vec<u8>, Fr>,
    next: u64,
    ops_acc: Fr,
    nets_acc: Fr,
    depth: usize,
}

fn key_bytes(k: Fr) -> Vec<u8> {
    use ark_ff::BigInteger;
    k.into_bigint().to_bytes_le()
}

impl EpochExecutor {
    pub fn new(depth: usize) -> Self {
        assert_eq!(depth, TREE_H - 1, "depth must equal TREE_H - 1");
        let c = cfg();
        let tree = MerkleSparseTree::<LedgerConfig<TREE_H>>::blank(&c, &c);
        Self {
            tree,
            c,
            slots: HashMap::new(),
            balances: HashMap::new(),
            nonces: HashMap::new(),
            next_keys: HashMap::new(),
            next: 0,
            ops_acc: Fr::from(0u64),
            nets_acc: Fr::from(0u64),
            depth,
        }
    }
    pub fn register(&mut self, key: Fr, token: Fr, bal: u128, nonce: u64) {
        let k = key_bytes(key);
        let slot = *self.slots.entry(k.clone()).or_insert_with(|| {
            let s = self.next;
            self.next += 1;
            s
        });
        self.balances.insert(k.clone(), bal);
        self.nonces.insert(k.clone(), nonce);
        // next_key defaults to 0 here; Phase 2b-3 maintains the real sorted-interval pointer.
        let next_key = *self.next_keys.entry(k.clone()).or_insert(Fr::from(0u64));
        self.tree
            .update_and_prove(
                slot as usize,
                &[key, next_key, token, Fr::from(bal), Fr::from(nonce)],
            )
            .expect("register: tree update");
    }
    pub fn initial_state(&self) -> [Fr; 3] {
        [self.tree.root(), Fr::from(0u64), Fr::from(0u64)]
    }
    pub fn state(&self) -> [Fr; 3] {
        [self.tree.root(), self.ops_acc, self.nets_acc]
    }
    pub fn apply(&mut self, kind: u64, from: Fr, to: Fr, token: Fr, amount: u128) -> OpWitness {
        let (fk, tk) = (key_bytes(from), key_bytes(to));
        let fbal = self.balances[&fk];
        let fnonce = self.nonces[&fk];
        let fslot = self.slots[&fk];
        let tslot = self.slots[&tk];
        assert!(fbal >= amount, "insufficient");
        // `from` siblings against the CURRENT root (valid for both old and new `from` leaf,
        // since updating a leaf leaves its own co-path siblings unchanged).
        let fnext = *self.next_keys.get(&fk).unwrap_or(&Fr::from(0u64));
        let fbits: Vec<bool> = index_bits(fslot, self.depth);
        let fsibs: Vec<Fr> = self.tree.siblings(fslot as usize).expect("from siblings");
        let fnew = fbal - amount;
        let fnn = fnonce + 1;
        self.tree
            .update_and_prove(
                fslot as usize,
                &[from, fnext, token, Fr::from(fnew), Fr::from(fnn)],
            )
            .expect("from: tree update");
        self.balances.insert(fk.clone(), fnew);
        self.nonces.insert(fk.clone(), fnn);

        let tbal = self.balances[&tk];
        let tnonce = self.nonces[&tk];
        let tnext = *self.next_keys.get(&tk).unwrap_or(&Fr::from(0u64));
        // `to` siblings against the INTERMEDIATE root (after the `from` update).
        let tbits: Vec<bool> = index_bits(tslot, self.depth);
        let tsibs: Vec<Fr> = self.tree.siblings(tslot as usize).expect("to siblings");
        let tnew = tbal + amount;
        self.tree
            .update_and_prove(
                tslot as usize,
                &[to, tnext, token, Fr::from(tnew), Fr::from(tnonce)],
            )
            .expect("to: tree update");
        self.balances.insert(tk.clone(), tnew);

        let op_hash = h_native(&self.c, vec![Fr::from(kind), from, to, token, Fr::from(amount), Fr::from(fnonce)]);
        self.ops_acc = h2n(&self.c, self.ops_acc, op_hash);
        if kind == WITHDRAW {
            self.nets_acc = h4n(&self.c, self.nets_acc, from, token, Fr::from(amount));
        }

        OpWitness {
            active: true,
            kind,
            from_key: from,
            to_key: to,
            token_id: token,
            amount: Fr::from(amount),
            nonce: Fr::from(fnonce),
            from_next_key: fnext,
            from_old_balance: Fr::from(fbal),
            from_old_nonce: Fr::from(fnonce),
            from_index_bits: fbits,
            from_siblings: fsibs,
            to_next_key: tnext,
            to_old_balance: Fr::from(tbal),
            to_old_nonce: Fr::from(tnonce),
            to_index_bits: tbits,
            to_siblings: tsibs,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::gr1cs::ConstraintSystem;

    // Helper: does `enforce_lt_when(a, b, should)` leave the CS satisfiable?
    fn lt_ok(a: u64, b: u64, should: bool) -> bool {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let av = FpVar::new_witness(cs.clone(), || Ok(Fr::from(a))).unwrap();
        let bv = FpVar::new_witness(cs.clone(), || Ok(Fr::from(b))).unwrap();
        let s = Boolean::new_witness(cs.clone(), || Ok(should)).unwrap();
        enforce_lt_when(&av, &bv, &s).unwrap();
        cs.is_satisfied().unwrap()
    }

    #[test]
    fn bounded_lt_gadget() {
        // active: strict less-than is enforced
        assert!(lt_ok(3, 7, true), "3 < 7 holds");
        assert!(!lt_ok(7, 3, true), "7 < 3 must fail");
        assert!(!lt_ok(5, 5, true), "5 < 5 must fail (strict)");
        assert!(lt_ok(0, 1, true), "0 < 1 holds");
        // inactive: neutralised, always satisfiable regardless of operands
        assert!(lt_ok(7, 3, false), "inactive comparison is neutralised");
        assert!(lt_ok(5, 5, false), "inactive comparison is neutralised");
    }

    #[test]
    fn single_batch_native_matches_circuit() {
        let d = config::TREE_H - 1;
        let b = 4usize;
        let token = Fr::from(1u64);
        let pool = Fr::from(1000u64);
        let a = Fr::from(2001u64);
        let bb = Fr::from(2002u64);
        let ret = Fr::from(3001u64);
        let sink = Fr::from(9999u64);
        let mut exec = EpochExecutor::new(d);
        exec.register(pool, token, 1_000_000, 0);
        exec.register(a, token, 0, 0);
        exec.register(bb, token, 0, 0);
        exec.register(ret, token, 0, 0);
        exec.register(sink, token, 0, 0);
        let z0 = exec.initial_state();

        let ops = vec![
            exec.apply(0, pool, a, token, 500),
            exec.apply(0, pool, bb, token, 300),
            exec.apply(1, a, ret, token, 200),
            exec.apply(2, ret, sink, token, 200),
        ];
        let z_expected = exec.state();

        let circuit = LedgerCircuit::new(b, d);
        use ark_relations::gr1cs::ConstraintSystem;
        let cs = ConstraintSystem::<Fr>::new_ref();
        let z_var =
            <[FpVar<Fr>; 3] as AllocVar<[Fr; 3], Fr>>::new_witness(cs.clone(), || Ok(z0)).unwrap();
        let i = FpVar::new_witness(cs.clone(), || Ok(Fr::from(0u64))).unwrap();
        let (z_next, _) = circuit
            .synthesize_step(i, z_var, EpochStepInput { ops })
            .unwrap();
        assert!(cs.is_satisfied().unwrap(), "circuit satisfied");
        let got: Vec<Fr> = z_next.iter().map(|v| v.value().unwrap()).collect();
        assert_eq!(got, z_expected.to_vec(), "circuit z_next == native");
    }

    // Prove the sparse-Merkle inclusion constraints actually bind: corrupt one `from` sibling
    // in the first op's witness and the constraint system must become unsatisfiable.
    #[test]
    fn tampered_sibling_breaks_inclusion() {
        let d = config::TREE_H - 1;
        let b = 2usize;
        let token = Fr::from(1u64);
        let pool = Fr::from(1000u64);
        let a = Fr::from(2001u64);
        let mut exec = EpochExecutor::new(d);
        exec.register(pool, token, 1_000_000, 0);
        exec.register(a, token, 0, 0);
        let z0 = exec.initial_state();

        let mut ops = vec![exec.apply(0, pool, a, token, 500), OpWitness::padding(d)];
        // Flip a sibling the `from` inclusion proof depends on.
        ops[0].from_siblings[0] += Fr::from(1u64);

        let circuit = LedgerCircuit::new(b, d);
        use ark_relations::gr1cs::ConstraintSystem;
        let cs = ConstraintSystem::<Fr>::new_ref();
        let z_var =
            <[FpVar<Fr>; 3] as AllocVar<[Fr; 3], Fr>>::new_witness(cs.clone(), || Ok(z0)).unwrap();
        let i = FpVar::new_witness(cs.clone(), || Ok(Fr::from(0u64))).unwrap();
        let _ = circuit
            .synthesize_step(i, z_var, EpochStepInput { ops })
            .unwrap();
        assert!(
            !cs.is_satisfied().unwrap(),
            "tampered sibling must violate the inclusion constraint"
        );
    }
}
