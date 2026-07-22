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
use ark_bn254::Fq as GrScalar; // Grumpkin scalar field == BN254 base field
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, PrimeField};
use ark_grumpkin::{constraints::GVar, Projective as GrProjective};
use ark_r1cs_std::{
    alloc::AllocVar,
    boolean::Boolean,
    convert::{ToBitsGadget, ToConstraintFieldGadget},
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
    select::CondSelectGadget,
    GR1CSVar,
};
use ark_relations::gr1cs::SynthesisError;
use sonobe_primitives::{circuits::FCircuit, transcripts::poseidon::poseidon_circom_config};
use std::collections::HashMap;

pub mod config;
pub mod schnorr;
pub mod sparsemt;

use crate::config::{LedgerConfig, LedgerConfigGadget, TREE_H};
use crate::schnorr::{Schnorr, SchnorrGadget};
use crate::sparsemt::{constraints::MerkleSparseTreeGadget, MerkleSparseTree};

/// Window size for the Schnorr `enforce_lt` sub-gadget (matches plasma-blind).
pub const SIG_WINDOW: usize = 32;

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

// ---- Schnorr spend-key helpers ----

// Commitment to a Grumpkin spend pubkey stored in the account leaf: Poseidon(x, y) of its affine
// coordinates. Must match the in-circuit derivation `h_gadget([pk.x, pk.y])`.
fn pk_hash_native(c: &PoseidonConfig<Fr>, pk: &GrProjective) -> Fr {
    let (x, y) = pk.into_affine().xy().unwrap_or_default();
    h2n(c, x, y)
}

// Little-endian bit decomposition of a Grumpkin scalar, truncated to the scalar modulus size —
// the wire format `SchnorrGadget::verify` expects for `s` and `e`.
fn scalar_bits(s: GrScalar) -> Vec<bool> {
    let mut bits = s.into_bigint().to_bits_le();
    bits.truncate(GrScalar::MODULUS_BIT_SIZE as usize);
    bits
}

// The message a debit signature covers: (from_key, to_key, token, amount, nonce).
fn debit_message(from: Fr, to: Fr, token: Fr, amount: Fr, nonce: Fr) -> [Fr; 5] {
    [from, to, token, amount, nonce]
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
    pub from_pk_hash: Fr,
    pub from_index_bits: Vec<bool>,
    pub from_siblings: Vec<Fr>,
    pub to_next_key: Fr,
    pub to_old_balance: Fr,
    pub to_old_nonce: Fr,
    pub to_pk_hash: Fr,
    pub to_index_bits: Vec<bool>,
    pub to_siblings: Vec<Fr>,
    // A1: the `from` account's delegated Schnorr spend pubkey + its signature over the debit.
    pub from_pk: GrProjective,
    pub from_sig: (GrScalar, GrScalar),
}

impl OpWitness {
    /// A padding op carries a *valid* dummy signature (over the all-zero debit message by a fixed
    /// dummy key) so the always-on in-circuit signature check is satisfied; `active = false` keeps
    /// it from touching the tree state.
    pub fn padding(c: &PoseidonConfig<Fr>, depth: usize) -> Self {
        let z = Fr::from(0u64);
        let (pk, sig) = dummy_sig(c, [z, z, z, z, z]);
        Self {
            active: false,
            kind: 0,
            from_key: z,
            to_key: z,
            token_id: z,
            amount: z,
            nonce: z,
            from_next_key: z,
            from_old_balance: z,
            from_old_nonce: z,
            from_pk_hash: z,
            from_index_bits: vec![false; depth],
            from_siblings: vec![z; depth],
            to_next_key: z,
            to_old_balance: z,
            to_old_nonce: z,
            to_pk_hash: z,
            to_index_bits: vec![false; depth],
            to_siblings: vec![z; depth],
            from_pk: pk,
            from_sig: sig,
        }
    }
}

// A fixed dummy keypair + a valid signature over `msg`, used to fill padding ops so the
// always-on signature check passes on inactive slots. Deterministic (seeded RNG).
fn dummy_sig(c: &PoseidonConfig<Fr>, msg: [Fr; 5]) -> (GrProjective, (GrScalar, GrScalar)) {
    use ark_std::rand::SeedableRng;
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(0xD00D);
    let (sk, pk) = Schnorr::key_gen::<GrProjective>(&mut rng);
    let sig = Schnorr::sign::<GrProjective>(c, sk, &msg, &mut rng).expect("dummy sign");
    (pk, sig)
}

/// Witness for an in-circuit account registration (indexed-tree non-membership + split-insert).
#[derive(Clone, Debug)]
pub struct RegWitness {
    pub active: bool,
    pub key: Fr,
    pub token: Fr,
    pub balance: Fr,
    pub nonce: Fr,
    pub pk_hash: Fr, // spend-key commitment for the new account (A1)
    // The bracketing "low" leaf, as it exists BEFORE the split (`low_next == 0` means +infinity):
    pub low_key: Fr,
    pub low_next: Fr,
    pub low_token: Fr,
    pub low_balance: Fr,
    pub low_nonce: Fr,
    pub low_pk_hash: Fr,
    pub low_index_bits: Vec<bool>,
    pub low_siblings: Vec<Fr>,
    // The fresh (empty) slot the new leaf is inserted at:
    pub new_index_bits: Vec<bool>,
    pub new_siblings: Vec<Fr>,
}

impl RegWitness {
    pub fn padding(depth: usize) -> Self {
        let z = Fr::from(0u64);
        Self {
            active: false,
            key: z,
            token: z,
            balance: z,
            nonce: z,
            pk_hash: z,
            low_key: z,
            low_next: z,
            low_token: z,
            low_balance: z,
            low_nonce: z,
            low_pk_hash: z,
            low_index_bits: vec![false; depth],
            low_siblings: vec![z; depth],
            new_index_bits: vec![false; depth],
            new_siblings: vec![z; depth],
        }
    }
}

#[derive(Clone, Debug)]
pub struct EpochStepInput {
    pub regs: Vec<RegWitness>,
    pub ops: Vec<OpWitness>,
}

// ============================ the F-circuit ============================

#[derive(Clone)]
pub struct LedgerCircuit {
    pub c: PoseidonConfig<Fr>,
    pub reg_batch: usize,
    pub batch: usize,
    pub depth: usize,
}

impl LedgerCircuit {
    /// `batch` transfer ops, no registrations (Phase 2a compatibility).
    pub fn new(batch: usize, depth: usize) -> Self {
        Self { c: cfg(), reg_batch: 0, batch, depth }
    }
    /// `reg_batch` registrations followed by `batch` transfer ops.
    pub fn new_with_regs(reg_batch: usize, batch: usize, depth: usize) -> Self {
        Self { c: cfg(), reg_batch, batch, depth }
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

// Recompute a Merkle root from a leaf **digest** (not a preimage) + siblings + path bits, using
// the same fold rule as `MerkleSparseTreeGadget::recover_root`. Used to prove a slot holds the
// empty digest `0` (an empty leaf), which `recover_root` cannot express since it always hashes a
// preimage. `TwoToOne(l, r) == h_gadget([l, r])` for Poseidon, so this matches the tree's hashing.
fn root_from_digest(
    p: &CRHParametersVar<Fr>,
    leaf_digest: &FpVar<Fr>,
    bits: &[Boolean<Fr>],
    sibs: &[FpVar<Fr>],
) -> Result<FpVar<Fr>, SynthesisError> {
    let mut hash = leaf_digest.clone();
    for (sib, bit) in sibs.iter().zip(bits) {
        let left = bit.select(sib, &hash)?;
        let right = &hash + sib - &left;
        hash = h_gadget(p, &[left, right])?;
    }
    Ok(hash)
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
        EpochStepInput {
            regs: (0..self.reg_batch).map(|_| RegWitness::padding(self.depth)).collect(),
            ops: (0..self.batch).map(|_| OpWitness::padding(&self.c, self.depth)).collect(),
        }
    }

    fn synthesize_step(
        &self,
        _i: FpVar<Fr>,
        state: Self::StateVar,
        ext: Self::ExternalInputs,
    ) -> Result<(Self::StateVar, Self::ExternalOutputs), SynthesisError> {
        assert_eq!(ext.regs.len(), self.reg_batch, "reg batch size mismatch");
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
        let zero = FpVar::<Fr>::zero();

        // ---- registrations: indexed-tree non-membership + split-insert ----
        for reg in ext.regs.iter() {
            let active = Boolean::new_witness(cs.clone(), || Ok(reg.active))?;
            let key = FpVar::new_witness(cs.clone(), || Ok(reg.key))?;
            let token = FpVar::new_witness(cs.clone(), || Ok(reg.token))?;
            let balance = FpVar::new_witness(cs.clone(), || Ok(reg.balance))?;
            let nonce = FpVar::new_witness(cs.clone(), || Ok(reg.nonce))?;
            let low_key = FpVar::new_witness(cs.clone(), || Ok(reg.low_key))?;
            let low_next = FpVar::new_witness(cs.clone(), || Ok(reg.low_next))?;
            let low_token = FpVar::new_witness(cs.clone(), || Ok(reg.low_token))?;
            let low_balance = FpVar::new_witness(cs.clone(), || Ok(reg.low_balance))?;
            let low_nonce = FpVar::new_witness(cs.clone(), || Ok(reg.low_nonce))?;
            let pk_hash = FpVar::new_witness(cs.clone(), || Ok(reg.pk_hash))?;
            let low_pk_hash = FpVar::new_witness(cs.clone(), || Ok(reg.low_pk_hash))?;
            let mut low_sibs = Vec::with_capacity(self.depth);
            let mut low_bits = Vec::with_capacity(self.depth);
            let mut new_sibs = Vec::with_capacity(self.depth);
            let mut new_bits = Vec::with_capacity(self.depth);
            for d in 0..self.depth {
                low_sibs.push(FpVar::new_witness(cs.clone(), || Ok(reg.low_siblings[d]))?);
                low_bits.push(Boolean::new_witness(cs.clone(), || Ok(reg.low_index_bits[d]))?);
                new_sibs.push(FpVar::new_witness(cs.clone(), || Ok(reg.new_siblings[d]))?);
                new_bits.push(Boolean::new_witness(cs.clone(), || Ok(reg.new_index_bits[d]))?);
            }

            // (R1) the low leaf is included in the current root
            let low_old_leaf = [
                low_key.clone(),
                low_next.clone(),
                low_token.clone(),
                low_balance.clone(),
                low_nonce.clone(),
                low_pk_hash.clone(),
            ];
            let low_old_root = mt.recover_root(&low_old_leaf, &low_bits, &low_sibs)?;
            low_old_root.conditional_enforce_equal(&state_root, &active)?;

            // (R2) non-membership: low_key < key, and (low_next == 0 [+inf] OR key < low_next)
            enforce_lt_when(&low_key, &key, &active)?;
            let low_is_inf = low_next.is_eq(&zero)?;
            let upper = active.clone() & (!low_is_inf);
            enforce_lt_when(&key, &low_next, &upper)?;

            // (R3) split the low interval: low.next := key (low's pk_hash unchanged)
            let low_new_leaf = [
                low_key.clone(),
                key.clone(),
                low_token.clone(),
                low_balance.clone(),
                low_nonce.clone(),
                low_pk_hash.clone(),
            ];
            let inter_active = mt.recover_root(&low_new_leaf, &low_bits, &low_sibs)?;
            let inter_root = FpVar::conditionally_select(&active, &inter_active, &state_root)?;

            // (R4) the target slot is empty (digest 0) in the intermediate tree — no clobber
            let empty_root = root_from_digest(&p, &zero, &new_bits, &new_sibs)?;
            empty_root.conditional_enforce_equal(&inter_root, &active)?;

            // (R5) insert the new leaf (key, low_next, token, balance, nonce, pk_hash)
            let new_leaf = [
                key.clone(),
                low_next.clone(),
                token.clone(),
                balance.clone(),
                nonce.clone(),
                pk_hash.clone(),
            ];
            let new_root = mt.recover_root(&new_leaf, &new_bits, &new_sibs)?;
            state_root = FpVar::conditionally_select(&active, &new_root, &inter_root)?;
        }

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
            let from_pk_hash = FpVar::new_witness(cs.clone(), || Ok(op.from_pk_hash))?;
            let to_next_key = FpVar::new_witness(cs.clone(), || Ok(op.to_next_key))?;
            let to_old_balance = FpVar::new_witness(cs.clone(), || Ok(op.to_old_balance))?;
            let to_old_nonce = FpVar::new_witness(cs.clone(), || Ok(op.to_old_nonce))?;
            let to_pk_hash = FpVar::new_witness(cs.clone(), || Ok(op.to_pk_hash))?;
            // A1: spend pubkey + signature over the debit
            let from_pk = GVar::new_witness(cs.clone(), || Ok(op.from_pk))?;
            let s_bits = Vec::<Boolean<Fr>>::new_witness(cs.clone(), || Ok(scalar_bits(op.from_sig.0)))?;
            let e_bits = Vec::<Boolean<Fr>>::new_witness(cs.clone(), || Ok(scalar_bits(op.from_sig.1)))?;
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
                from_pk_hash.clone(),
            ];
            let from_old_root = mt.recover_root(&from_old_leaf, &from_bits, &from_sibs)?;
            from_old_root.conditional_enforce_equal(&state_root, &active)?;

            // (1b) A1 authorization: the witnessed spend pubkey must match the leaf commitment,
            // and it must have signed this debit. `pk_hash = Poseidon(pk.x, pk.y)`.
            let mut pk_xy = from_pk.to_constraint_field()?;
            pk_xy.pop(); // drop the infinity flag; keep [x, y]
            let derived_pk_hash = h_gadget(&p, &pk_xy)?;
            derived_pk_hash.conditional_enforce_equal(&from_pk_hash, &active)?;
            let msg = [
                from_key.clone(),
                to_key.clone(),
                token_id.clone(),
                amount.clone(),
                nonce.clone(),
            ];
            // Signatures are always present (padding carries a valid dummy), so verify is uncond.
            SchnorrGadget::verify::<SIG_WINDOW, GrProjective, GVar>(
                &p,
                &from_pk,
                &msg,
                (s_bits.clone(), e_bits.clone()),
            )?;

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
                from_pk_hash.clone(),
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
                to_pk_hash.clone(),
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
                to_pk_hash.clone(),
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
    tokens: HashMap<Vec<u8>, Fr>,
    next_keys: HashMap<Vec<u8>, Fr>,
    // A1: each account's delegated Schnorr spend keypair + its leaf commitment.
    spend_sk: HashMap<Vec<u8>, GrScalar>,
    spend_pk: HashMap<Vec<u8>, GrProjective>,
    pk_hashes: HashMap<Vec<u8>, Fr>,
    rng: ark_std::rand::rngs::StdRng,
    next: u64,
    ops_acc: Fr,
    nets_acc: Fr,
    depth: usize,
}

fn key_bytes(k: Fr) -> Vec<u8> {
    use ark_ff::BigInteger;
    k.into_bigint().to_bytes_le()
}

// Ordering on field elements by canonical representative (valid for KEY_BITS-bounded keys).
fn fr_lt(a: Fr, b: Fr) -> bool {
    a.into_bigint() < b.into_bigint()
}

impl EpochExecutor {
    pub fn new(depth: usize) -> Self {
        assert_eq!(depth, TREE_H - 1, "depth must equal TREE_H - 1");
        use ark_std::rand::SeedableRng;
        let c = cfg();
        let tree = MerkleSparseTree::<LedgerConfig<TREE_H>>::blank(&c, &c);
        let mut this = Self {
            tree,
            c,
            slots: HashMap::new(),
            balances: HashMap::new(),
            nonces: HashMap::new(),
            tokens: HashMap::new(),
            next_keys: HashMap::new(),
            spend_sk: HashMap::new(),
            spend_pk: HashMap::new(),
            pk_hashes: HashMap::new(),
            rng: ark_std::rand::rngs::StdRng::seed_from_u64(0xC0FFEE),
            next: 0,
            ops_acc: Fr::from(0u64),
            nets_acc: Fr::from(0u64),
            depth,
        };
        // Sentinel leaf at slot 0: (0, 0[+inf], 0, 0, 0, 0). Its hash is LeafHash([0;6]) != 0,
        // whereas every empty slot hashes to 0 — this is what makes empty slots unusable as `low`
        // leaves and gives indexed-tree non-membership its soundness. Real accounts start at slot 1.
        let z = Fr::from(0u64);
        let zk = key_bytes(z);
        this.slots.insert(zk.clone(), 0);
        this.balances.insert(zk.clone(), 0);
        this.nonces.insert(zk.clone(), 0);
        this.tokens.insert(zk.clone(), z);
        this.next_keys.insert(zk.clone(), z);
        this.pk_hashes.insert(zk, z);
        this.next = 1;
        this.tree
            .update_and_prove(0, &[z, z, z, z, z, z])
            .expect("sentinel install");
        this
    }

    // Generate a fresh spend keypair for `key` and store it + its leaf commitment. Returns pk_hash.
    fn assign_spend_key(&mut self, kb: &[u8]) -> Fr {
        let (sk, pk) = Schnorr::key_gen::<GrProjective>(&mut self.rng);
        let pk_hash = pk_hash_native(&self.c, &pk);
        self.spend_sk.insert(kb.to_vec(), sk);
        self.spend_pk.insert(kb.to_vec(), pk);
        self.pk_hashes.insert(kb.to_vec(), pk_hash);
        pk_hash
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
        self.tokens.insert(k.clone(), token);
        let pk_hash = self.assign_spend_key(&k);
        // next_key defaults to 0 here; `register_indexed` maintains the real sorted-interval pointer.
        let next_key = *self.next_keys.entry(k.clone()).or_insert(Fr::from(0u64));
        self.tree
            .update_and_prove(
                slot as usize,
                &[key, next_key, token, Fr::from(bal), Fr::from(nonce), pk_hash],
            )
            .expect("register: tree update");
    }

    /// Predecessor of `key`: the registered key `L` (including the sentinel 0) with the largest
    /// `L < key`. In a correctly maintained sorted structure its `next` pointer is `> key` or 0.
    fn find_low(&self, key: Fr) -> (Fr, u64) {
        let mut best_key = Fr::from(0u64);
        let mut best_slot = 0u64; // sentinel
        for (kb, &slot) in &self.slots {
            let cand = Fr::from_le_bytes_mod_order(kb);
            if fr_lt(cand, key) && fr_lt(best_key, cand) {
                best_key = cand;
                best_slot = slot;
            }
        }
        (best_key, best_slot)
    }

    /// In-circuit-style registration: bracket `key` by its predecessor, split the interval, and
    /// insert the new account at a fresh slot. Returns the witness the circuit re-checks.
    pub fn register_indexed(&mut self, key: Fr, token: Fr, bal: u128, nonce: u64) -> RegWitness {
        let k = key_bytes(key);
        assert!(!self.slots.contains_key(&k), "duplicate key registration");
        assert!(key != Fr::from(0u64), "key 0 is reserved for the sentinel");

        let (low_key, low_slot) = self.find_low(key);
        let low_kb = key_bytes(low_key);
        let low_next = self.next_keys[&low_kb];
        let low_token = self.tokens[&low_kb];
        let low_bal = self.balances[&low_kb];
        let low_nonce = self.nonces[&low_kb];
        let low_pk_hash = self.pk_hashes[&low_kb];

        let low_bits = index_bits(low_slot, self.depth);
        let low_sibs = self.tree.siblings(low_slot as usize).expect("low siblings");

        // split: low.next := key (low's payload incl. pk_hash unchanged)
        self.tree
            .update_and_prove(
                low_slot as usize,
                &[low_key, key, low_token, Fr::from(low_bal), Fr::from(low_nonce), low_pk_hash],
            )
            .expect("low split update");
        self.next_keys.insert(low_kb, key);

        // fresh spend key for the new account
        let pk_hash = self.assign_spend_key(&k);

        // insert new leaf at a fresh (empty) slot
        let new_slot = self.next;
        self.next += 1;
        let new_bits = index_bits(new_slot, self.depth);
        let new_sibs = self.tree.siblings(new_slot as usize).expect("new siblings");
        self.tree
            .update_and_prove(
                new_slot as usize,
                &[key, low_next, token, Fr::from(bal), Fr::from(nonce), pk_hash],
            )
            .expect("new insert update");
        self.slots.insert(k.clone(), new_slot);
        self.next_keys.insert(k.clone(), low_next);
        self.tokens.insert(k.clone(), token);
        self.balances.insert(k.clone(), bal);
        self.nonces.insert(k.clone(), nonce);

        RegWitness {
            active: true,
            key,
            token,
            balance: Fr::from(bal),
            nonce: Fr::from(nonce),
            pk_hash,
            low_key,
            low_next,
            low_token,
            low_balance: Fr::from(low_bal),
            low_nonce: Fr::from(low_nonce),
            low_pk_hash,
            low_index_bits: low_bits,
            low_siblings: low_sibs,
            new_index_bits: new_bits,
            new_siblings: new_sibs,
        }
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
        let fnext = *self.next_keys.get(&fk).unwrap_or(&Fr::from(0u64));
        let from_pk_hash = self.pk_hashes[&fk];
        let from_pk = self.spend_pk[&fk];
        let from_sk = self.spend_sk[&fk];
        // A1: sign the debit (from, to, token, amount, nonce) with the account's spend key.
        let msg = debit_message(from, to, token, Fr::from(amount), Fr::from(fnonce));
        let from_sig = Schnorr::sign::<GrProjective>(&self.c, from_sk, &msg, &mut self.rng)
            .expect("debit sign");
        // `from` siblings against the CURRENT root (valid for both old and new `from` leaf,
        // since updating a leaf leaves its own co-path siblings unchanged).
        let fbits: Vec<bool> = index_bits(fslot, self.depth);
        let fsibs: Vec<Fr> = self.tree.siblings(fslot as usize).expect("from siblings");
        let fnew = fbal - amount;
        let fnn = fnonce + 1;
        self.tree
            .update_and_prove(
                fslot as usize,
                &[from, fnext, token, Fr::from(fnew), Fr::from(fnn), from_pk_hash],
            )
            .expect("from: tree update");
        self.balances.insert(fk.clone(), fnew);
        self.nonces.insert(fk.clone(), fnn);

        let tbal = self.balances[&tk];
        let tnonce = self.nonces[&tk];
        let tnext = *self.next_keys.get(&tk).unwrap_or(&Fr::from(0u64));
        let to_pk_hash = self.pk_hashes[&tk];
        // `to` siblings against the INTERMEDIATE root (after the `from` update).
        let tbits: Vec<bool> = index_bits(tslot, self.depth);
        let tsibs: Vec<Fr> = self.tree.siblings(tslot as usize).expect("to siblings");
        let tnew = tbal + amount;
        self.tree
            .update_and_prove(
                tslot as usize,
                &[to, tnext, token, Fr::from(tnew), Fr::from(tnonce), to_pk_hash],
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
            from_pk_hash,
            from_index_bits: fbits,
            from_siblings: fsibs,
            to_next_key: tnext,
            to_old_balance: Fr::from(tbal),
            to_old_nonce: Fr::from(tnonce),
            to_pk_hash,
            to_index_bits: tbits,
            to_siblings: tsibs,
            from_pk,
            from_sig,
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
            .synthesize_step(i, z_var, EpochStepInput { regs: vec![], ops })
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

        let mut ops = vec![exec.apply(0, pool, a, token, 500), OpWitness::padding(&cfg(), d)];
        // Flip a sibling the `from` inclusion proof depends on.
        ops[0].from_siblings[0] += Fr::from(1u64);

        let circuit = LedgerCircuit::new(b, d);
        use ark_relations::gr1cs::ConstraintSystem;
        let cs = ConstraintSystem::<Fr>::new_ref();
        let z_var =
            <[FpVar<Fr>; 3] as AllocVar<[Fr; 3], Fr>>::new_witness(cs.clone(), || Ok(z0)).unwrap();
        let i = FpVar::new_witness(cs.clone(), || Ok(Fr::from(0u64))).unwrap();
        let _ = circuit
            .synthesize_step(i, z_var, EpochStepInput { regs: vec![], ops })
            .unwrap();
        assert!(
            !cs.is_satisfied().unwrap(),
            "tampered sibling must violate the inclusion constraint"
        );
    }

    // Registrations run in-circuit and agree with the native indexed-tree executor.
    #[test]
    fn registrations_native_matches_circuit() {
        let d = config::TREE_H - 1;
        let token = Fr::from(1u64);
        let mut exec = EpochExecutor::new(d);
        let z0 = exec.initial_state();

        // Register three accounts out of key order to exercise interval splitting.
        let regs = vec![
            exec.register_indexed(Fr::from(500u64), token, 1_000, 0),
            exec.register_indexed(Fr::from(2000u64), token, 5, 0),
            exec.register_indexed(Fr::from(900u64), token, 0, 0),
        ];
        let z_expected = exec.state();

        let circuit = LedgerCircuit::new_with_regs(3, 0, d);
        let cs = ConstraintSystem::<Fr>::new_ref();
        let z_var =
            <[FpVar<Fr>; 3] as AllocVar<[Fr; 3], Fr>>::new_witness(cs.clone(), || Ok(z0)).unwrap();
        let i = FpVar::new_witness(cs.clone(), || Ok(Fr::from(0u64))).unwrap();
        let (z_next, _) = circuit
            .synthesize_step(i, z_var, EpochStepInput { regs, ops: vec![] })
            .unwrap();
        assert!(cs.is_satisfied().unwrap(), "register circuit satisfied");
        let got: Vec<Fr> = z_next.iter().map(|v| v.value().unwrap()).collect();
        assert_eq!(got, z_expected.to_vec(), "register z_next == native");
    }

    // A0 soundness: an operator cannot register the same key twice. The only leaf that could
    // bracket an already-present key `q` is its predecessor `L`, whose `next` now equals `q`, so
    // `q < L.next` (i.e. `q < q`) fails — no valid non-membership witness exists.
    #[test]
    fn duplicate_key_registration_rejected() {
        let d = config::TREE_H - 1;
        let token = Fr::from(1u64);
        let q = Fr::from(777u64);
        let mut exec = EpochExecutor::new(d);
        let _ = exec.register_indexed(q, token, 10, 0);
        let z1 = exec.state();

        // Craft a malicious second registration of `q`, using its true predecessor (the sentinel
        // 0, whose next is now q) as the claimed `low`. `key < low_next` => `q < q` must fail.
        let low_key = Fr::from(0u64);
        let low_slot = 0u64;
        let low_next = q; // sentinel's next was set to q by the first registration
        let low_bits = index_bits(low_slot, d);
        let low_sibs = exec.tree.siblings(low_slot as usize).unwrap();
        let new_slot = exec.next; // next fresh slot
        let new_bits = index_bits(new_slot, d);
        let new_sibs = exec.tree.siblings(new_slot as usize).unwrap();
        let malicious = RegWitness {
            active: true,
            key: q,
            token,
            balance: Fr::from(10u64),
            nonce: Fr::from(0u64),
            pk_hash: Fr::from(0u64),
            low_key,
            low_next,
            low_token: Fr::from(0u64),
            low_balance: Fr::from(0u64),
            low_nonce: Fr::from(0u64),
            low_pk_hash: Fr::from(0u64),
            low_index_bits: low_bits,
            low_siblings: low_sibs,
            new_index_bits: new_bits,
            new_siblings: new_sibs,
        };

        let circuit = LedgerCircuit::new_with_regs(1, 0, d);
        let cs = ConstraintSystem::<Fr>::new_ref();
        let z_var =
            <[FpVar<Fr>; 3] as AllocVar<[Fr; 3], Fr>>::new_witness(cs.clone(), || Ok(z1)).unwrap();
        let i = FpVar::new_witness(cs.clone(), || Ok(Fr::from(0u64))).unwrap();
        let _ = circuit
            .synthesize_step(i, z_var, EpochStepInput { regs: vec![malicious], ops: vec![] })
            .unwrap();
        assert!(
            !cs.is_satisfied().unwrap(),
            "duplicate key registration must be rejected (q < q fails)"
        );
    }

    // A1 soundness: a debit with an invalid spend-key signature must be rejected in-circuit.
    #[test]
    fn bad_signature_rejected() {
        let d = config::TREE_H - 1;
        let token = Fr::from(1u64);
        let pool = Fr::from(1000u64);
        let a = Fr::from(2001u64);
        let mut exec = EpochExecutor::new(d);
        exec.register(pool, token, 1_000_000, 0);
        exec.register(a, token, 0, 0);
        let z0 = exec.initial_state();

        let mut ops = vec![exec.apply(0, pool, a, token, 500)];
        // Corrupt the debit signature scalar `s`; the in-circuit Schnorr verify must fail.
        ops[0].from_sig.0 += GrScalar::from(1u64);

        let circuit = LedgerCircuit::new(1, d);
        let cs = ConstraintSystem::<Fr>::new_ref();
        let z_var =
            <[FpVar<Fr>; 3] as AllocVar<[Fr; 3], Fr>>::new_witness(cs.clone(), || Ok(z0)).unwrap();
        let i = FpVar::new_witness(cs.clone(), || Ok(Fr::from(0u64))).unwrap();
        let _ = circuit
            .synthesize_step(i, z_var, EpochStepInput { regs: vec![], ops })
            .unwrap();
        assert!(
            !cs.is_satisfied().unwrap(),
            "invalid debit signature must be rejected"
        );
    }
}
