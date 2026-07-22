//! Native epoch executor: maintains the real Poseidon IMT plus per-account balances and
//! nonces, and emits authentic `OpWitness`es (membership paths against the evolving tree)
//! together with the running IVC state. This is the source of truth the circuit must
//! reproduce, and what the prover streams into Nova.
//!
//! Prototype modelling choices (documented, not production):
//!
//! * Accounts are *registered* into the genesis tree (the epoch's initial `stateRoot`)
//!   before any op. A real deployment creates accounts lazily; here the epoch simply
//!   starts from a committed prior state that already contains every (key, tokenId).
//! * A `withdraw(payee)` moves the payee's net into a settlement `sink` leaf (value
//!   stays conserved in-tree) and folds `(payeeKey, tokenId, amount)` into `netsAcc`.
//!   The ordered `nets` list is exposed so the settlement calldata (and the on-chain
//!   `withdrawalsAcc` recomputation) can be built in the exact same order.

use ark_crypto_primitives::sponge::Absorb;
use ark_ff::{BigInteger, PrimeField};
use std::collections::HashMap;

use crate::imt::MerkleTree;
use crate::ops::{OpKind, OpWitness};
use crate::poseidon::PoseidonNative;

/// Reserved key for the settlement sink (receives withdrawn value).
const SINK_TAG: u64 = 0x5151_5151_5151_5151;

pub struct EpochExecutor<F: PrimeField + Absorb, const D: usize> {
    tree: MerkleTree<F>,
    poseidon: PoseidonNative<F>,
    slots: HashMap<Repr, u64>,
    token_of: HashMap<Repr, F>,
    balances: HashMap<Repr, u128>,
    nonces: HashMap<Repr, u64>,
    next_slot: u64,
    ops_acc: F,
    nets_acc: F,
    /// Ordered net-effect entries `(payeeKey, tokenId, amount)`, one per withdraw.
    pub nets: Vec<(F, F, u128)>,
    sink_key: F,
}

// We key maps by the field element's canonical byte representation.
type Repr = Vec<u8>;

fn repr<F: PrimeField>(x: &F) -> Repr {
    x.into_bigint().to_bytes_le()
}

impl<F: PrimeField + Absorb, const D: usize> EpochExecutor<F, D> {
    pub fn new() -> Self {
        let sink_key = F::from(SINK_TAG);
        // NOTE: the sink is NOT auto-registered here — a leaf binds its tokenId, and the
        // sink must be registered with the SAME token the withdraws use. The workload
        // registers it during genesis via `register(exec.sink_key(), token, 0, 0)`.
        Self {
            tree: MerkleTree::new(D),
            poseidon: PoseidonNative::new(),
            slots: HashMap::new(),
            token_of: HashMap::new(),
            balances: HashMap::new(),
            nonces: HashMap::new(),
            next_slot: 0,
            ops_acc: F::zero(),
            nets_acc: F::zero(),
            nets: Vec::new(),
            sink_key,
        }
    }

    /// Register an account into the genesis tree with a starting balance/nonce.
    pub fn register(&mut self, key: F, token_id: F, balance: u128, nonce: u64) {
        let k = repr(&key);
        if self.slots.contains_key(&k) {
            // update token/balance in place (used only for the sink placeholder)
            self.token_of.insert(k.clone(), token_id);
        } else {
            let slot = self.next_slot;
            self.next_slot += 1;
            assert!(slot < (1u64 << D), "tree of depth {D} is full");
            self.slots.insert(k.clone(), slot);
            self.token_of.insert(k.clone(), token_id);
        }
        self.balances.insert(k.clone(), balance);
        self.nonces.insert(k.clone(), nonce);
        let slot = self.slots[&k];
        let leaf = self
            .poseidon
            .h4(key, token_id, F::from(balance), F::from(nonce));
        self.tree.set_leaf(slot, leaf);
    }

    /// z_0 = [initial stateRoot, 0, 0]. Call after all registrations, before any op.
    pub fn initial_state(&self) -> [F; 3] {
        assert!(self.ops_acc.is_zero() && self.nets_acc.is_zero(), "call before ops");
        [self.tree.root(), F::zero(), F::zero()]
    }

    /// z_n = [stateRoot, opsAcc, netsAcc] after all applied ops.
    pub fn state(&self) -> [F; 3] {
        [self.tree.root(), self.ops_acc, self.nets_acc]
    }

    /// Exit witness for `key` against the *current* tree: `(balance, nonce, siblings, index_bits)`.
    /// Fed to the on-chain escape hatch, which recomputes the leaf and opens it to `stateRoot`.
    pub fn exit_witness(&self, key: F) -> Option<(u128, u64, Vec<F>, Vec<bool>)> {
        let k = repr(&key);
        let slot = *self.slots.get(&k)?;
        let balance = *self.balances.get(&k)?;
        let nonce = *self.nonces.get(&k)?;
        Some((balance, nonce, self.tree.siblings(slot), self.tree.index_bits(slot)))
    }

    pub fn sink_key(&self) -> F {
        self.sink_key
    }

    pub fn load(&mut self, from: F, to: F, token_id: F, amount: u128) -> OpWitness<F, D> {
        self.apply(OpKind::Load, from, to, token_id, amount)
    }

    pub fn spend(&mut self, from: F, to: F, token_id: F, amount: u128) -> OpWitness<F, D> {
        self.apply(OpKind::Spend, from, to, token_id, amount)
    }

    /// Settle a payee's net into the sink and fold it into `netsAcc`.
    pub fn withdraw(&mut self, payee: F, token_id: F, amount: u128) -> OpWitness<F, D> {
        self.apply(OpKind::Withdraw, payee, self.sink_key, token_id, amount)
    }

    fn apply(&mut self, kind: OpKind, from: F, to: F, token_id: F, amount: u128) -> OpWitness<F, D> {
        let (fk, tk) = (repr(&from), repr(&to));
        let from_old_balance = *self.balances.get(&fk).expect("from registered");
        let from_old_nonce = *self.nonces.get(&fk).expect("from registered");
        let from_slot = *self.slots.get(&fk).expect("from slot");
        let to_slot = *self.slots.get(&tk).expect("to slot");

        assert!(from_old_balance >= amount, "insufficient balance in native executor");

        // record the `from` path against the current root, then debit + rewrite.
        let from_index_bits: [bool; D] = self.tree.index_bits(from_slot).try_into().unwrap();
        let from_siblings: [F; D] = self.tree.siblings(from_slot).try_into().unwrap();

        let from_new_balance = from_old_balance - amount;
        let from_new_nonce = from_old_nonce + 1;
        let from_new_leaf = self.poseidon.h4(
            from,
            token_id,
            F::from(from_new_balance),
            F::from(from_new_nonce),
        );
        self.tree.set_leaf(from_slot, from_new_leaf);
        self.balances.insert(fk.clone(), from_new_balance);
        self.nonces.insert(fk.clone(), from_new_nonce);

        // record the `to` path against the intermediate root, then credit.
        let to_old_balance = *self.balances.get(&tk).expect("to registered");
        let to_old_nonce = *self.nonces.get(&tk).expect("to registered");
        let to_index_bits: [bool; D] = self.tree.index_bits(to_slot).try_into().unwrap();
        let to_siblings: [F; D] = self.tree.siblings(to_slot).try_into().unwrap();

        let to_new_balance = to_old_balance + amount;
        let to_new_leaf =
            self.poseidon
                .h4(to, token_id, F::from(to_new_balance), F::from(to_old_nonce));
        self.tree.set_leaf(to_slot, to_new_leaf);
        self.balances.insert(tk.clone(), to_new_balance);

        // accumulators (opHash uses the spender's expected nonce = from_old_nonce).
        let op_hash = self.poseidon.hn(&[
            F::from(kind.code()),
            from,
            to,
            token_id,
            F::from(amount),
            F::from(from_old_nonce),
        ]);
        self.ops_acc = self.poseidon.h2(self.ops_acc, op_hash);
        if kind == OpKind::Withdraw {
            self.nets_acc = self.poseidon.h4(self.nets_acc, from, token_id, F::from(amount));
            self.nets.push((from, token_id, amount));
        }

        OpWitness {
            active: true,
            kind: kind.code(),
            from_key: from,
            to_key: to,
            token_id,
            amount: F::from(amount),
            nonce: F::from(from_old_nonce),
            from_old_balance: F::from(from_old_balance),
            from_old_nonce: F::from(from_old_nonce),
            from_index_bits,
            from_siblings,
            to_old_balance: F::from(to_old_balance),
            to_old_nonce: F::from(to_old_nonce),
            to_index_bits,
            to_siblings,
        }
    }
}

impl<F: PrimeField + Absorb, const D: usize> Default for EpochExecutor<F, D> {
    fn default() -> Self {
        Self::new()
    }
}
