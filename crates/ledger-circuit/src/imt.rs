//! Poseidon incremental Merkle tree (depth `D`).
//!
//! * Native side: an index-addressed sparse tree used by the witness generator to
//!   produce authentic membership paths and roots.
//! * Circuit side: `merkle_root_from_leaf`, which recomputes a root from a leaf +
//!   siblings + index bits. The F-circuit calls it twice per leaf write (once to check
//!   the *old* root equals the committed `stateRoot`, once to derive the *new* root),
//!   sharing the sibling set so overlapping paths are handled by the witness generator.
//!
//! Empty leaves hash to `F::zero()`; `zeros[level]` are the all-empty subtree roots.

use ark_ff::PrimeField;
use ark_r1cs_std::{boolean::Boolean, fields::fp::FpVar, select::CondSelectGadget};
use ark_relations::gr1cs::SynthesisError;
use ark_crypto_primitives::sponge::Absorb;
use std::collections::HashMap;

use crate::poseidon::{PoseidonGadget, PoseidonNative};

/// Native sparse incremental Merkle tree.
#[derive(Clone)]
pub struct MerkleTree<F: PrimeField + Absorb> {
    pub depth: usize,
    poseidon: PoseidonNative<F>,
    /// zeros[l] = root of an all-empty subtree of height l (zeros[0] = empty leaf = 0).
    zeros: Vec<F>,
    /// Non-default nodes keyed by (level, index). level 0 = leaves.
    nodes: HashMap<(usize, u64), F>,
}

impl<F: PrimeField + Absorb> MerkleTree<F> {
    pub fn new(depth: usize) -> Self {
        let poseidon = PoseidonNative::<F>::new();
        let mut zeros = Vec::with_capacity(depth + 1);
        zeros.push(F::zero());
        for l in 0..depth {
            let z = zeros[l];
            zeros.push(poseidon.h2(z, z));
        }
        Self { depth, poseidon, zeros, nodes: HashMap::new() }
    }

    fn node(&self, level: usize, index: u64) -> F {
        *self.nodes.get(&(level, index)).unwrap_or(&self.zeros[level])
    }

    pub fn root(&self) -> F {
        self.node(self.depth, 0)
    }

    /// Current leaf hash at `index` (zero if empty).
    pub fn leaf(&self, index: u64) -> F {
        self.node(0, index)
    }

    /// Little-endian index bits (bit i = does the path go right at level i).
    pub fn index_bits(&self, index: u64) -> Vec<bool> {
        (0..self.depth).map(|i| (index >> i) & 1 == 1).collect()
    }

    /// Bottom-up sibling hashes along the path to `index`.
    pub fn siblings(&self, index: u64) -> Vec<F> {
        let mut sibs = Vec::with_capacity(self.depth);
        let mut idx = index;
        for level in 0..self.depth {
            let sib_index = idx ^ 1;
            sibs.push(self.node(level, sib_index));
            idx >>= 1;
        }
        sibs
    }

    /// Set the leaf hash at `index` and recompute the affected path to the root.
    pub fn set_leaf(&mut self, index: u64, leaf_hash: F) {
        self.nodes.insert((0, index), leaf_hash);
        let mut idx = index;
        for level in 0..self.depth {
            let left;
            let right;
            if idx & 1 == 0 {
                left = self.node(level, idx);
                right = self.node(level, idx ^ 1);
            } else {
                left = self.node(level, idx ^ 1);
                right = self.node(level, idx);
            }
            let parent = self.poseidon.h2(left, right);
            let parent_index = idx >> 1;
            self.nodes.insert((level + 1, parent_index), parent);
            idx = parent_index;
        }
    }

    /// Recompute a root from a leaf + siblings + index bits (native mirror of the gadget).
    pub fn root_from_leaf(&self, leaf: F, siblings: &[F], index_bits: &[bool]) -> F {
        let mut cur = leaf;
        for (sib, bit) in siblings.iter().zip(index_bits) {
            let (l, r) = if *bit { (*sib, cur) } else { (cur, *sib) };
            cur = self.poseidon.h2(l, r);
        }
        cur
    }
}

/// In-circuit: recompute a Merkle root from a leaf, its sibling path and index bits.
pub fn merkle_root_from_leaf<F: PrimeField + Absorb>(
    poseidon: &PoseidonGadget<F>,
    leaf: &FpVar<F>,
    siblings: &[FpVar<F>],
    index_bits: &[Boolean<F>],
) -> Result<FpVar<F>, SynthesisError> {
    let mut cur = leaf.clone();
    for (sib, bit) in siblings.iter().zip(index_bits) {
        // bit == true  => `cur` is the right child, sibling is left.
        let left = FpVar::conditionally_select(bit, sib, &cur)?;
        let right = FpVar::conditionally_select(bit, &cur, sib)?;
        cur = poseidon.h2(&left, &right)?;
    }
    Ok(cur)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_r1cs_std::{alloc::AllocVar, GR1CSVar};
    use ark_relations::gr1cs::ConstraintSystem;

    #[test]
    fn native_path_roundtrips() {
        let mut t = MerkleTree::<Fr>::new(22);
        let p = PoseidonNative::<Fr>::new();
        let leaf = p.h4(Fr::from(7u64), Fr::from(1u64), Fr::from(100u64), Fr::from(0u64));
        let index = 12345u64;
        t.set_leaf(index, leaf);

        let sibs = t.siblings(index);
        let bits = t.index_bits(index);
        assert_eq!(t.root_from_leaf(leaf, &sibs, &bits), t.root());
    }

    #[test]
    fn gadget_matches_native_root() {
        let mut t = MerkleTree::<Fr>::new(22);
        let native_p = PoseidonNative::<Fr>::new();
        let leaf = native_p.h4(Fr::from(9u64), Fr::from(1u64), Fr::from(50u64), Fr::from(3u64));
        let index = 999u64;
        t.set_leaf(index, leaf);

        let cs = ConstraintSystem::<Fr>::new_ref();
        let g = PoseidonGadget::<Fr>::new(cs.clone(), &native_p.config).unwrap();
        let leaf_var = FpVar::new_witness(cs.clone(), || Ok(leaf)).unwrap();
        let sib_vars: Vec<FpVar<Fr>> = t
            .siblings(index)
            .into_iter()
            .map(|s| FpVar::new_witness(cs.clone(), || Ok(s)).unwrap())
            .collect();
        let bit_vars: Vec<Boolean<Fr>> = t
            .index_bits(index)
            .into_iter()
            .map(|b| Boolean::new_witness(cs.clone(), || Ok(b)).unwrap())
            .collect();

        let root_var = merkle_root_from_leaf(&g, &leaf_var, &sib_vars, &bit_vars).unwrap();
        assert_eq!(root_var.value().unwrap(), t.root());
        assert!(cs.is_satisfied().unwrap());
    }
}
