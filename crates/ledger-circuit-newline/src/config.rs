//! Poseidon-backed `merkle_tree::Config` + `ConfigGadget` for the ledger account tree,
//! wired for plasma-blind's `sparsemt` (`MerkleSparseTree` + `MerkleSparseTreeGadget`).
//!
//! The account leaf is the 4-tuple `(key, tokenId, balance, nonce)`. We need a **sized**
//! leaf so the native side satisfies `SparseConfig: Config<Leaf: Default>` and the gadget
//! side satisfies `ConfigGadget::LeafHash: CRHSchemeGadget<_, InputVar = Self::Leaf>` with a
//! `Sized` leaf. arkworks' stock `poseidon::CRH` has `Input = [F]` (unsized), so — exactly as
//! plasma-blind does for its `UTXOCRH` — we wrap it in a sized-input CRH (`LeafCrh` /
//! `LeafCrhVar`) that delegates to the poseidon sponge. Node hashing uses arkworks' built-in
//! `poseidon::TwoToOneCRH`. Every hash takes `poseidon_circom_config()` as its parameters, so
//! the tree is **bit-identical** to the Phase-1 hand-rolled tree's hashing.

use std::borrow::Borrow;
use std::marker::PhantomData;

use ark_bn254::Fr;
use ark_crypto_primitives::{
    crh::{
        poseidon::{
            constraints::{CRHGadget, CRHParametersVar, TwoToOneCRHGadget},
            CRH, TwoToOneCRH,
        },
        CRHScheme, CRHSchemeGadget,
    },
    merkle_tree::{constraints::ConfigGadget, Config, IdentityDigestConverter},
    sponge::poseidon::PoseidonConfig,
    Error,
};
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::gr1cs::SynthesisError;
use ark_std::rand::Rng;
use sonobe_primitives::transcripts::poseidon::poseidon_circom_config;

use crate::sparsemt::{constraints::SparseConfigGadget, SparseConfig};

/// Number of field elements in an account leaf: (key, tokenId, balance, nonce).
pub const LEAF_ARITY: usize = 4;

/// Tree height (number of levels including the leaf level). Merkle depth = `TREE_H - 1`.
/// Kept small for fast constraint-satisfaction tests; production would raise this (e.g. 23 for
/// a depth-22 tree, matching the classic `main` prototype).
pub const TREE_H: usize = 11;

// ---------------- sized-input leaf CRH (native) ----------------

/// Poseidon hash of a sized 4-field account leaf. Delegates to `poseidon::CRH` (Input `[Fr]`).
pub struct LeafCrh;

impl CRHScheme for LeafCrh {
    type Input = [Fr; LEAF_ARITY];
    type Output = Fr;
    type Parameters = PoseidonConfig<Fr>;

    fn setup<R: Rng>(_rng: &mut R) -> Result<Self::Parameters, Error> {
        Ok(poseidon_circom_config())
    }

    fn evaluate<T: Borrow<Self::Input>>(
        parameters: &Self::Parameters,
        input: T,
    ) -> Result<Self::Output, Error> {
        let arr = input.borrow();
        CRH::<Fr>::evaluate(parameters, arr.as_slice())
    }
}

// ---------------- sized-input leaf CRH (gadget) ----------------

/// In-circuit counterpart of [`LeafCrh`].
pub struct LeafCrhVar;

impl CRHSchemeGadget<LeafCrh, Fr> for LeafCrhVar {
    type InputVar = [FpVar<Fr>; LEAF_ARITY];
    type OutputVar = FpVar<Fr>;
    type ParametersVar = CRHParametersVar<Fr>;

    fn evaluate(
        parameters: &Self::ParametersVar,
        input: &Self::InputVar,
    ) -> Result<Self::OutputVar, SynthesisError> {
        CRHGadget::<Fr>::evaluate(parameters, input.as_slice())
    }
}

// ---------------- merkle_tree::Config (native) ----------------

/// Account tree config: sized 4-field leaf, Poseidon leaf + two-to-one node hashes.
pub struct LedgerConfig<const H: usize> {
    _p: PhantomData<()>,
}

impl<const H: usize> Config for LedgerConfig<H> {
    type Leaf = [Fr; LEAF_ARITY];
    type LeafDigest = Fr;
    type LeafInnerDigestConverter = IdentityDigestConverter<Fr>;
    type InnerDigest = Fr;
    type LeafHash = LeafCrh;
    type TwoToOneHash = TwoToOneCRH<Fr>;
}

impl<const H: usize> SparseConfig for LedgerConfig<H> {
    const HEIGHT: usize = H;
}

// ---------------- ConfigGadget (gadget) ----------------

pub struct LedgerConfigGadget<const H: usize> {
    _p: PhantomData<()>,
}

impl<const H: usize> ConfigGadget<LedgerConfig<H>, Fr> for LedgerConfigGadget<H> {
    type Leaf = [FpVar<Fr>; LEAF_ARITY];
    type LeafDigest = FpVar<Fr>;
    type LeafInnerConverter = IdentityDigestConverter<FpVar<Fr>>;
    type InnerDigest = FpVar<Fr>;
    type LeafHash = LeafCrhVar;
    type TwoToOneHash = TwoToOneCRHGadget<Fr>;
}

impl<const H: usize> SparseConfigGadget<LedgerConfig<H>, Fr> for LedgerConfigGadget<H> {
    const HEIGHT: usize = H;
}
