//! Poseidon hashing for the ledger circuit.
//!
//! We use sonobe's `poseidon_canonical_config` (BN254 Fr: width t = 5, rate 4,
//! capacity 1, 8 full + 60 partial rounds, α = 5). That config is the one sonobe's
//! folding transcript uses and — per sonobe's own note — "agrees with Circom's
//! Poseidon(4)".
//!
//! Hash-arity discipline (this is load-bearing for the on-chain accumulator match):
//!
//! * `h4` — a **fixed 4-input** Poseidon (one full rate block, one permutation). This
//!   is the ONLY hash the contract ever recomputes on-chain (`netsAcc`/`withdrawalsAcc`).
//!   Because the state generator dumps arkworks' exact ark/MDS constants into
//!   `PoseidonT5.sol` (see `crates/prover` codegen), `h4` here and `PoseidonT5.hash4`
//!   on-chain are identical by construction, cross-checked by a committed fixture.
//! * `h2` / `hn` — internal-only hashes (Merkle nodes, `opsAcc`, `opHash`). Never
//!   recomputed on-chain, so they only need native/in-circuit agreement, which arkworks
//!   gives us for free (`CRH` vs `CRHGadget` share the sponge implementation).
//!
//! `h4` and `hn` are the arkworks Poseidon **sponge CRH** (absorb inputs, squeeze one).

use ark_crypto_primitives::{
    crh::{
        poseidon::{
            constraints::{CRHGadget, CRHParametersVar},
            CRH,
        },
        CRHScheme, CRHSchemeGadget,
    },
    sponge::{poseidon::PoseidonConfig, Absorb},
};
use ark_ff::PrimeField;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};
use folding_schemes::transcript::poseidon::poseidon_canonical_config;

/// The canonical BN254 Poseidon config (t = 5). Re-exported so the prover's Solidity
/// code-generator dumps the *same* constants the circuit uses.
pub fn canonical_config<F: PrimeField>() -> PoseidonConfig<F> {
    poseidon_canonical_config::<F>()
}

/// Native Poseidon helpers (used by the witness generator / native step function).
#[derive(Clone)]
pub struct PoseidonNative<F: PrimeField + Absorb> {
    pub config: PoseidonConfig<F>,
}

impl<F: PrimeField + Absorb> PoseidonNative<F> {
    pub fn new() -> Self {
        Self { config: canonical_config::<F>() }
    }

    /// Fixed 4-input Poseidon — the on-chain-matched primitive.
    pub fn h4(&self, a: F, b: F, c: F, d: F) -> F {
        CRH::<F>::evaluate(&self.config, [a, b, c, d]).expect("poseidon h4")
    }

    /// 2-input Poseidon (Merkle nodes, accumulator folds) — internal only.
    pub fn h2(&self, a: F, b: F) -> F {
        CRH::<F>::evaluate(&self.config, [a, b]).expect("poseidon h2")
    }

    /// Variable-length Poseidon (op hashing) — internal only.
    pub fn hn(&self, input: &[F]) -> F {
        CRH::<F>::evaluate(&self.config, input.to_vec()).expect("poseidon hn")
    }
}

impl<F: PrimeField + Absorb> Default for PoseidonNative<F> {
    fn default() -> Self {
        Self::new()
    }
}

/// In-circuit Poseidon helpers. Holds the parameters as a circuit constant.
pub struct PoseidonGadget<F: PrimeField + Absorb> {
    pub params: CRHParametersVar<F>,
}

impl<F: PrimeField + Absorb> PoseidonGadget<F> {
    pub fn new(cs: ConstraintSystemRef<F>, config: &PoseidonConfig<F>) -> Result<Self, SynthesisError> {
        Ok(Self { params: CRHParametersVar::<F>::new_constant(cs, config.clone())? })
    }

    pub fn h4(
        &self,
        a: &FpVar<F>,
        b: &FpVar<F>,
        c: &FpVar<F>,
        d: &FpVar<F>,
    ) -> Result<FpVar<F>, SynthesisError> {
        let input = [a.clone(), b.clone(), c.clone(), d.clone()];
        CRHGadget::<F>::evaluate(&self.params, &input)
    }

    pub fn h2(&self, a: &FpVar<F>, b: &FpVar<F>) -> Result<FpVar<F>, SynthesisError> {
        let input = [a.clone(), b.clone()];
        CRHGadget::<F>::evaluate(&self.params, &input)
    }

    pub fn hn(&self, input: &[FpVar<F>]) -> Result<FpVar<F>, SynthesisError> {
        CRHGadget::<F>::evaluate(&self.params, input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_r1cs_std::{alloc::AllocVar, GR1CSVar};
    use ark_relations::gr1cs::ConstraintSystem;

    /// Native and in-circuit `h4` must agree bit-for-bit; this is what the on-chain
    /// `PoseidonT5.sol` fixture is pinned to.
    #[test]
    fn h4_native_matches_gadget() {
        let native = PoseidonNative::<Fr>::new();
        let cs = ConstraintSystem::<Fr>::new_ref();
        let g = PoseidonGadget::<Fr>::new(cs.clone(), &native.config).unwrap();

        let vals = [Fr::from(1u64), Fr::from(2u64), Fr::from(3u64), Fr::from(4u64)];
        let out_native = native.h4(vals[0], vals[1], vals[2], vals[3]);

        let vars: Vec<FpVar<Fr>> = vals
            .iter()
            .map(|v| FpVar::new_witness(cs.clone(), || Ok(*v)).unwrap())
            .collect();
        let out_gadget = g.h4(&vars[0], &vars[1], &vars[2], &vars[3]).unwrap();

        assert_eq!(out_native, out_gadget.value().unwrap());
        assert!(cs.is_satisfied().unwrap());
    }
}
