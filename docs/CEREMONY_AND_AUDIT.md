# Phase 5 — trusted setup, audit scope, benchmarks

This consolidates what a production deployment of the new-line (A0 + A1) prover needs beyond a
green test suite: a real trusted setup, an audit scope that names every deviation and assumption,
and the measured figures in one place.

## Trusted setup / ceremony

The decider is **LegoGroth16** (a commit-and-prove Groth16). Like classic Groth16 it needs a
**per-circuit** structured reference string, so the setup is only valid for a **frozen circuit**.

Sequence:
1. **Freeze the circuit.** Fix `TREE_H` (production: 23 → depth 22), `batch`, `reg_batch`,
   `VALUE_BITS` (96), `KEY_BITS` (160), `SIG_WINDOW` (32), the Poseidon config
   (`poseidon_circom_config`), and the leaf layout `(key, next_key, token, balance, nonce, pk_hash)`.
   Any change invalidates the SRS.
2. **Phase 1 (universal):** reuse an existing Powers-of-Tau of sufficient degree (the circuit's
   constraint count sets the degree; measure it for the frozen params).
3. **Phase 2 (circuit-specific):** run a multi-party computation over the frozen constraint system
   to produce the LegoGroth16 proving/verifying keys. Publish all contribution transcripts; the
   setup is sound if ≥1 participant was honest.
4. **Pin the commitment key.** LegoGroth16 additionally commits to the folded instance; its
   commitment key must be part of the ceremony output and match the on-chain verifier.
5. **Render + freeze `DeciderVerifier.sol` / `LegoGroth16Verifier.sol`** from the ceremony vk (the
   dev artifacts in `contracts/generated/newline/` are rendered from a random-seeded key and are
   **not** usable in production).
6. **Re-derive on-chain Poseidon.** `PoseidonT5.sol` must be regenerated for `poseidon_circom_config`
   and extended to the arity-6 leaf so the exit path recomputes leaves identically to the circuit.

Until the ceremony, everything is **dev-mode** (random setup) — the same trust status the classic
`main` prototype documents.

## Audit scope — deviations & assumptions to review

Anything below is load-bearing for soundness and must be in scope:

- **Empty leaf = 0 (sparsemt deviation).** `sparsemt/mod.rs::gen_empty_hashes` was changed from
  upstream plasma-blind to seed empties with `F::zero()` instead of `LeafHash(default)`. This is
  **required** for A0 non-membership soundness (an empty slot must be distinguishable from a real
  `(0,0)` low leaf). The audited plasma-blind `sparsemt` does **not** have this change, so the tree
  is no longer byte-identical to the audited code — audit this modification specifically.
- **Indexed-tree construction (A0).** The sorted-interval invariant, the `low_key < key < low_next`
  bracketing (with `low_next == 0` = +∞), the split-insert, the anti-clobber empty-slot check (R4),
  and the sentinel at slot 0. The R4 anti-clobber path has **no dedicated negative test** yet — add
  one and audit that an occupied target slot is rejected.
- **Bounded comparison.** `enforce_lt_when` assumes operands `< 2^KEY_BITS` (160). Keys/values
  outside that range break the comparison's soundness; the circuit must enforce the bound wherever
  untrusted field elements enter (it does for the operands it compares — verify completeness).
- **A1 signature binding.** The debit message is `(from, to, token, amount, nonce)`; replay
  protection rides on `nonce == from_old_nonce`. `pk_hash = Poseidon(pk.x, pk.y)` binds the
  Grumpkin spend key; padding ops carry a valid dummy signature so verify is unconditional. Audit
  that every balance-decreasing path is gated by a verified signature (currently: the `from` side
  of every transfer/withdraw; registration credits only).
- **Hybrid ownership.** `key` = Ethereum (ECDSA) owner used for on-chain exit; `pk_hash` = delegated
  in-circuit spend key. The on-chain exit/escape-hatch (classic `ProvenCheckpoint`) must be
  re-checked against the arity-6 leaf.
- **Moving dependency.** Pinned to sonobe PR #259 (`243391e`, unmerged) and plasma-blind
  `dmpierre/sonobe@8269ea4`; reconcile to one audited rev before ceremony.

## Benchmarks (measured [M], 24 GB machine)

| Item | Value | Source |
|---|---|---|
| `verifyDeciderProof` gas (A0+A1, z_len 3) | 696,556 | [DECIDER_RESULTS.md](DECIDER_RESULTS.md) |
| Decider prove + verify wall time | ~280 s | same |
| Peak RSS (decider) | ~7.7 GB | same |
| In-circuit Schnorr verify | ~5,136 constraints | Phase 3 |
| Classic line on-chain (Groth16) | 799,731 gas | classic `main` |

Not yet measured (needed for production sign-off): step-circuit constraint count at
`TREE_H = 23` / larger `batch`; decider prove time + RAM at those params; end-to-end
`ProvenCheckpoint` forge gas once the contract is rewired.
