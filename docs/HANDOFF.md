# Handoff — resume state (2026-07-22)

This file lets a fresh session continue the `ivc-checkpoints` work with no prior context.
Read this, then `docs/BUILD_PLAN_A0_A1.md`, then the "Immediate next step" below.

## Repo & branches
- Repo: `~/ivc-checkpoints` (GitHub: `zulu0echo/ivc-checkpoints`, **public**, fresh history).
  - It is a genericized, public prototype. **Never reintroduce** the private
    `coordination-network` context (beneficiary/aid/S5/CROPS/specific org). Keep it generic.
- **`main`** — the working **classic** prototype: Rust ledger F-circuit + prover + `bench/` +
  Foundry `contracts/` (`ProvenCheckpoint.sol` with exit/freeze/branch, `PoseidonT5.sol`).
  arkworks **0.5** vendored under `vendor/` with `[patch]`, toolchain 1.97.1, classic sonobe
  (Groth16 `DeciderEth`). 14 forge tests green; Rust tests green. This is the reference; **leave
  it untouched** until the new line reaches parity.
- **`newline-port`** (current branch) — migration to the **new (audited) sonobe line**
  (`sonobe-primitives`/`fs`/`ivc`, crates.io arkworks **0.6.0**, gr1cs, edition 2024, LegoGroth16
  decider). No vendoring/`[patch]`. This is where Phases 1–5 happen.

## Goal of the migration (BUILD_PLAN_A0_A1.md)
Take the prototype from "escape-hatch non-custody" to **full non-custody**:
- **A0** (operator can't forge/duplicate your account) via an **indexed/interval Merkle tree**.
- **A1** (operator can't move your balance without your key) via **in-circuit Schnorr** per debit,
  with the leaf binding an **ECDSA owner + delegated Grumpkin/Poseidon Schnorr spend key** (hybrid;
  keep ECDSA for Ethereum-native ownership + free real-address exit via `msg.sender`).
Reuse [plasma-blind](https://github.com/privacy-ethereum/plasma-blind)'s primitives (`sparsemt`,
`IntervalCRH`/`NullifierTree`, `schnorr`) since it already lives on the new line.

## Phase status
| Phase | State |
|---|---|
| 0 — spike: new-line EVM decider works, gas ≈ 669k (LegoGroth16, trivial circuit) | ✅ done, measured |
| 1 — port ledger `FCircuit` to new trait; native-vs-circuit agreement test | ✅ done, green (`cargo test -p ledger-circuit-newline`) |
| **2a — adopt `sparsemt` as base Merkle-map gadget (behaviour-equivalent)** | **🚧 IN PROGRESS — see below** |
| 2b — add `IntervalCRH` indexed-tree layer (real A0 key-uniqueness/non-membership) | pending |
| 3 — A1: plasma-blind `schnorr` per-debit in-circuit auth | pending |
| 4 — decider/EVM re-target (LegoGroth16), regen `DeciderVerifier.sol`, update contracts, re-measure gas | pending — **GATED on sonobe PR #259 merging to `staging`** |
| 5 — ceremony/audit hardening | pending |

## Where Phase 2a is right now (exact)
Done and committed on `newline-port`:
- Copied plasma-blind `sparsemt/{mod.rs,constraints.rs}` into
  `crates/ledger-circuit-newline/src/sparsemt/`. Fixed internal path refs
  (`crate::primitives::sparsemt` → `crate::sparsemt`).
- Added `merkle_tree` to the crate's `ark-crypto-primitives` features.
- Added `pub mod sparsemt;` to `crates/ledger-circuit-newline/src/lib.rs`.
- **`cargo build -p ledger-circuit-newline --release` is GREEN** — the ported `sparsemt`
  (native `MerkleSparseTree` + gadget `MerkleSparseTreeGadget`) compiles **generically** in our
  arkworks-0.6 / sonobe-primitives@243391e stack. It is not yet *instantiated* or *used* by the
  circuit — that's the remaining 2a work.

## Immediate next step (finish 2a)
Behaviour-equivalent swap of the hand-rolled tree for `sparsemt`. In `ledger-circuit-newline`:

1. **Define a Poseidon-backed `merkle_tree::Config`** (new file `src/config.rs`), generic over
   height so tests can use a small tree:
   ```rust
   pub struct LedgerConfig<const H: usize>;
   impl<const H: usize> ark_crypto_primitives::merkle_tree::Config for LedgerConfig<H> {
       type Leaf = [Fr; 4];                 // (key, tokenId, balance, nonce)
       type LeafDigest = Fr;
       type LeafInnerDigestConverter = IdentityDigestConverter<Fr>;
       type InnerDigest = Fr;
       type LeafHash = poseidon::CRH<Fr>;         // params = PoseidonConfig (poseidon_circom_config)
       type TwoToOneHash = poseidon::TwoToOneCRH<Fr>;
   }
   impl<const H: usize> crate::sparsemt::SparseConfig for LedgerConfig<H> { const HEIGHT: usize = H; }
   // + ConfigGadget + SparseConfigGadget impls (poseidon::constraints::{CRHGadget,TwoToOneCRHGadget})
   ```
   Unknowns to resolve on build (arkworks 0.6): exact `ConfigGadget` associated-type names
   (`Leaf`/`LeafDigest`/`LeafInnerConverter`/`InnerDigest`/`LeafHash`/`TwoToOneHash`), and that
   `poseidon::CRH`/`TwoToOneCRH` both take `PoseidonConfig` params. `[Fr;4]: Default` holds (std
   array Default for N≤32); `[Fr;4]: Borrow<[Fr]>` satisfies `CRHScheme::Input=[Fr]`.
2. **Rewire `synthesize_step`** in `lib.rs`: replace the hand-rolled `merkle_root_gadget`
   (conditional_select left/right + `h_gadget`) with `MerkleSparseTreeGadget::update_root(old_leaf,
   new_leaf, index, proof)` for each account touched (from/to). `update_root` returns
   `(recover_root(old), recover_root(new))` sharing one proof; `index.to_n_bits_le(HEIGHT-1)`;
   `proof.len() == HEIGHT-1`. Index = the account **slot** (assigned index — behaviour-equivalent
   to today; key-uniqueness is 2b's job, not 2a's).
3. **Rebuild the native executor** (`EpochExecutor`) on `MerkleSparseTree` (native
   `new`/`generate_proof`/`update_and_prove`/`root`) instead of the hand-rolled `MerkleTree`, so
   witnesses (leaves + sibling proofs) come from the same structure the gadget verifies.
4. **Get the agreement test green**: `cargo test -p ledger-circuit-newline` — circuit output state
   must stay bit-identical to the native executor across a batch exercising every op kind. Use a
   small `H` (e.g. depth 10) in the test.
5. Commit + push. Update `README.md` (Phase 2a done) and `BUILD_PLAN_A0_A1.md`.

Then **2b**: add `IntervalCRH`/indexed-tree (plasma-blind `core/src/datastructures/nullifier/` +
`core/src/primitives/crh/`) so account keys are provably unique/non-duplicable (real A0). This is
where A0 soundness is actually won — see BUILD_PLAN_A0_A1.md §"Phase 2 (A0) design note".

## Key source locations (plasma-blind — the port source)
Scratchpad clones live under the **session-specific** dir and are **likely GONE in a new session**.
Re-clone if missing:
```
git clone https://github.com/privacy-ethereum/plasma-blind   # MIT; pins dmpierre/sonobe@8269ea4
git clone -b revamp/decider https://github.com/privacy-ethereum/sonobe sonobe-new  # PR #259, rev 243391e
```
In plasma-blind (`core/src/`):
- `primitives/sparsemt/{mod.rs,constraints.rs}` — the tree we ported (already copied in).
- `datastructures/nullifier/mod.rs` — `NullifierTreeConfig` (Leaf=(F,F), LeafHash=`IntervalCRH`): the
  indexed/interval tree for **2b**.
- `primitives/crh/` — Poseidon CRH + `IntervalCRH`/`IntervalCRHGadget`.
- `primitives/schnorr.rs` — native + gadget Schnorr over Grumpkin+Poseidon: **Phase 3 (A1)**.
- `datastructures/publickeymap/mod.rs` — example assigned-index map (leaf=PublicKey, index=UserId).
- `core/src/config.rs` — their `merkle_tree::Config` + Poseidon params wiring (reference for step 1).

In sonobe-new (new-line reference):
- `crates/primitives/src/circuits/mod.rs:69` — `FCircuit` trait (`synthesize_step`).
- `crates/ivc/src/lib.rs:660` `test_decider_evm` (instrumented to print `result.gas_used()`);
  `crates/ivc/src/compilers/cyclefold/adapters/nova.rs:317` `test_nova_nova_decider_evm`.
- `crates/snarks` — LegoGroth16 + `legogroth16.sol.askama`; `crates/ivc/templates/…decider.sol.askama`.

## Environment / gotchas
- `source ~/.cargo/env; export CARGO_NET_GIT_FETCH_WITH_CLI=true` before cargo (git deps).
- Toolchain: `main` uses 1.97.1 (vendored 0.5); `newline-port` crate declares rust-version 1.85.1
  and builds on stable (arkworks 0.6 crates.io). Machine has **24 GB RAM** — decider proving for the
  real step circuit is unmeasured (trivial-circuit decider fit in 24 GB; ours is larger).
- New line uses **`poseidon_circom_config()`** (from `sonobe_primitives`), NOT
  `poseidon_canonical_config`. On-chain Poseidon match must be re-derived for Phase 4.
- `solc 0.8.35` installed (needed for the new decider's `pragma ^0.8.35`).
- zsh: use `${=VAR}` to word-split; `$pipestatus[1]` (not bash `PIPESTATUS`).
- `sparsemt` gadget uses `sonobe_primitives::algebra::ops::bits::ToBitsGadgetExt` and
  `ark_crypto_primitives::merkle_tree::constraints::ConfigGadget`.

## Phase 4 gate (don't jump ahead)
Phases 1–3 (circuit) target the pinned new-line rev now. **Phase 4 (decider/EVM/contracts) is
gated on PR #259 merging to `staging`** — don't build the on-chain path on the moving
`revamp/decider` branch. Re-pin to `staging` when it lands, then regen `DeciderVerifier.sol`,
update `ProvenCheckpoint` (LegoGroth16 `verifyDeciderProof` entrypoint + digest + on-chain
leaf/Merkle hashing), and re-measure gas at z_len=3.
