# Handoff — resume state (2026-07-22, Phase 2a complete)

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
| 2a — adopt `sparsemt` as base Merkle-map gadget (behaviour-equivalent) | ✅ done — agreement + tamper tests green |
| **2b — add `IntervalCRH` indexed-tree layer (real A0 key-uniqueness/non-membership)** | **🚧 NEXT — see below** |
| 3 — A1: plasma-blind `schnorr` per-debit in-circuit auth | pending |
| 4 — decider/EVM re-target (LegoGroth16), regen `DeciderVerifier.sol`, update contracts, re-measure gas | pending — **GATED on sonobe PR #259 merging to `staging`** |
| 5 — ceremony/audit hardening | pending |

## Phase 2a — DONE (committed on `newline-port`)
The account tree is now plasma-blind's `sparsemt`, behaviour-equivalent to the Phase-1 hand-rolled
tree. What landed:
- `crates/ledger-circuit-newline/src/sparsemt/{mod.rs,constraints.rs}` — plasma-blind's
  `MerkleSparseTree` + `MerkleSparseTreeGadget`, path-fixed for this crate.
- `crates/ledger-circuit-newline/src/config.rs` — a Poseidon-backed `merkle_tree::Config` +
  `ConfigGadget` (`LedgerConfig<const H>` / `LedgerConfigGadget<const H>`). Leaf = **sized**
  `[Fr;4]` `(key, tokenId, balance, nonce)`; leaf hash = a custom sized-input CRH (`LeafCrh` /
  `LeafCrhVar`) wrapping `poseidon::CRH`/`CRHGadget` (needed because stock `poseidon::CRH` has
  unsized `Input=[F]` but the sparse tree needs `Leaf: Sized`+`Default`); node hash = arkworks
  built-in `poseidon::TwoToOneCRH`/`TwoToOneCRHGadget`. **All hashes take `poseidon_circom_config()`**,
  so the tree is bit-identical to Phase-1's hashing. `TREE_H` const = tree height (currently 11 →
  depth 10; production would raise to 23).
- `lib.rs`: `synthesize_step` uses `mt.recover_root(&leaf_preimage, &index_bits, &siblings)`
  (`recover_root` hashes the preimage internally, so the explicit leaf-hash step was removed);
  `EpochExecutor` runs on `MerkleSparseTree` (`blank`/`update_and_prove`/`siblings`). Assigned
  index = account slot (key-uniqueness is 2b's job). The hand-rolled `MerkleTree` +
  `merkle_root_gadget` are gone.
- Tests green: `single_batch_native_matches_circuit` (native == circuit, all op kinds) and
  `tampered_sibling_breaks_inclusion` (flipping a sibling makes the CS unsatisfiable → the
  inclusion constraints bind).

Notes for later: `recover_root`/`siblings` use LSB-first path bits where bit i = "node at level i
is a right child"; the native `MerkleSparseTree` heap layout (`is_left_child = idx % 2 == 1`,
leaf at `idx + 2^(H-1) - 1`) matches this exactly, and `poseidon::TwoToOneCRH(a,b)` equals
`CRH([a,b])`, which is why the swap is behaviour-equivalent. `sparsemt/{mod.rs,constraints.rs}`
carry two harmless `unused import` warnings inherited from plasma-blind.

## Immediate next step (Phase 2b — real A0)
Add plasma-blind's **`IntervalCRH` indexed/interval tree** so account keys are provably unique /
non-duplicable (an assigned-index map alone lets an operator place a key at two indices). This is
where A0 soundness is actually won. Sources (in the re-cloned plasma-blind, see below):
- `core/src/primitives/crh/{mod.rs,constraints.rs}` — `IntervalCRH` + `IntervalCRHGadget`, and the
  `Init` trait (`utils.rs`) that parameterizes Poseidon per arity. NOTE: 2b likely needs the
  `Init`-based `NTo1CRH` path (or an interval-specific config), unlike 2a which deliberately reused
  `poseidon_circom_config` directly.
- `core/src/datastructures/nullifier/mod.rs` — `NullifierTreeConfig` (`Leaf = (F, F)` sorted
  intervals, `LeafHash = IntervalCRH`): the indexed-tree pattern to mirror for the account tree.
Design: prove non-membership of a new key via the low interval bracketing it, then insert; key the
ledger accounts through the interval tree. See BUILD_PLAN_A0_A1.md §"Phase 2 (A0) design note".

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
