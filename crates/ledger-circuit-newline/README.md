# ledger-circuit-newline (Phase 1: migration to the new sonobe line)

This crate is the ledger F-circuit **ported to the new (audited) sonobe line**, per
[docs/BUILD_PLAN_A0_A1.md](../../docs/BUILD_PLAN_A0_A1.md). It lives on the `newline-port`
branch, a **parallel track** to `main` (which holds the working classic prototype).

## Stack
- `sonobe-primitives` @ `243391e` (branch `revamp/decider`, sonobe PR #259)
- **crates.io arkworks 0.6.0** — no forks, **no vendoring, no `[patch]`** (unlike the classic
  line). `gr1cs`, edition 2024.

## What's implemented (green)
- The new `FCircuit` trait: `synthesize_step(i, state, ext) -> (StateVar, ())`, `State = [Fr; 3]`
  (`[stateRoot, opsAcc, netsAcc]`), external inputs **passed by value** and allocated in-step,
  Poseidon via `poseidon_circom_config`.
- Full per-op logic (inclusion / 96-bit solvency / replay / conservation / ops+nets accumulation)
  plus a native executor.
- **Phase 2a:** the account tree is plasma-blind's `sparsemt` (`MerkleSparseTree` +
  `MerkleSparseTreeGadget`), wired through a Poseidon-backed `merkle_tree::Config`/`ConfigGadget`
  in [`src/config.rs`](src/config.rs) (sized 4-field leaf CRH + arkworks built-in
  `poseidon::TwoToOneCRH` node hash, all keyed by `poseidon_circom_config` so hashing is
  bit-identical to the Phase-1 hand-rolled tree). `recover_root` replaces the hand-rolled
  Merkle recomputation; the native executor runs on `MerkleSparseTree`.
- `cargo test -p ledger-circuit-newline` (2 tests):
  - `single_batch_native_matches_circuit` — circuit output state **bit-identical to the native
    executor** across a batch exercising every op kind.
  - `tampered_sibling_breaks_inclusion` — corrupting one sibling makes the CS **unsatisfiable**
    (the sparse-Merkle inclusion constraints actually bind).

## Status / next (see BUILD_PLAN_A0_A1.md)
- **Phase 1 (this crate): done.**
- **Phase 2a — A0 base tree: done** (behaviour-equivalent `sparsemt` swap; assigned-index map).
- Phase 2b — A0 soundness: add plasma-blind's `IntervalCRH` indexed/interval tree for provable
  key-uniqueness / non-membership (this is where A0 is actually won).
- Phase 3 — A1: add plasma-blind `schnorr` per-debit auth (ECDSA owner + delegated spend key).
- Phase 4 — decider/EVM re-target, **gated on PR #259 merging to `staging`**.

## Caveats
- The pinned sonobe rev is a **draft branch** (`revamp/decider`); re-pin to `staging` once the
  decider merges (Phase 4).
- Uses the same simplified workload semantics as the classic prototype (pre-registered accounts,
  single settlement sink) — real semantics come with A0/A1.
