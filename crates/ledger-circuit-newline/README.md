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
- **Phase 2b (A0):** the account tree is now a **unified indexed/interval Merkle tree** (Design B).
  Leaf = `(key, next_key, token, balance, nonce)`; the `next_key` pointers form a sorted linked
  list. Registration is an **in-circuit `RegWitness` op**: prove non-membership of the new key via
  the bracketing low leaf (`low_key < key` and `key < low_next` unless `low_next == 0` = +∞),
  split that interval (`low.next := key`), prove the target slot is empty, and insert
  `(key, low_next, …)`. Key uniqueness (A0) follows from the sorted-interval invariant — an
  operator cannot place the same key at two slots. Comparison uses a bounded `<` gadget
  (`KEY_BITS = 160`). **Soundness note:** empty leaves hash to `0` (a deliberate deviation from
  upstream `sparsemt`, documented in [`src/sparsemt/mod.rs`](src/sparsemt/mod.rs)) so an empty slot
  can never be passed off as a `(0, 0)` low leaf.
- `cargo test -p ledger-circuit-newline` (5 tests):
  - `single_batch_native_matches_circuit` — transfer batch: circuit state **bit-identical to native**.
  - `tampered_sibling_breaks_inclusion` — corrupting a sibling makes the CS **unsatisfiable**.
  - `bounded_lt_gadget` — the conditional bounded `<` gadget (active enforces strict `<`; inactive neutralised).
  - `registrations_native_matches_circuit` — in-circuit registrations (with interval splitting) **match native**.
  - `duplicate_key_registration_rejected` — **A0**: a crafted duplicate registration is rejected (`q < q` fails).

## Status / next (see BUILD_PLAN_A0_A1.md)
- **Phase 1 / 2a / 2b (this crate): done.** A0 (no account forgery/duplication) is enforced in-circuit.
- Phase 3 — A1: add plasma-blind `schnorr` per-debit auth (ECDSA owner + delegated spend key), so
  the operator can't move a balance without the owner's key.
- Phase 4 — decider/EVM re-target, **gated on PR #259 merging to `staging`**.

## Caveats
- The pinned sonobe rev is a **draft branch** (`revamp/decider`); re-pin to `staging` once the
  decider merges (Phase 4).
- Uses the same simplified workload semantics as the classic prototype (pre-registered accounts,
  single settlement sink) — real semantics come with A0/A1.
