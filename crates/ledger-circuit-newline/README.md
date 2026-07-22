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
- **Phase 3 (A1):** every **debit** carries a **Schnorr signature** (plasma-blind's gadget, over
  Grumpkin — whose base field is BN254 `Fr`, so verification runs in the ledger's own field) by the
  account's delegated spend key. The leaf's 6th field `pk_hash = Poseidon(pk.x, pk.y)` commits the
  spend pubkey; in `synthesize_step` the witnessed pubkey is checked against it and
  `SchnorrGadget::verify` runs over the debit message `(from, to, token, amount, nonce)`. The
  account identifier `key` is the Ethereum (ECDSA) owner used for on-chain exit; the Schnorr key is
  the delegated in-circuit spend key (hybrid). Signatures are always present (padding ops carry a
  valid dummy), so verify is unconditional; **~5,136 constraints per signature [M]**.
- `cargo test -p ledger-circuit-newline` (6 lib + 2 schnorr = 8 tests):
  - `single_batch_native_matches_circuit` — signed transfer batch: circuit state **bit-identical to native**.
  - `tampered_sibling_breaks_inclusion` — corrupting a sibling makes the CS **unsatisfiable**.
  - `bounded_lt_gadget` — the conditional bounded `<` gadget.
  - `registrations_native_matches_circuit` — in-circuit registrations (with interval splitting) **match native**.
  - `duplicate_key_registration_rejected` — **A0**: a crafted duplicate registration is rejected.
  - `bad_signature_rejected` — **A1**: a debit with an invalid spend-key signature is rejected.

## Status / next (see BUILD_PLAN_A0_A1.md)
- **Phases 1 / 2a / 2b / 3 (this crate): done. Full non-custody (A0 + A1) is enforced in-circuit** —
  the operator can neither forge/duplicate an account (A0) nor move a balance without the account's
  spend key (A1).
- **Phase 4 — decider measured:** the full circuit folds through Nova+CycleFold → LegoGroth16 and
  verifies on-chain in revm for **696,556 gas** (cheaper than the classic line's 799,731); see
  [docs/DECIDER_RESULTS.md](../../docs/DECIDER_RESULTS.md). Build `--features evm` to pull the
  decider crate and get `FCircuitEVMExt` (state → `uint256[3]`). **Still open:** the
  `ProvenCheckpoint` Solidity rewire (arity-6 Poseidon + `verifyDeciderProof` ABI).
- **Phase 5 — hardening docs:** ceremony plan + audit scope + benchmarks in
  [docs/CEREMONY_AND_AUDIT.md](../../docs/CEREMONY_AND_AUDIT.md).

## Caveats
- The pinned sonobe rev is a **draft branch** (`revamp/decider`); re-pin to `staging` once the
  decider merges (Phase 4).
- Uses the same simplified workload semantics as the classic prototype (pre-registered accounts,
  single settlement sink) — real semantics come with A0/A1.
