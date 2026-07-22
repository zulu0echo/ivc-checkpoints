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
- `cargo test -p ledger-circuit-newline` — the circuit's output state is **bit-identical to the
  native executor** across a batch exercising every op kind.

## Status / next (see BUILD_PLAN_A0_A1.md)
- **Phase 1 (this crate): done.**
- Phase 2 — A0: swap the hand-rolled tree for plasma-blind `sparsemt` (key-indexed; lazy insertion).
- Phase 3 — A1: add plasma-blind `schnorr` per-debit auth (ECDSA owner + delegated spend key).
- Phase 4 — decider/EVM re-target, **gated on PR #259 merging to `staging`**.

## Caveats
- The pinned sonobe rev is a **draft branch** (`revamp/decider`); re-pin to `staging` once the
  decider merges (Phase 4).
- Uses the same simplified workload semantics as the classic prototype (pre-registered accounts,
  single settlement sink) — real semantics come with A0/A1.
