# ivc-checkpoints

### A validity-proven checkpoint for an off-chain balance ledger — one constant-cost proof per epoch

An operator keeps a ledger of account balances **off-chain** and, once per **epoch**, posts a
small **on-chain checkpoint**: a commitment to the epoch's transfers plus one net payout per
payee. On its own that checkpoint is *evidence*, not enforcement — you have to trust the
operator's arithmetic. This repo adds a **folded zero-knowledge validity proof** (Nova +
CycleFold, via [sonobe](https://github.com/privacy-ethereum/sonobe)), verified on-chain at a
**flat ~0.8M gas no matter how many operations the epoch contained**, that the epoch's entire
ledger transition was applied correctly.

It builds the engine end-to-end: an arkworks F-circuit for one epoch's ledger transition, a
Nova+CycleFold prover that folds an epoch and produces a `DeciderEth` proof, a generated
on-chain `NovaDecider` verifier, and a `ProvenCheckpoint` contract that verifies the proof at
settlement. It's a **working prototype + measurement harness**: it turns the **[A]**
(analytical) verifier-cost figures into **[M]** (measured) ones on a real sonobe toolchain.

> **⚠️ This is a prototype, not production.** It uses a **dev-mode Groth16 setup** (no
> trusted-setup ceremony), pins **unaudited** sonobe/arkworks code, and takes deliberate
> modelling shortcuts (below). Do not deploy. See **§Security & prototype caveats**.

> 📄 **New to IVC / folding schemes or sonobe?** Start with the
> **[technical report](docs/REPORT.md)** — a self-contained explainer of what this is, what it
> costs, and why it matters, with diagrams and charts. Security details:
> **[docs/TRUST_MODEL.md](docs/TRUST_MODEL.md)**.

---

## What it demonstrates

Per epoch, one folded proof establishes — publicly, at constant on-chain cost — that the entire
ledger transition was applied correctly: no negative balances (96-bit solvency), no replayed
operations (per-account nonces), value conservation, and that the settled payee nets are
exactly what the proven operations imply. This replaces a commit-only checkpoint (fraud
*evidence*) with *validity*, without a per-account on-chain storage write.

---

## Architecture

```
crates/ledger-circuit/   The F-circuit (sonobe FCircuit trait, arkworks frontend — NOT Circom/Noir)
    poseidon.rs            Poseidon (canonical t=5 config); the on-chain-matched h4
    imt.rs                 Poseidon incremental Merkle tree, depth 22 (native + in-circuit)
    ops.rs                 Batch of B ops as external inputs (+ hand-written AllocVar)
    native.rs              EpochExecutor: real tree + ledger, emits authentic witnesses
    lib.rs                 LedgerCircuit<F, B, D>: per-op inclusion/solvency/replay/conservation/accumulation
    tests/constraints.rs   Prints measured per-op & per-step constraint counts [M]

crates/prover/           Epoch driver
    lib.rs                 Fold with Nova+CycleFold, DeciderEth prove, emit verifier + calldata
    workload.rs            Synthetic epochs (small / large daily)
    poseidon_codegen.rs    Generates PoseidonT5.sol from arkworks' OWN constants
    bin/prove_epoch.rs     CLI: fold an epoch, write contracts/generated/*
    bin/gen_poseidon.rs    CLI: write PoseidonT5.sol + fixture

contracts/               Foundry (solc 0.8.30, evm_version=prague, isolate mode)
    src/ProvenCheckpoint.sol   validity-proven settlement: extended digest, on-chain Poseidon nets
                               recomputation, state-root chaining, PROVER_TIMEOUT/UNPROVEN
                               degradation, governance-gated novaDecider + ppHash
    src/PoseidonT5.sol         GENERATED — arkworks-identical Poseidon(4)
    src/interfaces/IOpaqueDecider.sol
    generated/                 Prover output: NovaDecider.sol, proof.json, calldata (committed)
    test/                      Poseidon fixture cross-check; functional + negative; gas metering

bench/                   End-to-end measurement -> results/prover.json
script/compare_to_model.py   Merge [M], compare vs analytical model, flag >5%, -> results/
vendor/                  Pinned arkworks (algebra/snark/std) + groth16 + flyingnobita forks
```

### Design → code

| Design element | Here |
| --- | --- |
| IVC state `z = [stateRoot, opsAcc, netsAcc]`, `z_len = 3` | `LedgerCircuit`, `STATE_LEN` |
| Poseidon IMT depth 22, leaf `(key, tokenId, balance, nonce)` | `imt.rs`, `poseidon.h4` |
| Batch `B = 16` ops/step, `B` a const generic | `LedgerCircuit<F, const B, const D>`, `BATCH=16` |
| Per-op inclusion / solvency (96-bit) / replay / conservation / accumulation | `generate_step_constraints` |
| `settleEpochProven` extended digest incl. `newStateRoot` + keccak(nets) | `ProvenCheckpoint.settleEpochProven` |
| On-chain `withdrawalsAcc` Poseidon == proof `netsAcc` | `PoseidonT5.foldNet`, `NetsAccMismatch` |
| State-root chaining (`z_0` = prev proven root) | contract builds `z0` from `lastProvenRoot` |
| Prover-outage / UNPROVEN degradation, catch-up bound | `settleEpoch`, `EpochStatus`, `unprovenStreak` |
| Governance-gated verifier + `ppHash` (timelocked) | `initializeDecider` / `proposeDeciderUpgrade` / `executeDeciderUpgrade` |
| Public inputs are only `(i, z_0, z_n)` | verifier called with contract-supplied z0/zi + opaque proof |

---

## Pinned versions

| Component | Pin | Why |
| --- | --- | --- |
| **sonobe** | `main @ 63f2930d363150d4490ce2c4be8e0c25c2e1d92c` | see note below |
| Rust | `1.97.1` (see `rust-toolchain.toml`) | sonobe pins 1.88, but `ruint` (via revm) needs ≥1.90 |
| arkworks/algebra | `4cec9f0e` (vendored) | newest **0.5.x** with `SmallFp`, before the 0.6.0 release |
| arkworks/snark (gr1cs) | `845ce9d` (vendored) | matching 0.5.x gr1cs |
| arkworks/std | `1693bc5` (vendored) | matching 0.5.x |
| ark-groth16 | `b3b4a15` (vendored, de-gitted) | sonobe's pin |
| crypto-primitives / r1cs-std | flyingnobita `f559264` / `b4bab0c` (vendored) | sonobe's forks (gr1cs) |
| Foundry | forge 1.5.1, solc 0.8.30, evm_version=prague | tx-level gas accounting |

### ⚠️ The sonobe pin is `main`, not `staging` — read this

sonobe's audits are slated to run on the `staging` branch, but **`staging` does not yet contain
the EVM decider**: its HEAD is a ground-up rewrite with **no `DeciderEth`, no
`solidity-verifiers`, no `NovaDecider.sol` generation**, and a different `FCircuit` trait. The
complete Nova+CycleFold+EVM-decider pipeline this prototype needs lives on **`main`** (and
`dev`), so it pins `main @ 63f2930d`.

**When sonobe ports the decider onto the audited `staging`, this prototype MUST be re-validated
against it.** The F-circuit semantics are stable; the sonobe API is not.

### The `[patch]` / `vendor/` situation

sonobe's `Cargo.toml` repoints arkworks at **unpinned** git HEADs, and cargo honors `[patch]`
only from the root workspace. Reproducing sonobe's build today therefore requires pinning
arkworks to the 0.5.x-with-`SmallFp` set it actually built against (HEAD has since moved to
0.6.0 / MSRV 1.89). Because `ark-groth16` and the flyingnobita forks pull arkworks via their
**own** git deps — which `[patch.crates-io]` cannot reach, and which cargo will not let you
rev-pin against the same git URL — those crates are **vendored under `vendor/`** with their
arkworks git deps rewritten to crates.io requirements, so the whole graph unifies to one crate
per package. `Cargo.lock` is committed. Full rationale in `Cargo.toml` comments.

---

## Quick start

```bash
# 1. Circuit unit tests + measured constraint counts (no proving; ~1 min)
cargo test -p ledger-circuit --release -- --nocapture

# 2. Fold a small epoch -> DeciderEth proof -> generate verifier + calldata.
#    `light-test` shrinks the decider so this runs on modest hardware / CI.
cargo run -p prover --bin prove_epoch --release --features light-test -- --scale small

# 3. On-chain: verify the proof, run functional + negative tests, meter gas.
cd contracts && forge test -vv          # first run downloads solc 0.8.30

# 4. End-to-end measurement + comparison table.
cargo run -p bench --features light-test          # writes results/prover.json
(cd contracts && forge test --mt test_meter_and_write_gas)   # writes results/forge_gas.json
python3 script/compare_to_model.py                # writes results/measured.json + comparison.md

# Regenerate the on-chain Poseidon from arkworks' constants (rarely needed):
cargo run -p prover --bin gen_poseidon
```

### Definition of done (what actually passes here)

- `cargo test -p ledger-circuit` — green (Poseidon native==gadget, IMT, native==circuit step).
- Small-epoch end-to-end: fold → decider → generated verifier verifies on-chain in Foundry;
  valid proof **accepted**, mutated calldata **rejected**, wrong prev-root **rejected**, nets
  mismatch **rejected** (`contracts/test/ProvenCheckpoint.t.sol`).
- Poseidon on-chain == circuit `h4` (`contracts/test/PoseidonT5.t.sol`, arkworks-computed fixture).
- Verifier upgrades are timelocked; bootstrap/propose/execute + reverts tested
  (`GovernanceTimelockTest`).
- Constant-`i` padding is a no-op on state (`inactive_batch_is_noop`) — the basis for the
  privacy mode that hides epoch op-count (see docs/TRUST_MODEL.md §Privacy).
- Bench emits `results/prover.json`; `compare_to_model.py` emits the comparison table.

---

## Hardware requirements

| Path | RAM | Notes |
| --- | --- | --- |
| Circuit tests, constraint counts | any | no proving |
| **Small epoch + `light-test`** | ~**a few GB** | CI / laptop; the decider's ~9M-constraint Pedersen checks are skipped |
| **Full epoch (`--features full-bench`, no light-test)** | **≥ 64 GB** | real decider (~12M constraints); the production prover box |

`light-test` is **not sound** — the emitted verifier corresponds to the reduced circuit. Use it
only to exercise the pipeline. It does **not** change the verifier's public-input layout, so
**`verifyNovaProof` gas measured under light-test is structurally representative of the
production number**; prover **time and RAM under light-test are not**.

This repo's committed `contracts/generated/*` were produced with `light-test` on a 24 GB machine
(Apple Silicon). Regenerate with `full-bench` on a ≥64 GB box for production figures.

---

## Results

Provenance: **[M]** measured on the pinned toolchain, **[A]** analytical from the verifier
cost model. Numbers marked **[M, light-test]** / **[M, small]** are real measurements but on the
reduced circuit / small epoch and are **not** production figures.

### Circuit size [M] (depth 22, real sonobe/arkworks)

| metric | analytical [A] | measured [M] |
| --- | ---: | ---: |
| constraints / op | ~24,000 | **31,404** |
| constraints / step (B=16) | ~390,000 | **502,464** |
| decider circuit (`10,543,489 + 3x`) | ~11.7M | **12,050,881** |

### On-chain verifier [M]

| metric | model [A] | measured [M] | Δ |
| --- | ---: | ---: | ---: |
| calldata bytes (z_len=3) | 1,028 | **1,028** | 0% |
| `verifyNovaProof` tx gas | 784,428 | **799,731** | **+1.95%** ✅ |
| `NovaDecider` deploy gas | ~4–6M [A, rough] | **3,221,311** | — |
| `settleEpochProven` tx gas (full settlement) | — | **3,613,984** | verify + Poseidon nets + storage + credits |

The measured `verifyNovaProof` gas lands **within 1.95% of the analytical 784,428** — the whole
economic argument (constant ~0.8M/epoch) holds on the real toolchain. `compare_to_model.py`
flags any deviation > 5%. (These are `light-test` verifier figures, which are structurally
representative — see §Hardware.)

### Prover [M, light-test, small epoch, 24 GB]

| metric | model [A] | measured [M, light-test] |
| --- | ---: | ---: |
| fold time / step | 0.5–2 s [A] | **~1.7 s** |
| decider prove | 5–20 min [A] | **~27.8 s** (reduced circuit — not production) |
| epoch | large daily ~42,705 ops | small path: 183 ops, 12 steps |

Re-measure fold/decider/RSS with `--features full-bench` on ≥64 GB hardware for production
numbers. Wrap the bench in `/usr/bin/time -v` (GNU) for authoritative peak RSS (macOS
`/usr/bin/time` lacks `-v`; the bench self-reports `ru_maxrss` as a fallback).

Cost at different scales, and the full significance write-up, are in
**[docs/REPORT.md](docs/REPORT.md) §Estimated cost at different scales**.

---

## Security & prototype caveats

> Full threat model, trust assumptions, and privacy guarantees: **[docs/TRUST_MODEL.md](docs/TRUST_MODEL.md)**.

- **Dev-mode Groth16 setup.** The decider's Groth16 keys come from sonobe's in-process
  `preprocess` (an unsafe, single-party setup). **Production requires a real circuit-specific
  phase-2 ceremony** over a perpetual powers-of-tau, with published transcripts and at least one
  honest participant. Every circuit change (batch size, tree depth, op semantics) needs a new
  ceremony and a governance-approved verifier redeployment.
- **Unaudited stack.** sonobe (Nova+CycleFold+DeciderEth) is experimental and unaudited; the
  F-circuit and `ProvenCheckpoint` are also unaudited. Production is gated on all of these.
- **`light-test`** verifiers are unsound (see Hardware).
- **Privacy:** public inputs are exactly `(i, z_0, z_n)` — roots and accumulators only; no
  account-correlated value appears. Witness data (operations, paths) never leaves the prover.
  The one new metadata leak — epoch op-count via the step count `i` — is closed by
  **constant-`i` padding** (`--pad-steps` / `WorkloadSpec.pad_to_steps`; no-op soundness proven
  by `inactive_batch_is_noop`). See TRUST_MODEL.md §Privacy.
- **Governance timelock — implemented.** Verifier upgrades go `proposeDeciderUpgrade` → wait
  `DECIDER_TIMELOCK` (2 days) → `executeDeciderUpgrade`; `initializeDecider` is a one-time
  bootstrap (tested by `GovernanceTimelockTest`). PROTOTYPE: single-address governance stands in
  for a real multisig.
- **Key↔position binding (known gap, #1 for production).** The tree uses dense slots + an
  off-circuit key→slot map and does not enforce `position = f(key)`, so a malicious prover could
  duplicate a key across positions. Masked here (the operator is the trusted prover) but must be
  closed with a key-indexed *indexed Merkle tree*. See TRUST_MODEL.md §4.2.
- **Modelling shortcuts** (prototype, documented in code):
  - Accounts are pre-registered into the genesis root; a real deployment creates them lazily.
  - `withdraw` moves a payee's net into a single settlement *sink* leaf; the ordered nets list is
    what settlement credits and what `withdrawalsAcc` recomputes. The synthetic workload emits one
    withdraw per payee, in payee order, so `netsAcc == withdrawalsAcc`.
  - Single token per run (the sink binds one tokenId). Multi-token needs a per-token sink.
  - On-chain Poseidon `withdrawalsAcc` is O(payees) and, with this prototype's naive Solidity
    Poseidon (~0.86M gas/hash), dominates the settle cost at scale; production wants a Poseidon
    precompile or per-payee claims against a proven `netsRoot`. See TRUST_MODEL.md.
- **Toolchain:** forge 1.5.1, solc 0.8.30, `evm_version=prague`. (Rust bumped to 1.97.1, not
  sonobe's 1.88.0 — see §Pinned versions for why.)

## License

MIT (© zulu0echo). Vendored crates under `vendor/` retain their own licenses (arkworks:
MIT/Apache-2.0).
