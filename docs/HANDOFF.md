# Handoff — resume state (2026-07-22, Phases 1–5 substantively done; on-chain contract rewire is the residual)

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
| 2b — unified indexed/interval account tree (real A0 key-uniqueness/non-membership) | ✅ done — register agreement + duplicate-key-rejected tests green |
| 3 — A1: plasma-blind `schnorr` per-debit in-circuit auth | ✅ done — bad-signature-rejected test green; ~5,136 constraints/verify |
| 4 — decider/EVM (LegoGroth16) on the real circuit | ✅ measured — **696,556 gas** in revm; `--features evm` compiles; DeciderVerifier.sol rendered. See DECIDER_RESULTS.md |
| 5 — ceremony plan + audit scope + benchmarks | ✅ docs — CEREMONY_AND_AUDIT.md |
| **residual — `ProvenCheckpoint.sol` on-chain rewire** | **🚧 NEXT — arity-6 Poseidon + `verifyDeciderProof` ABI + forge** |
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

## Phase 2b — DONE (committed on `newline-port`)
A0 is now enforced in-circuit via a **unified indexed/interval account tree (Design B)** — we did
*not* use plasma-blind's 2-field `IntervalCRH`; instead the interval pointer rides inside the
account leaf. What landed in `crates/ledger-circuit-newline`:
- **Leaf arity 4→5**: `(key, next_key, token, balance, nonce)` (`config.rs`, `LEAF_ARITY = 5`).
  `next_key` pointers form a sorted linked list; `next_key == 0` means +∞.
- **Bounded `<` gadget** `enforce_lt_when(a, b, should)` (`KEY_BITS = 160`): strict less-than on
  bounded operands, neutralised (compares `0 < 1`) when `should` is false so it's safe on padding.
- **In-circuit REGISTER** (`RegWitness` + a registration loop in `synthesize_step`, run before the
  transfer loop): (R1) low-leaf inclusion, (R2) non-membership `low_key < key` & (`low_next==0` |
  `key < low_next`), (R3) split `low.next := key`, (R4) prove the target slot is empty (digest 0)
  via `root_from_digest`, (R5) insert. `LedgerCircuit::new_with_regs(reg_batch, batch, depth)`.
- **Native** `EpochExecutor::register_indexed` maintains the sorted intervals (`find_low`, sentinel
  at slot 0, `tokens`/`next_keys` maps) and emits the witness.
- **Soundness-critical deviation**: `sparsemt/mod.rs::gen_empty_hashes` now seeds empties with
  `F::zero()` (not `LeafHash(default)`), so a real leaf `H(preimage) != 0` can never be confused
  with an empty slot — the fix that makes non-membership sound. See the comment there.
- Tests (5, all green): `registrations_native_matches_circuit`, `duplicate_key_registration_rejected`
  (the A0 property), `bounded_lt_gadget`, plus the two Phase-2a tests.

Not yet done in 2b (fine to leave for later / note in report): the R4 anti-clobber check has no
dedicated negative test; registrations are a fixed `reg_batch` per step; keys are assumed
`< 2^160`.

## Phase 3 — DONE (committed on `newline-port`)
A1 is enforced in-circuit: every debit needs a Schnorr signature by the account's leaf-bound spend
key. What landed:
- `crates/ledger-circuit-newline/src/schnorr.rs` — plasma-blind's Schnorr (native + gadget) over
  Grumpkin; `ark-grumpkin`/`ark-ec` deps. Grumpkin base field = BN254 `Fr` → verify runs in-circuit.
- Leaf arity 5→6: `+ pk_hash = Poseidon(pk.x, pk.y)`. `key` = ECDSA owner (on-chain exit); `pk_hash`
  = delegated Schnorr spend key (hybrid). `OpWitness` gained `from_pk` (GVar point), `from_sig`
  `(s, e)` (Grumpkin scalars), `from_pk_hash`, `to_pk_hash`; `RegWitness` gained `pk_hash`,
  `low_pk_hash`. Native `EpochExecutor` holds a seeded RNG + `spend_sk`/`spend_pk`/`pk_hashes` maps,
  `assign_spend_key`, and signs each debit in `apply`.
- In `synthesize_step`, the transfer loop derives `pk_hash` from the witnessed `from_pk`
  (`to_constraint_field` → pop flag → `h_gadget([x,y])`), binds it to the leaf (conditional on
  active), and runs `SchnorrGadget::verify::<SIG_WINDOW=32>` over `(from,to,token,amount,nonce)`.
  Verify is **unconditional** — padding ops carry a valid dummy signature (`dummy_sig`, seeded).
- Tests (8 total): `bad_signature_rejected` (A1) + `duplicate_key_registration_rejected` (A0) + the
  agreement/gadget tests + 2 ported schnorr tests. `~5,136 constraints per in-circuit verify`.

**Full non-custody (A0 + A1) is now enforced in the folding circuit.** The classic `main` prototype
remains the on-chain reference until Phase 4 lands.

## Phase 4/5 — DONE (committed on `newline-port`)
Built against sonobe PR #259 (`243391e`) at the user's explicit direction (i.e. NOT gated on the
merge). The full A0+A1 circuit folds through Nova+CycleFold → LegoGroth16 → `DeciderVerifier.sol` →
solc 0.8.35 → revm, **verifying for 696,556 gas** (~280 s, 7.7 GB peak) — cheaper than the classic
line (799,731). Reproduction: `test_ledger_decider_evm` in a sonobe `revamp/decider` checkout whose
`crates/ledger` == this circuit. In-repo: `cargo +1.97.1 build -p ledger-circuit-newline --features
evm` compiles the circuit against the decider crate (`FCircuitEVMExt`, state → `uint256[3]`).
Artifacts: `contracts/generated/newline/{DeciderVerifier,LegoGroth16Verifier}.sol` (dev setup).
Docs: `docs/DECIDER_RESULTS.md`, `docs/CEREMONY_AND_AUDIT.md`. Requires Rust 1.97.1 for the EVM path
(revm needs ≥1.91; repo default toolchain is 1.97.1).

## Immediate next step (residual — on-chain `ProvenCheckpoint` rewire)
The only substantive unfinished piece. The Solidity still targets the **classic** `DeciderEth` ABI +
an **arity-4** leaf. To finish (all Solidity/Foundry, no new circuit work):
1. **`PoseidonT5.sol` → arity-6.** Generate the arity-6 Poseidon constants for
   `poseidon_circom_config`, add a `hash6` (leaf) alongside the existing `hash2` (node), and add a
   Rust↔Solidity fixture cross-check (mirror the existing hash4/hash2 fixture flow on `main`).
2. **Verify entrypoint.** Replace the classic verify call with
   `verifyDeciderProof(i, z_0[3], z_i[3], challenge, U_cm_e[2], cm_t[2], U_cm_w[2], u_cm_w[2],
   proof[12])` (see `contracts/generated/newline/DeciderVerifier.sol`, pragma `^0.8.35`); store /
   compare the `z = [root, opsAcc, netsAcc]` digest.
3. **Exit path.** Recompute the exit leaf as the arity-6 interval leaf
   `(key, next_key, token, balance, nonce, pk_hash)`; the escape hatch still keys ownership on `key`
   (ECDSA/`msg.sender`).
4. Forge tests + gas; note it targets the **dev-setup** verifier until the ceremony.
A repo-side runnable prover binary (folding LedgerCircuit → decider) is deferred alongside this —
it wants the same git-pinned decider deps in a runnable crate; the `evm` feature already proves the
dep wiring resolves.

Known smaller follow-ups (also in `docs/CEREMONY_AND_AUDIT.md` audit scope): R4 anti-clobber has no
dedicated negative test; fixed `reg_batch`/`batch` per step; keys assumed `< 2^160`; empty-leaf-=0
`sparsemt` deviation; re-measure at `TREE_H=23` / larger batch on bigger hardware.

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
