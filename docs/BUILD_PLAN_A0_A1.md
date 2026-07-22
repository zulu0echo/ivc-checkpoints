# Build plan: full non-custody (A0 + A1) via migration to the new sonobe line

This plan takes the prototype from "escape-hatch non-custody" to **full non-custody** — the
operator can neither move your balance without your key (A1) nor forge your account (A0) — by
**migrating from the classic sonobe line to the new (audited) line** and reusing
[plasma-blind](https://github.com/privacy-ethereum/plasma-blind)'s circuit primitives.

Status: **Phase 0 complete (spike, measured). Phases 1–5 pending.** The working classic
prototype on `main` stays untouched as the reference until the new-line version reaches parity.

## Why migrate lines (rather than back-port)

Three things now line up on the **new sonobe line** (`sonobe-primitives`/`fs`/`ivc`, official
arkworks 0.6, gr1cs):
- It is **the branch being audited**.
- **plasma-blind** already lives there and ships the two hardest pieces (`sparsemt` → A0,
  `schnorr` → A1), so they become near-drop-in instead of a cross-version port.
- Its EVM decider (sonobe PR #259, LegoGroth16) measures **cheaper** than our classic verifier
  (below).

Back-porting plasma-blind *down* to our classic arkworks-0.5 stack would be throwaway work; the
new line is the convergence target.

## Phase 0 — spike results (measured, on a 24 GB machine)

- The new-line **EVM decider stack compiles** on stable Rust 1.97 (arkworks 0.6 + revm + askama
  + LegoGroth16).
- End-to-end **`test_nova_nova_decider_evm` PASSES**: fold (Nova+CycleFold) → **LegoGroth16**
  decider → render `DeciderVerifier.sol` → compile (`solc 0.8.35`) → **verify in revm = success**.
- **`verifyDeciderProof` gas ≈ 669,362** (LegoGroth16, trivial `CircuitForTest`, state length 1)
  — versus our classic line's **799,731** (Groth16, z_len 3). The new line looks **~16% cheaper**;
  our z_len=3 circuit adds a public-input delta (classic z_len 1→3 was ~+27k), so re-measure, but
  it is likely **≤ classic**.
- The decider proved in ~5 min **within 24 GB** for the trivial circuit (our larger step circuit's
  decider will need more — re-measure). Only friction was a `solc` pragma (`^0.8.35`).
- New `FCircuit` trait shape confirmed (see Phase 1).

## Design decision carried in: keep ECDSA, add Schnorr (hybrid)

Ownership/custody/exit stay anchored to an **Ethereum (ECDSA) address** — no extra user key,
free real-address exit via `msg.sender`, and smart-account/multisig compatibility. A
**Poseidon-friendly Schnorr key (plasma-blind, over Grumpkin) is added only as a delegated,
in-circuit spend key** bound to the ECDSA owner. Cheap in-circuit auth + Ethereum-native
ownership. The leaf binds both.

## Phases

| Phase | Deliverable | Go/no-go gate |
|---|---|---|
| **0 ✅** | Spike: new-line EVM decider works end-to-end; gas measured (669k); reuse confirmed | done |
| **1 ✅** | Port the ledger `FCircuit` to the new trait; minimal circuit compiles + native-vs-circuit test green (no decider yet) | done |
| **2a ✅** | Adopt `sparsemt` as the base Merkle map (behaviour-equivalent; assigned-index). Native `MerkleSparseTree` + `MerkleSparseTreeGadget::recover_root`, Poseidon `Config`/`ConfigGadget`. | done — agreement + tamper tests green |
| **2b ✅ — A0** | Unified indexed/interval account tree (Design B): leaf `(key, next_key, token, balance, nonce)`; in-circuit REGISTER = non-membership + split-insert; bounded `<` gadget; empty leaf = 0. | done — register agreement + **duplicate-key-rejected** tests green |
| **3 ✅ — A1** | plasma-blind `schnorr` (Grumpkin) in-circuit verify on every debit; leaf binds a `pk_hash` spend-key commitment; padding carries a valid dummy sig. | done — bad-signature-rejected test green; ~5,136 constraints/verify [M] |
| **4 — decider + on-chain** | Re-target prover to the LegoGroth16 decider; regenerate `DeciderVerifier.sol`; update `ProvenCheckpoint` (verify call + digest) and the escape hatch's on-chain leaf/Merkle hashing; re-measure gas | **PR #259 merged to `staging`**; forge tests green; gas re-measured at z_len=3 |
| **5 — hardening** | New Groth16/LegoGroth16 phase-2 ceremony plan; audit realignment; full-bench measurement | ceremony transcripts; audit scope |

## Phase 2 (A0) design note — corrected after reading plasma-blind

Investigating plasma-blind's `sparsemt` corrected an earlier assumption. Two distinct primitives
matter, and A0 needs the second:

- **`sparsemt`** (`MerkleSparseTree` + `MerkleSparseTreeGadget`, built on arkworks
  `merkle_tree::Config`) is a **sparse Merkle *map* addressed by an assigned index** (e.g.
  plasma-blind's `publickeymap` uses a `UserId` as the leaf position, storing the key in the
  leaf). Its gadget (`recover_root`/`update_root`/`check_update`) is a clean, `Config`-generic
  version of our hand-rolled tree. Adopting it alone does **not** close the key-duplication gap —
  an operator could still place a key at two indices, exactly like our current tree.
- **The indexed/interval tree** — plasma-blind's `NullifierTree` uses `IntervalCRH` /
  `IntervalCRHGadget` with `Leaf = (value, next)` sorted intervals. This is the
  **indexed-Merkle-tree / non-membership** primitive that gives collision-free key-binding
  (prove a key is absent via the low interval bracketing it, then insert). **This is the real A0
  machinery**, and plasma-blind already implements it.

So Phase 2 = port `sparsemt` (base map + gadget) **and** the `IntervalCRH`/indexed-tree layer, then
key the ledger accounts through the interval tree (unforgeable membership + lazy insertion).
Recommended staging: **2a** adopt `sparsemt` as the base Merkle-map gadget (replacing the
hand-rolled tree, behaviour-equivalent); **2b** add the `IntervalCRH` indexed-tree layer for
key-uniqueness/non-membership. 2a is mechanical; 2b is where A0's soundness is actually won.

## The new `FCircuit` trait (Phase 1 target)

```
trait FCircuit {
  type Field: PrimeField;
  type State: Clone + PartialEq + Absorbable;
  type StateVar: GR1CSVar + AllocVar + AbsorbableVar + EqGadget + Inputize;
  type ExternalInputs; type ExternalOutputs;
  fn same_state_shape(a,b) -> bool;
  fn dummy_state(&self) -> State;
  fn generate_step_constraints(&self, i: FpVar, state: StateVar, ext: ExternalInputs)
      -> (StateVar, ExternalOutputs);
}
```
`z = [stateRoot, opsAcc, netsAcc]` → `State = [F; 3]`. Note the new line uses **Griffin** as the
default transcript and `poseidon_paper_config`/`poseidon_circom_config` (not
`poseidon_canonical_config`) — the on-chain Poseidon match must be re-derived accordingly.

## Caveats / risks to manage

- **PR #259 is a draft** (LegoGroth16 decider, branch `revamp/decider`). Phases 1–3 (circuit) can
  target a pinned new-line rev now; **Phase 4 (decider/EVM) is gated on it merging to `staging`** —
  don't build the on-chain path on a moving branch.
- **Rev reconciliation:** plasma-blind pins `dmpierre/sonobe@8269ea4`; the decider is on
  `privacy-ethereum/revamp-decider`. Both new-line; align on one rev (small, same-family) as part
  of Phase 4.
- **LegoGroth16 ≠ classic Groth16** → different verifier entrypoint (`verifyDeciderProof`) and
  calldata; re-measure gas at z_len=3.
- **Decider RAM** for the real ledger step circuit is unmeasured (trivial-circuit decider fit in
  24 GB; ours is larger).
- **Fresh trusted-setup ceremony + re-audit** for the new circuit.

## What this still does not buy

Even fully done, this is **not** a rollup: amounts stay public at settlement and the operator
still orders/includes transactions. A0+A1 get to "operator can't touch or forge your funds," not
"trustless sequencing" (that needs public DA, which costs the amount-privacy this design keeps).
