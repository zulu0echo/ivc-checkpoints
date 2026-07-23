# Phase 4 — decider + on-chain verifier (measured)

The full **A0 + A1 ledger circuit** now runs end-to-end through the new-line proving pipeline and
verifies on-chain. Everything below is **measured [M]** on a 24 GB machine, built against sonobe
`revamp/decider` (PR #259, rev `243391e`) under Rust 1.97.1.

## Pipeline
```
LedgerCircuit  --fold-->  Nova + CycleFold  --decide-->  LegoGroth16
   (A0 indexed/interval tree + A1 per-debit Schnorr)          |
                                                render DeciderVerifier.sol + LegoGroth16Verifier.sol
                                                              |
                                            solc 0.8.35  -->  revm  -->  verifyDeciderProof
```
State folded: `z = [stateRoot, opsAcc, netsAcc]` (`uint256[3]` on-chain). One **active** transfer
step was folded (real indexed-tree inclusion + a real Schnorr signature verify) — not padding.

## Measured
| Metric | Value |
|---|---|
| `verifyDeciderProof` gas (this circuit, z_len 3) | **696,556** |
| Phase-0 trivial circuit (z_len 1), same decider | 669,362 |
| Classic line (Groth16 `DeciderEth`, z_len 3) | 799,731 |
| Peak resident memory (max RSS) | ~7.7 GB (fits 24 GB) |
| In-circuit Schnorr verify | ~5,136 constraints |

### Prover wall-time breakdown (measured, this circuit)
| Phase | LegoGroth16 (new line) | Groth16 (`main`, small workload) |
|---|---|---|
| IVC keygen | ~12 s | (part of setup) |
| Fold | ~0.27 s/step | ~1.69 s/step |
| **Decider keygen** (one-time / ceremony) | **~201 s** | (cached in dev path) |
| **Decider PROVE** | **~85 s** | **~27 s** |
| Peak RSS | ~7.7 GB | ~6.6 GB |

**Takeaways.** (1) On-chain verifier cost is essentially **independent of step-circuit complexity**
— the whole A0 tree + A1 Schnorr over the trivial circuit cost only ~+27k gas (the `z_len 1→3`
public-input delta), and the new line is **~13% cheaper on-chain than classic Groth16** while doing
strictly more. (2) The big ~310 s wall is **dominated by decider *keygen* (~201 s), a one-time
per-circuit setup** (the ceremony output in production — *not* a per-epoch cost), not proving.
(3) **Isolated decider PROVE is ~85 s vs classic ~27 s (~3×)**, and peak RAM +17% — but this is
LegoGroth16 over a *bigger* circuit (arity-6 + ~5,136-constraint Schnorr/debit) vs Groth16 over a
smaller one, so it is **not** a like-for-like primitive comparison. Both fit comfortably in 24 GB.

## Generated artifacts (dev setup)
[`contracts/generated/newline/DeciderVerifier.sol`](../contracts/generated/newline/DeciderVerifier.sol)
and `LegoGroth16Verifier.sol` are the **rendered** verifier for this circuit/params. Entry point:
```solidity
function verifyDeciderProof(
    uint256 i, uint256[3] z_0, uint256[3] z_i, uint256 challenge,
    uint256[2] U_cm_e, uint256[2] cm_t, uint256[2] U_cm_w, uint256[2] u_cm_w,
    uint256[12] proof) public view;   // pragma ^0.8.35
```
⚠️ **Dev setup only.** The verifying key comes from a random-seeded setup (`thread_rng`), exactly
like the classic line's dev-mode Groth16. A real deployment needs the Phase-5 ceremony
(see [CEREMONY_AND_AUDIT.md](CEREMONY_AND_AUDIT.md)). The ABI (`verifyDeciderProof`, `uint256[12]`
proof, folded-commitment RLC inputs) differs from the classic `DeciderEth.verifyProof`.

## Reproduce
The pipeline lives as a test in the sonobe `revamp/decider` checkout (rev `243391e`), driving
`ledger::LedgerCircuit` through `test_decider_evm`:
```
# in a sonobe revamp/decider checkout with crates/ledger = this circuit
LEDGER_SOL_OUT=<dir> cargo +1.97.1 test -p sonobe-ivc --release test_ledger_decider_evm -- --nocapture
# prints: [SPIKE] verifyDeciderProof gas_used = 696556
```
### Repo-side integration (validated)
`LedgerCircuit` implements the new line's `FCircuitEVMExt` (state = `uint256[3]`), which the decider
verifier template requires. This lives in the circuit crate behind the `evm` feature (optional
`sonobe-ivc` dep), so the circuit compiles directly against the decider stack:
```
cargo +1.97.1 build -p ledger-circuit-newline --features evm   # green
```
The runnable fold→prove→render→verify→gas pipeline itself is the `test_ledger_decider_evm` test in
the sonobe `revamp/decider` checkout (it uses that crate's in-tree EVM test harness). A standalone
in-repo prover binary is deferred with the `ProvenCheckpoint` rewire below (both want the same
git-pinned decider deps wired into a runnable crate).

## On-chain `ProvenCheckpoint` rewire — DONE
Implemented on this branch (Solidity/Foundry, 22/22 forge tests green):
- **`PoseidonT5.sol` → `hash6` + `leafHash`** for the arity-6 interval leaf
  `(key, next_key, token, balance, nonce, pk_hash)`. `poseidon_circom_config` is
  **parameter-identical** to the classic `poseidon_canonical_config`, so the existing permutation
  constants are reused (verified cross-version by `generated/newline/poseidon_fixture.json`); `hash6`
  is the rate-4 sponge (absorb 4 → permute → absorb 2 → permute). Pinned by `PoseidonNewline.t.sol`.
- **`ProvenCheckpointNewline.sol`** — settlement calls the new `verifyDeciderProof` ABI (reverts on a
  bad proof; folded commitments reconstructed on-chain), stores/compares the `z = [root, opsAcc,
  netsAcc]` digest, recomputes `netsAcc` on-chain, and the escape hatch opens the **arity-6** leaf.
  `IDeciderVerifier.sol` is the calling interface. Governance (timelock/freeze) + nets + chaining
  carried over from the classic contract.
- **`ProvenCheckpointNewline.t.sol`** — arity-6 exit against a real in-test Merkle tree (+ double-exit
  / wrong-balance rejection) and settlement plumbing (happy path, bad-proof reject, nets-mismatch
  reject) via a `MockDecider`. The classic `ProvenCheckpoint`/tests are untouched (still the `main`
  reference).

Deferred (mechanical): a real-proof **end-to-end** forge test that drives `settleEpochProven` through
the actual generated `DeciderVerifier.sol` needs the structured proof calldata exported from the
prover. The cryptographic verification itself is already proven in revm (696,556 gas above); the
forge test uses a mock verifier for the contract-logic plumbing.

## Still open (audit / production)
- **Pinned to an unmerged branch.** rev `243391e` is PR #259, not yet on `staging`; re-pin when it
  merges and reconcile with plasma-blind's `dmpierre/sonobe@8269ea4`.
- **Dev setup.** The generated verifier uses random keys — needs the Phase-5 ceremony before deploy.
- Batch/reg-batch are fixed per step; a production run should re-measure at larger `batch` and
  `TREE_H = 23` (depth 22), and on hardware with more RAM headroom.
