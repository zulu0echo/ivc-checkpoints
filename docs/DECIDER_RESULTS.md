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
| Decider prove + verify wall time | ~280 s |
| Peak resident memory | ~7.7 GB (fits 24 GB) |
| In-circuit Schnorr verify | ~5,136 constraints |

**Takeaways.** (1) The on-chain verifier cost is essentially **independent of step-circuit
complexity** — adding the entire A0 tree + A1 Schnorr over the trivial circuit cost only ~+27k gas,
all attributable to the `z_len 1→3` public-input delta, exactly as the Phase-0 spike predicted.
(2) The new line is **~13% cheaper on-chain than the classic Groth16 line** while doing strictly
more (full non-custody). (3) The real-circuit decider fits comfortably in 24 GB.

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

## Still open (tracked for Phase 4 completion / audit)
- **`ProvenCheckpoint` on-chain rewire is not done.** The Solidity contract still targets the
  classic `DeciderEth` ABI and hashes an **arity-4** leaf. To finish: swap the verify call to
  `verifyDeciderProof`, store/compare the `z = [root, opsAcc, netsAcc]` digest, and extend the exit
  path's on-chain Poseidon (`PoseidonT5`) to the **arity-6** interval leaf
  `(key, next_key, token, balance, nonce, pk_hash)` — re-derived for `poseidon_circom_config`.
- **Pinned to an unmerged branch.** rev `243391e` is PR #259, not yet on `staging`; re-pin when it
  merges and reconcile with plasma-blind's `dmpierre/sonobe@8269ea4`.
- Batch/reg-batch are fixed per step; a production run should re-measure at larger `batch` and
  `TREE_H = 23` (depth 22), and on hardware with more RAM headroom.
