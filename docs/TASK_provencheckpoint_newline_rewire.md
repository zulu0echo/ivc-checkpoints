# Task: rewire `ProvenCheckpoint` on-chain for the new-line (A0+A1) decider

**Status:** open — the only substantive unfinished piece of the new-sonobe-line migration.
**Kind:** Solidity / Foundry only. **No new circuit work** — Phases 1–5 (circuit + decider) are done.
**Branch base:** `newline-port`.

## Why
The `newline-port` branch enforces full non-custody in the folding circuit — A0 (no account
forgery/duplication, via a unified indexed/interval account tree) and A1 (no unauthorized debit, via
a per-debit Grumpkin/Poseidon Schnorr signature). The off-chain decider is proven end-to-end and
the on-chain verifier is measured (**696,556 gas**, see [DECIDER_RESULTS.md](DECIDER_RESULTS.md)).

But `contracts/` still targets the **classic** line: the `DeciderEth`/Groth16 ABI and an **arity-4**
account leaf `(key, tokenId, balance, nonce)`. Until the contract is rewired, the on-chain path does
not match the new circuit, so the migration cannot be exercised on-chain.

## Scope (acceptance criteria)
1. **`PoseidonT5.sol` → arity-6 leaf hash.**
   - The new account leaf is the 6-tuple `(key, next_key, tokenId, balance, nonce, pk_hash)`
     (interval pointer + Schnorr spend-key commitment). Add a `hash6` for the leaf alongside the
     existing `hash2` node hash.
   - Constants must be **re-derived for `poseidon_circom_config`** (the config the circuit uses),
     not the classic `poseidon_canonical_config`.
   - Add a Rust↔Solidity **fixture cross-check** (mirror the existing hash4/hash2 fixture flow used
     on `main`): a Rust test emits `hash6(...)` for known inputs; a forge test asserts the Solidity
     matches.
2. **Verify entrypoint → `verifyDeciderProof`.**
   - Replace the classic verify call with the new-line ABI (see
     `contracts/generated/newline/DeciderVerifier.sol`, `pragma ^0.8.35`):
     ```solidity
     function verifyDeciderProof(
         uint256 i, uint256[3] z_0, uint256[3] z_i, uint256 challenge,
         uint256[2] U_cm_e, uint256[2] cm_t, uint256[2] U_cm_w, uint256[2] u_cm_w,
         uint256[12] proof) public view;
     ```
   - Store / compare the folded state digest `z = [stateRoot, opsAcc, netsAcc]` (`uint256[3]`).
   - Wire against the generated `DeciderVerifier` + `LegoGroth16Verifier` (dev setup — see caveat).
3. **Exit / escape-hatch path → arity-6 interval leaf.**
   - Recompute the exit leaf as `(key, next_key, token, balance, nonce, pk_hash)` using the new
     `hash6`. Ownership still keys on `key` (Ethereum/ECDSA owner via `msg.sender`); `pk_hash` is the
     delegated in-circuit spend key and is not needed to authorize the on-chain exit.
   - Keep the existing freeze/branch-challenge governance behaviour.
4. **Tests + gas.** Foundry tests green; report measured gas for `verifyDeciderProof` invoked
     through `ProvenCheckpoint` and for the exit path.

## Important caveats
- **Dev setup.** `contracts/generated/newline/*.sol` are rendered from a **random-seeded** verifying
  key (like the classic line's dev-mode Groth16). This task targets that dev artifact; a real
  deployment needs the Phase-5 ceremony ([CEREMONY_AND_AUDIT.md](CEREMONY_AND_AUDIT.md)). Do not
  present dev-setup results as production-ready.
- **Toolchain.** The EVM/prover path needs Rust ≥ 1.91 (revm); the repo's `rust-toolchain` pins
  1.97.1, which is fine. `solc 0.8.35` is required for the generated `pragma ^0.8.35`.
- **Moving dependency.** The generated verifier comes from sonobe PR #259 (rev `243391e`, unmerged).
  If that ABI changes before merge, regenerate `DeciderVerifier.sol` and adjust.
- **Keep the repo generic/public.** No `coordination-network` / beneficiary context.

## Related / deferred alongside
- A repo-side **runnable prover binary** (fold `LedgerCircuit` → LegoGroth16 → render + verify) —
  wants the same git-pinned decider deps in a runnable crate. The `evm` feature on
  `ledger-circuit-newline` already proves the dep wiring resolves; the reproduction today is
  `test_ledger_decider_evm` in a sonobe `revamp/decider` checkout.

## References
- [DECIDER_RESULTS.md](DECIDER_RESULTS.md) — measured decider gas + reproduction + generated ABI.
- [CEREMONY_AND_AUDIT.md](CEREMONY_AND_AUDIT.md) — ceremony plan + audit scope + benchmarks.
- [BUILD_PLAN_A0_A1.md](BUILD_PLAN_A0_A1.md) — full phase plan.
- [HANDOFF.md](HANDOFF.md) — resume state.
- `contracts/generated/newline/{DeciderVerifier,LegoGroth16Verifier}.sol` — the rendered verifier.
