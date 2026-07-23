# Potential use cases

A validity-proven checkpoint for an off-chain balance ledger is a narrow but reusable
primitive. This page sketches where it fits — and, just as importantly, where it doesn't. For
what it *is* and what it costs, see the [technical report](REPORT.md); for the security picture,
[TRUST_MODEL.md](TRUST_MODEL.md).

## When it fits

The primitive is a good match when **all** of these hold:

1. An **operator** maintains an off-chain ledger of many account balances.
2. There's **high internal transaction volume**, so amortizing a constant per-epoch proof matters.
3. Settlement is **periodic** and **nets down to a modest number of on-chain payees**.
4. You want **cryptographic integrity of the bookkeeping** posted on-chain — no inflation, no
   double-spend, no negative balances, value conserved, nets consistent — **cheaply**, without a
   per-account storage write and without standing up a full rollup.
5. Individual balances, amounts, and account identities **can stay off-chain**.
6. An **operator-for-liveness** trust model is acceptable **on the `main` line**. With the escape
   hatch, funds are non-custodial *for exit* (a user can always withdraw their proven balance with
   their own key); full non-custody — the operator can't move a balance even *before* you exit — is
   **implemented on the `newline-port` branch** (A0 indexed tree + A1 per-debit Schnorr; dev-setup,
   ≈696k-gas decider — see [BUILD_PLAN_A0_A1.md](BUILD_PLAN_A0_A1.md) and
   [DECIDER_RESULTS.md](DECIDER_RESULTS.md)).

## Where that shape shows up

| Use case | How it maps |
| --- | --- |
| **Closed-loop / stored-value payments** — gift cards, prepaid balances, campus/transit cards, in-app or platform wallets | Balances live in the operator's ledger; the proof shows users' funds aren't invented or double-spent, and per-merchant settlement is exact — without putting every balance on-chain. |
| **Exchange / custodian "proof of correct bookkeeping"** | A *dynamic* complement to static proof-of-reserves: instead of only attesting balances at an instant, prove each epoch's ledger *transition* was applied correctly (conservation, no negatives). |
| **Payroll / mass disbursement / remittance aggregation** | High-volume internal transfers, periodic net settlement to rails or recipients; correctness proven without exposing individual amounts on-chain. |
| **Loyalty & rewards points ledgers** | Points issued/spent off-chain, net redemptions settled to merchants; proof rules out points minted from nothing. |
| **Netting / clearing hubs, payment-channel hubs** | A hub nets many off-chain payments and settles per epoch; the proof guarantees the netting is a correct function of the underlying transactions. |
| **Micropayment / streaming aggregation** | Aggregate huge numbers of micro-transactions off-chain; at ~18 gas/op amortized, per-op on-chain cost is negligible. |
| **Minimal validity anchor for an app-specific accounting engine** ("validium-lite") | When you need proven integrity of a *balance-ledger* transition — not general computation — this is a far smaller commitment than a general rollup/validium: one step circuit, one constant-gas verifier, no sequencer/DA/upgrade stack. |

Several of these benefit from pairing the ledger with **one-time / unlinkable recipient
addresses** (e.g. [ERC-5564](https://eips.ethereum.org/EIPS/eip-5564)): the proof adds no
on-chain linkage, so recipient privacy composes cleanly on top (see
[REPORT.md §Composing with one-time / unlinkable recipient addresses](REPORT.md)).

## Where it is *not* the right tool

- **Confidential settlement amounts** — per-payee net amounts are public on-chain. If amounts
  must be hidden, you need a shielded pool, not this.
- **Full decentralization / non-custody** — *on the `main` line* this proves an *operator's* books
  are correct and lets users unilaterally *exit* (escape hatch) but does not remove the operator's
  authority to move a balance before you exit. The **`newline-port` branch closes that gap**
  (in-circuit user-signed debits + unforgeable accounts have landed — see
  [DECIDER_RESULTS.md](DECIDER_RESULTS.md)); it is still dev-setup and pinned to an unmerged sonobe
  PR. Removing the operator from *sequencing* entirely is a rollup, which this is not.
- **Many thousands of distinct settlement payees per epoch** — the on-chain nets recomputation is
  currently O(payees) and expensive; this needs the production fix (per-payee claims against a
  proven `netsRoot`, or a Poseidon precompile) before large payee sets are practical.
- **General-purpose computation** — this proves a balance-ledger transition, not arbitrary state.
  If you need to prove EVM execution, that's a rollup.

> **Prototype — not production.** Any use above is gated on the production requirements in
> [TRUST_MODEL.md §6](TRUST_MODEL.md) (key-indexed tree, a real trusted-setup ceremony, audits).
