# Decentralization: user sovereignty & exit

This document tracks how far the protocol reduces trust in the operator, and how. The design
goal is deliberate: **turn the operator from a *custodian* (controls your funds) into a *service
you can leave* (can't move your funds without your key, can't trap them) — while keeping data
private and user-held, i.e. *without* becoming a validity rollup.** That's a rollup-grade
*funds-safety* model (can't be stolen, always exitable) achieved without a rollup's public
data-availability cost or its loss of amount-privacy. The price of staying private is that
exit-liveness depends on *your own branch* being available (held by you, or served by the
operator), not on globally reconstructable data.

Status legend: **✅ implemented & tested (this `main` line)** · **📐 specified (deferred)** ·
**🟢 implemented on the `newline-port` branch** (the audited-sonobe migration).

> **🟢 Update — the deferred cryptography (A0 + A1) is now built on `newline-port`.** What this
> document specifies as "deferred deeper cryptography" is implemented and tested on the migration
> branch: the key-indexed **indexed interval tree** (A0) and **in-circuit per-debit Schnorr** (A1),
> folded through a LegoGroth16 decider measured at ≈696k on-chain gas, with `ProvenCheckpoint`
> rewired to the arity-6 leaf. It remains dev-setup + pinned to an unmerged sonobe PR. See
> [BUILD_PLAN_A0_A1.md](BUILD_PLAN_A0_A1.md), [DECIDER_RESULTS.md](DECIDER_RESULTS.md),
> [CEREMONY_AND_AUDIT.md](CEREMONY_AND_AUDIT.md). The 📐 markers below describe the `main` line.

Everything here rests on one prerequisite:

> **Key-indexed tree (📐 on `main`; 🟢 done on `newline-port`).** Move to a key-indexed *indexed
> Merkle tree* so each leaf provably belongs to exactly one owner key and can't be duplicated.
> Unforgeable leaf ownership and lazy account insertion both need it. It is the #1 production
> requirement ([TRUST_MODEL.md §6](TRUST_MODEL.md)).

---

## Implemented now (✅)

### Escape hatch — unilateral, operator-free withdrawal (`exit`)
A user withdraws their proven balance directly from the contract by proving their leaf opens to
the **last proven `stateRoot`**:

- `exit(tokenId, balance, nonce, siblings[22], isRight[22])` recomputes the leaf
  (`hash4(key, tokenId, balance, nonce)`), walks the Merkle path with on-chain Poseidon
  (`hash2`), and requires the result to equal `lastProvenRoot`.
- **Owner binding:** `key = _fieldKey(msg.sender, tokenId)`, so only the owning address can pull,
  and funds go to that address. No operator signature needed.
- **Nullifier:** a per-`(tokenId, key)` flag prevents double-exit.
- **Guarantee:** funds **can't be trapped** by a rogue or vanished operator, and you can always
  leave with your own key. Tested (accept / double-exit / tampered-balance / wrong-caller) in
  `contracts/test/ProvenCheckpoint.t.sol:EscapeHatchTest`.
- **On-chain Poseidon match:** `hash2` is generated from arkworks' own constants and pinned to
  the circuit by a fixture (`PoseidonT5Test.test_hash2_matches_circuit_fixture`), so the path
  check is bit-identical to the tree the proof commits to.
- **Cost caveat:** a depth-22 path is ~23 on-chain Poseidon hashes — expensive with the naive
  Solidity Poseidon (an escape hatch is rare, so acceptable; a precompile makes it cheap).
- **Reconciliation note (prototype):** an exit is a claim against a *fixed* proven root. In
  continued operation the **next epoch's proof must debit the exited leaf**, or the operator
  could re-credit it off-chain. Enforcing that in-circuit is part of productionizing this.

### Verifier immutability / governance (`freezeVerifier`)
`freezeVerifier()` renounces upgradability — the verifier becomes immutable, removing the
governance-capture vector entirely. Until frozen, upgrades remain timelocked
(`proposeDeciderUpgrade` → `DECIDER_TIMELOCK` → `executeDeciderUpgrade`). `governance` is a plain
address, so it can already be an M-of-N multisig. Tested in `GovernanceTimelockTest`.

### Branch-serving accountability (`requestExitData`)
Exit only works if you have *your* branch. To bound operator data-withholding without publishing
the whole ledger (which would break privacy and make this a rollup): `requestExitData(epoch)`
creates an on-chain, timestamped, **attributable** record of a branch request; `answerExitData`
marks it served; `exitDataOverdue(epoch)` is true once a request goes unanswered past
`EXIT_DATA_WINDOW`. It is intentionally **non-blocking** (so it can't grief settlement); binding
`overdue` to a settlement freeze or slashing is a deployment policy choice.

---

## Specified here (📐 on `main`) — A0 + A1 now built on `newline-port` (🟢)

These deliver *full* sovereignty and are each a substantial circuit addition with its own build
and audit effort. They are specified here for the `main` line; **A0 and A1 are now implemented and
tested on the `newline-port` branch** (see [DECIDER_RESULTS.md](DECIDER_RESULTS.md)).

### Key-indexed indexed Merkle tree (A0) — 🟢 done on `newline-port`
Replace the dense-slot tree + off-circuit key→slot map with an indexed Merkle tree: leaves are
key-sorted with `next` pointers, insertion proves *non-membership* of the new key, and every
op's position is `= f(key)`. Closes the key-duplication soundness gap and makes **lazy account
creation** sound (required once accounts are one-time / unlinkable addresses — see
[REPORT.md](REPORT.md) §Composing with one-time / unlinkable recipient addresses).

### In-circuit user-authorized debits (A1) — 🟢 done on `newline-port`
Bind each leaf to an owner public key and require the circuit to verify a **signature by that owner
over every debit** (on `newline-port`: a Schnorr signature over Grumpkin, ~5,136 constraints/op).
This is what stops an operator from moving your balance in an *arithmetically-valid* way (the base
proof checks conservation, not authorization). Privacy is preserved — keys/signatures are witness data.

### Forced-inclusion queue (A4, optional)
An on-chain queue where a user posts an owner-signed op (a transfer *or* an exit) that the next
epoch's proof **must** consume, or the proof is rejected. Upgrades "if censored, exit against the
stale root" into "force your transaction through." Only needed if active censorship *of spends*
(not just exit) is in scope; the escape hatch already guarantees funds can't be stolen or trapped.

---

## The sovereignty boundary, stated honestly

| Property | Status |
| --- | --- |
| Funds can't be **trapped** (always exitable with your key) | ✅ implemented (escape hatch) |
| Governance can't **silently** swap the verifier | ✅ implemented (timelock + freeze) |
| Data-withholding is **attributable** on-chain | ✅ implemented (branch challenge) |
| Operator can't move your balance **without your signature** | 📐 on `main` · 🟢 done on `newline-port` (A1) |
| Leaf ownership is **unforgeable** / lazy insertion is sound | 📐 on `main` · 🟢 done on `newline-port` (A0) |
| Spends (not just exit) are **censorship-resistant** | 📐 deferred (A4) |

So today: **you can always unilaterally withdraw your last-proven balance** (operator can't trap
or freeze funds). It does **not** yet prevent an operator from moving your balance in a
valid-looking transition *before* you exit — that is A1. The implemented set reaches
"**non-custodial funds with an operator trusted only for liveness/UX**"; A0+A1 close the gap to
"operator cannot touch your funds at all."

## The tension (why we stop short of a rollup)

There is a real **cost ↔ privacy ↔ decentralization** trilemma. Full censorship-resistance at the
*ordering* layer needs public data availability (so anyone can reconstruct, prove, and exit) —
which costs DA fees and **exposes amounts**, giving up the privacy this design exists to keep.
That is the rollup step. This roadmap deliberately buys the trust-minimization that *doesn't*
require it — exit, immutable/timelocked governance, attributable withholding, and (deferred)
per-op user authorization — and stops before public DA. In any institutional framing this should
be stated plainly: **private, non-custodial, operator-for-liveness — not trustless sequencing.**
