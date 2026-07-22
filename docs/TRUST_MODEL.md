# Trust model, threat model, and privacy guarantees

Scope: the `ivc-checkpoints` prototype (this repo) — a validity-proven checkpoint for an
operator-custodied, off-chain balance ledger.

> **Status: prototype, not production.** Several claims below are *proven by the code*, several
> are *arranged to hold in the synthetic workload*, and several are *deferred to production
> hardening*. Each is labelled. Do not deploy this.

The one-line framing: **the validity proof changes the *threat* surface, not the *privacy*
surface.** It proves the operator's ledger *arithmetic*; it adds no new on-chain data about
accounts. So most of the analysis below is about the new integrity / liveness / setup surfaces
folding introduces, plus the one place folding *does* leak something new.

---

## 1. Baseline (unchanged by the proof)

Fixed by the design, not by the proof: the **operator authorizes every transfer** (the proof
adds arithmetic correctness, not authorization); **amounts are visible on-chain** (confidential
amounts are out of scope — that needs a shielded pool, a different primitive); the operator, as
custodian, sees the entire ledger by design. A validity proof changes none of these — in
particular it does **not** hide amounts and does **not** remove custody.

---

## 2. What the proof guarantees (integrity)

Per epoch, verified on-chain before settlement is accepted, publicly and forever:

1. **Inclusion** — every touched leaf opened against the committed `stateRoot` (Poseidon IMT).
2. **Solvency** — no balance goes negative; balances/amounts are range-checked to 96 bits, so
   field wraparound cannot forge solvency.
3. **Replay protection** — per-leaf nonces; a debit increments the leaf nonce.
4. **Conservation** — every op debits `from` and credits `to` by exactly `amount`.
5. **Nets consistency** — the settled payee nets equal the proof's `netsAcc`, recomputed
   on-chain as `withdrawalsAcc` (bit-identical Poseidon).
6. **State-root chaining** — epoch *e*'s proof is verified with `z_0` built from the stored
   last-proven root, so history cannot be forked or a prior root forged.

These hold **iff** (a) the circuit is sound, (b) the proving system is sound, and (c) the
trusted setup was honest. See §4.

---

## 3. Principals and trust assumptions

| Principal | Trusted for | NOT trusted for | If it misbehaves |
| --- | --- | --- | --- |
| Operator / prover service | fund custody, authorization, honest proving & witness handling | ledger arithmetic (now *proven*) | invalid transition ⇒ proof fails; but see §4 setup/soundness |
| Submitter (settlement tx) | tx submission | — | censorship ⇒ liveness (§4.4) |
| Governance multisig | verifier + `ppHash` upgrades, **timelocked** | immediate/silent upgrades | malicious verifier ⇒ total break, but public for `DECIDER_TIMELOCK` first |
| Ceremony participants | ≥1 honest ⇒ Groth16 setup sound | — | all-dishonest ⇒ forge any proof (§4.1) |
| Auditor | reads chain | — | — (integrity needs no auditor cooperation) |
| Account / payee / observer / adversary | nothing | — | — |

Trust **concentration** is deliberately unchanged: the operator custodies funds and authorizes
transfers. The proof adds *integrity* (arithmetic is proven), not *decentralization* or
*non-custody*. It does **not** protect an account or payee from the operator's authority — it
protects the *record* from being arithmetically inconsistent.

---

## 4. Threat model

### 4.1 Proving-system & setup (new surfaces folding introduces)
- **Trusted-setup subversion** — Groth16 phase-2 toxic waste ⇒ forge arbitrary proofs ⇒ silent,
  total integrity break. **PROTOTYPE uses a dev-mode setup (single-party, unsafe).** Production
  MUST run a phase-2 ceremony with ≥1 honest-participant guarantee and published transcripts.
  Every circuit change ⇒ new ceremony.
- **Unsound / unaudited stack** — bugs in sonobe (Nova+CycleFold+DeciderEth) or in the F-circuit
  / contract ⇒ acceptance of invalid transitions. Currently **unaudited**; sonobe's audits
  target the `staging` branch, which this prototype is not yet on (it pins `main` @ `63f2930d`
  for the EVM decider — see README §Pinned versions).
- **Circuit-version confusion** — a proof for circuit v1 replayed against a v2 verifier.
  Mitigated by `ppHash` pinning + one `NovaDecider` address per version; the binding is only as
  good as governance's discipline in rotating it (now timelocked, §4.3).

### 4.2 Ledger-integrity / circuit soundness
- The properties in §2 hold **only if the circuit binds what it claims to**. **Known gap
  (prototype): no key↔position binding.** The tree uses dense sequential slots + an off-circuit
  key→slot map; the circuit checks inclusion at a *witnessed* index but never enforces
  `position = f(key)`. A malicious prover could place one key at two positions. Masked here
  because the operator is the trusted prover — but a validity proof exists precisely to reduce
  that trust, so **this is the #1 production requirement** (§6). The fix is a key-indexed
  *indexed Merkle tree* with insert-time non-membership proofs.
- Self-transfer (`from == to` in one op) is *sound* (inclusion forces the credit to observe the
  debited leaf), so it is a nonce-bumping no-op, not a value-creation path.

### 4.3 Contract / authorization
- **Proof replay against different nets** — defended: the settlement digest binds
  `newStateRoot`, `opsAcc`, `netsAcc`, and `keccak(tos‖amounts)`. Verified by
  `test_nets_mismatch_rejected`.
- **Governance capture** — a malicious verifier swap forges everything. Defended:
  `initializeDecider` is one-time bootstrap; upgrades go `proposeDeciderUpgrade` → wait
  `DECIDER_TIMELOCK` → `executeDeciderUpgrade`, so a swap is public before it can be used.
  Verified by `GovernanceTimelockTest`. (PROTOTYPE: single-address governance stands in for a
  real multisig.)
- **Degradation-path abuse** — the `PROVER_TIMEOUT`/`UNPROVEN` legacy path is a deliberate trust
  downgrade; an adversary who can *induce* prover outages forces settlement onto it. Bounded by
  `CATCHUP_EPOCHS` and made publicly attributable (`EpochSettledUnproven`); the proven chain only
  advances via a spanning proof from the last proven root.
- **On-chain DoS / gas ceiling** — `withdrawalsAcc` is O(payees) on-chain Poseidon, and in this
  prototype each hash is a naive pure-Solidity Poseidon measured at **855,623 gas**, so the
  payee-linear term dominates the settle cost (~4.2M gas at 4 payees, ~36.7M at 42). This is an
  implementation artifact; production wants a Poseidon precompile (~40× cheaper) or per-payee
  claims against a proven `netsRoot` (O(1) settle). Until then it is a real griefing/gas-ceiling
  surface at large payee counts.

### 4.4 Liveness / availability
- Prover-hardware failure is a real dependency: the decider is ~12M constraints (≥64 GB,
  minutes/epoch). Mitigated operationally + by the degradation path.
- Settlement-tx censorship, gas spikes — inherited chain liveness risks.

### 4.5 Data / witness confidentiality
- The prover holds the **entire plaintext ledger** as witness (balances, amounts, keys, paths).
  Exfiltration or **outsourcing the prover** = catastrophic disclosure. Provers must not be
  outsourced without a data-protection review.

### What folding *removes*
A bonded fraud-proof challenge game, watchtowers, and the challenge-window delay to finality.
Finality is immediate at settlement.

---

## 5. Privacy model

### 5.1 Guarantee
**Public inputs are exactly `(i, z_0, z_n)`** = step count + `[stateRoot, opsAcc, netsAcc]`
before/after. No account-correlated value is a public input (asserted in tests). Per-payee net
amounts and the transfers commitment are on-chain exactly as in a commit-only checkpoint — the
proof reveals nothing beyond that.

### 5.2 The one new leak — and the mitigation
- **Epoch operation volume via `i`.** Nova's public inputs include the step count `i`; an
  observer learns `≈ total_ops / B`. A commit-only checkpoint doesn't reveal a per-epoch
  operation count, so this is a *new* coarse metadata leak. **Mitigation implemented:**
  constant-`i` padding — pad every epoch to a fixed step count with all-inactive (no-op) fold
  steps (`WorkloadSpec.pad_to_steps` / `--pad-steps`; soundness proven by `inactive_batch_is_noop`).
  With a fixed target, `i` reveals nothing about real volume, at the cost of worst-case proving
  every epoch. Off by default (so the bench can measure real per-op cost); turn on for deployment.

### 5.3 Accumulator preimage safety
`opsAcc`/`netsAcc` are public Poseidon accumulators over private ops. Preimages include
high-entropy account keys (≈ 254-bit field elements) alongside low-entropy amounts, so the
outputs are not dictionary-attackable. `withdrawalsAcc` is recomputed on-chain from the plaintext
payee addresses + amounts — i.e. payee addresses and their nets are on-chain, exactly as in a
commit-only checkpoint, no worse.

### 5.4 What the proof does NOT protect (to avoid over-claiming)
- **Amounts are not confidential** — observers see per-payee nets (and coarse volume via `i`
  unless padded). Hiding amounts needs a shielded pool.
- **Operator-side visibility is unchanged** — the custodian sees everything by design; the proof
  adds integrity, not confidentiality from the custodian.

### 5.5 Composing with one-time / unlinkable recipient addresses
The circuit is agnostic to how an account address was derived, so it composes with schemes that
use fresh, unlinkable recipient addresses (e.g. ERC-5564 stealth addresses): those provide
recipient unlinkability off-chain, while the proof keeps identities/amounts in the witness and
adds no on-chain linkage (accumulators are hashes of high-entropy keys). The impact is
**operational, not cryptographic** — one-time addresses force real lazy leaf insertion
(production requirement #1, §6) and tree-capacity planning; they do not change what the proof
reveals or the trust assumptions above.

---

## 6. Known limitations & production requirements

Ordered by importance. Items 1–3 are blocking for any non-prototype use.

1. **Key↔position binding** — replace the dense-slot tree with a key-indexed indexed Merkle tree
   so keys cannot be duplicated across positions (§4.2). *The integrity guarantee is only real
   once this lands.*
2. **Real Groth16 phase-2 ceremony** — replaces the dev-mode setup (§4.1).
3. **Audits** — F-circuit + `ProvenCheckpoint` + the sonobe pipeline; re-target sonobe `staging`
   once its EVM decider lands.
4. **Prover time/RSS are `light-test` figures**, not production — re-measure with
   `--features full-bench` on ≥64 GB.
5. **Nets-accumulator scaling** — the O(payees) on-chain Poseidon needs a precompile or a
   proven-`netsRoot` claim path before large payee counts (§4.3).
6. **Governance** — replace the single-address governance with a real multisig behind the
   timelock; consider a `ppHash`↔on-chain assertion.
7. **Workload realism** — drive the circuit from real transfer/op semantics (lazy account
   creation, multi-token, genuine per-payee netting) rather than the arranged synthetic epoch,
   which is what makes `netsAcc == withdrawalsAcc` hold exactly here.

---

## 7. Trust delta vs a commit-only checkpoint

- **Removed:** trust in the operator's arithmetic; the need for a bonded fraud-proof challenge
  game; the challenge-window delay to finality.
- **Added (threat):** trusted-setup ceremony; unaudited proving stack; prover-liveness
  dependency; verifier/`ppHash` governance surface (mitigated by timelock); a circuit-soundness
  class (incl. the key-binding gap).
- **Added (privacy):** epoch op-count via `i` — mitigated by constant-`i` padding; a hard
  "prover stays in-house" requirement.
- **Unchanged:** amounts visible on-chain, operator custody, and the on-chain linkability
  surface.
