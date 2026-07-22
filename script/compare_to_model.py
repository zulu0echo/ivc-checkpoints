#!/usr/bin/env python3
"""Compare measured [M] numbers against the analytical verifier cost model [A].

The analytical model counts the generated verifier's elliptic-curve operations (Groth16 MSM +
pairing, two KZG opening checks, fold RLC ops) priced at Prague rules — a public, reproducible
gas estimate for the Nova+CycleFold decider verifier as a function of the IVC state length.

Reads (whichever exist):
  results/prover.json     — prover-side [M] (fold/decider time, peak RSS, calldata, revm gas)
  results/forge_gas.json  — on-chain [M] (deploy gas, verifyNovaProof tx gas, settle tx gas)

Writes:
  results/measured.json   — merged, provenance-labeled numbers
  results/comparison.md    — measured-vs-model markdown table (flags deviation > 5%)
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
RESULTS = os.path.join(ROOT, "results")

# Analytical verifier cost model (EC-op count at Prague pricing). z_len = 3 is the default.
ANALYTICAL_MODEL = {
    1: {"public_inputs": 38, "calldata": 900, "exec_gas": 721_700, "tx_gas": 756_992},
    3: {"public_inputs": 42, "calldata": 1028, "exec_gas": 747_100, "tx_gas": 784_428},
    5: {"public_inputs": 46, "calldata": 1156, "exec_gas": 772_500, "tx_gas": 811_852},
}
DEVIATION_FLAG = 0.05  # 5%, per the task
Z_LEN = 3


def load(name):
    path = os.path.join(RESULTS, name)
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return json.load(f)


def pct(measured, model):
    if model == 0:
        return float("nan")
    return (measured - model) / model * 100.0


def main():
    prover = load("prover.json")
    forge = load("forge_gas.json")
    model = ANALYTICAL_MODEL[Z_LEN]

    if prover is None and forge is None:
        print("No results found. Run:\n"
              "  cargo run -p bench --features light-test\n"
              "  (cd contracts && forge test --mt test_meter_and_write_gas)")
        sys.exit(1)

    rows = []  # (metric, model_A, measured_M, note)

    if forge:
        m_verify = forge.get("verify_nova_proof_tx_gas")
        if m_verify:
            d = pct(m_verify, model["tx_gas"])
            flag = "  ⚠️ >5%" if abs(d) > DEVIATION_FLAG * 100 else ""
            rows.append(("verifyNovaProof tx gas", model["tx_gas"], m_verify, f"{d:+.2f}%{flag}"))
        if forge.get("settle_epoch_proven_tx_gas"):
            rows.append(("settleEpochProven tx gas", "—", forge["settle_epoch_proven_tx_gas"],
                         "verify + Poseidon nets + storage + credits"))
        if forge.get("deploy_gas"):
            rows.append(("NovaDecider deploy gas", "~4–6M [A, rough]", forge["deploy_gas"],
                         "per-circuit-version, one-time"))
        if forge.get("calldata_bytes"):
            rows.append(("calldata bytes", model["calldata"], forge["calldata_bytes"], ""))

    if prover:
        for key, label, model_a in [
            ("fold_ms_per_step_avg", "fold time / step (ms)", "0.5–2 s/step [A]"),
            ("decider_prove_ms", "decider prove (ms)", "5–20 min [A]"),
            ("peak_rss_bytes", "peak RSS (bytes)", "tens of GB [A]"),
        ]:
            if prover.get(key) is not None:
                rows.append((label, model_a, prover[key], ""))
        if prover.get("verify_gas_revm"):
            rows.append(("verifyNovaProof gas (revm exec)", model["exec_gas"],
                         prover["verify_gas_revm"], "execution-only cross-check"))

    # measured.json (merged, labeled)
    merged = {
        "provenance": "[M] measured on the pinned toolchain unless noted [A]",
        "z_len": Z_LEN,
        "analytical_model_reference": model,
        "prover": prover or {},
        "forge_gas": forge or {},
    }
    os.makedirs(RESULTS, exist_ok=True)
    with open(os.path.join(RESULTS, "measured.json"), "w") as f:
        json.dump(merged, f, indent=2)

    # comparison.md
    lines = [
        "# Measured [M] vs analytical model [A]",
        "",
        f"z_len = {Z_LEN}. Deviation flagged at > {int(DEVIATION_FLAG*100)}%.",
        "",
        "| metric | model [A] | measured [M] | Δ / note |",
        "| --- | ---: | ---: | --- |",
    ]
    for metric, a, m, note in rows:
        lines.append(f"| {metric} | {a} | {m} | {note} |")
    if prover and prover.get("light_test"):
        lines += ["", "> **light-test build**: prover time/RSS are NOT production figures. The "
                  "verifier gas IS structurally representative (light-test only drops in-circuit "
                  "Pedersen witness checks, not the public-input layout that drives gas)."]
    md = "\n".join(lines) + "\n"
    with open(os.path.join(RESULTS, "comparison.md"), "w") as f:
        f.write(md)

    print(md)
    print("Wrote results/measured.json and results/comparison.md")


if __name__ == "__main__":
    main()
