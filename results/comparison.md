# Measured [M] vs analytical model [A]

z_len = 3. Deviation flagged at > 5%.

| metric | model [A] | measured [M] | Δ / note |
| --- | ---: | ---: | --- |
| verifyNovaProof tx gas | 784428 | 799731 | +1.95% |
| settleEpochProven tx gas | — | 3616175 | verify + Poseidon nets + storage + credits |
| NovaDecider deploy gas | ~4–6M [A, rough] | 3221483 | per-circuit-version, one-time |
| calldata bytes | 1028 | 1028 |  |
| fold time / step (ms) | 0.5–2 s/step [A] | 1838 |  |
| decider prove (ms) | 5–20 min [A] | 29111 |  |
| peak RSS (bytes) | tens of GB [A] | 7545520128 |  |

> **light-test build**: prover time/RSS are NOT production figures. The verifier gas IS structurally representative (light-test only drops in-circuit Pedersen witness checks, not the public-input layout that drives gas).
