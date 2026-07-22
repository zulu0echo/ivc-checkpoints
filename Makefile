# ivc-checkpoints — common workflows. See README.md.
.PHONY: help circuit-test constraints prove prove-full gen-poseidon forge-test bench compare all clean

help:
	@echo "circuit-test  - ledger-circuit unit tests + measured constraint counts"
	@echo "prove         - fold small epoch (light-test) -> contracts/generated/*"
	@echo "prove-full    - fold large daily epoch (needs >=64 GB RAM)"
	@echo "gen-poseidon  - regenerate contracts/src/PoseidonT5.sol from arkworks constants"
	@echo "forge-test    - Foundry: Poseidon fixture + functional + negative + gas"
	@echo "bench         - end-to-end measurement -> results/prover.json"
	@echo "compare       - merge [M] vs analytical model -> results/{measured.json,comparison.md}"
	@echo "all           - circuit-test + prove + forge-test + bench + compare"

circuit-test constraints:
	cargo test -p ledger-circuit --release -- --nocapture

prove:
	cargo run -p prover --bin prove_epoch --release --features light-test -- --scale small

prove-full:
	cargo run -p prover --bin prove_epoch --release -- --scale large

gen-poseidon:
	cargo run -p prover --bin gen_poseidon

forge-test:
	cd contracts && forge test -vv

bench:
	cargo run -p bench --features light-test

compare:
	python3 script/compare_to_model.py

all: circuit-test prove forge-test bench compare

clean:
	cargo clean
	rm -rf contracts/out contracts/cache
