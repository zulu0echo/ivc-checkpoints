// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {CheckpointFixture} from "./ProvenCheckpoint.t.sol";
import {NovaDecider} from "../generated/NovaDecider.sol";

/// Meters the on-chain [M] gas figures (tx-level, isolate mode) and writes them to
/// results/forge_gas.json for script/compare_to_model.py:
///   * NovaDecider deployment gas
///   * verifyNovaProof (verifyOpaqueNovaProofWithInputs) tx gas  <- the ~784k analytical row
///   * settleEpochProven tx gas (full settlement: verify + Poseidon nets + storage + credits)
contract GasTest is CheckpointFixture {
    function setUp() public {
        _load();
        _deploy(prevRoot);
    }

    function test_meter_and_write_gas() public {
        // --- deployment gas ---
        uint256 g = gasleft();
        NovaDecider fresh = new NovaDecider();
        uint256 deployGas = g - gasleft();
        require(address(fresh) != address(0), "deploy");

        // --- verifyNovaProof tx gas (isolate => tx-level) ---
        uint256[3] memory z0;
        z0[0] = uint256(prevRoot);
        decider.verifyOpaqueNovaProofWithInputs(steps, z0, zi, proof);
        uint256 verifyGas = vm.lastCallGas().gasTotalUsed;

        // --- settleEpochProven tx gas ---
        bytes memory sig = _sign(0, tos, amounts);
        pc.settleEpochProven(epoch, transfersRoot, zi, tokenId, tos, amounts, 0, sig, steps, proof);
        uint256 settleGas = vm.lastCallGas().gasTotalUsed;

        // calldata bytes reported by the prover (1,028 at z_len=3).
        string memory pj = vm.readFile("./generated/proof.json");
        uint256 calldataBytes = vm.parseJsonUint(pj, ".calldataBytes");

        emit log_named_uint("NovaDecider deploy gas", deployGas);
        emit log_named_uint("verifyNovaProof tx gas", verifyGas);
        emit log_named_uint("settleEpochProven tx gas", settleGas);

        string memory obj = "forge_gas";
        vm.serializeUint(obj, "deploy_gas", deployGas);
        vm.serializeUint(obj, "verify_nova_proof_tx_gas", verifyGas);
        vm.serializeUint(obj, "settle_epoch_proven_tx_gas", settleGas);
        vm.serializeUint(obj, "calldata_bytes", calldataBytes);
        vm.serializeUint(obj, "z_len", 3);
        string memory out = vm.serializeString(obj, "note", "light-test verifier; gas is structurally representative of production (see README)");
        vm.writeJson(out, "../results/forge_gas.json");
    }
}
