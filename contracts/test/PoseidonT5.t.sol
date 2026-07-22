// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";
import {PoseidonT5} from "../src/PoseidonT5.sol";

/// Pins the on-chain Poseidon to the circuit's hashes. Fixtures are computed in Rust by the
/// SAME arkworks `CRH` the F-circuit uses (crates/prover gen_poseidon). If this passes, the
/// contract's `netsAcc` recomputation (hash4) and the escape-hatch Merkle path (hash2) are
/// bit-identical to what the proof commits to.
contract PoseidonT5Test is Test {
    function test_hash4_matches_circuit_fixture() public view {
        string memory json = vm.readFile("./generated/poseidon_t5_fixture.json");
        uint256 count = vm.parseJsonUint(json, ".hash4Count");
        assertGt(count, 0, "no hash4 vectors");
        for (uint256 i = 0; i < count; i++) {
            string memory base = string.concat(".hash4[", vm.toString(i), "]");
            uint256 a = vm.parseJsonUint(json, string.concat(base, ".inputs[0]"));
            uint256 b = vm.parseJsonUint(json, string.concat(base, ".inputs[1]"));
            uint256 c = vm.parseJsonUint(json, string.concat(base, ".inputs[2]"));
            uint256 d = vm.parseJsonUint(json, string.concat(base, ".inputs[3]"));
            uint256 expected = vm.parseJsonUint(json, string.concat(base, ".output"));
            assertEq(PoseidonT5.hash4(a, b, c, d), expected, "PoseidonT5.hash4 != arkworks");
        }
    }

    function test_hash2_matches_circuit_fixture() public view {
        string memory json = vm.readFile("./generated/poseidon_t5_fixture.json");
        uint256 count = vm.parseJsonUint(json, ".hash2Count");
        assertGt(count, 0, "no hash2 vectors");
        for (uint256 i = 0; i < count; i++) {
            string memory base = string.concat(".hash2[", vm.toString(i), "]");
            uint256 a = vm.parseJsonUint(json, string.concat(base, ".inputs[0]"));
            uint256 b = vm.parseJsonUint(json, string.concat(base, ".inputs[1]"));
            uint256 expected = vm.parseJsonUint(json, string.concat(base, ".output"));
            assertEq(PoseidonT5.hash2(a, b), expected, "PoseidonT5.hash2 != arkworks");
        }
    }
}
