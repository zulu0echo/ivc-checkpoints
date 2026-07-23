// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";
import {PoseidonT5} from "../src/PoseidonT5.sol";

/// Pins the on-chain Poseidon to the NEW-line circuit's hashes. Fixtures are computed in Rust by
/// the same arkworks 0.6 `CRH` the F-circuit uses under `poseidon_circom_config`
/// (crates/ledger-circuit-newline gen_poseidon_fixture). hash2/hash4 double as a cross-version
/// check that `poseidon_circom_config` == the classic `poseidon_canonical_config` constants; hash6
/// validates the arity-6 interval-leaf sponge.
contract PoseidonNewlineTest is Test {
    string constant FIX = "./generated/newline/poseidon_fixture.json";

    function test_hash2_matches_circuit_fixture() public view {
        string memory json = vm.readFile(FIX);
        uint256 count = vm.parseJsonUint(json, ".hash2Count");
        assertGt(count, 0, "no hash2 vectors");
        for (uint256 i = 0; i < count; i++) {
            string memory base = string.concat(".hash2[", vm.toString(i), "]");
            uint256 a = vm.parseJsonUint(json, string.concat(base, ".inputs[0]"));
            uint256 b = vm.parseJsonUint(json, string.concat(base, ".inputs[1]"));
            uint256 expected = vm.parseJsonUint(json, string.concat(base, ".output"));
            assertEq(PoseidonT5.hash2(a, b), expected, "hash2 != arkworks");
        }
    }

    function test_hash4_matches_circuit_fixture() public view {
        string memory json = vm.readFile(FIX);
        uint256 count = vm.parseJsonUint(json, ".hash4Count");
        assertGt(count, 0, "no hash4 vectors");
        for (uint256 i = 0; i < count; i++) {
            string memory base = string.concat(".hash4[", vm.toString(i), "]");
            uint256 a = vm.parseJsonUint(json, string.concat(base, ".inputs[0]"));
            uint256 b = vm.parseJsonUint(json, string.concat(base, ".inputs[1]"));
            uint256 c = vm.parseJsonUint(json, string.concat(base, ".inputs[2]"));
            uint256 d = vm.parseJsonUint(json, string.concat(base, ".inputs[3]"));
            uint256 expected = vm.parseJsonUint(json, string.concat(base, ".output"));
            assertEq(PoseidonT5.hash4(a, b, c, d), expected, "hash4 != arkworks");
        }
    }

    function test_hash6_matches_circuit_fixture() public view {
        string memory json = vm.readFile(FIX);
        uint256 count = vm.parseJsonUint(json, ".hash6Count");
        assertGt(count, 0, "no hash6 vectors");
        for (uint256 i = 0; i < count; i++) {
            string memory base = string.concat(".hash6[", vm.toString(i), "]");
            uint256[6] memory in6;
            for (uint256 k = 0; k < 6; k++) {
                in6[k] = vm.parseJsonUint(json, string.concat(base, ".inputs[", vm.toString(k), "]"));
            }
            uint256 expected = vm.parseJsonUint(json, string.concat(base, ".output"));
            assertEq(
                PoseidonT5.hash6(in6[0], in6[1], in6[2], in6[3], in6[4], in6[5]),
                expected,
                "hash6 != arkworks"
            );
        }
    }
}
