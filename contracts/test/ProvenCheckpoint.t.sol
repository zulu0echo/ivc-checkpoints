// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";
import {ProvenCheckpoint} from "../src/ProvenCheckpoint.sol";
import {NovaDecider} from "../generated/NovaDecider.sol";

/// Loads the prover-generated epoch artifacts (contracts/generated/proof.json) and exercises
/// settleEpochProven end-to-end against the generated NovaDecider. Run the prover first:
///   cargo run -p prover --bin prove_epoch --release --features light-test -- --scale small
abstract contract CheckpointFixture is Test {
    uint256 internal constant ORG_PK = 0xA11CE;

    ProvenCheckpoint internal pc;
    NovaDecider internal decider;
    address internal org;

    // loaded artifacts
    uint256 internal epoch;
    uint256 internal tokenId;
    uint256 internal steps;
    bytes32 internal prevRoot;
    bytes32 internal transfersRoot;
    uint256[3] internal zi; // [newStateRoot, opsAcc, netsAcc]
    uint256[25] internal proof;
    address[] internal tos;
    uint96[] internal amounts;

    function _load() internal {
        string memory json = vm.readFile("./generated/proof.json");
        epoch = vm.parseJsonUint(json, ".epoch");
        tokenId = vm.parseJsonUint(json, ".tokenId");
        steps = vm.parseJsonUint(json, ".steps");
        prevRoot = vm.parseJsonBytes32(json, ".prevStateRoot");
        transfersRoot = vm.parseJsonBytes32(json, ".transfersRoot");
        zi[0] = vm.parseJsonUint(json, ".newStateRoot");
        zi[1] = vm.parseJsonUint(json, ".opsAcc");
        zi[2] = vm.parseJsonUint(json, ".netsAcc");

        uint256[] memory p = vm.parseJsonUintArray(json, ".proof");
        require(p.length == 25, "proof must be 25 words");
        for (uint256 i = 0; i < 25; i++) {
            proof[i] = p[i];
        }

        tos = vm.parseJsonAddressArray(json, ".netAddrs");
        uint256[] memory amt = vm.parseJsonUintArray(json, ".netAmounts");
        require(amt.length == tos.length, "nets length mismatch");
        amounts = new uint96[](amt.length);
        for (uint256 i = 0; i < amt.length; i++) {
            amounts[i] = uint96(amt[i]);
        }
    }

    function _deploy(bytes32 genesisRoot) internal {
        org = vm.addr(ORG_PK);
        decider = new NovaDecider();
        pc = new ProvenCheckpoint(address(this), genesisRoot);
        pc.createToken(tokenId, org);
        pc.initializeDecider(address(decider), bytes32(uint256(0xdad0))); // dev ppHash bootstrap
    }

    /// Reconstruct the exact digest ProvenCheckpoint signs and produce a 65-byte sig.
    function _sign(uint32 nonce, address[] memory tos_, uint96[] memory amounts_)
        internal
        view
        returns (bytes memory)
    {
        bytes32 digest = keccak256(
            abi.encodePacked(
                block.chainid,
                address(pc),
                uint8(40), // TAG_SETTLE_V
                epoch,
                transfersRoot,
                bytes32(zi[0]), // newStateRoot
                zi[1], // opsAcc
                zi[2], // netsAcc
                uint32(tokenId),
                keccak256(abi.encodePacked(tos_)),
                keccak256(abi.encodePacked(amounts_)),
                steps,
                nonce
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ORG_PK, digest);
        return abi.encodePacked(r, s, v);
    }
}

contract ProvenCheckpointTest is CheckpointFixture {
    function setUp() public {
        _load();
    }

    /// Happy path: a valid proof is accepted, roots chain, and payee nets are credited.
    function test_valid_proof_accepted() public {
        _deploy(prevRoot);
        bytes memory sig = _sign(0, tos, amounts);

        pc.settleEpochProven(epoch, transfersRoot, zi, tokenId, tos, amounts, 0, sig, steps, proof);

        assertEq(pc.stateRoot(epoch), bytes32(zi[0]), "new root stored");
        assertEq(uint256(pc.lastProvenRoot()), zi[0], "chain advanced");
        assertEq(uint8(pc.statusOf(epoch)), uint8(ProvenCheckpoint.EpochStatus.PROVEN));
        for (uint256 i = 0; i < tos.length; i++) {
            assertEq(pc.balanceOf(tokenId, tos[i]), amounts[i], "payee net credited");
        }
    }

    /// Mutated calldata: flipping any decider proof word must be rejected by the verifier.
    function test_mutated_proof_rejected() public {
        _deploy(prevRoot);
        bytes memory sig = _sign(0, tos, amounts);

        uint256[25] memory bad = proof;
        bad[0] = bad[0] ^ 1; // flip a bit

        vm.expectRevert(ProvenCheckpoint.ProofRejected.selector);
        pc.settleEpochProven(epoch, transfersRoot, zi, tokenId, tos, amounts, 0, sig, steps, bad);
    }

    /// Wrong previous root: the contract builds z0 from its stored chain, so a genesis that
    /// doesn't match the proof's z_0 makes the proof fail (chaining is enforced on-chain).
    function test_wrong_prev_root_rejected() public {
        _deploy(bytes32(uint256(prevRoot) ^ 1)); // wrong genesis
        bytes memory sig = _sign(0, tos, amounts);

        vm.expectRevert(ProvenCheckpoint.ProofRejected.selector);
        pc.settleEpochProven(epoch, transfersRoot, zi, tokenId, tos, amounts, 0, sig, steps, proof);
    }

    /// Nets mismatch: tamper an amount (and re-sign so auth still passes) — the on-chain
    /// withdrawalsAcc recomputation no longer equals the proof's netsAcc.
    function test_nets_mismatch_rejected() public {
        _deploy(prevRoot);
        require(amounts.length > 0, "need at least one net");

        uint96[] memory badAmounts = new uint96[](amounts.length);
        for (uint256 i = 0; i < amounts.length; i++) {
            badAmounts[i] = amounts[i];
        }
        badAmounts[0] = badAmounts[0] + 1;

        bytes memory sig = _sign(0, tos, badAmounts); // re-sign to pass _auth

        vm.expectRevert(ProvenCheckpoint.NetsAccMismatch.selector);
        pc.settleEpochProven(epoch, transfersRoot, zi, tokenId, tos, badAmounts, 0, sig, steps, proof);
    }
}

/// Governance-timelock behaviour for verifier upgrades (threat model: governance capture).
contract GovernanceTimelockTest is CheckpointFixture {
    function setUp() public {
        _load();
    }

    function test_upgrade_is_timelocked() public {
        _deploy(prevRoot); // bootstraps decider via initializeDecider
        address newDecider = address(0xBEEF);
        bytes32 newPp = bytes32(uint256(0xF00D));

        // second init is rejected (already bootstrapped)
        vm.expectRevert(ProvenCheckpoint.AlreadyInitialized.selector);
        pc.initializeDecider(newDecider, newPp);

        // non-governance cannot propose
        vm.prank(address(0xBAD));
        vm.expectRevert(ProvenCheckpoint.NotGovernance.selector);
        pc.proposeDeciderUpgrade(newDecider, newPp);

        // propose, then executing before the timelock reverts
        pc.proposeDeciderUpgrade(newDecider, newPp);
        vm.expectRevert(ProvenCheckpoint.TimelockNotElapsed.selector);
        pc.executeDeciderUpgrade();

        // after the delay it applies
        vm.warp(block.timestamp + pc.DECIDER_TIMELOCK());
        pc.executeDeciderUpgrade();
        assertEq(pc.novaDecider(), newDecider, "decider upgraded");
        assertEq(pc.ppHash(), newPp, "ppHash upgraded");
        assertEq(pc.deciderEta(), 0, "pending cleared");
    }

    function test_execute_without_proposal_reverts() public {
        _deploy(prevRoot);
        vm.expectRevert(ProvenCheckpoint.NoPendingUpgrade.selector);
        pc.executeDeciderUpgrade();
    }
}
