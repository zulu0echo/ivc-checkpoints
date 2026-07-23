// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";
import {ProvenCheckpointNewline} from "../src/ProvenCheckpointNewline.sol";
import {PoseidonT5} from "../src/PoseidonT5.sol";

/// Mock of the new-line decider verifier: `verifyDeciderProof` reverts on a bad proof (matching the
/// generated `DeciderVerifier`'s behaviour), toggled via `pass`. Lets us test `settleEpochProven`'s
/// plumbing (nets recompute, auth, chaining, accept/reject) without a real proof — the real proof is
/// verified end-to-end in revm (see docs/DECIDER_RESULTS.md, 696,556 gas).
contract MockDecider {
    bool public pass = true;

    function setPass(bool p) external {
        pass = p;
    }

    function verifyDeciderProof(
        uint256,
        uint256[3] calldata,
        uint256[3] calldata,
        uint256,
        uint256[2] calldata,
        uint256[2] calldata,
        uint256[2] calldata,
        uint256[2] calldata,
        uint256[12] calldata
    ) external view {
        require(pass, "bad proof");
    }
}

contract ProvenCheckpointNewlineTest is Test {
    uint256 internal constant BN254_FR =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint8 internal constant TAG_SETTLE_V = 41;

    address gov = address(0x6047);
    uint256 orgPk = 0xA11CE;
    address org;

    function setUp() public {
        org = vm.addr(orgPk);
    }

    function _fieldKey(address a, uint256 tokenId) internal pure returns (uint256) {
        return uint256(keccak256(abi.encodePacked(a, uint32(tokenId)))) % BN254_FR;
    }

    // Empty-subtree hash at each level (new circuit: empty leaf node == 0).
    function _emptyHashes(uint256 depth) internal pure returns (uint256[] memory e) {
        e = new uint256[](depth);
        uint256 cur = 0; // empty leaf
        for (uint256 i = 0; i < depth; i++) {
            e[i] = cur;
            cur = PoseidonT5.hash2(cur, cur);
        }
    }

    // ---- escape hatch: arity-6 interval leaf opens to the proven root ----
    function test_exit_arity6_leaf() public {
        uint256 depth = 6;
        uint256 tokenId = 1;
        address alice = address(0xA11CE0);

        // Alice's account leaf at index 0 (all-left path); neighbours are empty (0).
        uint256 key = _fieldKey(alice, tokenId);
        uint256 nextKey = 900;
        uint96 balance = 4200;
        uint64 nonce = 3;
        uint256 pkHash = 123456;
        uint256 leaf = PoseidonT5.leafHash(key, nextKey, tokenId, balance, nonce, pkHash);

        uint256[] memory e = _emptyHashes(depth);
        uint256[] memory siblings = new uint256[](depth);
        bool[] memory isRight = new bool[](depth);
        uint256 node = leaf;
        for (uint256 i = 0; i < depth; i++) {
            siblings[i] = e[i];
            isRight[i] = false; // index 0 => always a left child
            node = PoseidonT5.hash2(node, e[i]);
        }
        bytes32 root = bytes32(node);

        ProvenCheckpointNewline pc = new ProvenCheckpointNewline(gov, root, depth);

        vm.prank(alice);
        pc.exit(tokenId, nextKey, balance, nonce, pkHash, siblings, isRight);
        assertEq(pc.balanceOf(tokenId, alice), balance, "exit did not credit");

        // double-exit is blocked
        vm.prank(alice);
        vm.expectRevert(ProvenCheckpointNewline.AlreadyExited.selector);
        pc.exit(tokenId, nextKey, balance, nonce, pkHash, siblings, isRight);
    }

    function test_exit_wrong_balance_reverts() public {
        uint256 depth = 6;
        uint256 tokenId = 1;
        address alice = address(0xA11CE0);
        uint256 key = _fieldKey(alice, tokenId);
        uint256 leaf = PoseidonT5.leafHash(key, 900, tokenId, 4200, 3, 123456);

        uint256[] memory e = _emptyHashes(depth);
        uint256[] memory siblings = new uint256[](depth);
        bool[] memory isRight = new bool[](depth);
        uint256 node = leaf;
        for (uint256 i = 0; i < depth; i++) {
            siblings[i] = e[i];
            node = PoseidonT5.hash2(node, e[i]);
        }
        ProvenCheckpointNewline pc = new ProvenCheckpointNewline(gov, bytes32(node), depth);

        // claim a larger balance than committed => leaf differs => inclusion fails
        vm.prank(alice);
        vm.expectRevert(ProvenCheckpointNewline.InclusionFailed.selector);
        pc.exit(tokenId, 900, 9999, 3, 123456, siblings, isRight);
    }

    // ---- proven settlement against the new-line decider ABI (mock verifier) ----
    function _settle(ProvenCheckpointNewline pc, uint256 epoch, uint256 tokenId, uint32 nonce)
        internal
        returns (bytes32 newRoot)
    {
        address[] memory tos = new address[](2);
        tos[0] = address(0xBEEF);
        tos[1] = address(0xCAFE);
        uint96[] memory amounts = new uint96[](2);
        amounts[0] = 500;
        amounts[1] = 300;

        // netsAcc = on-chain fold order (must equal zi[2])
        uint256 acc = 0;
        for (uint256 i = 0; i < tos.length; i++) {
            acc = PoseidonT5.foldNet(acc, _fieldKey(tos[i], tokenId), tokenId, uint256(amounts[i]));
        }
        newRoot = keccak256(abi.encodePacked("root", epoch));
        uint256[3] memory zi = [uint256(newRoot), uint256(7), acc];
        bytes32 transfersRoot_ = keccak256(abi.encodePacked("transfers", epoch));
        uint256 steps = 1;

        bytes32 digest = keccak256(
            abi.encodePacked(
                block.chainid,
                address(pc),
                TAG_SETTLE_V,
                epoch,
                transfersRoot_,
                newRoot,
                zi[1],
                zi[2],
                uint32(tokenId),
                keccak256(abi.encodePacked(tos)),
                keccak256(abi.encodePacked(amounts)),
                steps,
                nonce
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(orgPk, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        ProvenCheckpointNewline.DeciderProof memory dp; // zeros — mock ignores content
        pc.settleEpochProven(epoch, transfersRoot_, zi, tokenId, tos, amounts, nonce, sig, steps, dp);
    }

    function test_settle_proven_happy_path() public {
        uint256 tokenId = 1;
        ProvenCheckpointNewline pc = new ProvenCheckpointNewline(gov, bytes32(uint256(1)), 22);
        pc.createToken(tokenId, org);
        MockDecider dec = new MockDecider();
        vm.prank(gov);
        pc.initializeDecider(address(dec), bytes32(uint256(0xABC)));

        bytes32 newRoot = _settle(pc, 1, tokenId, 0);
        assertEq(uint256(pc.lastProvenRoot()), uint256(newRoot), "root not advanced");
        assertEq(uint256(pc.statusOf(1)), uint256(ProvenCheckpointNewline.EpochStatus.PROVEN));
        assertEq(pc.balanceOf(tokenId, address(0xBEEF)), 500);
        assertEq(pc.balanceOf(tokenId, address(0xCAFE)), 300);
    }

    function test_settle_rejects_on_bad_proof() public {
        uint256 tokenId = 1;
        ProvenCheckpointNewline pc = new ProvenCheckpointNewline(gov, bytes32(uint256(1)), 22);
        pc.createToken(tokenId, org);
        MockDecider dec = new MockDecider();
        dec.setPass(false); // verifier reverts
        vm.prank(gov);
        pc.initializeDecider(address(dec), bytes32(uint256(0xABC)));

        vm.expectRevert(ProvenCheckpointNewline.ProofRejected.selector);
        _settle(pc, 1, tokenId, 0);
    }

    function test_settle_rejects_bad_netsAcc() public {
        uint256 tokenId = 1;
        ProvenCheckpointNewline pc = new ProvenCheckpointNewline(gov, bytes32(uint256(1)), 22);
        pc.createToken(tokenId, org);
        MockDecider dec = new MockDecider();
        vm.prank(gov);
        pc.initializeDecider(address(dec), bytes32(uint256(0xABC)));

        address[] memory tos = new address[](1);
        tos[0] = address(0xBEEF);
        uint96[] memory amounts = new uint96[](1);
        amounts[0] = 500;
        // zi[2] deliberately wrong (not the on-chain fold)
        uint256[3] memory zi = [uint256(123), uint256(7), uint256(999999)];
        uint256 steps = 1;
        bytes32 tr = keccak256("tr");
        bytes32 digest = keccak256(
            abi.encodePacked(
                block.chainid, address(pc), TAG_SETTLE_V, uint256(1), tr, bytes32(zi[0]),
                zi[1], zi[2], uint32(tokenId), keccak256(abi.encodePacked(tos)),
                keccak256(abi.encodePacked(amounts)), steps, uint32(0)
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(orgPk, digest);
        ProvenCheckpointNewline.DeciderProof memory dp;
        vm.expectRevert(ProvenCheckpointNewline.NetsAccMismatch.selector);
        pc.settleEpochProven(1, tr, zi, tokenId, tos, amounts, 0, abi.encodePacked(r, s, v), steps, dp);
    }
}
