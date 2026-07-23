// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IDeciderVerifier} from "./interfaces/IDeciderVerifier.sol";
import {PoseidonT5} from "./PoseidonT5.sol";

/// @title ProvenCheckpointNewline — validity-proven checkpoint wired to the new-line (A0+A1) decider
/// @notice New-sonobe-line variant of `ProvenCheckpoint`. Two things change vs the classic contract:
///   1. **Verifier ABI.** Settlement calls the LegoGroth16 `verifyDeciderProof` (which *reverts* on a
///      bad proof) instead of the classic opaque `verifyOpaqueNovaProofWithInputs` bool return. The
///      folded commitments are reconstructed on-chain from the unfolded ones + the RLC challenge (the
///      generated `DeciderVerifier` does this), so the caller passes the raw decider-proof bundle.
///   2. **Account leaf is arity-6.** The escape hatch opens the interval-tree leaf
///      `(key, next_key, tokenId, balance, nonce, pk_hash)` via `PoseidonT5.leafHash` (A0 interval
///      pointer + A1 spend-key commitment), and the Merkle empty-leaf convention is `0`.
///
/// The state transition still commits `z = [stateRoot, opsAcc, netsAcc]`; the contract supplies
/// `z0` (from the last proven root) and recomputes `netsAcc` on-chain, so root-chaining and the nets
/// accumulator cannot be forged from calldata.
///
/// PROTOTYPE — targets the **dev-setup** generated verifier (random keys). Verifier upgrades are
/// timelocked + freezable; governance is a single address standing in for a multisig. See
/// docs/DECIDER_RESULTS.md and docs/CEREMONY_AND_AUDIT.md.
contract ProvenCheckpointNewline {
    uint256 internal constant BN254_FR =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    uint8 private constant TAG_SETTLE_V = 41; // new-line proven settle (distinct from classic 40)

    enum EpochStatus {
        NONE,
        PROVEN,
        UNPROVEN
    }

    /// The raw new-line decider-proof bundle (unfolded commitments + RLC challenge + proof).
    struct DeciderProof {
        uint256 challenge;
        uint256[2] U_cm_e;
        uint256[2] cm_t;
        uint256[2] U_cm_w;
        uint256[2] u_cm_w;
        uint256[12] proof;
    }

    // base state
    mapping(uint256 => bytes32) public transfersRoot;
    mapping(uint256 => address) public orgOf;
    mapping(uint256 => uint256) public orgNonce;
    mapping(uint256 => mapping(address => uint256)) public balanceOf;

    // validity-proof state
    mapping(uint256 => bytes32) public stateRoot;
    mapping(uint256 => EpochStatus) public epochStatus;
    bytes32 public lastProvenRoot;
    uint256 public lastProvenEpoch;

    // verifier + governance (timelocked, freezable)
    address public decider;
    bytes32 public ppHash;
    address public governance;
    bool public verifierFrozen;
    uint256 public constant DECIDER_TIMELOCK = 2 days;
    address public pendingDecider;
    bytes32 public pendingPpHash;
    uint256 public deciderEta;

    // escape hatch
    uint256 public immutable treeDepth;
    mapping(bytes32 => bool) public exited; // keccak(tokenId, key) => already withdrawn

    event EpochSettledProven(
        uint256 indexed epoch, uint256 indexed tokenId, bytes32 prevRoot, bytes32 newRoot, bytes32 netsAcc, uint256 nets
    );
    event DeciderInitialized(address decider, bytes32 ppHash);
    event DeciderProposed(address decider, bytes32 ppHash, uint256 eta);
    event DeciderUpdated(address decider, bytes32 ppHash);
    event VerifierFrozen();
    event Exited(uint256 indexed tokenId, address indexed owner, uint96 amount);

    error BadAuth();
    error BadNonce();
    error Exists();
    error NotGovernance();
    error DeciderUnset();
    error AlreadyInitialized();
    error NoPendingUpgrade();
    error TimelockNotElapsed();
    error NetsAccMismatch();
    error ProofRejected();
    error LengthMismatch();
    error AlreadyProven();
    error Frozen();
    error AlreadyExited();
    error InclusionFailed();
    error BadPathLength();

    constructor(address governance_, bytes32 genesisRoot, uint256 treeDepth_) {
        governance = governance_;
        treeDepth = treeDepth_;
        stateRoot[0] = genesisRoot;
        epochStatus[0] = EpochStatus.PROVEN;
        lastProvenRoot = genesisRoot;
        lastProvenEpoch = 0;
    }

    // --- governance ----------------------------------------------------------

    modifier onlyGovernance() {
        if (msg.sender != governance) revert NotGovernance();
        _;
    }

    function createToken(uint256 id, address org) external {
        if (orgOf[id] != address(0)) revert Exists();
        orgOf[id] = org;
    }

    function initializeDecider(address decider_, bytes32 ppHash_) external onlyGovernance {
        if (decider != address(0)) revert AlreadyInitialized();
        decider = decider_;
        ppHash = ppHash_;
        emit DeciderInitialized(decider_, ppHash_);
    }

    function proposeDeciderUpgrade(address decider_, bytes32 ppHash_) external onlyGovernance {
        if (verifierFrozen) revert Frozen();
        pendingDecider = decider_;
        pendingPpHash = ppHash_;
        deciderEta = block.timestamp + DECIDER_TIMELOCK;
        emit DeciderProposed(decider_, ppHash_, deciderEta);
    }

    function executeDeciderUpgrade() external onlyGovernance {
        if (verifierFrozen) revert Frozen();
        if (deciderEta == 0) revert NoPendingUpgrade();
        if (block.timestamp < deciderEta) revert TimelockNotElapsed();
        decider = pendingDecider;
        ppHash = pendingPpHash;
        pendingDecider = address(0);
        pendingPpHash = bytes32(0);
        deciderEta = 0;
        emit DeciderUpdated(decider, ppHash);
    }

    function freezeVerifier() external onlyGovernance {
        verifierFrozen = true;
        emit VerifierFrozen();
    }

    // --- escape hatch: unilateral withdrawal against the last proven root (arity-6 leaf) ----

    /// Withdraw your proven balance without operator involvement: prove your arity-6 interval leaf
    /// `(key, next_key, tokenId, balance, nonce, pk_hash)` opens to the last proven `stateRoot`.
    /// Ownership is bound via `key = _fieldKey(msg.sender, tokenId)`; a per-(token,key) nullifier
    /// prevents double-exit. `siblings`/`isRight` are the bottom-up Merkle path
    /// (`isRight[i] == true` ⇒ this node is the right child at level i; empty siblings are `0`).
    function exit(
        uint256 tokenId,
        uint256 nextKey,
        uint96 balance,
        uint64 nonce,
        uint256 pkHash,
        uint256[] calldata siblings,
        bool[] calldata isRight
    ) external {
        if (siblings.length != treeDepth || isRight.length != treeDepth) revert BadPathLength();
        uint256 key = _fieldKey(msg.sender, tokenId);
        uint256 node = PoseidonT5.leafHash(key, nextKey, tokenId, uint256(balance), uint256(nonce), pkHash);
        for (uint256 i = 0; i < treeDepth; i++) {
            node = isRight[i] ? PoseidonT5.hash2(siblings[i], node) : PoseidonT5.hash2(node, siblings[i]);
        }
        if (bytes32(node) != lastProvenRoot) revert InclusionFailed();

        bytes32 nk = keccak256(abi.encodePacked(tokenId, key));
        if (exited[nk]) revert AlreadyExited();
        exited[nk] = true;

        balanceOf[tokenId][msg.sender] += balance;
        emit Exited(tokenId, msg.sender, balance);
    }

    // --- proven settlement (new-line decider ABI) ----------------------------

    /// @param zi [newStateRoot, opsAcc, netsAcc] — the proof's final IVC state.
    /// @param dp the new-line decider-proof bundle (unfolded commitments + RLC challenge + proof).
    function settleEpochProven(
        uint256 epoch,
        bytes32 transfersRoot_,
        uint256[3] calldata zi,
        uint256 tokenId,
        address[] calldata tos,
        uint96[] calldata amounts,
        uint32 nonce,
        bytes calldata sig,
        uint256 steps,
        DeciderProof calldata dp
    ) external {
        if (tos.length != amounts.length) revert LengthMismatch();
        if (decider == address(0)) revert DeciderUnset();
        if (epochStatus[epoch] == EpochStatus.PROVEN) revert AlreadyProven();

        bytes32 newStateRoot = bytes32(zi[0]);

        // (a) org signature binds newStateRoot + the nets array (no cross-nets replay).
        _auth(
            tokenId,
            nonce,
            keccak256(
                abi.encodePacked(
                    block.chainid,
                    address(this),
                    TAG_SETTLE_V,
                    epoch,
                    transfersRoot_,
                    newStateRoot,
                    zi[1],
                    zi[2],
                    uint32(tokenId),
                    keccak256(abi.encodePacked(tos)),
                    keccak256(abi.encodePacked(amounts)),
                    steps,
                    nonce
                )
            ),
            sig
        );

        // (b) recompute netsAcc on-chain; MUST equal the proof's zi[2]. Fold order matches the circuit.
        uint256 acc = 0;
        for (uint256 i = 0; i < tos.length; ++i) {
            uint256 key = _fieldKey(tos[i], tokenId);
            acc = PoseidonT5.foldNet(acc, key, tokenId, uint256(amounts[i]));
        }
        if (acc != zi[2]) revert NetsAccMismatch();

        // (c) z0 from the last proven root (chaining) + verify. The decider verifier *reverts* on a
        //     bad proof; treat any revert as rejection.
        bytes32 prevRoot = lastProvenRoot;
        uint256[3] memory z0;
        z0[0] = uint256(lastProvenRoot);
        try IDeciderVerifier(decider).verifyDeciderProof(
            steps, z0, zi, dp.challenge, dp.U_cm_e, dp.cm_t, dp.U_cm_w, dp.u_cm_w, dp.proof
        ) {} catch {
            revert ProofRejected();
        }

        // (d) commit.
        transfersRoot[epoch] = transfersRoot_;
        stateRoot[epoch] = newStateRoot;
        epochStatus[epoch] = EpochStatus.PROVEN;
        lastProvenRoot = newStateRoot;
        lastProvenEpoch = epoch;

        mapping(address => uint256) storage bal = balanceOf[tokenId];
        for (uint256 i = 0; i < tos.length; ++i) {
            bal[tos[i]] += amounts[i];
        }
        emit EpochSettledProven(epoch, tokenId, prevRoot, newStateRoot, bytes32(zi[2]), tos.length);
    }

    // --- helpers -------------------------------------------------------------

    function _auth(uint256 tokenId, uint32 nonce, bytes32 digest, bytes calldata sig) private {
        if (nonce != orgNonce[tokenId]) revert BadNonce();
        orgNonce[tokenId] = nonce + 1;
        (bytes32 r, bytes32 s) = abi.decode(sig[:64], (bytes32, bytes32));
        if (ecrecover(digest, uint8(sig[64]), r, s) != orgOf[tokenId]) revert BadAuth();
    }

    /// Field key for an address, matching the circuit's key derivation:
    /// uint256(keccak256(abi.encodePacked(addr, uint32(tokenId)))) mod r.
    function _fieldKey(address a, uint256 tokenId) internal pure returns (uint256) {
        return uint256(keccak256(abi.encodePacked(a, uint32(tokenId)))) % BN254_FR;
    }

    function statusOf(uint256 epoch) external view returns (EpochStatus) {
        return epochStatus[epoch];
    }
}
