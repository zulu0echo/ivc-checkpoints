// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IOpaqueDecider} from "./interfaces/IOpaqueDecider.sol";
import {PoseidonT5} from "./PoseidonT5.sol";

/// @title ProvenCheckpoint — a validity-proven checkpoint for an off-chain balance ledger
/// @notice A netting/checkpoint settlement contract extended with a per-epoch Nova+CycleFold
///         decider proof of the entire ledger transition: spends happen off-chain as
///         operator-signed transfers; each epoch posts a commitment to those transfers plus
///         one net payout per payee, and a proof that the epoch's ledger update was applied
///         correctly.
///
/// The operator signature still authorizes settlement; the proof adds arithmetic
/// correctness. The contract supplies the IVC public inputs `z0`/`zi` itself, so:
///   * root-chaining (z0 = last proven root) cannot be forged from calldata, and
///   * `netsAcc` is recomputed on-chain (`withdrawalsAcc`) and required to match the proof.
///
/// PROTOTYPE — not production. Verifier upgrades are timelocked (§DECIDER_TIMELOCK) but
/// governance is a single address standing in for a multisig, and the verifier is dev-mode
/// (dev Groth16 setup). See README and docs/TRUST_MODEL.md.
contract ProvenCheckpoint {
    // BN254 scalar field — payee keys/accumulator operands live in this field.
    uint256 internal constant BN254_FR =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    uint8 private constant TAG_SETTLE_V = 40; // extended (proven) settle
    uint8 private constant TAG_SETTLE = 30; // legacy unproven settle (degradation path)

    // Prover-outage handling (graceful degradation).
    uint256 public constant PROVER_TIMEOUT = 6 hours;
    uint256 public constant CATCHUP_EPOCHS = 3;

    enum EpochStatus {
        NONE,
        PROVEN,
        UNPROVEN
    }

    // --- base netting/checkpoint state ---------------------------------------
    mapping(uint256 => bytes32) public transfersRoot;
    mapping(uint256 => address) public orgOf;
    mapping(uint256 => uint256) public orgNonce;
    mapping(uint256 => mapping(address => uint256)) public balanceOf;

    // --- validity-proof additions --------------------------------------------
    /// Proven Poseidon state root per epoch. Chains via `lastProvenRoot`.
    mapping(uint256 => bytes32) public stateRoot;
    mapping(uint256 => EpochStatus) public epochStatus;
    mapping(uint256 => uint256) public epochClosedAt;

    /// Current verifier + sonobe public-params hash (governance-gated, timelocked).
    address public novaDecider;
    bytes32 public ppHash;
    address public governance;

    /// Timelock for verifier upgrades. A malicious verifier swap forges arbitrary proofs, so
    /// the change MUST be publicly observable before it takes effect.
    uint256 public constant DECIDER_TIMELOCK = 2 days;
    address public pendingDecider;
    bytes32 public pendingPpHash;
    uint256 public deciderEta; // 0 = no pending upgrade

    /// The last PROVEN root and epoch — spanning proofs must chain from here, so an
    /// UNPROVEN gap is closed rather than silently accepted.
    bytes32 public lastProvenRoot;
    uint256 public lastProvenEpoch;
    /// Consecutive unproven epochs since the last proven settlement.
    uint256 public unprovenStreak;

    event EpochSettledProven(
        uint256 indexed epoch,
        uint256 indexed tokenId,
        bytes32 prevRoot,
        bytes32 newRoot,
        bytes32 netsAcc,
        uint256 nets
    );
    event EpochSettledUnproven(uint256 indexed epoch, uint256 indexed tokenId, uint256 streak);
    event DeciderInitialized(address novaDecider, bytes32 ppHash);
    event DeciderProposed(address novaDecider, bytes32 ppHash, uint256 eta);
    event DeciderUpdated(address novaDecider, bytes32 ppHash);

    error BadAuth();
    error BadNonce();
    error Exists();
    error RootMismatch();
    error NotGovernance();
    error DeciderUnset();
    error AlreadyInitialized();
    error NoPendingUpgrade();
    error TimelockNotElapsed();
    error NetsAccMismatch();
    error ProofRejected();
    error PrevRootMismatch();
    error TimeoutNotElapsed();
    error CatchupExceeded();
    error LengthMismatch();
    error AlreadyProven();

    constructor(address governance_, bytes32 genesisRoot) {
        governance = governance_;
        // Genesis: epoch 0 is the committed prior state the first epoch chains from.
        stateRoot[0] = genesisRoot;
        epochStatus[0] = EpochStatus.PROVEN;
        lastProvenRoot = genesisRoot;
        lastProvenEpoch = 0;
    }

    // --- governance ----------------------------------------------------------

    function createToken(uint256 id, address org) external {
        if (orgOf[id] != address(0)) revert Exists();
        orgOf[id] = org;
    }

    modifier onlyGovernance() {
        if (msg.sender != governance) revert NotGovernance();
        _;
    }

    /// One-time bootstrap of the initial verifier (no prior version to protect, so no
    /// timelock). `ppHash` binds proofs to one circuit version.
    function initializeDecider(address decider, bytes32 ppHash_) external onlyGovernance {
        if (novaDecider != address(0)) revert AlreadyInitialized();
        novaDecider = decider;
        ppHash = ppHash_;
        emit DeciderInitialized(decider, ppHash_);
    }

    /// Propose a verifier upgrade. Takes effect only after `DECIDER_TIMELOCK` via
    /// `executeDeciderUpgrade`, so the swap is public before it can be used.
    function proposeDeciderUpgrade(address decider, bytes32 ppHash_) external onlyGovernance {
        pendingDecider = decider;
        pendingPpHash = ppHash_;
        deciderEta = block.timestamp + DECIDER_TIMELOCK;
        emit DeciderProposed(decider, ppHash_, deciderEta);
    }

    /// Apply a proposed upgrade once the timelock has elapsed.
    function executeDeciderUpgrade() external onlyGovernance {
        if (deciderEta == 0) revert NoPendingUpgrade();
        if (block.timestamp < deciderEta) revert TimelockNotElapsed();
        novaDecider = pendingDecider;
        ppHash = pendingPpHash;
        pendingDecider = address(0);
        pendingPpHash = bytes32(0);
        deciderEta = 0;
        emit DeciderUpdated(novaDecider, ppHash);
    }

    /// Mark an epoch closed (starts the PROVER_TIMEOUT clock for the degradation path).
    function markEpochClosed(uint256 epoch) external {
        if (epochClosedAt[epoch] == 0) epochClosedAt[epoch] = block.timestamp;
    }

    // --- proven settlement -----------------------------------------------------

    /// @param zi [newStateRoot, opsAcc, netsAcc] — the proof's final IVC state.
    /// @param proof the 25-word opaque decider proof.
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
        uint256[25] calldata proof
    ) external {
        if (tos.length != amounts.length) revert LengthMismatch();
        if (novaDecider == address(0)) revert DeciderUnset();
        if (epochStatus[epoch] == EpochStatus.PROVEN) revert AlreadyProven();

        bytes32 newStateRoot = bytes32(zi[0]);

        // (a) org signature over the extended digest — MUST bind newStateRoot and the nets
        //     array, else a valid proof could be replayed vs other nets.
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
                    zi[1], // opsAcc
                    zi[2], // netsAcc
                    uint32(tokenId),
                    keccak256(abi.encodePacked(tos)),
                    keccak256(abi.encodePacked(amounts)),
                    steps,
                    nonce
                )
            ),
            sig
        );

        // (b) recompute withdrawalsAcc on-chain and require it equals the proof's netsAcc.
        //     Fold order MUST match the circuit (payee/withdraw order).
        uint256 acc = 0;
        for (uint256 i = 0; i < tos.length; ++i) {
            uint256 key = _fieldKey(tos[i], tokenId);
            acc = PoseidonT5.foldNet(acc, key, tokenId, uint256(amounts[i]));
        }
        if (acc != zi[2]) revert NetsAccMismatch();

        // (c) build z0 from the last proven root (chaining; spans any UNPROVEN gap) and
        //     verify the decider proof.
        bytes32 prevRoot = lastProvenRoot;
        uint256[3] memory z0;
        z0[0] = uint256(lastProvenRoot);
        z0[1] = 0;
        z0[2] = 0;
        // The generated verifier reverts (KZG/Groth16 `require`) on a bad proof rather than
        // returning false; treat both as rejection so callers get a stable error.
        try IOpaqueDecider(novaDecider).verifyOpaqueNovaProofWithInputs(steps, z0, zi, proof)
            returns (bool ok)
        {
            if (!ok) revert ProofRejected();
        } catch {
            revert ProofRejected();
        }

        // (d) commit: advance the proven chain, store roots, credit payee nets.
        transfersRoot[epoch] = transfersRoot_;
        stateRoot[epoch] = newStateRoot;
        epochStatus[epoch] = EpochStatus.PROVEN;
        lastProvenRoot = newStateRoot;
        lastProvenEpoch = epoch;
        unprovenStreak = 0;

        mapping(address => uint256) storage bal = balanceOf[tokenId];
        for (uint256 i = 0; i < tos.length; ++i) {
            bal[tos[i]] += amounts[i];
        }

        emit EpochSettledProven(epoch, tokenId, prevRoot, newStateRoot, bytes32(zi[2]), tos.length);
    }

    // --- legacy unproven settlement behind the timeout (graceful degradation) -------

    /// Unproven settlement, allowed only once `PROVER_TIMEOUT` has elapsed after the epoch
    /// was marked closed. Records an UNPROVEN gap; the chain does not advance until a
    /// spanning proof lands. Reverts once `CATCHUP_EPOCHS` unproven epochs accumulate.
    function settleEpoch(
        uint256 epoch,
        bytes32 root,
        uint256 tokenId,
        address[] calldata tos,
        uint96[] calldata amounts,
        uint32 nonce,
        bytes calldata sig
    ) external {
        if (tos.length != amounts.length) revert LengthMismatch();
        if (epochStatus[epoch] == EpochStatus.PROVEN) revert AlreadyProven();
        uint256 closedAt = epochClosedAt[epoch];
        if (closedAt == 0 || block.timestamp < closedAt + PROVER_TIMEOUT) revert TimeoutNotElapsed();
        if (unprovenStreak + 1 > CATCHUP_EPOCHS) revert CatchupExceeded();

        _auth(
            tokenId,
            nonce,
            keccak256(
                abi.encodePacked(
                    block.chainid,
                    address(this),
                    TAG_SETTLE,
                    epoch,
                    root,
                    uint32(tokenId),
                    keccak256(abi.encodePacked(tos)),
                    keccak256(abi.encodePacked(amounts)),
                    nonce
                )
            ),
            sig
        );

        transfersRoot[epoch] = root;
        epochStatus[epoch] = EpochStatus.UNPROVEN;
        unprovenStreak += 1;

        mapping(address => uint256) storage bal = balanceOf[tokenId];
        for (uint256 i = 0; i < tos.length; ++i) {
            bal[tos[i]] += amounts[i];
        }
        emit EpochSettledUnproven(epoch, tokenId, unprovenStreak);
    }

    // --- helpers -------------------------------------------------------------

    function _auth(uint256 tokenId, uint32 nonce, bytes32 digest, bytes calldata sig) private {
        if (nonce != orgNonce[tokenId]) revert BadNonce();
        orgNonce[tokenId] = nonce + 1;
        (bytes32 r, bytes32 s) = abi.decode(sig[:64], (bytes32, bytes32));
        if (ecrecover(digest, uint8(sig[64]), r, s) != orgOf[tokenId]) revert BadAuth();
    }

    /// Field key for a payee, matching the circuit's `to_key`/`from_key` derivation and
    /// `prover::field_key`: uint256(keccak256(abi.encodePacked(addr, uint32(tokenId)))) mod r.
    function _fieldKey(address a, uint256 tokenId) internal pure returns (uint256) {
        return uint256(keccak256(abi.encodePacked(a, uint32(tokenId)))) % BN254_FR;
    }

    // views
    function statusOf(uint256 epoch) external view returns (EpochStatus) {
        return epochStatus[epoch];
    }
}
