// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/// Subset of the sonobe-generated `NovaDecider` contract that `ProvenCheckpoint` calls.
/// z_len = 3 ([stateRoot, opsAcc, netsAcc]), so the IVC state arrays are `uint256[3]` and
/// the opaque proof is `uint256[25]` (see sonobe nova_cyclefold_decider template).
interface IOpaqueDecider {
    /// Verifies a Nova+CycleFold decider proof for the given IVC states. The contract
    /// supplies `z0`/`zi` itself so root-chaining and the nets accumulator are enforced
    /// on-chain rather than trusted from calldata.
    function verifyOpaqueNovaProofWithInputs(
        uint256 steps,
        uint256[3] calldata z0,
        uint256[3] calldata zi,
        uint256[25] calldata proof
    ) external view returns (bool);
}
