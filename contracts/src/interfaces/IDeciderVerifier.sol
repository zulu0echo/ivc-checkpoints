// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/// The new-line (sonobe PR #259) LegoGroth16 decider verifier, as rendered by
/// `CycleFoldBasedIVCDeciderVerifierTemplate` into `generated/newline/DeciderVerifier.sol`.
/// z_len = 3 ([stateRoot, opsAcc, netsAcc]). Unlike the classic `IOpaqueDecider`, this
/// `view` function **reverts** on an invalid proof rather than returning a bool, and takes the
/// unfolded commitments + RLC challenge + a `uint256[12]` proof (the folded commitments are
/// reconstructed on-chain from `(U_*, cm_t, u_cm_w)` and `challenge`).
interface IDeciderVerifier {
    function verifyDeciderProof(
        uint256 i,
        uint256[3] calldata z_0,
        uint256[3] calldata z_i,
        uint256 challenge,
        uint256[2] calldata U_cm_e,
        uint256[2] calldata cm_t,
        uint256[2] calldata U_cm_w,
        uint256[2] calldata u_cm_w,
        uint256[12] calldata proof
    ) external view;
}
