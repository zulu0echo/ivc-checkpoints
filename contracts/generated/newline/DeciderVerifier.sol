
// SPDX-License-Identifier: MIT

pragma solidity ^0.8.35;

import "LegoGroth16Verifier.sol";



contract DeciderVerifier is LegoGroth16Verifier {
    error PointRLCFailed();
    error BaseCaseMismatch();
    error StateShapeMismatch();

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
    ) public view {
        _checkStateShape(z_0);
        _checkStateShape(z_i);
        uint256[3] memory z_0_flattened = _flattenState(z_0);
        uint256[3] memory z_i_flattened = _flattenState(z_i);

        if (i == 0) {
            for (uint256 k = 0; k < 3; k++) {
                if (z_0_flattened[k] != z_i_flattened[k]) {
                    revert BaseCaseMismatch();
                }
            }
            return;
        }

        // Scheme-emitted point RLC, which computes the folded commitments from
        // the unfolded ones and the challenge.
        uint256 rho = challenge & ((1 << 128) - 1);
        uint256[2] memory cm_e = _ecAdd(U_cm_e, _ecMul(cm_t, rho));
        uint256[2] memory cm_w = _ecAdd(U_cm_w, _ecMul(u_cm_w, rho));

        uint256[4] memory c = [
            cm_e[0], cm_e[1],
            cm_w[0], cm_w[1]
        ];

        // x = [i, z_0.., z_i.., challenge, inputize(cm)].
        uint256[40] memory x;
        x[0] = i;
        for (uint256 k = 0; k < 3; k++) {
            x[1 + k] = z_0_flattened[k];
            x[1 + 3 + k] = z_i_flattened[k];
        }
        x[7] = challenge;
        for (uint256 i = 0; i < 4; i++) {
            for (uint256 k = 0; k < 8; k++) {
                x[8 + i * 8 + k] = (c[i] >> (32 * k)) & 0xFFFFFFFF;
            }
        }

        this.verifyProof(x, c, proof);
    }

    function _checkStateShape(uint256[3] calldata z) internal pure {
        
    }

    function _flattenState(uint256[3] calldata z) internal pure returns (uint256[3] memory) {
        return z;
    }

    function _ecMul(uint256[2] calldata p, uint256 s)
        internal
        view
        returns (uint256[2] memory r)
    {
        uint256[3] memory input = [p[0], p[1], s];
        bool ok;
        assembly ("memory-safe") {
            ok := staticcall(gas(), 0x07, input, 0x60, r, 0x40)
        }
        if (!ok) {
            revert PointRLCFailed();
        }
    }

    function _ecAdd(uint256[2] calldata a, uint256[2] memory b)
        internal
        view
        returns (uint256[2] memory r)
    {
        uint256[4] memory input = [a[0], a[1], b[0], b[1]];
        bool ok;
        assembly ("memory-safe") {
            ok := staticcall(gas(), 0x06, input, 0x80, r, 0x40)
        }
        if (!ok) {
            revert PointRLCFailed();
        }
    }
}