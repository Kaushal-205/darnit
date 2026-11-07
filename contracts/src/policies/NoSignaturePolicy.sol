// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {I1271Policy, IPolicy, IERC165} from "../interfaces/ISmartSessions.sol";

/// @title NoSignaturePolicy
/// @notice Smart Sessions ERC-1271 policy (R7): session keys can never produce account signatures, so they
///         cannot sign permits, maker orders, or anything else that settles outside the hook.
/// @dev The plan's optional EIP-4361 login flag is not implemented: Smart Sessions hands 1271 policies only
///      the final hash, so a policy cannot tell a login message from a permit. See docs/decisions.md D13.
contract NoSignaturePolicy is I1271Policy {
    function initializeWithMultiplexer(address account, bytes32 configId, bytes calldata) external override {
        emit PolicySet(configId, msg.sender, account);
    }

    function check1271SignedAction(bytes32, address, address, bytes32, bytes calldata)
        external
        pure
        override
        returns (bool)
    {
        return false;
    }

    function supportsInterface(bytes4 interfaceId) external pure override returns (bool) {
        return interfaceId == type(I1271Policy).interfaceId || interfaceId == type(IPolicy).interfaceId
            || interfaceId == type(IERC165).interfaceId;
    }
}
