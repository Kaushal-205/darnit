// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IActionPolicy, IPolicy, IERC165} from "../interfaces/ISmartSessions.sol";
import {IFirewallModule} from "../interfaces/IFirewallModule.sol";
import {FirewallErrors} from "../interfaces/FirewallErrors.sol";

/// @title FirewallActionPolicy
/// @notice Smart Sessions action policy (R1 for sessions). A session may only call the account's tracked
///         tokens, registered markets and their share tokens, with no native value, while the account is
///         not frozen and its session epoch is unchanged since the session was enabled. Expiry is returned
///         as `validUntil`, so the EntryPoint enforces it and the policy never reads TIMESTAMP.
/// @dev Runs during ERC-4337 validation. Storage is keyed config => multiplexer => account (associated
///      storage); the only external reads are the module's per-account state, also associated storage.
///      The hook remains the enforcement point; this policy is defence in depth and makes session
///      revocation and freeze take effect at validation.
contract FirewallActionPolicy is IActionPolicy {
    uint256 internal constant VALIDATION_FAILED = 1;

    IFirewallModule public immutable MODULE;

    struct Grant {
        uint64 epochPlusOne; // 0 = not initialised
        uint48 validUntil;
    }

    mapping(bytes32 configId => mapping(address multiplexer => mapping(address account => Grant))) internal _grants;

    constructor(IFirewallModule module) {
        MODULE = module;
    }

    /// @param initData abi.encode(uint48 validUntil)
    function initializeWithMultiplexer(address account, bytes32 configId, bytes calldata initData)
        external
        override
    {
        uint48 validUntil = abi.decode(initData, (uint48));
        if (validUntil == 0) revert FirewallErrors.InvalidExpiry();
        _grants[configId][msg.sender][account] =
            Grant({epochPlusOne: MODULE.sessionEpoch(account) + 1, validUntil: validUntil});
        emit PolicySet(configId, msg.sender, account);
    }

    function checkAction(bytes32 id, address account, address target, uint256 value, bytes calldata)
        external
        view
        override
        returns (uint256)
    {
        Grant memory g = _grants[id][msg.sender][account];
        if (g.epochPlusOne == 0 || g.epochPlusOne != MODULE.sessionEpoch(account) + 1) return VALIDATION_FAILED;
        if (value != 0) return VALIDATION_FAILED;

        IFirewallModule.AccountView memory v = MODULE.accountView(account);
        if (v.config.frozen) return VALIDATION_FAILED;
        if (!_contains(v.tokens, target) && !_contains(v.markets, target) && !_contains(v.shareTokens, target)) {
            return VALIDATION_FAILED;
        }
        // ERC-4337 validation data: sigFailed = 0, validUntil in bits 160..207, validAfter = 0
        return uint256(g.validUntil) << 160;
    }

    function grant(bytes32 configId, address multiplexer, address account) external view returns (Grant memory) {
        return _grants[configId][multiplexer][account];
    }

    function supportsInterface(bytes4 interfaceId) external pure override returns (bool) {
        return interfaceId == type(IActionPolicy).interfaceId || interfaceId == type(IPolicy).interfaceId
            || interfaceId == type(IERC165).interfaceId;
    }

    function _contains(address[] memory list, address a) internal pure returns (bool) {
        for (uint256 i; i < list.length; ++i) {
            if (list[i] == a) return true;
        }
        return false;
    }
}
