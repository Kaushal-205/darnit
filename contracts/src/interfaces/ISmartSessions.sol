// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Minimal, ABI-compatible view of Smart Sessions as bundled in ModuleKit 0.5.9
///         (`allowedERC7739Content` is `string[]`; newer releases use a struct, see docs/decisions.md V13).
struct SSPolicyData {
    address policy;
    bytes initData;
}

struct SSActionData {
    bytes4 actionTargetSelector;
    address actionTarget;
    SSPolicyData[] actionPolicies;
}

struct SSERC7739Data {
    string[] allowedERC7739Content;
    SSPolicyData[] erc1271Policies;
}

struct SSSession {
    address sessionValidator;
    bytes sessionValidatorInitData;
    bytes32 salt;
    SSPolicyData[] userOpPolicies;
    SSERC7739Data erc7739Policies;
    SSActionData[] actions;
}

// Smart Sessions fallback action: applies to every target/selector not configured explicitly,
// except calls into Smart Sessions itself.
address constant SS_FALLBACK_TARGET = address(1);
bytes4 constant SS_FALLBACK_SELECTOR = 0x00000001;

interface ISmartSessions {
    function enableSessions(SSSession[] calldata sessions) external returns (bytes32[] memory permissionIds);
    function removeSession(bytes32 permissionId) external;
    function isPermissionEnabled(bytes32 permissionId, address account) external view returns (bool);
}

interface IERC165 {
    function supportsInterface(bytes4 interfaceId) external view returns (bool);
}

interface IPolicy is IERC165 {
    event PolicySet(bytes32 id, address multiplexer, address account);

    function initializeWithMultiplexer(address account, bytes32 configId, bytes calldata initData) external;
}

interface IActionPolicy is IPolicy {
    function checkAction(bytes32 id, address account, address target, uint256 value, bytes calldata data)
        external
        returns (uint256);
}

interface I1271Policy is IPolicy {
    function check1271SignedAction(
        bytes32 id,
        address requestSender,
        address account,
        bytes32 hash,
        bytes calldata signature
    ) external view returns (bool);
}
