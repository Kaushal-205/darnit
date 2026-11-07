// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Minimal ERC-7579 types used by the firewall. Align with ModuleKit in M0 (docs/decisions.md).

struct Execution {
    address target;
    uint256 value;
    bytes callData;
}

uint256 constant MODULE_TYPE_VALIDATOR = 1;
uint256 constant MODULE_TYPE_EXECUTOR = 2;
uint256 constant MODULE_TYPE_FALLBACK = 3;
uint256 constant MODULE_TYPE_HOOK = 4;

// ModeCode layout: callType (1) | execType (1) | unused (4) | modeSelector (4) | modePayload (22)
bytes1 constant CALLTYPE_SINGLE = 0x00;
bytes1 constant CALLTYPE_BATCH = 0x01;
bytes1 constant CALLTYPE_STATIC = 0xFE;
bytes1 constant CALLTYPE_DELEGATECALL = 0xFF;
bytes1 constant EXECTYPE_DEFAULT = 0x00;
bytes1 constant EXECTYPE_TRY = 0x01;

interface IERC7579Account {
    function execute(bytes32 mode, bytes calldata executionCalldata) external payable;
    function executeFromExecutor(bytes32 mode, bytes calldata executionCalldata)
        external
        payable
        returns (bytes[] memory returnData);
    function installModule(uint256 moduleTypeId, address module, bytes calldata initData) external payable;
    function uninstallModule(uint256 moduleTypeId, address module, bytes calldata deInitData) external payable;
}

/// @dev ERC-4337 v0.7 packed user operation.
struct PackedUserOperation {
    address sender;
    uint256 nonce;
    bytes initCode;
    bytes callData;
    bytes32 accountGasLimits;
    uint256 preVerificationGas;
    bytes32 gasFees;
    bytes paymasterAndData;
    bytes signature;
}

interface IAccountExecute {
    function executeUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash) external;
}

interface IModule {
    function onInstall(bytes calldata data) external;
    function onUninstall(bytes calldata data) external;
    function isModuleType(uint256 moduleTypeId) external view returns (bool);
    function isInitialized(address smartAccount) external view returns (bool);
}

interface IHook is IModule {
    function preCheck(address msgSender, uint256 msgValue, bytes calldata msgData)
        external
        returns (bytes memory hookData);
    function postCheck(bytes calldata hookData) external;
}
