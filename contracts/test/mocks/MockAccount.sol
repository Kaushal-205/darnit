// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {
    IHook,
    IModule,
    Execution,
    MODULE_TYPE_EXECUTOR,
    MODULE_TYPE_HOOK,
    CALLTYPE_SINGLE,
    CALLTYPE_BATCH,
    CALLTYPE_DELEGATECALL,
    EXECTYPE_TRY,
    PackedUserOperation
} from "../../src/interfaces/IERC7579.sol";

/// @notice Minimal ERC-7579 account for unit tests. Mirrors Safe7579's shape: one global hook wrapping
///         execute, executeFromExecutor, installModule and uninstallModule. It deliberately supports
///         delegatecall so tests prove the hook (not the account) rejects it. M0 adds the same suites
///         against real Safe7579 via ModuleKit.
contract MockAccount {
    address public immutable entryPoint;
    IHook public hook;
    mapping(address => bool) public isExecutor;

    error Unauthorized();
    error ExecutionFailed(uint256 index, bytes reason);

    constructor(address entryPoint_) {
        entryPoint = entryPoint_;
    }

    modifier onlyEntryPointOrSelf() {
        if (msg.sender != entryPoint && msg.sender != address(this)) revert Unauthorized();
        _;
    }

    modifier withHook() {
        IHook h = hook;
        if (address(h) == address(0)) {
            _;
        } else {
            bytes memory hookData = h.preCheck(msg.sender, msg.value, msg.data);
            _;
            h.postCheck(hookData);
        }
    }

    function execute(bytes32 mode, bytes calldata executionCalldata)
        external
        payable
        onlyEntryPointOrSelf
        withHook
    {
        _execute(mode, executionCalldata);
    }

    function executeFromExecutor(bytes32 mode, bytes calldata executionCalldata)
        external
        payable
        withHook
        returns (bytes[] memory)
    {
        if (!isExecutor[msg.sender]) revert Unauthorized();
        return _execute(mode, executionCalldata);
    }

    function executeUserOp(PackedUserOperation calldata userOp, bytes32)
        external
        payable
        onlyEntryPointOrSelf
        withHook
    {
        (bool ok, bytes memory ret) = address(this).call(userOp.callData[4:]);
        if (!ok) revert ExecutionFailed(0, ret);
    }

    function installModule(uint256 moduleTypeId, address module, bytes calldata initData)
        external
        payable
        onlyEntryPointOrSelf
        withHook
    {
        if (moduleTypeId == MODULE_TYPE_EXECUTOR) isExecutor[module] = true;
        else if (moduleTypeId == MODULE_TYPE_HOOK) hook = IHook(module);
        IModule(module).onInstall(initData);
    }

    function uninstallModule(uint256 moduleTypeId, address module, bytes calldata deInitData)
        external
        payable
        onlyEntryPointOrSelf
        withHook
    {
        if (moduleTypeId == MODULE_TYPE_EXECUTOR) isExecutor[module] = false;
        else if (moduleTypeId == MODULE_TYPE_HOOK && address(hook) == module) hook = IHook(address(0));
        IModule(module).onUninstall(deInitData);
    }

    function _execute(bytes32 mode, bytes calldata ec) internal returns (bytes[] memory ret) {
        bytes1 callType = mode[0];
        bool tryMode = mode[1] == EXECTYPE_TRY;
        if (callType == CALLTYPE_SINGLE) {
            ret = new bytes[](1);
            ret[0] = _call(0, address(bytes20(ec[0:20])), uint256(bytes32(ec[20:52])), ec[52:], tryMode);
        } else if (callType == CALLTYPE_BATCH) {
            Execution[] memory execs = abi.decode(ec, (Execution[]));
            ret = new bytes[](execs.length);
            for (uint256 i; i < execs.length; ++i) {
                ret[i] = _call(i, execs[i].target, execs[i].value, execs[i].callData, tryMode);
            }
        } else if (callType == CALLTYPE_DELEGATECALL) {
            ret = new bytes[](1);
            (bool ok, bytes memory r) = address(bytes20(ec[0:20])).delegatecall(ec[20:]);
            if (!ok && !tryMode) revert ExecutionFailed(0, r);
            ret[0] = r;
        } else {
            revert Unauthorized();
        }
    }

    function _call(uint256 i, address target, uint256 value, bytes memory data, bool tryMode)
        internal
        returns (bytes memory)
    {
        (bool ok, bytes memory r) = target.call{value: value}(data);
        if (!ok && !tryMode) {
            // bubble the inner revert unchanged so tests can match firewall errors from nested calls
            assembly ("memory-safe") {
                revert(add(r, 32), mload(r))
            }
        }
        i;
        return r;
    }

    function onERC1155Received(address, address, uint256, uint256, bytes calldata)
        external
        pure
        returns (bytes4)
    {
        return this.onERC1155Received.selector;
    }

    function onERC1155BatchReceived(address, address, uint256[] calldata, uint256[] calldata, bytes calldata)
        external
        pure
        returns (bytes4)
    {
        return this.onERC1155BatchReceived.selector;
    }

    receive() external payable {}
}
