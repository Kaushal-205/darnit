// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Every custom error the firewall can raise. The SDK and web app map each to a plain sentence.
interface FirewallErrors {
    // R1
    error UnknownTarget(address target, bytes4 selector);
    error ForbiddenExecution();
    // R2
    error UnregisteredSpender(address spender);
    // R3
    error UnexplainedOutflow(address asset, uint256 id);
    // R4
    error BudgetExceeded(uint256 requested, uint256 available);
    // R6
    error TooEarly(uint256 eta);
    error UnknownChange(bytes32 id);
    error NotLoosening();
    error NotTightening();
    // R8
    error Frozen();
    // module housekeeping
    error NotInitialized(address account);
    error AlreadyInitialized(address account);
    error OnlyHook();
    error TooMany();
    error InvalidEntry(address entry);
    error ZeroAddress();
}
