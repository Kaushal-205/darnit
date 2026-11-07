// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {FirewallErrors} from "./FirewallErrors.sol";

interface IFirewallModule is FirewallErrors {
    struct Config {
        uint128 hourlyCap;
        uint32 delay;
        bool frozen;
    }

    enum ChangeKind {
        AddDestination, // abi.encode(address destination)
        AddMarket, // abi.encode(address market, address adapter)
        AddToken, // abi.encode(address token)
        RaiseCap, // abi.encode(uint128 newCap)
        Unfreeze, // ""
        ConfigCall // abi.encode(address target, uint256 value, bytes callData), run via executeFromExecutor
    }

    struct Change {
        ChangeKind kind;
        uint64 eta;
        bytes data;
    }

    /// @notice Everything the hook needs, in one call.
    struct AccountView {
        Config config;
        address[] tokens;
        address[] destinations;
        address[] markets;
        address[] adapters;
        address[] shareTokens;
    }

    event Installed(address indexed account, uint128 hourlyCap);
    event Uninstalled(address indexed account);
    event ChangeQueued(address indexed account, bytes32 indexed id, ChangeKind kind, bytes data, uint64 eta);
    event ChangeExecuted(address indexed account, bytes32 indexed id);
    event ChangeCancelled(address indexed account, bytes32 indexed id);
    event BudgetConsumed(address indexed account, uint256 amount, uint256 remaining);
    event DestinationRemoved(address indexed account, address destination);
    event MarketRemoved(address indexed account, address market);
    event CapLowered(address indexed account, uint128 newCap);
    event SessionsRevoked(address indexed account, uint64 epoch);
    event FreezeActivated(address indexed account);

    // reads
    function isDestination(address account, address dest) external view returns (bool);
    function marketAdapter(address account, address market) external view returns (address adapter);
    function trackedTokens(address account) external view returns (address[] memory);
    function config(address account) external view returns (Config memory);
    function accountView(address account) external view returns (AccountView memory);
    function sessionEpoch(address account) external view returns (uint64);
    function configCallActive(address account) external view returns (bool);
    function availableBudget(address account) external view returns (uint256);

    // budget
    function consume(address account, uint256 worstCaseOut) external;

    // loosening
    function queue(ChangeKind kind, bytes calldata data) external returns (bytes32 id);
    function execute(bytes32 id) external;
    function cancel(bytes32 id) external;

    // tightening
    function removeDestination(address dest) external;
    function removeMarket(address market) external;
    function lowerCap(uint128 newCap) external;
    function revokeSessions() external;
    function freeze() external;
}
