// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console2} from "forge-std/Script.sol";
import {SMART_SESSION_DEPLOYED_BYTECODE} from "modulekit/deployment/precompiles/SmartSessionsPrecompiles.sol";

/// @title DeploySmartSessions (LOCAL ONLY)
/// @notice Deploys the Smart Sessions build bundled with ModuleKit 0.5.9, whose `Session` ABI matches
///         src/interfaces/ISmartSessions.sol (`allowedERC7739Content` is `string[]`, no paymaster flag).
///         The canonical Smart Sessions on Ethereum Sepolia uses a newer ABI (see docs/decisions.md V13), so
///         `local` (Anvil fork) uses this build until the contracts are moved to the deployed ABI.
/// @dev The runtime is ~24.4 KB, above the EIP-170 limit: start Anvil with `--disable-code-size-limit`.
///      This cannot be deployed to a public chain; the script refuses unless ALLOW_OVERSIZE=true.
///      Output: deployments/<chainId>.smartsessions.json
contract DeploySmartSessions is Script {
    bytes32 internal constant SALT = keccak256("session-firewall.smart-sessions.modulekit-0.5.9");

    function run() external returns (address smartSessions) {
        require(block.chainid == 31337, "local Anvil only: chain id must be 31337");
        require(vm.envOr("ALLOW_OVERSIZE", false), "local only: set ALLOW_OVERSIZE=true on an Anvil node");
        bytes memory runtime = SMART_SESSION_DEPLOYED_BYTECODE;
        // init code: CODECOPY the runtime that follows this 12-byte prefix and RETURN it
        bytes memory initCode =
            abi.encodePacked(hex"61", uint16(runtime.length), hex"80600c6000396000f3", runtime);
        smartSessions = vm.computeCreate2Address(SALT, keccak256(initCode));
        if (smartSessions.code.length == 0) {
            vm.broadcast();
            (bool ok,) = CREATE2_FACTORY.call(abi.encodePacked(SALT, initCode));
            require(ok && smartSessions.code.length == runtime.length, "Smart Sessions deployment failed");
            console2.log("deployed Smart Sessions (ModuleKit 0.5.9 build)", smartSessions);
        } else {
            console2.log("exists Smart Sessions", smartSessions);
        }
        string memory json = vm.serializeAddress("ss", "smartSessions", smartSessions);
        vm.writeJson(
            json, string.concat(vm.projectRoot(), "/deployments/", vm.toString(block.chainid), ".smartsessions.json")
        );
    }
}
