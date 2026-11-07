// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console2} from "forge-std/Script.sol";
import {FirewallModule} from "../src/FirewallModule.sol";
import {FirewallHook} from "../src/FirewallHook.sol";
import {FirewallActionPolicy} from "../src/policies/FirewallActionPolicy.sol";
import {NoSignaturePolicy} from "../src/policies/NoSignaturePolicy.sol";
import {ISmartSessions} from "../src/interfaces/ISmartSessions.sol";
import {FirewallDeployer} from "./FirewallDeployer.sol";
import {NoSafeOwner} from "./NoSafeOwner.sol";

/// @title Deploy
/// @notice Deterministic deployment of the firewall (docs/decisions.md D5):
///         - NoSignaturePolicy and NoSafeOwner via the standard CREATE2 factory;
///         - FirewallDeployer via CREATE2, which builds FirewallHook, FirewallActionPolicy and FirewallModule
///           with CREATE against the predicted module address.
///         Same Smart Sessions address + same salt = same addresses on every chain. Re-running is a no-op.
///
///   SMART_SESSIONS=0x... forge script script/Deploy.s.sol --rpc-url $RPC --broadcast --private-key $KEY
///
/// Env: SMART_SESSIONS (required), DEPLOY_SALT (optional bytes32).
/// Output: deployments/<chainId>.json
contract Deploy is Script {
    bytes32 internal constant DEFAULT_SALT = keccak256("session-firewall.v1");

    struct Deployment {
        address smartSessions;
        address signaturePolicy;
        address noSafeOwner;
        address deployer;
        address hook;
        address actionPolicy;
        address module;
    }

    function run() external returns (Deployment memory d) {
        d.smartSessions = vm.envAddress("SMART_SESSIONS");
        bytes32 salt = vm.envOr("DEPLOY_SALT", DEFAULT_SALT);
        checkSmartSessionsAbi(d.smartSessions);

        vm.startBroadcast();
        d.signaturePolicy = _create2(salt, type(NoSignaturePolicy).creationCode);
        d.noSafeOwner = _create2(salt, type(NoSafeOwner).creationCode);
        d.deployer = _create2(
            salt,
            abi.encodePacked(
                type(FirewallDeployer).creationCode, abi.encode(ISmartSessions(d.smartSessions), d.signaturePolicy)
            )
        );
        vm.stopBroadcast();

        FirewallDeployer fd = FirewallDeployer(d.deployer);
        d.hook = address(fd.hook());
        d.actionPolicy = address(fd.actionPolicy());
        d.module = address(fd.module());

        // wiring sanity: every immutable points where it should
        require(address(FirewallHook(d.hook).MODULE()) == d.module, "hook.MODULE");
        require(address(FirewallActionPolicy(d.actionPolicy).MODULE()) == d.module, "actionPolicy.MODULE");
        FirewallModule m = FirewallModule(d.module);
        require(m.HOOK() == d.hook, "module.HOOK");
        require(address(m.SMART_SESSIONS()) == d.smartSessions, "module.SMART_SESSIONS");
        require(m.ACTION_POLICY() == d.actionPolicy, "module.ACTION_POLICY");
        require(m.SIGNATURE_POLICY() == d.signaturePolicy, "module.SIGNATURE_POLICY");

        _write(d, salt);
    }

    /// @notice V13: FirewallModule ABI-encodes the Smart Sessions `Session` itself, so the target Smart Sessions
    ///         must expose `enableSessions` with exactly the struct layout in src/interfaces/ISmartSessions.sol.
    ///         The selector encodes the full tuple type, so its presence in the dispatcher is a sound check.
    function checkSmartSessionsAbi(address smartSessions) public view {
        bytes memory code = smartSessions.code;
        require(code.length > 0, "SMART_SESSIONS has no code");
        bytes4 sel = ISmartSessions.enableSessions.selector;
        for (uint256 i; i + 4 < code.length; ++i) {
            if (
                code[i] == 0x63 && code[i + 1] == sel[0] && code[i + 2] == sel[1] && code[i + 3] == sel[2]
                    && code[i + 4] == sel[3]
            ) return;
        }
        revert("SMART_SESSIONS: enableSessions ABI differs from ISmartSessions.sol (docs/decisions.md V13)");
    }

    function _create2(bytes32 salt, bytes memory initCode) internal returns (address addr) {
        addr = vm.computeCreate2Address(salt, keccak256(initCode));
        if (addr.code.length > 0) {
            console2.log("exists  ", addr);
            return addr;
        }
        (bool ok,) = CREATE2_FACTORY.call(abi.encodePacked(salt, initCode));
        require(ok && addr.code.length > 0, "CREATE2 deployment failed");
        console2.log("deployed", addr);
    }

    function _write(Deployment memory d, bytes32 salt) internal {
        string memory k = "firewall";
        vm.serializeUint(k, "chainId", block.chainid);
        vm.serializeBytes32(k, "salt", salt);
        vm.serializeAddress(k, "smartSessions", d.smartSessions);
        vm.serializeAddress(k, "signaturePolicy", d.signaturePolicy);
        vm.serializeAddress(k, "noSafeOwner", d.noSafeOwner);
        vm.serializeAddress(k, "firewallDeployer", d.deployer);
        vm.serializeAddress(k, "hook", d.hook);
        vm.serializeAddress(k, "actionPolicy", d.actionPolicy);
        string memory json = vm.serializeAddress(k, "module", d.module);
        string memory path = string.concat(vm.projectRoot(), "/deployments/", vm.toString(block.chainid), ".json");
        vm.writeJson(json, path);
        console2.log("wrote", path);
    }
}
