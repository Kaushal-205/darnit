// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {FirewallModule} from "../../src/FirewallModule.sol";
import {FirewallHook} from "../../src/FirewallHook.sol";
import {FirewallActionPolicy} from "../../src/policies/FirewallActionPolicy.sol";
import {NoSignaturePolicy} from "../../src/policies/NoSignaturePolicy.sol";
import {IFirewallModule} from "../../src/interfaces/IFirewallModule.sol";
import {ISmartSessions} from "../../src/interfaces/ISmartSessions.sol";

/// @notice Deploys the four firewall contracts. The hook and action policy hold the module immutably and
///         the module holds them, so both are deployed against the module's predicted CREATE address.
///         Deploy.s.sol does the same with CREATE2 (docs/decisions.md D5).
abstract contract FirewallDeploy is Test {
    struct Firewall {
        FirewallHook hook;
        FirewallModule module;
        FirewallActionPolicy actionPolicy;
        NoSignaturePolicy signaturePolicy;
    }

    function _deployFirewall(address smartSessions) internal returns (Firewall memory f) {
        address predicted = vm.computeCreateAddress(address(this), vm.getNonce(address(this)) + 3);
        f.signaturePolicy = new NoSignaturePolicy();
        f.hook = new FirewallHook(IFirewallModule(predicted));
        f.actionPolicy = new FirewallActionPolicy(IFirewallModule(predicted));
        f.module = new FirewallModule(
            address(f.hook), ISmartSessions(smartSessions), address(f.actionPolicy), address(f.signaturePolicy)
        );
        assertEq(address(f.module), predicted, "module address prediction");
    }
}
