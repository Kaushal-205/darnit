// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {FirewallModule} from "../src/FirewallModule.sol";
import {FirewallHook} from "../src/FirewallHook.sol";
import {FirewallActionPolicy} from "../src/policies/FirewallActionPolicy.sol";
import {IFirewallModule} from "../src/interfaces/IFirewallModule.sol";
import {ISmartSessions} from "../src/interfaces/ISmartSessions.sol";

/// @title FirewallDeployer
/// @notice One-shot deployer for the three mutually dependent firewall contracts (docs/decisions.md D5).
///         The hook and the action policy hold the module address immutably and the module holds theirs,
///         so pure CREATE2 is circular. Instead this contract is deployed with CREATE2 (deterministic
///         address from its init code, i.e. from the Smart Sessions and signature policy addresses) and
///         deploys the three with CREATE from its own fresh nonce, so their addresses are deterministic
///         too and the module address can be predicted before the hook and policy are built.
/// @dev No functions, no owner: after the constructor it is inert.
contract FirewallDeployer {
    FirewallHook public immutable hook;
    FirewallActionPolicy public immutable actionPolicy;
    FirewallModule public immutable module;

    error PredictionMismatch();

    constructor(ISmartSessions smartSessions, address signaturePolicy) {
        // a contract's nonce starts at 1 (EIP-161): hook = 1, action policy = 2, module = 3
        address predicted = createAddress(address(this), 3);
        FirewallHook h = new FirewallHook(IFirewallModule(predicted));
        FirewallActionPolicy p = new FirewallActionPolicy(IFirewallModule(predicted));
        FirewallModule m = new FirewallModule(address(h), smartSessions, address(p), signaturePolicy);
        if (address(m) != predicted) revert PredictionMismatch();
        (hook, actionPolicy, module) = (h, p, m);
    }

    /// @notice CREATE address of `deployer` at `nonce` (nonce < 0x80).
    function createAddress(address deployer, uint8 nonce) public pure returns (address) {
        return address(uint160(uint256(keccak256(abi.encodePacked(bytes2(0xd694), deployer, bytes1(nonce))))));
    }
}
