// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Base} from "../Base.t.sol";
import {FirewallErrors} from "../../src/interfaces/FirewallErrors.sol";
import {FirewallActionPolicy} from "../../src/policies/FirewallActionPolicy.sol";
import {
    SSSession, SS_FALLBACK_TARGET, SS_FALLBACK_SELECTOR, IActionPolicy, I1271Policy, IPolicy
} from "../../src/interfaces/ISmartSessions.sol";

/// @notice FirewallActionPolicy (R1 for sessions), NoSignaturePolicy (R7), module-built sessions.
contract PoliciesTest is Base {
    address internal sessionValidator = makeAddr("sessionValidator");
    uint48 internal validUntil;
    bytes32 internal permissionId;
    bytes32 internal configId;

    function setUp() public override {
        super.setUp();
        validUntil = uint48(block.timestamp + 7 days);
        _moduleCall(abi.encodeCall(module.createSession, (sessionValidator, "k", bytes32("s1"), validUntil)));
        permissionId = keccak256(abi.encode(sessionValidator, bytes("k"), bytes32("s1")));
        configId = smartSessions.configId(permissionId, 0);
    }

    function _check(address target, uint256 value) internal returns (uint256) {
        vm.prank(address(smartSessions));
        return actionPolicy.checkAction(configId, address(account), target, value, "");
    }

    // ---------------------------------------------------------------- session construction

    function test_session_builtByModule() public view {
        SSSession memory s = smartSessions.last();
        assertEq(s.sessionValidator, sessionValidator);
        assertEq(s.userOpPolicies.length, 0);
        assertEq(s.actions.length, 1);
        assertEq(s.actions[0].actionTarget, SS_FALLBACK_TARGET);
        assertEq(bytes32(s.actions[0].actionTargetSelector), bytes32(SS_FALLBACK_SELECTOR));
        assertEq(s.actions[0].actionPolicies.length, 1);
        assertEq(s.actions[0].actionPolicies[0].policy, address(actionPolicy));
        assertEq(s.erc7739Policies.allowedERC7739Content.length, 0);
        assertEq(s.erc7739Policies.erc1271Policies.length, 1);
        assertEq(s.erc7739Policies.erc1271Policies[0].policy, address(signaturePolicy));
        assertTrue(smartSessions.isPermissionEnabled(permissionId, address(account)));
    }

    function test_session_expiryBounds() public {
        vm.expectRevert(FirewallErrors.InvalidExpiry.selector);
        _moduleCall(abi.encodeCall(module.createSession, (sessionValidator, "k", bytes32("s2"), uint48(block.timestamp))));
        vm.expectRevert(FirewallErrors.InvalidExpiry.selector);
        _moduleCall(
            abi.encodeCall(module.createSession, (sessionValidator, "k", bytes32("s2"), uint48(block.timestamp + 31 days)))
        );
    }

    function test_session_notWhileFrozen() public {
        _moduleCall(abi.encodeCall(module.freeze, ()));
        vm.expectRevert(FirewallErrors.Frozen.selector);
        _moduleCall(abi.encodeCall(module.createSession, (sessionValidator, "k", bytes32("s2"), validUntil)));
    }

    function test_session_remove() public {
        _moduleCall(abi.encodeCall(module.removeSession, (permissionId)));
        assertFalse(smartSessions.isPermissionEnabled(permissionId, address(account)));
    }

    function test_session_onlyModuleBuiltCallsReachSmartSessions() public {
        // the account calling Smart Sessions directly is an unknown target
        vm.expectRevert(
            abi.encodeWithSelector(FirewallErrors.UnknownTarget.selector, address(smartSessions), smartSessions.removeSession.selector)
        );
        _exec(address(smartSessions), 0, abi.encodeCall(smartSessions.removeSession, (permissionId)));
    }

    // ---------------------------------------------------------------- FirewallActionPolicy

    function test_policy_allowsRegisteredTargetsWithExpiry() public {
        uint256 expected = uint256(validUntil) << 160;
        assertEq(_check(address(market), 0), expected);
        assertEq(_check(address(usdc), 0), expected);
        assertEq(_check(address(shares), 0), expected);
    }

    function test_policy_rejectsOtherTargets() public {
        assertEq(_check(attacker, 0), 1);
        assertEq(_check(dest, 0), 1); // exits are for the owner, not sessions
        assertEq(_check(address(module), 0), 1);
        assertEq(_check(address(account), 0), 1);
        assertEq(_check(address(hook), 0), 1);
    }

    function test_policy_rejectsValue() public {
        assertEq(_check(address(market), 1), 1);
    }

    function test_policy_rejectsAfterRevoke() public {
        _moduleCall(abi.encodeCall(module.revokeSessions, ()));
        assertEq(_check(address(market), 0), 1);
    }

    function test_policy_rejectsWhenFrozen() public {
        _moduleCall(abi.encodeCall(module.freeze, ()));
        assertEq(_check(address(market), 0), 1);
    }

    function test_policy_rejectsUnknownConfigOrMultiplexer() public {
        vm.prank(attacker);
        assertEq(actionPolicy.checkAction(configId, address(account), address(market), 0, ""), 1);
        vm.prank(address(smartSessions));
        assertEq(actionPolicy.checkAction(bytes32("other"), address(account), address(market), 0, ""), 1);
    }

    function test_policy_rejectsZeroExpiryInit() public {
        vm.expectRevert(FirewallErrors.InvalidExpiry.selector);
        actionPolicy.initializeWithMultiplexer(address(account), bytes32("x"), abi.encode(uint48(0)));
    }

    function test_policy_interfaces() public view {
        assertTrue(actionPolicy.supportsInterface(type(IActionPolicy).interfaceId));
        assertTrue(actionPolicy.supportsInterface(type(IPolicy).interfaceId));
        assertFalse(actionPolicy.supportsInterface(type(I1271Policy).interfaceId));
        assertTrue(signaturePolicy.supportsInterface(type(I1271Policy).interfaceId));
    }

    // ---------------------------------------------------------------- NoSignaturePolicy (R7)

    function testFuzz_R7_noSessionSignatures(bytes32 id, address sender, bytes32 hash, bytes calldata sig) public view {
        assertFalse(signaturePolicy.check1271SignedAction(id, sender, address(account), hash, sig));
    }
}
