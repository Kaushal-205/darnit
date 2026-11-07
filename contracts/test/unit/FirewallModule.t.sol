// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Base} from "../Base.t.sol";
import {FirewallErrors} from "../../src/interfaces/FirewallErrors.sol";
import {IFirewallModule} from "../../src/interfaces/IFirewallModule.sol";
import {ReferenceMarketAdapter} from "../../src/adapters/ReferenceMarketAdapter.sol";
import {ReferenceMarket} from "../fixtures/ReferenceMarket.sol";
import {Execution, MODULE_TYPE_EXECUTOR, MODULE_TYPE_HOOK} from "../../src/interfaces/IERC7579.sol";

/// @notice R4 state, R6 and R8 on FirewallModule.
contract FirewallModuleTest is Base {
    // ---------------------------------------------------------------- install

    function test_install_setsConfig() public view {
        IFirewallModule.AccountView memory v = module.accountView(address(account));
        assertEq(v.config.hourlyCap, CAP);
        assertEq(v.config.delay, 24 hours);
        assertFalse(v.config.frozen);
        assertEq(v.tokens[0], address(usdc));
        assertEq(v.destinations[0], dest);
        assertEq(v.markets[0], address(market));
        assertEq(v.adapters[0], address(adapter));
        assertEq(v.shareTokens[0], address(shares));
        assertEq(module.availableBudget(address(account)), CAP);
        assertTrue(module.isDestination(address(account), dest));
        assertEq(module.marketAdapter(address(account), address(market)), address(adapter));
    }

    function test_install_twiceReverts() public {
        module.onInstall(
            abi.encode(CAP, new address[](0), new address[](0), new address[](0), new address[](0))
        );
        vm.expectRevert(abi.encodeWithSelector(FirewallErrors.AlreadyInitialized.selector, address(this)));
        module.onInstall(
            abi.encode(CAP, new address[](0), new address[](0), new address[](0), new address[](0))
        );
    }

    function test_install_rejectsOverlap() public {
        address[] memory tokens = new address[](1);
        tokens[0] = address(usdc);
        address[] memory dests = new address[](1);
        dests[0] = address(usdc); // a token cannot also be a destination
        vm.expectRevert(abi.encodeWithSelector(FirewallErrors.InvalidEntry.selector, address(usdc)));
        module.onInstall(abi.encode(CAP, tokens, dests, new address[](0), new address[](0)));
    }

    function test_install_rejectsSelfAsDestination() public {
        address[] memory dests = new address[](1);
        dests[0] = address(this);
        vm.expectRevert(abi.encodeWithSelector(FirewallErrors.InvalidEntry.selector, address(this)));
        module.onInstall(abi.encode(CAP, new address[](0), dests, new address[](0), new address[](0)));
    }

    function test_install_boundsDestinations() public {
        address[] memory dests = new address[](9);
        for (uint256 i; i < 9; ++i) {
            dests[i] = address(uint160(0x1000 + i));
        }
        vm.expectRevert(FirewallErrors.TooMany.selector);
        module.onInstall(abi.encode(CAP, new address[](0), dests, new address[](0), new address[](0)));
    }

    function test_install_rejectsAdapterForOtherMarket() public {
        ReferenceMarket other = new ReferenceMarket(usdc, address(this));
        address[] memory markets = new address[](1);
        markets[0] = address(market);
        address[] memory adapters = new address[](1);
        adapters[0] = address(new ReferenceMarketAdapter(other));
        vm.expectRevert(abi.encodeWithSelector(FirewallErrors.InvalidEntry.selector, adapters[0]));
        module.onInstall(abi.encode(CAP, new address[](0), new address[](0), markets, adapters));
    }

    // ---------------------------------------------------------------- R6 queue

    function test_R6_addDestinationAfterDelay() public {
        address newDest = makeAddr("newDest");
        bytes32 id = _queue(IFirewallModule.ChangeKind.AddDestination, abi.encode(newDest));
        IFirewallModule.Change memory c = module.pendingChange(address(account), id);
        assertEq(c.eta, block.timestamp + 24 hours);

        vm.warp(block.timestamp + 24 hours);
        _moduleCall(abi.encodeCall(module.execute, (id)));
        assertTrue(module.isDestination(address(account), newDest));
        assertEq(module.pendingChange(address(account), id).eta, 0);
    }

    function test_R6_tooEarly() public {
        bytes32 id = _queue(IFirewallModule.ChangeKind.AddDestination, abi.encode(makeAddr("x")));
        vm.expectRevert(abi.encodeWithSelector(FirewallErrors.TooEarly.selector, block.timestamp + 24 hours));
        _moduleCall(abi.encodeCall(module.execute, (id)));
    }

    function test_R6_cancel() public {
        bytes32 id = _queue(IFirewallModule.ChangeKind.AddDestination, abi.encode(makeAddr("x")));
        _moduleCall(abi.encodeCall(module.cancel, (id)));
        vm.warp(block.timestamp + 24 hours);
        vm.expectRevert(abi.encodeWithSelector(FirewallErrors.UnknownChange.selector, id));
        _moduleCall(abi.encodeCall(module.execute, (id)));
    }

    function test_R6_executeOnce() public {
        bytes32 id = _queue(IFirewallModule.ChangeKind.AddToken, abi.encode(makeAddr("token2")));
        vm.warp(block.timestamp + 24 hours);
        _moduleCall(abi.encodeCall(module.execute, (id)));
        vm.expectRevert(abi.encodeWithSelector(FirewallErrors.UnknownChange.selector, id));
        _moduleCall(abi.encodeCall(module.execute, (id)));
    }

    function test_R6_raiseCapQueued() public {
        bytes32 id = _queue(IFirewallModule.ChangeKind.RaiseCap, abi.encode(uint128(2 * CAP)));
        assertEq(module.config(address(account)).hourlyCap, CAP);
        vm.warp(block.timestamp + 24 hours);
        _moduleCall(abi.encodeCall(module.execute, (id)));
        assertEq(module.config(address(account)).hourlyCap, 2 * CAP);
    }

    function test_R6_raiseCapMustRaise() public {
        vm.expectRevert(FirewallErrors.NotLoosening.selector);
        _moduleCall(abi.encodeCall(module.queue, (IFirewallModule.ChangeKind.RaiseCap, abi.encode(CAP))));
    }

    function test_R6_addMarketQueued() public {
        ReferenceMarket m2 = new ReferenceMarket(usdc, address(this));
        ReferenceMarketAdapter a2 = new ReferenceMarketAdapter(m2);
        bytes32 id = _queue(IFirewallModule.ChangeKind.AddMarket, abi.encode(address(m2), address(a2)));
        assertEq(module.marketAdapter(address(account), address(m2)), address(0));
        vm.warp(block.timestamp + 24 hours);
        _moduleCall(abi.encodeCall(module.execute, (id)));
        assertEq(module.marketAdapter(address(account), address(m2)), address(a2));
    }

    function test_R6_configCallUninstallsHookAfterDelay() public {
        bytes memory call_ = abi.encodeCall(account.uninstallModule, (MODULE_TYPE_HOOK, address(hook), ""));
        bytes32 id =
            _queue(IFirewallModule.ChangeKind.ConfigCall, abi.encode(address(account), uint256(0), call_));
        vm.warp(block.timestamp + 24 hours);
        _moduleCall(abi.encodeCall(module.execute, (id)));
        assertEq(address(account.hook()), address(0));
        assertFalse(hook.isInitialized(address(account)));
    }

    function test_R6_configCallInstallsExecutorAfterDelay() public {
        address exec = address(new MockModule());
        bytes memory call_ = abi.encodeCall(account.installModule, (MODULE_TYPE_EXECUTOR, exec, ""));
        bytes32 id =
            _queue(IFirewallModule.ChangeKind.ConfigCall, abi.encode(address(account), uint256(0), call_));
        vm.warp(block.timestamp + 24 hours);
        _moduleCall(abi.encodeCall(module.execute, (id)));
        assertTrue(account.isExecutor(exec));
    }

    function test_R6_executeMustBeAlone() public {
        bytes32 id = _queue(IFirewallModule.ChangeKind.AddDestination, abi.encode(makeAddr("x")));
        vm.warp(block.timestamp + 24 hours);
        bytes memory batch = abi.encode(
            _two(
                address(module),
                abi.encodeCall(module.execute, (id)),
                address(usdc),
                abi.encodeCall(usdc.transfer, (dest, 1e6))
            )
        );
        vm.expectRevert(FirewallErrors.ForbiddenExecution.selector);
        vm.prank(entryPoint);
        account.execute(MODE_BATCH, batch);
    }

    function test_R6_queueOnlyByInitializedAccount() public {
        vm.expectRevert(abi.encodeWithSelector(FirewallErrors.NotInitialized.selector, attacker));
        vm.prank(attacker);
        module.queue(IFirewallModule.ChangeKind.AddDestination, abi.encode(attacker));
    }

    // ---------------------------------------------------------------- tightening is instant

    function test_tighten_removeDestination() public {
        _moduleCall(abi.encodeCall(module.removeDestination, (dest)));
        assertFalse(module.isDestination(address(account), dest));
    }

    function test_tighten_removeMarket() public {
        _moduleCall(abi.encodeCall(module.removeMarket, (address(market))));
        assertEq(module.marketAdapter(address(account), address(market)), address(0));
    }

    function test_tighten_lowerCap() public {
        _moduleCall(abi.encodeCall(module.lowerCap, (uint128(100e6))));
        assertEq(module.config(address(account)).hourlyCap, 100e6);
        assertEq(module.availableBudget(address(account)), 100e6);
    }

    function test_tighten_lowerCapCannotRaise() public {
        vm.expectRevert(FirewallErrors.NotTightening.selector);
        _moduleCall(abi.encodeCall(module.lowerCap, (CAP + 1)));
    }

    function test_tighten_revokeSessions() public {
        uint64 e = module.sessionEpoch(address(account));
        _moduleCall(abi.encodeCall(module.revokeSessions, ()));
        assertEq(module.sessionEpoch(address(account)), e + 1);
    }

    // ---------------------------------------------------------------- R8

    function test_R8_freeze() public {
        uint64 e = module.sessionEpoch(address(account));
        _moduleCall(abi.encodeCall(module.freeze, ()));
        IFirewallModule.Config memory c = module.config(address(account));
        assertTrue(c.frozen);
        assertEq(c.hourlyCap, 0);
        assertEq(module.availableBudget(address(account)), 0);
        assertEq(module.sessionEpoch(address(account)), e + 1);
    }

    function test_R8_unfreezeIsQueued() public {
        _moduleCall(abi.encodeCall(module.freeze, ()));
        bytes32 id = _queue(IFirewallModule.ChangeKind.Unfreeze, "");
        assertTrue(module.config(address(account)).frozen);
        vm.warp(block.timestamp + 24 hours);
        _moduleCall(abi.encodeCall(module.execute, (id)));
        assertFalse(module.config(address(account)).frozen);
    }

    // ---------------------------------------------------------------- R4 access

    function test_R4_consumeOnlyHook() public {
        vm.expectRevert(FirewallErrors.OnlyHook.selector);
        module.consume(address(account), 1);
    }

    // ---------------------------------------------------------------- helpers

    function _two(address t0, bytes memory d0, address t1, bytes memory d1)
        internal
        pure
        returns (Execution[] memory e)
    {
        e = new Execution[](2);
        e[0] = Execution(t0, 0, d0);
        e[1] = Execution(t1, 0, d1);
    }
}

contract MockModule {
    function onInstall(bytes calldata) external {}
    function onUninstall(bytes calldata) external {}
}
