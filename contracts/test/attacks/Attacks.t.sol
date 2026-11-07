// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Base} from "../Base.t.sol";
import {FirewallErrors} from "../../src/interfaces/FirewallErrors.sol";
import {IFirewallModule} from "../../src/interfaces/IFirewallModule.sol";
import {IReferenceMarket} from "../../src/interfaces/IReferenceMarket.sol";
import {
    Execution,
    MODULE_TYPE_EXECUTOR,
    PackedUserOperation,
    IAccountExecute
} from "../../src/interfaces/IERC7579.sol";

contract Drainer {
    function drain() external {}
}

/// @notice Section 8 of the plan. Each attack must fail with the named error.
///         These run on the owner path; M2 repeats every row from a Smart Sessions session key.
contract AttacksTest is Base {
    // A1 / R3
    function test_A1_transferUsdcToAttacker() public {
        vm.expectRevert(abi.encodeWithSelector(FirewallErrors.UnexplainedOutflow.selector, address(usdc), 0));
        _exec(address(usdc), 0, abi.encodeCall(usdc.transfer, (attacker, 1e6)));
    }

    function test_A1_transferFromToAttacker() public {
        vm.expectRevert(abi.encodeWithSelector(FirewallErrors.UnexplainedOutflow.selector, address(usdc), 0));
        _exec(address(usdc), 0, abi.encodeCall(usdc.transferFrom, (address(account), attacker, 1e6)));
    }

    function test_A1_hiddenInBatchWithTrade() public {
        Execution[] memory execs = new Execution[](2);
        execs[0] = Execution(
            address(market), 0, _fillCall(IReferenceMarket.Side.Sell, yesId, 0.5e6, 10e6, address(account))
        );
        execs[1] = Execution(address(usdc), 0, abi.encodeCall(usdc.transfer, (attacker, 1e6)));
        vm.expectRevert(abi.encodeWithSelector(FirewallErrors.UnexplainedOutflow.selector, address(usdc), 0));
        _execBatch(execs);
    }

    // A2 / R2
    function test_A2_approveAttackerMax() public {
        vm.expectRevert(abi.encodeWithSelector(FirewallErrors.UnregisteredSpender.selector, attacker));
        _exec(address(usdc), 0, abi.encodeCall(usdc.approve, (attacker, type(uint256).max)));
    }

    function test_A2_permitToAttacker() public {
        bytes memory data = abi.encodeCall(
            usdc.permit, (address(account), attacker, 1e6, block.timestamp, uint8(27), bytes32(0), bytes32(0))
        );
        vm.expectRevert(abi.encodeWithSelector(FirewallErrors.UnregisteredSpender.selector, attacker));
        _exec(address(usdc), 0, data);
    }

    // A3 / R2
    function test_A3_setApprovalForAllAttacker() public {
        vm.expectRevert(abi.encodeWithSelector(FirewallErrors.UnregisteredSpender.selector, attacker));
        _exec(address(shares), 0, abi.encodeCall(shares.setApprovalForAll, (attacker, true)));
    }

    // A4 / R1
    function test_A4_callAttackerContract() public {
        Drainer d = new Drainer();
        vm.expectRevert(
            abi.encodeWithSelector(FirewallErrors.UnknownTarget.selector, address(d), Drainer.drain.selector)
        );
        _exec(address(d), 0, abi.encodeCall(Drainer.drain, ()));
    }

    function test_A4_nativeValueToAttacker() public {
        vm.deal(address(account), 1 ether);
        vm.expectRevert(abi.encodeWithSelector(FirewallErrors.UnknownTarget.selector, attacker, bytes4(0)));
        _exec(attacker, 1 ether, "");
    }

    // A5 / R3
    function test_A5_marketProceedsToAttacker() public {
        bytes memory data = _fillCall(IReferenceMarket.Side.Sell, yesId, 0.5e6, 100e6, attacker);
        vm.expectRevert(
            abi.encodeWithSelector(FirewallErrors.UnexplainedOutflow.selector, address(market), 0)
        );
        _exec(address(market), 0, data);
    }

    function test_A5_sellProceedsToAttacker() public {
        _giftShares(yesId, 100e6);
        bytes memory data = _fillCall(IReferenceMarket.Side.Buy, yesId, 0.5e6, 100e6, attacker);
        vm.expectRevert(
            abi.encodeWithSelector(FirewallErrors.UnexplainedOutflow.selector, address(market), 0)
        );
        _exec(address(market), 0, data);
    }

    // A6 / R4
    function test_A6_dumpSharesBeyondBudget() public {
        _giftShares(yesId, 2_000e6);
        // 2,000 shares at $0.01: worst case = 2,000 - 20 = $1,980 > $1,000 cap
        bytes memory data = _fillCall(IReferenceMarket.Side.Buy, yesId, 0.01e6, 2_000e6, address(account));
        vm.expectRevert(abi.encodeWithSelector(FirewallErrors.BudgetExceeded.selector, 1_980e6, uint256(CAP)));
        _exec(address(market), 0, data);
    }

    // A7 / R4
    function test_A7_buyPastHourlyCap() public {
        for (uint256 i; i < 5; ++i) {
            _buy(yesId, 0.5e6, 400e6); // $200 each
        }
        assertEq(module.availableBudget(address(account)), 0);
        bytes memory data = _fillCall(IReferenceMarket.Side.Sell, yesId, 0.5e6, 400e6, address(account));
        vm.expectRevert(abi.encodeWithSelector(FirewallErrors.BudgetExceeded.selector, 200e6, 0));
        _exec(address(market), 0, data);
    }

    // A8 / R1
    function test_A8_delegatecallMode() public {
        Drainer d = new Drainer();
        vm.expectRevert(FirewallErrors.ForbiddenExecution.selector);
        vm.prank(entryPoint);
        account.execute(MODE_DELEGATECALL, abi.encodePacked(address(d), abi.encodeCall(Drainer.drain, ())));
    }

    function test_A8_staticcallMode() public {
        vm.expectRevert(FirewallErrors.ForbiddenExecution.selector);
        vm.prank(entryPoint);
        account.execute(bytes32(bytes1(0xFE)), abi.encodePacked(address(usdc), uint256(0), ""));
    }

    // A9 / R1, R6
    function test_A9_selfCallInstallModule() public {
        bytes memory data = abi.encodeCall(account.installModule, (MODULE_TYPE_EXECUTOR, attacker, ""));
        vm.expectRevert(FirewallErrors.ForbiddenExecution.selector);
        _exec(address(account), 0, data);
    }

    function test_A9_directInstallModule() public {
        vm.expectRevert(FirewallErrors.ForbiddenExecution.selector);
        vm.prank(entryPoint);
        account.installModule(MODULE_TYPE_EXECUTOR, attacker, "");
    }

    function test_A9_directUninstallHook() public {
        vm.expectRevert(FirewallErrors.ForbiddenExecution.selector);
        vm.prank(entryPoint);
        account.uninstallModule(4, address(hook), "");
    }

    function test_A9_executeUserOpWrapper() public {
        PackedUserOperation memory op;
        op.sender = address(account);
        op.callData = abi.encodeCall(
            account.execute,
            (
                MODE_SINGLE,
                abi.encodePacked(address(usdc), uint256(0), abi.encodeCall(usdc.transfer, (attacker, 1e6)))
            )
        );
        op.callData = bytes.concat(IAccountExecute.executeUserOp.selector, op.callData);
        vm.expectRevert(FirewallErrors.ForbiddenExecution.selector);
        vm.prank(entryPoint);
        account.executeUserOp(op, bytes32(0));
    }

    // A10 / R6
    function test_A10_executeQueuedDestinationEarly() public {
        bytes32 id = _queue(IFirewallModule.ChangeKind.AddDestination, abi.encode(attacker));
        vm.warp(block.timestamp + 24 hours - 1);
        vm.expectRevert(abi.encodeWithSelector(FirewallErrors.TooEarly.selector, uint64(block.timestamp + 1)));
        _moduleCall(abi.encodeCall(module.execute, (id)));
        assertFalse(module.isDestination(address(account), attacker));
    }

    // A12 / R8
    function test_A12_tradeAfterFreeze() public {
        _moduleCall(abi.encodeCall(module.freeze, ()));
        bytes memory data = _fillCall(IReferenceMarket.Side.Sell, yesId, 0.5e6, 10e6, address(account));
        vm.expectRevert(FirewallErrors.Frozen.selector);
        _exec(address(market), 0, data);
    }

    function test_A12_approveAfterFreeze() public {
        _moduleCall(abi.encodeCall(module.freeze, ()));
        vm.expectRevert(FirewallErrors.Frozen.selector);
        _exec(address(usdc), 0, abi.encodeCall(usdc.approve, (address(market), 1)));
    }

    // C1 / R5
    function test_C1_exitWithZeroBudget() public {
        _moduleCall(abi.encodeCall(module.freeze, ()));
        assertEq(module.availableBudget(address(account)), 0);
        _giftShares(yesId, 50e6);

        Execution[] memory execs = new Execution[](2);
        execs[0] = Execution(address(usdc), 0, abi.encodeCall(usdc.transfer, (dest, START_USDC)));
        execs[1] = Execution(
            address(shares),
            0,
            abi.encodeCall(shares.safeTransferFrom, (address(account), dest, yesId, 50e6, ""))
        );
        _execBatch(execs);

        assertEq(usdc.balanceOf(dest), START_USDC);
        assertEq(shares.balanceOf(dest, yesId), 50e6);
        assertEq(usdc.balanceOf(address(account)), 0);
    }

    function test_C1_exitAfterBudgetSpent() public {
        for (uint256 i; i < 5; ++i) {
            _buy(yesId, 0.5e6, 400e6);
        }
        assertEq(module.availableBudget(address(account)), 0);
        _exec(address(usdc), 0, abi.encodeCall(usdc.transfer, (dest, 1_000e6)));
        assertEq(usdc.balanceOf(dest), 1_000e6);
    }

    // C2
    function test_C2_normalFillWithinBudget() public {
        _buy(yesId, 0.6e6, 100e6);
        assertEq(shares.balanceOf(address(account), yesId), 100e6);
        assertEq(usdc.balanceOf(address(account)), START_USDC - 60e6);
        assertEq(module.availableBudget(address(account)), CAP - 60e6);
    }
}
