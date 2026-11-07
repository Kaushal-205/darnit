// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Base} from "../Base.t.sol";
import {FirewallErrors} from "../../src/interfaces/FirewallErrors.sol";
import {IMarketAdapter} from "../../src/interfaces/IMarketAdapter.sol";
import {IReferenceMarket} from "../../src/interfaces/IReferenceMarket.sol";
import {Execution} from "../../src/interfaces/IERC7579.sol";
import {ExecutionDecoder} from "../../src/lib/ExecutionDecoder.sol";
import {MockAccount} from "../mocks/MockAccount.sol";

/// @notice Adapter that under-declares: claims a fill touches no ERC-20. Used to prove postCheck (R3)
///         catches outflows the pre-checks did not anticipate.
contract LyingAdapter is IMarketAdapter {
    address public immutable override market;
    address public immutable override shareToken;

    constructor(IReferenceMarket m) {
        market = address(m);
        shareToken = m.shares();
    }

    function touched(address account, bytes calldata) external pure override returns (Touched memory t) {
        t.supported = true;
        t.recipients = new address[](1);
        t.recipients[0] = account;
    }
}

/// @notice R1-R5 on FirewallHook, rule by rule.
contract FirewallHookTest is Base {
    // ---------------------------------------------------------------- R1 targets

    function test_R1_plainValueToDestination() public {
        vm.deal(address(account), 1 ether);
        _exec(dest, 1 ether, "");
        assertEq(dest.balance, 1 ether);
    }

    function test_R1_destinationCalldataRejected() public {
        vm.expectRevert(
            abi.encodeWithSelector(FirewallErrors.UnknownTarget.selector, dest, bytes4(0x12345678))
        );
        _exec(dest, 0, abi.encodeWithSelector(bytes4(0x12345678)));
    }

    function test_R1_valueToMarketRejected() public {
        vm.deal(address(account), 1 ether);
        bytes memory data = _fillCall(IReferenceMarket.Side.Sell, yesId, 0.5e6, 1e6, address(account));
        vm.expectRevert(
            abi.encodeWithSelector(
                FirewallErrors.UnknownTarget.selector, address(market), market.fill.selector
            )
        );
        _exec(address(market), 1, data);
    }

    function test_R1_unknownTokenSelector() public {
        bytes memory data = abi.encodeWithSignature("mint(address,uint256)", address(account), 1);
        vm.expectRevert(
            abi.encodeWithSelector(FirewallErrors.UnknownTarget.selector, address(usdc), bytes4(data))
        );
        _exec(address(usdc), 0, data);
    }

    function test_R1_unknownMarketSelector() public {
        bytes memory data = abi.encodeCall(market.createMarket, ("x"));
        vm.expectRevert(
            abi.encodeWithSelector(FirewallErrors.UnknownTarget.selector, address(market), bytes4(data))
        );
        _exec(address(market), 0, data);
    }

    function test_R1_hookIsNotATarget() public {
        vm.expectRevert(FirewallErrors.ForbiddenExecution.selector);
        _exec(address(hook), 0, abi.encodeCall(hook.onUninstall, ("")));
    }

    function test_R1_malformedSingleExecution() public {
        vm.expectRevert(ExecutionDecoder.Malformed.selector);
        vm.prank(entryPoint);
        account.execute(MODE_SINGLE, hex"1234");
    }

    function test_R1_uninitializedAccountRejected() public {
        MockAccount bare = new MockAccount(entryPoint);
        vm.prank(entryPoint);
        bare.installModule(4, address(hook), "");
        vm.expectRevert(abi.encodeWithSelector(FirewallErrors.NotInitialized.selector, address(bare)));
        _execOn(bare, address(usdc), 0, abi.encodeCall(usdc.transfer, (dest, 0)));
    }

    function test_R1_fallbackCallPassesThrough() public {
        // ERC-1155 receipt during a gift is a fallback-style call: it must not be blocked
        _giftShares(yesId, 1e6);
        assertEq(shares.balanceOf(address(account), yesId), 1e6);
    }

    function test_R1_moduleReinstallFromAccountRejected() public {
        bytes memory data = abi.encodeCall(
            module.onInstall,
            (abi.encode(CAP, new address[](0), new address[](0), new address[](0), new address[](0)))
        );
        vm.expectRevert(
            abi.encodeWithSelector(
                FirewallErrors.UnknownTarget.selector, address(module), module.onInstall.selector
            )
        );
        _exec(address(module), 0, data);
    }

    function test_R1_moduleUninstallFromAccountRejected() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                FirewallErrors.UnknownTarget.selector, address(module), module.onUninstall.selector
            )
        );
        _exec(address(module), 0, abi.encodeCall(module.onUninstall, ("")));
    }

    // ---------------------------------------------------------------- R2 approvals

    function test_R2_approveMarketAllowed() public {
        _exec(address(usdc), 0, abi.encodeCall(usdc.approve, (address(market), 5e6)));
        assertEq(usdc.allowance(address(account), address(market)), 5e6);
    }

    function test_R2_revokeAnySpenderAllowed() public {
        _exec(address(usdc), 0, abi.encodeCall(usdc.approve, (attacker, 0)));
        _exec(address(shares), 0, abi.encodeCall(shares.setApprovalForAll, (attacker, false)));
    }

    function test_R2_increaseAllowanceAttacker() public {
        bytes memory data = abi.encodeWithSignature("increaseAllowance(address,uint256)", attacker, 1);
        vm.expectRevert(abi.encodeWithSelector(FirewallErrors.UnregisteredSpender.selector, attacker));
        _exec(address(usdc), 0, data);
    }

    function test_R2_dirtyAddressRejected() public {
        bytes memory data = abi.encodeWithSelector(usdc.approve.selector, uint256(type(uint160).max) + 1, 1);
        vm.expectRevert(ExecutionDecoder.Malformed.selector);
        _exec(address(usdc), 0, data);
    }

    function test_R2_setApprovalForAllNonBoolRejected() public {
        bytes memory data =
            abi.encodeWithSelector(shares.setApprovalForAll.selector, address(market), uint256(2));
        vm.expectRevert(ExecutionDecoder.Malformed.selector);
        _exec(address(shares), 0, data);
    }

    // ---------------------------------------------------------------- R3 conservation

    function test_R3_transferToDestination() public {
        _exec(address(usdc), 0, abi.encodeCall(usdc.transfer, (dest, 1_000e6)));
        assertEq(usdc.balanceOf(dest), 1_000e6);
        assertEq(module.availableBudget(address(account)), CAP);
    }

    function test_R3_shareTransferToAttacker() public {
        _giftShares(yesId, 10e6);
        bytes memory data =
            abi.encodeCall(shares.safeTransferFrom, (address(account), attacker, yesId, 10e6, ""));
        vm.expectRevert(
            abi.encodeWithSelector(FirewallErrors.UnexplainedOutflow.selector, address(shares), yesId)
        );
        _exec(address(shares), 0, data);
    }

    function test_R3_batchShareTransferToAttacker() public {
        _giftShares(yesId, 10e6);
        uint256[] memory ids = new uint256[](1);
        ids[0] = yesId;
        uint256[] memory amts = new uint256[](1);
        amts[0] = 10e6;
        bytes memory data =
            abi.encodeCall(shares.safeBatchTransferFrom, (address(account), attacker, ids, amts, ""));
        vm.expectRevert(
            abi.encodeWithSelector(FirewallErrors.UnexplainedOutflow.selector, address(shares), yesId)
        );
        _exec(address(shares), 0, data);
    }

    function test_R3_postCheckCatchesUndeclaredOutflow() public {
        LyingAdapter liar = new LyingAdapter(market);
        MockAccount acc = _newAccount(address(liar));
        vm.startPrank(entryPoint);
        acc.execute(
            MODE_SINGLE,
            abi.encodePacked(
                address(usdc), uint256(0), abi.encodeCall(usdc.approve, (address(market), type(uint256).max))
            )
        );
        vm.stopPrank();

        (IReferenceMarket.Order memory o, bytes memory sig) =
            _order(IReferenceMarket.Side.Sell, yesId, 0.5e6, 10e6);
        bytes memory data = abi.encodeCall(market.fill, (o, sig, 10e6, address(acc)));
        vm.expectRevert(abi.encodeWithSelector(FirewallErrors.UnexplainedOutflow.selector, address(usdc), 0));
        _execOn(acc, address(market), 0, data);
    }

    // ---------------------------------------------------------------- R4 budget

    function test_R4_buyConsumesCost() public {
        _buy(yesId, 0.25e6, 400e6);
        assertEq(module.availableBudget(address(account)), CAP - 100e6);
    }

    function test_R4_sellConsumesDiscountFromOneDollar() public {
        _giftShares(yesId, 100e6);
        _sell(yesId, 0.9e6, 100e6); // $0.10 per share
        assertEq(module.availableBudget(address(account)), CAP - 10e6);
        assertEq(usdc.balanceOf(address(account)), START_USDC + 90e6);
    }

    function test_R4_refillOverTime() public {
        _buy(yesId, 0.5e6, 2_000e6); // spend the whole $1,000
        assertEq(module.availableBudget(address(account)), 0);
        vm.warp(block.timestamp + 1_800);
        assertEq(module.availableBudget(address(account)), CAP / 2);
        _buy(yesId, 0.5e6, 1_000e6);
    }

    function test_R4_splitIsChargedConservatively() public {
        _exec(address(market), 0, abi.encodeCall(market.split, (marketId, 100e6)));
        // shares received are never credited
        assertEq(module.availableBudget(address(account)), CAP - 100e6);
    }

    function test_R4_redeemWinnerIsFree() public {
        _giftShares(yesId, 100e6);
        market.resolve(marketId, true);
        _exec(address(market), 0, abi.encodeCall(market.redeem, (marketId)));
        assertEq(module.availableBudget(address(account)), CAP);
        assertEq(usdc.balanceOf(address(account)), START_USDC + 100e6);
    }

    // ---------------------------------------------------------------- R5 exit

    function test_R5_exitMixedWithTradeOnlyChargesTrade() public {
        Execution[] memory execs = new Execution[](2);
        execs[0] = Execution(address(usdc), 0, abi.encodeCall(usdc.transfer, (dest, 5_000e6)));
        execs[1] = Execution(
            address(market), 0, _fillCall(IReferenceMarket.Side.Sell, yesId, 0.5e6, 100e6, address(account))
        );
        _execBatch(execs);
        assertEq(module.availableBudget(address(account)), CAP - 50e6);
        assertEq(usdc.balanceOf(dest), 5_000e6);
    }

    function test_R5_proceedsToDestinationAllowed() public {
        _exec(address(market), 0, _fillCall(IReferenceMarket.Side.Sell, yesId, 0.5e6, 100e6, dest));
        assertEq(shares.balanceOf(dest, yesId), 100e6);
        // USDC out $50, shares landed in the trust zone but are not credited
        assertEq(module.availableBudget(address(account)), CAP - 50e6);
    }

    // ---------------------------------------------------------------- R8

    function test_R8_frozenAllowsRevokeAndExit() public {
        _moduleCall(abi.encodeCall(module.freeze, ()));
        _exec(address(usdc), 0, abi.encodeCall(usdc.approve, (address(market), 0)));
        _exec(address(usdc), 0, abi.encodeCall(usdc.transfer, (dest, 1e6)));
    }
}
