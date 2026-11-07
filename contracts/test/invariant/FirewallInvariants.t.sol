// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Base} from "../Base.t.sol";
import {IFirewallModule} from "../../src/interfaces/IFirewallModule.sol";
import {ReferenceMarketAdapter} from "../../src/adapters/ReferenceMarketAdapter.sol";
import {MODULE_TYPE_EXECUTOR} from "../../src/interfaces/IERC7579.sol";
import {MockUSDC} from "../fixtures/MockUSDC.sol";
import {ReferenceMarket, OutcomeShares} from "../fixtures/ReferenceMarket.sol";
import {FirewallHandler, HandlerRefs, Drainer} from "./FirewallHandler.sol";

/// @notice Plan section 8, INV1-INV4, over random sequences of owner trades, exits, attacks, time jumps,
///         queue operations and tightening calls (see FirewallHandler). Default profile is a quick smoke run;
///         `FOUNDRY_PROFILE=ci` runs 10,000 sequences per invariant (docs/decisions.md, "M3 results").
///         INV4 lives in its own contract so the two campaigns run in parallel.
abstract contract FirewallInvariantBase is Base {
    FirewallHandler internal handler;
    MockUSDC internal token2;
    ReferenceMarket internal market1;
    ReferenceMarketAdapter internal adapter1;
    Drainer internal drainer;

    function setUp() public override {
        super.setUp();

        token2 = new MockUSDC();
        market1 = new ReferenceMarket(usdc, address(this));
        adapter1 = new ReferenceMarketAdapter(market1);
        drainer = new Drainer();

        // second market: not registered yet (AddMarket goes through the queue); maker liquidity on id 1
        assertEq(market1.createMarket("second"), 1);
        usdc.mint(maker, 10_000_000e6);
        vm.startPrank(maker);
        usdc.approve(address(market1), type(uint256).max);
        OutcomeShares(market1.shares()).setApprovalForAll(address(market1), true);
        market1.split(1, 100_000e6);
        vm.stopPrank();

        token2.mint(address(account), START_USDC); // untracked until AddToken executes
        vm.deal(address(account), 10 ether);

        handler = new FirewallHandler(
            HandlerRefs({
                account: account,
                module: module,
                hook: hook,
                usdc: usdc,
                token2: token2,
                market0: market,
                market1: market1,
                adapter0: adapter,
                adapter1: adapter1,
                entryPoint: entryPoint,
                resolver: address(this),
                maker: maker,
                makerKey: makerKey,
                primaryDest: dest,
                attacker: attacker,
                drainer: drainer,
                initialCap: CAP
            })
        );

        bytes4[] memory sels = new bytes4[](28);
        sels[0] = FirewallHandler.buy.selector;
        sels[1] = FirewallHandler.sell.selector;
        sels[2] = FirewallHandler.dumpOrOverpay.selector;
        sels[3] = FirewallHandler.split.selector;
        sels[4] = FirewallHandler.merge.selector;
        sels[5] = FirewallHandler.redeem.selector;
        sels[6] = FirewallHandler.batchTrade.selector;
        sels[7] = FirewallHandler.approveMarkets.selector;
        sels[8] = FirewallHandler.exitUsdc.selector;
        sels[9] = FirewallHandler.exitShares.selector;
        sels[10] = FirewallHandler.exitEth.selector;
        sels[11] = FirewallHandler.destReturns.selector;
        sels[12] = FirewallHandler.fundAccount.selector;
        sels[13] = FirewallHandler.newMarket.selector;
        sels[14] = FirewallHandler.resolveMarket.selector;
        sels[15] = FirewallHandler.warp.selector;
        sels[16] = FirewallHandler.queueChange.selector;
        sels[17] = FirewallHandler.executeChange.selector;
        sels[18] = FirewallHandler.cancelChange.selector;
        sels[19] = FirewallHandler.lowerCap.selector;
        sels[20] = FirewallHandler.freeze.selector;
        sels[21] = FirewallHandler.revokeSessions.selector;
        sels[22] = FirewallHandler.removeDestination.selector;
        sels[23] = FirewallHandler.removeMarket.selector;
        sels[24] = FirewallHandler.attack.selector;
        sels[25] = FirewallHandler.attackDirect.selector;
        sels[26] = FirewallHandler.exitToUnregistered.selector;
        sels[27] = FirewallHandler.queueAndMature.selector;
        targetSelector(FuzzSelector({addr: address(handler), selectors: sels}));
        targetContract(address(handler));
    }

    function _assertSameSet(address[] memory a, address[] memory b, string memory what) internal pure {
        assertEq(a.length, b.length, what);
        for (uint256 i; i < a.length; ++i) {
            bool found;
            for (uint256 j; j < b.length; ++j) {
                if (a[i] == b[j]) found = true;
            }
            assertTrue(found, what);
        }
    }
}

/// @title FirewallInvariants (INV1-INV3)
contract FirewallInvariants is FirewallInvariantBase {
    // ---------------------------------------------------------------- INV1

    /// @notice Nothing the account holds ever reaches an address outside the trust zone, except through
    ///         market fills with the counterparty (bounded by INV1b). Checked two ways: (1) every token event
    ///         of every account execution: value leaving the zone may only go to the maker, a market or a
    ///         burn; (2) balances of the attacker EOA (all assets), the attacker contract and never-registered
    ///         candidate destinations (ERC-20s and ETH), plus allowances and operator approvals.
    function invariant_INV1_noValueToUnregistered() public view {
        assertEq(handler.valueOf(attacker), 0, "attacker received value");
        assertEq(handler.liquidOf(address(drainer)), 0, "attacker contract received value");
        assertEq(handler.leakedToUnregistered(), 0, "value left the trust zone to a non-counterparty");
        address[3] memory cands = handler.candidateList();
        for (uint256 i; i < 3; ++i) {
            if (!handler.everRegistered(cands[i])) {
                assertEq(handler.liquidOf(cands[i]), 0, "never-registered destination received value");
            }
        }
        assertEq(handler.attackSuccesses(), 0, "an attack execution succeeded");
        // no approvals to the attacker either
        assertEq(usdc.allowance(address(account), attacker), 0);
        assertEq(usdc.allowance(address(account), address(drainer)), 0);
        assertFalse(shares.isApprovedForAll(address(account), attacker));
        assertFalse(OutcomeShares(market1.shares()).isApprovedForAll(address(account), attacker));
    }

    /// @notice INV1b: whatever the counterparty (maker) gains from the account, valuing every share at $1,
    ///         is covered by budget consumed (R4 is an upper bound on value lost to markets).
    function invariant_INV1b_counterpartyGainWithinBudget() public view {
        uint256 v = handler.makerValue();
        uint256 base = handler.makerValue0() + handler.makerAdj();
        uint256 gain = v > base ? v - base : 0;
        assertLe(gain, handler.totalConsumed(), "counterparty gained more than the budget consumed");
    }

    // ---------------------------------------------------------------- INV2

    function invariant_INV2_budgetPerWindow() public view {
        assertEq(handler.windowViolations(), 0, "budget consumed in a 3600s window exceeds cap + start level");
        assertLe(module.availableBudget(address(account)), module.config(address(account)).hourlyCap);
    }

    /// @notice R4/R5 at runtime: each consumption equals max(0, out - in) over the trust zone, and executions
    ///         without a market call never consume.
    function invariant_INV2b_consumptionMatchesFormula() public view {
        assertEq(handler.budgetMismatches(), 0, "consumption differs from worst-case formula");
    }

    // ---------------------------------------------------------------- INV3

    function invariant_INV3_configOnlyViaQueueOrTightening() public view {
        IFirewallModule.AccountView memory v = module.accountView(address(account));
        _assertSameSet(v.destinations, handler.expectedDests(), "destinations");
        _assertSameSet(v.markets, handler.expectedMarkets(), "markets");
        _assertSameSet(v.tokens, handler.expectedTokens(), "tokens");
        assertEq(v.config.hourlyCap, handler.mCap(), "cap");
        assertEq(v.config.frozen, handler.mFrozen(), "frozen");
        assertEq(v.config.delay, 24 hours, "delay");
        assertEq(module.sessionEpoch(address(account)), handler.mEpoch(), "session epoch");
        assertEq(handler.earlyExecutions(), 0, "queue item executed before 24h");
        // module wiring cannot be changed from an execution
        assertEq(address(account.hook()), address(hook), "hook replaced");
        assertTrue(account.isExecutor(address(module)), "module removed");
        assertFalse(account.isExecutor(address(drainer)), "attacker executor installed");
        assertFalse(account.isExecutor(attacker), "attacker executor installed");
    }
}

/// @title FirewallExitInvariant (INV4)
contract FirewallExitInvariant is FirewallInvariantBase {
    /// @notice From the current state, the owner can move every tracked asset (and ETH) to the primary
    ///         destination in one execution, whatever the budget, freeze or queue state. Rolled back after.
    function invariant_INV4_exitAlwaysWorks() public {
        assertTrue(handler.exitAllSucceeds(), "owner exit to a registered destination failed");
        assertEq(handler.exitsFailed(), 0, "a handler exit of a tracked asset failed");
    }
}

/// @title FirewallHandlerCoverage
/// @notice Not an invariant: drives the handler through a fixed pseudo-random sequence and checks that every
///         path the invariants rely on is actually reached (trades succeed and hit the budget, queue items
///         mature and execute, attacks are attempted), so a passing campaign is not a vacuous one.
contract FirewallHandlerCoverage is FirewallInvariantBase {
    function test_handlerReachesEveryPath() public {
        FirewallHandler h = handler;
        for (uint256 i; i < 2000; ++i) {
            uint256 r = uint256(keccak256(abi.encode(i)));
            uint256 a = r >> 8;
            uint256 b = r >> 64;
            uint256 c = r >> 128;
            bool f = (r >> 200) % 2 == 0;
            uint256 k = r % 28;
            if (k == 0) h.buy(a, b, c, a ^ b, c);
            else if (k == 1) h.sell(a, b, c, a ^ b, c);
            else if (k == 2) h.dumpOrOverpay(a, b, c, f);
            else if (k == 3) h.split(a, b, c);
            else if (k == 4) h.merge(a, b, c);
            else if (k == 5) h.redeem(a, b);
            else if (k == 6) h.batchTrade(a, b, c, f);
            else if (k == 7) h.approveMarkets(a);
            else if (k == 8) h.exitUsdc(a, b, f);
            else if (k == 9) h.exitShares(a, b, c, a ^ c, f);
            else if (k == 10) h.exitEth(a, b);
            else if (k == 11) h.destReturns(a, b, c, a ^ c);
            else if (k == 12) h.fundAccount(a, f);
            else if (k == 13) h.newMarket(a);
            else if (k == 14) h.resolveMarket(a, b, f);
            else if (k == 15) h.warp(a);
            else if (k == 16) h.queueChange(a, b);
            else if (k == 17) h.executeChange(a, f);
            else if (k == 18) h.cancelChange(a);
            else if (k == 19) h.lowerCap(a);
            else if (k == 20) h.freeze(a);
            else if (k == 21) h.revokeSessions();
            else if (k == 22) h.removeDestination(a);
            else if (k == 23) h.removeMarket(a);
            else if (k == 24) h.attack(a, b, c);
            else if (k == 25) h.attackDirect(a, b);
            else if (k == 26) h.exitToUnregistered(a, b);
            else if (k == 27) h.queueAndMature(a, b);
        }
        emit log_named_uint("trades ok", h.tradesOk());
        emit log_named_uint("trades failed", h.tradesFailed());
        emit log_named_uint("budget exceeded", h.budgetExceeded());
        emit log_named_uint("consumptions", h.consumptionCount());
        emit log_named_uint("exits ok", h.exitsOk());
        emit log_named_uint("changes executed", h.changesExecuted());
        emit log_named_uint("tightening calls", h.tighteningCalls());
        emit log_named_uint("attack attempts", h.attackAttempts());
        emit log_named_uint("warps", h.warps());
        assertGt(h.tradesOk(), 25, "trades");
        assertGt(h.budgetExceeded(), 0, "budget never binds");
        assertGt(h.exitsOk(), 20, "exits");
        assertGt(h.changesExecuted(), 3, "queue never matures");
        assertGt(h.tighteningCalls(), 5, "tightening");
        assertGt(h.attackAttempts(), 50, "attacks");
        assertEq(h.attackSuccesses(), 0);
        assertEq(h.budgetMismatches(), 0);
        assertEq(h.leakedToUnregistered(), 0);
        assertEq(h.windowViolations(), 0);
        assertTrue(h.exitAllSucceeds());
    }
}
