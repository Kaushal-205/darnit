// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {CommonBase} from "forge-std/Base.sol";
import {StdCheats} from "forge-std/StdCheats.sol";
import {StdUtils} from "forge-std/StdUtils.sol";
import {Vm} from "forge-std/Vm.sol";
import {FirewallModule} from "../../src/FirewallModule.sol";
import {FirewallHook} from "../../src/FirewallHook.sol";
import {IFirewallModule} from "../../src/interfaces/IFirewallModule.sol";
import {FirewallErrors} from "../../src/interfaces/FirewallErrors.sol";
import {IReferenceMarket} from "../../src/interfaces/IReferenceMarket.sol";
import {ReferenceMarketAdapter} from "../../src/adapters/ReferenceMarketAdapter.sol";
import {Execution, MODULE_TYPE_HOOK, MODULE_TYPE_EXECUTOR} from "../../src/interfaces/IERC7579.sol";
import {MockUSDC} from "../fixtures/MockUSDC.sol";
import {ReferenceMarket, OutcomeShares} from "../fixtures/ReferenceMarket.sol";
import {MockAccount} from "../mocks/MockAccount.sol";
import {IERC1155} from "@openzeppelin/contracts/token/ERC1155/IERC1155.sol";

interface IERC20Min {
    function transfer(address, uint256) external returns (bool);
    function balanceOf(address) external view returns (uint256);
}

/// @notice Attacker contract. As a call target it must be rejected (R1); as a delegatecall target it would
///         drain the account if delegatecall were ever allowed.
contract Drainer {
    function drain(address token, address to) external {
        IERC20Min(token).transfer(to, IERC20Min(token).balanceOf(address(this)));
    }

    function onERC1155Received(address, address, uint256, uint256, bytes calldata)
        external
        pure
        returns (bytes4)
    {
        return this.onERC1155Received.selector;
    }
}

/// @notice Everything the handler needs from the invariant test's setUp.
struct HandlerRefs {
    MockAccount account;
    FirewallModule module;
    FirewallHook hook;
    MockUSDC usdc;
    MockUSDC token2;
    ReferenceMarket market0;
    ReferenceMarket market1;
    ReferenceMarketAdapter adapter0;
    ReferenceMarketAdapter adapter1;
    address entryPoint;
    address resolver;
    address maker;
    uint256 makerKey;
    address primaryDest;
    address attacker;
    Drainer drainer;
    uint128 initialCap;
}

/// @title FirewallHandler
/// @notice Drives random sequences of owner trades, exits, attacks, time jumps and queue operations against
///         one firewalled MockAccount, keeping ghost state for INV1-INV4. The handler never reverts: every
///         account execution is a low-level call whose outcome is classified.
contract FirewallHandler is CommonBase, StdCheats, StdUtils {
    bytes32 internal constant MODE_SINGLE = bytes32(0);
    bytes32 internal constant MODE_BATCH = bytes32(bytes1(0x01));
    bytes32 internal constant MODE_TRY_SINGLE = bytes32(bytes2(0x0001));
    bytes32 internal constant MODE_DELEGATECALL = bytes32(bytes1(0xFF));
    bytes32 internal constant BUDGET_CONSUMED = keccak256("BudgetConsumed(address,uint256,uint256)");
    bytes32 internal constant CHANGE_QUEUED = keccak256("ChangeQueued(address,bytes32,uint8,bytes,uint64)");
    uint256 internal constant ONE = 1e6;
    uint256 internal constant MAX_IDS_PER_MARKET = 3;
    uint256 internal constant MAX_PENDING = 6;

    MockAccount public account;
    FirewallModule public module;
    FirewallHook public hook;
    MockUSDC public usdc;
    MockUSDC public token2;
    ReferenceMarket[2] public markets;
    ReferenceMarketAdapter[2] public adapters;
    OutcomeShares[2] public shareTokens;
    address public entryPoint;
    address public resolver;
    address public maker;
    uint256 internal makerKey;
    address public primaryDest;
    address public attacker;
    Drainer public drainer;
    address[3] public candidates;

    // market ids created on each market
    uint256[MAX_IDS_PER_MARKET][2] internal marketIds;
    uint256[2] public nMarketIds;
    mapping(uint256 mi => mapping(uint256 marketId => bool)) internal resolved;

    // ---------------------------------------------------------------- ghost: expected config (INV3)
    address[] internal mDests;
    address[] internal mMarkets;
    address[] internal mTokens;
    uint128 public mCap;
    bool public mFrozen;
    uint64 public mEpoch;

    struct Pending {
        bytes32 id;
        IFirewallModule.ChangeKind kind;
        bytes data;
        uint256 queuedAt;
        uint64 eta;
    }

    Pending[] internal pending;

    // ---------------------------------------------------------------- ghost: budget log (INV2)
    uint256[] public cTime;
    uint256[] public cAmount;
    uint256[] public cAvailBefore;
    uint256 public maxCap;
    uint256 public totalConsumed;

    // ---------------------------------------------------------------- ghost: outcomes
    uint256 public attackAttempts;
    uint256 public attackSuccesses; // must stay 0
    uint256 public earlyExecutions; // queue items executed < 24h after queueing; must stay 0
    uint256 public budgetMismatches; // consumption != max(0, out - in), or consumption without market call
    uint256 public leakedToUnregistered; // value that left the trust zone to a non-counterparty
    uint256 public tradesOk;
    uint256 public tradesFailed;
    uint256 public budgetExceeded;
    uint256 public exitsOk;
    uint256 public exitsFailed; // exits to registered destinations of tracked assets; must stay 0
    uint256 public changesExecuted;
    uint256 public tighteningCalls;
    uint256 public warps;

    // counterparty (maker) value baseline for INV1b
    uint256 public makerValue0;
    uint256 public makerAdj;

    // last seen balances of watched unregistered parties, for the leak check
    mapping(address => bool) public everRegistered;
    address[] internal shareTok;
    uint256[] internal shareId;

    uint256 public gNow;
    uint256 internal salt;

    constructor(HandlerRefs memory r) {
        account = r.account;
        module = r.module;
        hook = r.hook;
        usdc = r.usdc;
        token2 = r.token2;
        markets[0] = r.market0;
        markets[1] = r.market1;
        adapters[0] = r.adapter0;
        adapters[1] = r.adapter1;
        shareTokens[0] = OutcomeShares(r.market0.shares());
        shareTokens[1] = OutcomeShares(r.market1.shares());
        entryPoint = r.entryPoint;
        resolver = r.resolver;
        maker = r.maker;
        makerKey = r.makerKey;
        primaryDest = r.primaryDest;
        attacker = r.attacker;
        drainer = r.drainer;
        candidates[0] = makeAddr("candidate0");
        candidates[1] = makeAddr("candidate1");
        candidates[2] = makeAddr("candidate2");

        marketIds[0][0] = 1;
        marketIds[1][0] = 1;
        nMarketIds[0] = 1;
        nMarketIds[1] = 1;
        _cacheIds(0, 1);
        _cacheIds(1, 1);

        mDests.push(r.primaryDest);
        mMarkets.push(address(r.market0));
        mTokens.push(address(r.usdc));
        mCap = r.initialCap;
        maxCap = r.initialCap;
        gNow = block.timestamp;

        makerValue0 = makerValue();
    }

    modifier step() {
        vm.warp(gNow);
        _;
        _afterStep();
    }

    // =================================================================== owner trades

    function buy(uint256 mSeed, uint256 idSeed, uint256 price, uint256 amount, uint256 recipSeed)
        external
        step
    {
        (uint256 mi, uint256 tokenId) = _pickId(mSeed, idSeed);
        price = bound(price, 1, ONE - 1);
        amount = bound(amount, 1, 1_500e6);
        address recipient = _pickZone(recipSeed);
        bytes memory data = _fill(mi, IReferenceMarket.Side.Sell, tokenId, price, amount, recipient);
        _trade(MODE_SINGLE, abi.encodePacked(address(markets[mi]), uint256(0), data));
    }

    function sell(uint256 mSeed, uint256 idSeed, uint256 price, uint256 amount, uint256 recipSeed)
        external
        step
    {
        (uint256 mi, uint256 tokenId) = _pickId(mSeed, idSeed);
        price = bound(price, 1, ONE - 1);
        uint256 bal = shareTokens[mi].balanceOf(address(account), tokenId);
        amount = _boundHeld(amount, bal);
        address recipient = _pickZone(recipSeed);
        bytes memory data = _fill(mi, IReferenceMarket.Side.Buy, tokenId, price, amount, recipient);
        _trade(MODE_SINGLE, abi.encodePacked(address(markets[mi]), uint256(0), data));
    }

    /// @dev Dumping at $0.01 (A6) or overpaying at $0.99: large worst-case value out, mostly BudgetExceeded.
    function dumpOrOverpay(uint256 mSeed, uint256 idSeed, uint256 amount, bool dump) external step {
        (uint256 mi, uint256 tokenId) = _pickId(mSeed, idSeed);
        IReferenceMarket.Side side = dump ? IReferenceMarket.Side.Buy : IReferenceMarket.Side.Sell;
        uint256 price = dump ? 0.01e6 : 0.99e6;
        if (dump) amount = _boundHeld(amount, shareTokens[mi].balanceOf(address(account), tokenId));
        else amount = bound(amount, 1, 3_000e6);
        bytes memory data = _fill(mi, side, tokenId, price, amount, address(account));
        _trade(MODE_SINGLE, abi.encodePacked(address(markets[mi]), uint256(0), data));
    }

    function split(uint256 mSeed, uint256 idSeed, uint256 amount) external step {
        (uint256 mi, uint256 marketId) = _pickMarketId(mSeed, idSeed);
        amount = bound(amount, 1, 1_500e6);
        bytes memory data = abi.encodeCall(IReferenceMarket.split, (marketId, amount));
        _trade(MODE_SINGLE, abi.encodePacked(address(markets[mi]), uint256(0), data));
    }

    function merge(uint256 mSeed, uint256 idSeed, uint256 amount) external step {
        (uint256 mi, uint256 marketId) = _pickMarketId(mSeed, idSeed);
        (uint256 yes, uint256 no) = _ids(marketId);
        uint256 a = shareTokens[mi].balanceOf(address(account), yes);
        uint256 b = shareTokens[mi].balanceOf(address(account), no);
        amount = _boundHeld(amount, a < b ? a : b);
        bytes memory data = abi.encodeCall(IReferenceMarket.merge, (marketId, amount));
        _trade(MODE_SINGLE, abi.encodePacked(address(markets[mi]), uint256(0), data));
    }

    function redeem(uint256 mSeed, uint256 idSeed) external step {
        (uint256 mi, uint256 marketId) = _pickResolved(mSeed, idSeed);
        bytes memory data = abi.encodeCall(IReferenceMarket.redeem, (marketId));
        _trade(MODE_SINGLE, abi.encodePacked(address(markets[mi]), uint256(0), data));
    }

    /// @dev Two or three fills plus an optional exit, in one batch (one consume call).
    function batchTrade(uint256 seed, uint256 price, uint256 amount, bool withExit) external step {
        uint256 n = 2 + (seed % 2);
        Execution[] memory execs = new Execution[](n + (withExit ? 1 : 0));
        for (uint256 i; i < n; ++i) {
            uint256 s = uint256(keccak256(abi.encode(seed, i)));
            (uint256 mi, uint256 tokenId) = _pickId(s, s >> 8);
            uint256 p = bound(uint256(keccak256(abi.encode(price, i))), 1, ONE - 1);
            uint256 a = bound(uint256(keccak256(abi.encode(amount, i))), 1, 600e6);
            IReferenceMarket.Side side =
                (s >> 16) % 2 == 0 ? IReferenceMarket.Side.Sell : IReferenceMarket.Side.Buy;
            if (side == IReferenceMarket.Side.Buy) {
                a = _boundHeld(a, shareTokens[mi].balanceOf(address(account), tokenId));
            }
            execs[i] = Execution(address(markets[mi]), 0, _fill(mi, side, tokenId, p, a, _pickZone(s >> 24)));
        }
        if (withExit) {
            uint256 bal = usdc.balanceOf(address(account));
            execs[n] = Execution(
                address(usdc),
                0,
                abi.encodeCall(usdc.transfer, (_pickDest(seed >> 32), bound(amount, 0, bal)))
            );
        }
        _trade(MODE_BATCH, abi.encode(execs));
    }

    function approveMarkets(uint256 mSeed) external step {
        uint256 mi = mSeed % 2;
        Execution[] memory execs = new Execution[](2);
        execs[0] = Execution(
            address(usdc), 0, abi.encodeCall(usdc.approve, (address(markets[mi]), type(uint256).max))
        );
        execs[1] = Execution(
            address(shareTokens[mi]),
            0,
            abi.encodeCall(shareTokens[mi].setApprovalForAll, (address(markets[mi]), true))
        );
        _ownerExec(MODE_BATCH, abi.encode(execs), false);
    }

    // =================================================================== exits (R5)

    function exitUsdc(uint256 amount, uint256 destSeed, bool useToken2) external step {
        MockUSDC t = useToken2 ? token2 : usdc;
        amount = bound(amount, 0, t.balanceOf(address(account)));
        bool expectOk = _inList(mTokens, address(t));
        (bool ok,) = _ownerExec(
            MODE_SINGLE,
            abi.encodePacked(
                address(t), uint256(0), abi.encodeCall(t.transfer, (_pickDest(destSeed), amount))
            ),
            false
        );
        _countExit(expectOk, ok);
    }

    function exitShares(uint256 mSeed, uint256 idSeed, uint256 amount, uint256 destSeed, bool asBatch)
        external
        step
    {
        (uint256 mi, uint256 tokenId) = _pickId(mSeed, idSeed);
        amount = bound(amount, 0, shareTokens[mi].balanceOf(address(account), tokenId));
        address to = _pickDest(destSeed);
        bytes memory data;
        if (asBatch) {
            uint256[] memory ids = new uint256[](1);
            uint256[] memory amts = new uint256[](1);
            ids[0] = tokenId;
            amts[0] = amount;
            data =
                abi.encodeCall(shareTokens[mi].safeBatchTransferFrom, (address(account), to, ids, amts, ""));
        } else {
            data =
                abi.encodeCall(shareTokens[mi].safeTransferFrom, (address(account), to, tokenId, amount, ""));
        }
        bool expectOk = _inList(mMarkets, address(markets[mi]));
        (bool ok,) =
            _ownerExec(MODE_SINGLE, abi.encodePacked(address(shareTokens[mi]), uint256(0), data), false);
        _countExit(expectOk, ok);
    }

    function exitEth(uint256 amount, uint256 destSeed) external step {
        amount = bound(amount, 0, address(account).balance);
        (bool ok,) = _ownerExec(MODE_SINGLE, abi.encodePacked(_pickDest(destSeed), amount, ""), false);
        _countExit(true, ok);
    }

    /// @dev A destination (EOA) sends funds back to the account, keeping value circulating.
    function destReturns(uint256 destSeed, uint256 amount, uint256 mSeed, uint256 idSeed) external step {
        address d = _pickDest(destSeed);
        uint256 a = bound(amount, 0, usdc.balanceOf(d));
        vm.prank(d);
        usdc.transfer(address(account), a);
        (uint256 mi, uint256 tokenId) = _pickId(mSeed, idSeed);
        uint256 s = bound(amount, 0, shareTokens[mi].balanceOf(d, tokenId));
        vm.prank(d);
        shareTokens[mi].safeTransferFrom(d, address(account), tokenId, s, "");
    }

    function fundAccount(uint256 amount, bool useToken2) external step {
        amount = bound(amount, 0, 5_000e6);
        (useToken2 ? token2 : usdc).mint(address(account), amount);
    }

    // =================================================================== market lifecycle (not the account)

    function newMarket(uint256 mSeed) external step {
        uint256 mi = mSeed % 2;
        if (nMarketIds[mi] == MAX_IDS_PER_MARKET) return;
        vm.prank(resolver);
        uint256 id = markets[mi].createMarket("q");
        marketIds[mi][nMarketIds[mi]++] = id;
        _cacheIds(mi, id);
        vm.prank(maker);
        markets[mi].split(id, 100_000e6);
        makerAdj += 100_000e6; // split doubles the maker's share count: +amount at $1 per share
    }

    function resolveMarket(uint256 mSeed, uint256 idSeed, bool yesWins) external step {
        // rare: each market id can only trade until it resolves
        if ((idSeed >> 16) % 8 != 0) return;
        (uint256 mi, uint256 marketId) = _pickMarketId(mSeed, idSeed);
        if (resolved[mi][marketId]) return;
        resolved[mi][marketId] = true;
        vm.prank(resolver);
        markets[mi].resolve(marketId, yesWins);
    }

    // =================================================================== time

    function warp(uint256 secs) external step {
        // short jumps inside the 1h window, medium ones across it, and long ones past the 24h delay
        uint256 r = secs % 10;
        if (r < 4) secs = bound(secs, 1, 900);
        else if (r < 7) secs = bound(secs, 900, 2 hours);
        else secs = bound(secs, 12 hours, 30 hours);
        gNow += secs;
        vm.warp(gNow);
        ++warps;
    }

    // =================================================================== queue (R6)

    function queueChange(uint256 kindSeed, uint256 seed) external step {
        _queueChange(kindSeed, seed);
    }

    /// @dev The full loosening flow in one step (queue, wait 24h, execute), so short sequences still reach
    ///      states with extra destinations, markets and tokens, and recover from a freeze.
    function queueAndMature(uint256 kindSeed, uint256 seed) external step {
        if (!_queueChange(kindSeed, seed)) return;
        uint256 i = pending.length - 1;
        Pending memory p = pending[i];
        gNow = p.eta;
        vm.warp(gNow);
        ++warps;
        (bool ok,) = _ownerExec(MODE_SINGLE, _moduleEc(abi.encodeCall(module.execute, (p.id))), false);
        if (!ok) return;
        _applyChange(p);
        _removePending(i);
        ++changesExecuted;
    }

    function _queueChange(uint256 kindSeed, uint256 seed) internal returns (bool) {
        if (pending.length >= MAX_PENDING) return false;
        uint256 k = kindSeed % 5;
        // a frozen account (or a zero cap) mostly works its way back to trading
        if (mFrozen && kindSeed % 2 == 0) k = 4;
        else if (mCap == 0 && kindSeed % 2 == 0) k = 3;
        IFirewallModule.ChangeKind kind;
        bytes memory data;
        if (k == 0) {
            kind = IFirewallModule.ChangeKind.AddDestination;
            data = abi.encode(candidates[seed % 3]);
        } else if (k == 1) {
            uint256 mi = seed % 2;
            kind = IFirewallModule.ChangeKind.AddMarket;
            data = abi.encode(address(markets[mi]), address(adapters[mi]));
        } else if (k == 2) {
            kind = IFirewallModule.ChangeKind.AddToken;
            data = abi.encode(address(token2));
        } else if (k == 3) {
            kind = IFirewallModule.ChangeKind.RaiseCap;
            data = abi.encode(uint128(bound(seed, 1, 5_000e6)));
        } else {
            kind = IFirewallModule.ChangeKind.Unfreeze;
            data = "";
        }
        (bool ok, Vm.Log[] memory logs) =
            _ownerExec(MODE_SINGLE, _moduleEc(abi.encodeCall(module.queue, (kind, data))), false);
        if (!ok) return false;
        bytes32 id = _queuedId(logs);
        pending.push(
            Pending({
                id: id,
                kind: kind,
                data: data,
                queuedAt: block.timestamp,
                eta: uint64(block.timestamp + 24 hours)
            })
        );
        return true;
    }

    /// @param waitForEta jump to the item's eta first (a matured execution); otherwise try it now, which
    ///        must fail with TooEarly if it is younger than 24h.
    function executeChange(uint256 seed, bool waitForEta) external step {
        if (pending.length == 0) return;
        uint256 i = seed % pending.length;
        Pending memory p = pending[i];
        if (waitForEta && gNow < p.eta) {
            gNow = p.eta;
            vm.warp(gNow);
            ++warps;
        }
        (bool ok,) = _ownerExec(MODE_SINGLE, _moduleEc(abi.encodeCall(module.execute, (p.id))), false);
        if (!ok) return;
        if (block.timestamp < p.queuedAt + 24 hours) ++earlyExecutions;
        _applyChange(p);
        _removePending(i);
        ++changesExecuted;
    }

    function cancelChange(uint256 seed) external step {
        if (pending.length == 0) return;
        uint256 i = seed % pending.length;
        (bool ok,) = _ownerExec(MODE_SINGLE, _moduleEc(abi.encodeCall(module.cancel, (pending[i].id))), false);
        if (ok) _removePending(i);
    }

    // =================================================================== tightening (instant)

    function lowerCap(uint256 newCap) external step {
        // usually a modest cut, so the budget keeps binding without ending all trading
        uint128 c = uint128(newCap % 8 == 0 ? bound(newCap, 0, mCap) : bound(newCap, mCap / 2, mCap));
        (bool ok,) = _ownerExec(MODE_SINGLE, _moduleEc(abi.encodeCall(module.lowerCap, (c))), false);
        if (ok) {
            mCap = c;
            ++tighteningCalls;
        }
    }

    /// @dev Gated: an unconditional freeze would leave most of each sequence with no trading at all.
    function freeze(uint256 seed) external step {
        if (seed % 16 != 0) return;
        (bool ok,) = _ownerExec(MODE_SINGLE, _moduleEc(abi.encodeCall(module.freeze, ())), false);
        if (ok) {
            mFrozen = true;
            mCap = 0;
            ++mEpoch;
            ++tighteningCalls;
        }
    }

    function revokeSessions() external step {
        (bool ok,) = _ownerExec(MODE_SINGLE, _moduleEc(abi.encodeCall(module.revokeSessions, ())), false);
        if (ok) {
            ++mEpoch;
            ++tighteningCalls;
        }
    }

    function removeDestination(uint256 seed) external step {
        // the primary destination stays, so INV4 always has somewhere to exit to
        if (mDests.length < 2) return;
        address d = mDests[1 + seed % (mDests.length - 1)];
        (bool ok,) = _ownerExec(MODE_SINGLE, _moduleEc(abi.encodeCall(module.removeDestination, (d))), false);
        if (ok) {
            _removeFrom(mDests, d);
            ++tighteningCalls;
        }
    }

    function removeMarket(uint256 seed) external step {
        if (mMarkets.length == 0 || (seed >> 8) % 8 != 0) return;
        address m = mMarkets[seed % mMarkets.length];
        (bool ok,) = _ownerExec(MODE_SINGLE, _moduleEc(abi.encodeCall(module.removeMarket, (m))), false);
        if (ok) {
            _removeFrom(mMarkets, m);
            ++tighteningCalls;
        }
    }

    // =================================================================== attacks (all must fail)

    /// @dev Account executions on the owner path (a phished owner signature or a session key reach the
    ///      same hook). Every variant must revert.
    struct AttackCtx {
        address account;
        address thief;
        uint256 amount;
        uint256 seed;
        uint256 mi;
        uint256 tokenId;
        address st;
        address mk;
    }

    function attack(uint256 kindSeed, uint256 amount, uint256 seed) external step {
        uint256 k = kindSeed % 22;
        AttackCtx memory c;
        c.account = address(account);
        c.amount = bound(amount, 1, 1_000e6);
        c.thief = _pickThief(seed);
        c.seed = seed;
        (c.mi, c.tokenId) = _pickId(seed, seed >> 8);
        c.st = address(shareTokens[c.mi]);
        c.mk = address(markets[c.mi]);
        if (k == 21) return _attackQueuedDrain(c);
        (bytes32 mode, bytes memory ec) = k < 11 ? _attackA(k, c) : _attackB(k, c);
        _attackExec(mode, ec);
    }

    function _attackA(uint256 k, AttackCtx memory c) internal view returns (bytes32 mode, bytes memory ec) {
        mode = MODE_SINGLE;
        if (k == 0) {
            ec = abi.encodePacked(
                address(usdc), uint256(0), abi.encodeCall(usdc.transfer, (c.thief, c.amount))
            );
        } else if (k == 1) {
            ec = abi.encodePacked(
                address(usdc), uint256(0), abi.encodeCall(usdc.transferFrom, (c.account, c.thief, c.amount))
            );
        } else if (k == 2) {
            ec = abi.encodePacked(
                address(usdc), uint256(0), abi.encodeCall(usdc.approve, (c.thief, type(uint256).max))
            );
        } else if (k == 3) {
            ec = abi.encodePacked(
                address(usdc),
                uint256(0),
                abi.encodeWithSignature("increaseAllowance(address,uint256)", c.thief, c.amount)
            );
        } else if (k == 4) {
            ec = abi.encodePacked(
                address(usdc),
                uint256(0),
                abi.encodeCall(
                    usdc.permit,
                    (c.account, c.thief, c.amount, block.timestamp, uint8(27), bytes32(0), bytes32(0))
                )
            );
        } else if (k == 5) {
            ec = abi.encodePacked(
                c.st, uint256(0), abi.encodeCall(IERC1155.setApprovalForAll, (c.thief, true))
            );
        } else if (k == 6) {
            ec = abi.encodePacked(
                c.st,
                uint256(0),
                abi.encodeCall(IERC1155.safeTransferFrom, (c.account, c.thief, c.tokenId, 1, ""))
            );
        } else if (k == 7) {
            uint256[] memory ids = new uint256[](2);
            uint256[] memory amts = new uint256[](2);
            (ids[0], ids[1]) = _ids(marketIds[c.mi][0]);
            amts[0] = 1;
            amts[1] = 1;
            ec = abi.encodePacked(
                c.st,
                uint256(0),
                abi.encodeCall(IERC1155.safeBatchTransferFrom, (c.account, c.thief, ids, amts, ""))
            );
        } else if (k == 8) {
            ec = abi.encodePacked(c.thief, uint256(1), ""); // native value to a non-destination
        } else if (k == 9) {
            ec = abi.encodePacked(
                address(drainer), uint256(0), abi.encodeCall(Drainer.drain, (address(usdc), attacker))
            );
        } else if (k == 10) {
            mode = MODE_DELEGATECALL;
            ec = abi.encodePacked(address(drainer), abi.encodeCall(Drainer.drain, (address(usdc), attacker)));
        }
    }

    function _attackB(uint256 k, AttackCtx memory c) internal returns (bytes32 mode, bytes memory ec) {
        mode = MODE_SINGLE;
        if (k == 11) {
            // self-call: install the attacker as an executor
            ec = abi.encodePacked(
                c.account,
                uint256(0),
                abi.encodeCall(MockAccount.installModule, (MODULE_TYPE_EXECUTOR, address(drainer), ""))
            );
        } else if (k == 12) {
            ec = abi.encodePacked(
                c.account,
                uint256(0),
                abi.encodeCall(MockAccount.uninstallModule, (MODULE_TYPE_HOOK, address(hook), ""))
            );
        } else if (k == 13) {
            ec = abi.encodePacked(address(hook), uint256(0), abi.encodeCall(hook.onUninstall, ("")));
        } else if (k == 14) {
            // re-install the module with the attacker as destination (would skip the queue)
            ec = _moduleEc(
                abi.encodeCall(
                    module.onInstall,
                    (abi.encode(
                            uint128(1e30), new address[](0), _one(c.thief), new address[](0), new address[](0)
                        ))
                )
            );
        } else if (k == 15) {
            ec = _moduleEc(abi.encodeCall(module.onUninstall, ("")));
        } else if (k == 16) {
            // module.execute must run alone: hide a theft next to it
            Execution[] memory execs = new Execution[](2);
            bytes32 pid = pending.length > 0 ? pending[c.seed % pending.length].id : bytes32(c.seed);
            execs[0] = Execution(address(module), 0, abi.encodeCall(module.execute, (pid)));
            execs[1] = Execution(address(usdc), 0, abi.encodeCall(usdc.transfer, (c.thief, c.amount)));
            mode = MODE_BATCH;
            ec = abi.encode(execs);
        } else if (k == 17) {
            // A5: market proceeds to the attacker
            ec = abi.encodePacked(
                c.mk, uint256(0), _fill(c.mi, IReferenceMarket.Side.Sell, c.tokenId, 0.5e6, c.amount, c.thief)
            );
        } else if (k == 18) {
            // A1 hidden in a batch with a legitimate trade
            Execution[] memory execs = new Execution[](2);
            execs[0] = Execution(
                c.mk, 0, _fill(c.mi, IReferenceMarket.Side.Sell, c.tokenId, 0.5e6, c.amount, c.account)
            );
            execs[1] = Execution(address(usdc), 0, abi.encodeCall(usdc.transfer, (c.thief, 1)));
            mode = MODE_BATCH;
            ec = abi.encode(execs);
        } else if (k == 19) {
            // try-mode does not soften the pre-check
            mode = MODE_TRY_SINGLE;
            ec = abi.encodePacked(
                address(usdc), uint256(0), abi.encodeCall(usdc.transfer, (c.thief, c.amount))
            );
        } else {
            // the account calling consume() would let it burn or skip budget accounting
            ec = _moduleEc(abi.encodeCall(module.consume, (c.account, 0)));
        }
    }

    function _attackQueuedDrain(AttackCtx memory c) internal {
        {
            // queue a drain as a ConfigCall and try to run it immediately (A10); then cancel it
            bytes memory cc =
                abi.encode(address(usdc), uint256(0), abi.encodeCall(usdc.transfer, (c.thief, c.amount)));
            (bool qok, Vm.Log[] memory logs) = _ownerExec(
                MODE_SINGLE,
                _moduleEc(abi.encodeCall(module.queue, (IFirewallModule.ChangeKind.ConfigCall, cc))),
                false
            );
            if (!qok) return;
            bytes32 id = _queuedId(logs);
            _attackExec(MODE_SINGLE, _moduleEc(abi.encodeCall(module.execute, (id))));
            _ownerExec(MODE_SINGLE, _moduleEc(abi.encodeCall(module.cancel, (id))), false);
        }
    }

    /// @dev Calls an attacker can make without any account signature.
    function attackDirect(uint256 kindSeed, uint256 amount) external step {
        uint256 k = kindSeed % 7;
        amount = bound(amount, 0, 1_000e6);
        bool ok;
        ++attackAttempts;
        vm.startPrank(attacker);
        if (k == 0) {
            (ok,) = address(account)
                .call(
                    abi.encodeCall(
                        MockAccount.execute,
                        (
                            MODE_SINGLE,
                            abi.encodePacked(
                                address(usdc), uint256(0), abi.encodeCall(usdc.transfer, (attacker, amount))
                            )
                        )
                    )
                );
        } else if (k == 1) {
            (ok,) = address(account)
                .call(
                    abi.encodeCall(
                        MockAccount.executeFromExecutor,
                        (
                            MODE_SINGLE,
                            abi.encodePacked(
                                address(usdc), uint256(0), abi.encodeCall(usdc.transfer, (attacker, amount))
                            )
                        )
                    )
                );
        } else if (k == 2) {
            (ok,) = address(module).call(abi.encodeCall(module.consume, (address(account), amount)));
        } else if (k == 3) {
            // forged hookData claiming to be the account
            bytes memory forged = abi.encode(
                address(account), new address[](0), new FirewallHook.Asset[](0), new uint256[](0), true
            );
            (ok,) = address(hook).call(abi.encodeCall(hook.postCheck, (forged)));
        } else if (k == 4) {
            (ok,) = address(account)
                .call(abi.encodeCall(MockAccount.installModule, (MODULE_TYPE_EXECUTOR, address(drainer), "")));
        } else if (k == 5) {
            (ok,) = address(module)
                .call(
                    abi.encodeCall(
                        module.execute,
                        (pending.length > 0 ? pending[amount % pending.length].id : bytes32(amount))
                    )
                );
        } else {
            (ok,) = address(module).call(abi.encodeCall(module.lowerCap, (0)));
            // succeeds only for the attacker's own (uninitialised) state; it must revert
        }
        vm.stopPrank();
        if (ok) ++attackSuccesses;
    }

    /// @dev Exits to an address that is not (or no longer) a destination must fail.
    function exitToUnregistered(uint256 seed, uint256 amount) external step {
        address to = candidates[seed % 3];
        if (_inList(mDests, to)) return;
        amount = bound(amount, 1, 1_000e6);
        _attackExec(
            MODE_SINGLE,
            abi.encodePacked(address(usdc), uint256(0), abi.encodeCall(usdc.transfer, (to, amount)))
        );
    }

    // =================================================================== INV4 (called from invariant)

    /// @notice Exit every tracked asset to the primary destination, then roll back. Returns false on failure.
    function exitAllSucceeds() external returns (bool) {
        uint256 snap = vm.snapshotState();
        bool good = _exitAll();
        vm.revertToState(snap);
        return good;
    }

    function _exitAll() internal returns (bool) {
        address to = primaryDest;
        Execution[] memory execs = new Execution[](mTokens.length + 1 + 2 * MAX_IDS_PER_MARKET * 2);
        uint256 n;
        uint256[] memory expectTok = new uint256[](mTokens.length);
        for (uint256 i; i < mTokens.length; ++i) {
            uint256 b = IERC20Min(mTokens[i]).balanceOf(address(account));
            expectTok[i] = IERC20Min(mTokens[i]).balanceOf(to) + b;
            if (b > 0) execs[n++] = Execution(mTokens[i], 0, abi.encodeCall(usdc.transfer, (to, b)));
        }
        uint256 eth = address(account).balance;
        if (eth > 0) execs[n++] = Execution(to, eth, "");
        for (uint256 mi; mi < 2; ++mi) {
            if (!_inList(mMarkets, address(markets[mi]))) continue;
            for (uint256 j; j < nMarketIds[mi]; ++j) {
                (uint256 yes, uint256 no) = _ids(marketIds[mi][j]);
                uint256[2] memory both = [yes, no];
                for (uint256 x; x < 2; ++x) {
                    uint256 b = shareTokens[mi].balanceOf(address(account), both[x]);
                    if (b == 0) continue;
                    execs[n++] = Execution(
                        address(shareTokens[mi]),
                        0,
                        abi.encodeCall(IERC1155.safeTransferFrom, (address(account), to, both[x], b, ""))
                    );
                }
            }
        }
        if (n == 0) return true;
        assembly ("memory-safe") {
            mstore(execs, n)
        }
        uint256 ethTo = to.balance + eth;
        vm.prank(entryPoint);
        (bool ok,) =
            address(account).call(abi.encodeCall(MockAccount.execute, (MODE_BATCH, abi.encode(execs))));
        if (!ok) return false;
        for (uint256 i; i < mTokens.length; ++i) {
            if (IERC20Min(mTokens[i]).balanceOf(address(account)) != 0) return false;
            if (IERC20Min(mTokens[i]).balanceOf(to) != expectTok[i]) return false;
        }
        if (address(account).balance != 0 || to.balance != ethTo) return false;
        for (uint256 mi; mi < 2; ++mi) {
            if (!_inList(mMarkets, address(markets[mi]))) continue;
            for (uint256 j; j < nMarketIds[mi]; ++j) {
                (uint256 yes, uint256 no) = _ids(marketIds[mi][j]);
                if (shareTokens[mi].balanceOf(address(account), yes) != 0) return false;
                if (shareTokens[mi].balanceOf(address(account), no) != 0) return false;
            }
        }
        return true;
    }

    // =================================================================== views for the invariants

    function expectedDests() external view returns (address[] memory) {
        return mDests;
    }

    function expectedMarkets() external view returns (address[] memory) {
        return mMarkets;
    }

    function expectedTokens() external view returns (address[] memory) {
        return mTokens;
    }

    function consumptionCount() external view returns (uint256) {
        return cTime.length;
    }

    function candidateList() external view returns (address[3] memory) {
        return candidates;
    }

    /// @notice All (shareToken, id) pairs that have existed, for balance checks.
    function allShareIds() public view returns (address[] memory, uint256[] memory) {
        return (shareTok, shareId);
    }

    /// @notice Value held by `who`: ERC-20s at $1, every share at $1 (an upper bound), plus native balance.
    function valueOf(address who) public view returns (uint256 v) {
        v = usdc.balanceOf(who) + token2.balanceOf(who) + who.balance;
        for (uint256 i; i < shareId.length; ++i) {
            v += OutcomeShares(shareTok[i]).balanceOf(who, shareId[i]);
        }
    }

    /// @notice ERC-20 and native balances of `who` (shares are covered by the event-based leak check).
    function liquidOf(address who) public view returns (uint256) {
        return usdc.balanceOf(who) + token2.balanceOf(who) + who.balance;
    }

    function makerValue() public view returns (uint256) {
        return valueOf(maker);
    }

    /// @notice INV2. For every consumption i taken as a window start, and every later consumption k with
    ///         t_k - t_i < 3600: sum(amount i..k) <= availBefore_i + maxCap * (t_k - t_i) / 3600.
    ///         This implies the plan's form (<= cap + level at window start) for windows starting at any time.
    function windowViolations() external view returns (uint256 bad) {
        uint256 n = cTime.length;
        for (uint256 i; i < n; ++i) {
            uint256 sum;
            for (uint256 k = i; k < n; ++k) {
                uint256 dt = cTime[k] - cTime[i];
                if (dt >= 3600) break;
                sum += cAmount[k];
                if (sum * 3600 > cAvailBefore[i] * 3600 + maxCap * dt) ++bad;
                if (sum > cAvailBefore[i] + maxCap) ++bad;
            }
        }
    }

    // =================================================================== internals

    function _trade(bytes32 mode, bytes memory ec) internal {
        (bool ok,) = _ownerExec(mode, ec, true);
        if (ok) ++tradesOk;
        else ++tradesFailed;
    }

    function _attackExec(bytes32 mode, bytes memory ec) internal {
        ++attackAttempts;
        uint256 ethBefore = _zoneEth();
        vm.recordLogs();
        vm.prank(entryPoint);
        (bool ok,) = address(account).call(abi.encodeCall(MockAccount.execute, (mode, ec)));
        Vm.Log[] memory logs = vm.getRecordedLogs();
        (Flow[] memory f, uint256 n, uint256 leak) = _flows(logs);
        bool anyOut;
        for (uint256 i; i < n; ++i) {
            if (f[i].out > 0) anyOut = true;
        }
        if (ok || anyOut || _zoneEth() < ethBefore) ++attackSuccesses;
        leakedToUnregistered += leak;
    }

    /// @dev Runs an owner-path execution and checks R4/R5 accounting on success: the budget consumed must
    ///      equal max(0, ERC-20 out + shares out - ERC-20 in) over the trust zone (account + destinations),
    ///      and be zero without a market call. Value flows are read from the token events of the execution.
    function _ownerExec(bytes32 mode, bytes memory ec, bool hasMarketCall)
        internal
        returns (bool ok, Vm.Log[] memory logs)
    {
        uint256 availBefore = module.availableBudget(address(account));
        uint256 ethBefore = _zoneEth();

        vm.recordLogs();
        vm.prank(entryPoint);
        bytes memory ret;
        (ok, ret) = address(account).call(abi.encodeCall(MockAccount.execute, (mode, ec)));
        logs = vm.getRecordedLogs();
        if (!ok) {
            if (ret.length >= 4 && bytes4(ret) == FirewallErrors.BudgetExceeded.selector) ++budgetExceeded;
            return (ok, logs);
        }
        if (_zoneEth() < ethBefore) leakedToUnregistered += ethBefore - _zoneEth();

        uint256 consumed;
        uint256 events;
        for (uint256 i; i < logs.length; ++i) {
            if (logs[i].emitter == address(module) && logs[i].topics[0] == BUDGET_CONSUMED) {
                (uint256 amt,) = abi.decode(logs[i].data, (uint256, uint256));
                consumed += amt;
                ++events;
            }
        }
        if (events > 0) {
            cTime.push(block.timestamp);
            cAmount.push(consumed);
            cAvailBefore.push(availBefore);
            totalConsumed += consumed;
        }

        (Flow[] memory f, uint256 n, uint256 leak) = _flows(logs);
        leakedToUnregistered += leak;
        uint256 out;
        uint256 inflow;
        for (uint256 i; i < n; ++i) {
            if (f[i].out > f[i].inn) out += f[i].out - f[i].inn;
            else if (!f[i].isShare) inflow += f[i].inn - f[i].out;
        }
        uint256 expected = out > inflow ? out - inflow : 0;
        if (!hasMarketCall) {
            if (events != 0 || out != 0) ++budgetMismatches; // R5 / R3: no market call, no charge, no drop
        } else if (consumed != expected) {
            ++budgetMismatches;
        }
    }

    struct Flow {
        address token;
        uint256 id;
        bool isShare;
        uint256 out; // left the trust zone
        uint256 inn; // entered the trust zone
    }

    bytes32 internal constant ERC20_TRANSFER = keccak256("Transfer(address,address,uint256)");
    bytes32 internal constant TRANSFER_SINGLE =
        keccak256("TransferSingle(address,address,address,uint256,uint256)");
    bytes32 internal constant TRANSFER_BATCH =
        keccak256("TransferBatch(address,address,address,uint256[],uint256[])");

    /// @dev Net zone flows per asset, and the amount sent out of the zone to anyone other than a market
    ///      counterparty (the maker, a market contract, or a burn).
    function _flows(Vm.Log[] memory logs) internal view returns (Flow[] memory f, uint256 n, uint256 leak) {
        f = new Flow[](logs.length * 2 + 1);
        for (uint256 i; i < logs.length; ++i) {
            Vm.Log memory l = logs[i];
            if (l.topics.length == 0) continue;
            if ((l.emitter == address(usdc) || l.emitter == address(token2)) && l.topics[0] == ERC20_TRANSFER)
            {
                (n, leak) = _record(
                    f,
                    n,
                    leak,
                    l.emitter,
                    0,
                    false,
                    _a(l.topics[1]),
                    _a(l.topics[2]),
                    abi.decode(l.data, (uint256))
                );
            } else if (l.emitter == address(shareTokens[0]) || l.emitter == address(shareTokens[1])) {
                if (l.topics[0] == TRANSFER_SINGLE) {
                    (uint256 id, uint256 v) = abi.decode(l.data, (uint256, uint256));
                    (n, leak) = _record(f, n, leak, l.emitter, id, true, _a(l.topics[2]), _a(l.topics[3]), v);
                } else if (l.topics[0] == TRANSFER_BATCH) {
                    (uint256[] memory ids, uint256[] memory vs) = abi.decode(l.data, (uint256[], uint256[]));
                    for (uint256 j; j < ids.length; ++j) {
                        if (n == f.length) break;
                        (n, leak) = _record(
                            f, n, leak, l.emitter, ids[j], true, _a(l.topics[2]), _a(l.topics[3]), vs[j]
                        );
                    }
                }
            }
        }
    }

    function _record(
        Flow[] memory f,
        uint256 n,
        uint256 leak,
        address token,
        uint256 id,
        bool isShare,
        address from,
        address to,
        uint256 amt
    ) internal view returns (uint256, uint256) {
        bool fz = _isZone(from);
        bool tz = _isZone(to);
        if (fz == tz) return (n, leak);
        uint256 k;
        while (k < n && !(f[k].token == token && f[k].id == id && f[k].isShare == isShare)) ++k;
        if (k == n) {
            if (n == f.length) return (n, leak);
            f[n++] = Flow(token, id, isShare, 0, 0);
        }
        if (fz) {
            f[k].out += amt;
            if (to != maker && to != address(markets[0]) && to != address(markets[1]) && to != address(0)) {
                leak += amt;
            }
        } else {
            f[k].inn += amt;
        }
        return (n, leak);
    }

    function _isZone(address a) internal view returns (bool) {
        return a == address(account) || _inList(mDests, a);
    }

    function _zoneEth() internal view returns (uint256 v) {
        v = address(account).balance;
        for (uint256 i; i < mDests.length; ++i) {
            v += mDests[i].balance;
        }
    }

    /// @dev ReferenceMarket.outcomeIds, inlined (it is pure) to save an external call per lookup.
    function _ids(uint256 marketId) internal pure returns (uint256 yes, uint256 no) {
        yes = marketId << 1;
        no = (marketId << 1) | 1;
    }

    function _a(bytes32 t) internal pure returns (address) {
        return address(uint160(uint256(t)));
    }

    function _afterStep() internal {
        if (mCap > maxCap) maxCap = mCap;
    }

    function _cacheIds(uint256 mi, uint256 marketId) internal {
        (uint256 yes, uint256 no) = _ids(marketId);
        shareTok.push(address(shareTokens[mi]));
        shareId.push(yes);
        shareTok.push(address(shareTokens[mi]));
        shareId.push(no);
    }

    function _applyChange(Pending memory p) internal {
        if (p.kind == IFirewallModule.ChangeKind.AddDestination) {
            address d = abi.decode(p.data, (address));
            mDests.push(d);
            everRegistered[d] = true;
        } else if (p.kind == IFirewallModule.ChangeKind.AddMarket) {
            (address m,) = abi.decode(p.data, (address, address));
            mMarkets.push(m);
        } else if (p.kind == IFirewallModule.ChangeKind.AddToken) {
            mTokens.push(abi.decode(p.data, (address)));
        } else if (p.kind == IFirewallModule.ChangeKind.RaiseCap) {
            mCap = abi.decode(p.data, (uint128));
        } else if (p.kind == IFirewallModule.ChangeKind.Unfreeze) {
            mFrozen = false;
        }
    }

    function _removePending(uint256 i) internal {
        pending[i] = pending[pending.length - 1];
        pending.pop();
    }

    function _queuedId(Vm.Log[] memory logs) internal view returns (bytes32) {
        for (uint256 i; i < logs.length; ++i) {
            if (logs[i].emitter == address(module) && logs[i].topics[0] == CHANGE_QUEUED) {
                return logs[i].topics[2];
            }
        }
        revert("no ChangeQueued");
    }

    function _countExit(bool expectOk, bool ok) internal {
        if (ok) ++exitsOk;
        else if (expectOk) ++exitsFailed;
    }

    function _fill(
        uint256 mi,
        IReferenceMarket.Side side,
        uint256 tokenId,
        uint256 price,
        uint256 amount,
        address recipient
    ) internal returns (bytes memory) {
        IReferenceMarket.Order memory o = IReferenceMarket.Order({
            maker: maker,
            tokenId: tokenId,
            side: side,
            price: price,
            amount: amount,
            expiry: block.timestamp + 1 days,
            salt: ++salt
        });
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(makerKey, markets[mi].hashOrder(o));
        return abi.encodeCall(IReferenceMarket.fill, (o, abi.encodePacked(r, s, v), amount, recipient));
    }

    function _moduleEc(bytes memory data) internal view returns (bytes memory) {
        return abi.encodePacked(address(module), uint256(0), data);
    }

    /// @dev Mostly a registered market and an unresolved id, so most trades can succeed; the rest (1 in 8)
    ///      deliberately hit unregistered markets and resolved ids.
    function _pickMarketId(uint256 mSeed, uint256 idSeed)
        internal
        view
        returns (uint256 mi, uint256 marketId)
    {
        mi = mSeed % 2;
        if (!_inList(mMarkets, address(markets[mi])) && (mSeed >> 8) % 8 != 0) mi = 1 - mi;
        uint256 n = nMarketIds[mi];
        uint256 start = idSeed % n;
        marketId = marketIds[mi][start];
        if ((idSeed >> 8) % 8 == 0) return (mi, marketId);
        for (uint256 i; i < n; ++i) {
            uint256 id = marketIds[mi][(start + i) % n];
            if (!resolved[mi][id]) return (mi, id);
        }
    }

    function _pickResolved(uint256 mSeed, uint256 idSeed)
        internal
        view
        returns (uint256 mi, uint256 marketId)
    {
        (mi, marketId) = _pickMarketId(mSeed, idSeed);
        uint256 n = nMarketIds[mi];
        for (uint256 i; i < n; ++i) {
            uint256 id = marketIds[mi][(idSeed + i) % n];
            if (resolved[mi][id]) return (mi, id);
        }
    }

    /// @dev Up to the balance, and 1 in 8 times past it (which must fail without side effects).
    function _boundHeld(uint256 amount, uint256 bal) internal pure returns (uint256) {
        if (bal == 0 || amount % 8 == 0) return bound(amount, 1, bal + 10e6);
        return bound(amount, 1, bal);
    }

    function _pickId(uint256 mSeed, uint256 idSeed) internal view returns (uint256 mi, uint256 tokenId) {
        uint256 marketId;
        (mi, marketId) = _pickMarketId(mSeed, idSeed);
        (uint256 yes, uint256 no) = _ids(marketId);
        tokenId = (idSeed >> 4) % 2 == 0 ? yes : no;
    }

    /// @dev The account or a registered destination.
    function _pickZone(uint256 seed) internal view returns (address) {
        uint256 i = seed % (mDests.length + 1);
        return i == 0 ? address(account) : mDests[i - 1];
    }

    function _pickDest(uint256 seed) internal view returns (address) {
        return mDests[seed % mDests.length];
    }

    function _pickThief(uint256 seed) internal view returns (address) {
        uint256 r = seed % 3;
        if (r == 0) return attacker;
        if (r == 1) return address(drainer);
        // an unregistered candidate destination (falls back to the attacker if all are registered)
        for (uint256 i; i < 3; ++i) {
            address c = candidates[(seed + i) % 3];
            if (!_inList(mDests, c)) return c;
        }
        return attacker;
    }

    function _inList(address[] storage list, address a) internal view returns (bool) {
        for (uint256 i; i < list.length; ++i) {
            if (list[i] == a) return true;
        }
        return false;
    }

    function _removeFrom(address[] storage list, address a) internal {
        for (uint256 i; i < list.length; ++i) {
            if (list[i] == a) {
                list[i] = list[list.length - 1];
                list.pop();
                return;
            }
        }
    }

    function _one(address a) internal pure returns (address[] memory out) {
        out = new address[](1);
        out[0] = a;
    }
}
