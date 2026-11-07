// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {FirewallModule} from "../src/FirewallModule.sol";
import {FirewallHook} from "../src/FirewallHook.sol";
import {ReferenceMarketAdapter} from "../src/adapters/ReferenceMarketAdapter.sol";
import {IFirewallModule} from "../src/interfaces/IFirewallModule.sol";
import {FirewallErrors} from "../src/interfaces/FirewallErrors.sol";
import {IReferenceMarket} from "../src/interfaces/IReferenceMarket.sol";
import {Execution, MODULE_TYPE_EXECUTOR, MODULE_TYPE_HOOK} from "../src/interfaces/IERC7579.sol";
import {MockUSDC} from "./fixtures/MockUSDC.sol";
import {ReferenceMarket, OutcomeShares} from "./fixtures/ReferenceMarket.sol";
import {MockAccount} from "./mocks/MockAccount.sol";

/// @notice Shared deployment and helpers. "Owner" executions arrive through the EntryPoint address,
///         exactly where a passkey-signed user operation would; the hook treats every signer alike.
abstract contract Base is Test {
    uint128 internal constant CAP = 1_000e6; // $1,000 per hour
    uint256 internal constant START_USDC = 10_000e6;
    uint256 internal constant ONE = 1e6;

    bytes32 internal constant MODE_SINGLE = bytes32(0);
    bytes32 internal constant MODE_BATCH = bytes32(bytes1(0x01));
    bytes32 internal constant MODE_DELEGATECALL = bytes32(bytes1(0xFF));

    MockUSDC internal usdc;
    ReferenceMarket internal market;
    OutcomeShares internal shares;
    ReferenceMarketAdapter internal adapter;
    FirewallHook internal hook;
    FirewallModule internal module;
    MockAccount internal account;

    address internal entryPoint = makeAddr("entryPoint");
    address internal dest = makeAddr("destination");
    address internal attacker = makeAddr("attacker");
    address internal maker;
    uint256 internal makerKey;

    uint256 internal marketId;
    uint256 internal yesId;
    uint256 internal noId;

    function setUp() public virtual {
        (maker, makerKey) = makeAddrAndKey("maker");

        usdc = new MockUSDC();
        market = new ReferenceMarket(usdc, address(this));
        shares = OutcomeShares(market.shares());
        adapter = new ReferenceMarketAdapter(market);

        // hook and module reference each other immutably: deploy the hook against the predicted module address
        address predicted = vm.computeCreateAddress(address(this), vm.getNonce(address(this)) + 1);
        hook = new FirewallHook(IFirewallModule(predicted));
        module = new FirewallModule(address(hook));
        assertEq(address(module), predicted, "module address prediction");

        account = _newAccount(address(adapter));

        marketId = market.createMarket("Will it rain tomorrow?");
        (yesId, noId) = market.outcomeIds(marketId);

        // maker liquidity
        usdc.mint(maker, 1_000_000e6);
        vm.startPrank(maker);
        usdc.approve(address(market), type(uint256).max);
        shares.setApprovalForAll(address(market), true);
        market.split(marketId, 100_000e6);
        vm.stopPrank();

        // account approvals go through the firewall like any other call (R2 allows registered markets)
        _exec(address(usdc), 0, abi.encodeCall(usdc.approve, (address(market), type(uint256).max)));
        _exec(address(shares), 0, abi.encodeCall(shares.setApprovalForAll, (address(market), true)));
    }

    function _newAccount(address adapter_) internal returns (MockAccount acc) {
        acc = new MockAccount(entryPoint);
        address[] memory tokens = new address[](1);
        tokens[0] = address(usdc);
        address[] memory dests = new address[](1);
        dests[0] = dest;
        address[] memory markets = new address[](1);
        markets[0] = address(market);
        address[] memory adapters = new address[](1);
        adapters[0] = adapter_;

        vm.startPrank(entryPoint);
        acc.installModule(
            MODULE_TYPE_EXECUTOR, address(module), abi.encode(CAP, tokens, dests, markets, adapters)
        );
        acc.installModule(MODULE_TYPE_HOOK, address(hook), "");
        vm.stopPrank();
        usdc.mint(address(acc), START_USDC);
    }

    // ---------------------------------------------------------------- execution helpers

    function _exec(address target, uint256 value, bytes memory data) internal {
        _execOn(account, target, value, data);
    }

    function _execOn(MockAccount acc, address target, uint256 value, bytes memory data) internal {
        vm.prank(entryPoint);
        acc.execute(MODE_SINGLE, abi.encodePacked(target, value, data));
    }

    function _execBatch(Execution[] memory execs) internal {
        vm.prank(entryPoint);
        account.execute(MODE_BATCH, abi.encode(execs));
    }

    /// @dev Owner-path call into the module, as the account.
    function _moduleCall(bytes memory data) internal {
        _exec(address(module), 0, data);
    }

    function _queue(IFirewallModule.ChangeKind kind, bytes memory data) internal returns (bytes32 id) {
        _moduleCall(abi.encodeCall(module.queue, (kind, data)));
        // id is deterministic: keccak(account, nonce, kind, data); nonce is the count of prior queue calls
        id = keccak256(abi.encode(address(account), _queued++, kind, data));
    }

    uint64 private _queued;

    // ---------------------------------------------------------------- orders

    uint256 private _salt;

    function _order(IReferenceMarket.Side side, uint256 tokenId, uint256 price, uint256 amount)
        internal
        returns (IReferenceMarket.Order memory o, bytes memory sig)
    {
        o = IReferenceMarket.Order({
            maker: maker,
            tokenId: tokenId,
            side: side,
            price: price,
            amount: amount,
            expiry: block.timestamp + 1 days,
            salt: ++_salt
        });
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(makerKey, market.hashOrder(o));
        sig = abi.encodePacked(r, s, v);
    }

    /// @dev Calldata for the account to fill a fresh maker order.
    function _fillCall(
        IReferenceMarket.Side makerSide,
        uint256 tokenId,
        uint256 price,
        uint256 amount,
        address recipient
    ) internal returns (bytes memory) {
        (IReferenceMarket.Order memory o, bytes memory sig) = _order(makerSide, tokenId, price, amount);
        return abi.encodeCall(market.fill, (o, sig, amount, recipient));
    }

    function _buy(uint256 tokenId, uint256 price, uint256 amount) internal {
        _exec(
            address(market),
            0,
            _fillCall(IReferenceMarket.Side.Sell, tokenId, price, amount, address(account))
        );
    }

    function _sell(uint256 tokenId, uint256 price, uint256 amount) internal {
        _exec(
            address(market), 0, _fillCall(IReferenceMarket.Side.Buy, tokenId, price, amount, address(account))
        );
    }

    /// @dev Give the account shares without touching its budget: the maker just sends them.
    function _giftShares(uint256 tokenId, uint256 amount) internal {
        vm.prank(maker);
        shares.safeTransferFrom(maker, address(account), tokenId, amount, "");
    }

    function _err(bytes4 sel) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(sel);
    }
}
