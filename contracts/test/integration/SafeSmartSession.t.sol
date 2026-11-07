// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {
    RhinestoneModuleKit,
    AccountInstance,
    AccountType,
    UserOpData
} from "modulekit/test/RhinestoneModuleKit.sol";
import {ModuleKitHelpers} from "modulekit/test/ModuleKitHelpers.sol";
import {MockPolicy} from "modulekit/Mocks.sol";
import {
    Session,
    PolicyData,
    ActionData,
    ERC7739Data,
    ISessionValidator
} from "modulekit/integrations/interfaces/ISmartSession.sol";

import {FirewallModule} from "../../src/FirewallModule.sol";
import {FirewallHook} from "../../src/FirewallHook.sol";
import {ReferenceMarketAdapter} from "../../src/adapters/ReferenceMarketAdapter.sol";
import {IFirewallModule} from "../../src/interfaces/IFirewallModule.sol";
import {FirewallErrors} from "../../src/interfaces/FirewallErrors.sol";
import {IReferenceMarket} from "../../src/interfaces/IReferenceMarket.sol";
import {
    MODULE_TYPE_EXECUTOR,
    MODULE_TYPE_HOOK,
    MODULE_TYPE_VALIDATOR
} from "../../src/interfaces/IERC7579.sol";
import {MockUSDC} from "../fixtures/MockUSDC.sol";
import {ReferenceMarket, OutcomeShares} from "../fixtures/ReferenceMarket.sol";

/// @notice M0 acceptance: a real Safe + Safe7579 account with Smart Sessions and the firewall hook
///         executes one session user operation, and the hook blocks session attacks on the same path.
contract SafeSmartSessionTest is RhinestoneModuleKit, Test {
    using ModuleKitHelpers for AccountInstance;
    using ModuleKitHelpers for UserOpData;

    uint128 internal constant CAP = 1_000e6;

    AccountInstance internal instance;
    MockUSDC internal usdc;
    ReferenceMarket internal market;
    OutcomeShares internal shares;
    ReferenceMarketAdapter internal adapter;
    FirewallHook internal hook;
    FirewallModule internal module;
    MockPolicy internal allowAll;

    address internal dest = makeAddr("destination");
    address internal attacker = makeAddr("attacker");
    address internal maker;
    uint256 internal makerKey;
    uint256 internal yesId;
    uint256 internal salt;

    function setUp() public {
        ModuleKitHelpers.setAccountType(AccountType.SAFE);
        instance = makeAccountInstance("firewalled-safe");
        (maker, makerKey) = makeAddrAndKey("maker");

        usdc = new MockUSDC();
        market = new ReferenceMarket(usdc, address(this));
        shares = OutcomeShares(market.shares());
        adapter = new ReferenceMarketAdapter(market);
        allowAll = new MockPolicy();
        allowAll.setValidationData(instance.account, 0);

        address predicted = vm.computeCreateAddress(address(this), vm.getNonce(address(this)) + 1);
        hook = new FirewallHook(IFirewallModule(predicted));
        module = new FirewallModule(address(hook));

        uint256 marketId = market.createMarket("Will it rain tomorrow?");
        (yesId,) = market.outcomeIds(marketId);
        usdc.mint(maker, 1_000_000e6);
        vm.startPrank(maker);
        usdc.approve(address(market), type(uint256).max);
        shares.setApprovalForAll(address(market), true);
        market.split(marketId, 100_000e6);
        vm.stopPrank();

        // Install order matters: once the hook is on, further installs need the 24h queue.
        instance.installModule(MODULE_TYPE_VALIDATOR, address(instance.smartSession), "");
        instance.installModule(MODULE_TYPE_EXECUTOR, address(module), _moduleInit());
        instance.installModule(MODULE_TYPE_HOOK, address(hook), "");

        usdc.mint(instance.account, 10_000e6);
        instance.exec(address(usdc), abi.encodeCall(usdc.approve, (address(market), type(uint256).max)));
    }

    function test_M0_hookInstalledOnSafe7579() public {
        assertTrue(instance.isModuleInstalled(MODULE_TYPE_HOOK, address(hook)));
        assertTrue(instance.isModuleInstalled(MODULE_TYPE_EXECUTOR, address(module)));
        assertTrue(module.isInitialized(instance.account));
    }

    /// C2 on the real stack: a session key fills an order; the hook charges the budget.
    function test_M0_sessionFillsOrder() public {
        instance.useSession(
            _session(address(market), market.fill.selector), address(market), 0, _buyCall(100e6)
        );
        assertEq(shares.balanceOf(instance.account, yesId), 100e6);
        assertEq(module.availableBudget(instance.account), CAP - 50e6);
    }

    /// A1 from a session whose Smart Sessions policies would allow it: the hook still blocks it.
    function test_M0_sessionTransferToAttackerBlocked() public {
        Session memory s = _session(address(usdc), usdc.transfer.selector);
        // exact firewall error: the op passed Smart Sessions validation and the hook stopped it
        instance.expect4337Revert(
            abi.encodeWithSelector(FirewallErrors.UnexplainedOutflow.selector, address(usdc), 0)
        );
        instance.useSession(s, address(usdc), 0, abi.encodeCall(usdc.transfer, (attacker, 1e6)));
        assertEq(usdc.balanceOf(attacker), 0);
    }

    /// Control for the two tests around it: the same permissive session passes Smart Sessions
    /// validation and succeeds when the transfer goes to a registered destination.
    function test_M0_sessionTransferToDestinationAllowed() public {
        Session memory s = _session(address(usdc), usdc.transfer.selector);
        instance.useSession(s, address(usdc), 0, abi.encodeCall(usdc.transfer, (dest, 1e6)));
        assertEq(usdc.balanceOf(dest), 1e6);
    }

    /// A2 from a session: approving the attacker is blocked by R2.
    function test_M0_sessionApproveAttackerBlocked() public {
        Session memory s = _session(address(usdc), usdc.approve.selector);
        instance.expect4337Revert(
            abi.encodeWithSelector(FirewallErrors.UnregisteredSpender.selector, attacker)
        );
        instance.useSession(s, address(usdc), 0, abi.encodeCall(usdc.approve, (attacker, type(uint256).max)));
        assertEq(usdc.allowance(instance.account, attacker), 0);
    }

    /// C1 on the real stack: the owner exits to the registered destination.
    function test_M0_ownerExits() public {
        instance.exec(address(usdc), abi.encodeCall(usdc.transfer, (dest, 10_000e6)));
        assertEq(usdc.balanceOf(dest), 10_000e6);
    }

    /// A9 on the real stack: the owner cannot install another module once the hook is on.
    function test_M0_ownerInstallBlocked() public {
        instance.expect4337Revert(FirewallErrors.ForbiddenExecution.selector);
        instance.installModule(MODULE_TYPE_EXECUTOR, attacker, "");
    }

    // ---------------------------------------------------------------- helpers

    function _moduleInit() internal view returns (bytes memory) {
        address[] memory tokens = new address[](1);
        tokens[0] = address(usdc);
        address[] memory dests = new address[](1);
        dests[0] = dest;
        address[] memory markets = new address[](1);
        markets[0] = address(market);
        address[] memory adapters = new address[](1);
        adapters[0] = address(adapter);
        return abi.encode(CAP, tokens, dests, markets, adapters);
    }

    /// @dev A deliberately permissive session (allow-all policy, no ERC-1271 content), so any block
    ///      in these tests comes from the firewall hook, not from Smart Sessions.
    function _session(address target, bytes4 selector) internal view returns (Session memory) {
        PolicyData[] memory policies = new PolicyData[](1);
        policies[0] = PolicyData({policy: address(allowAll), initData: ""});
        ActionData[] memory actions = new ActionData[](1);
        actions[0] =
            ActionData({actionTargetSelector: selector, actionTarget: target, actionPolicies: policies});
        return Session({
            sessionValidator: ISessionValidator(address(instance.defaultSessionValidator)),
            sessionValidatorInitData: "mockInitData",
            salt: keccak256(abi.encode(target, selector)),
            userOpPolicies: policies,
            erc7739Policies: ERC7739Data({
                allowedERC7739Content: new string[](0), erc1271Policies: new PolicyData[](0)
            }),
            actions: actions
        });
    }

    function _buyCall(uint256 amount) internal returns (bytes memory) {
        IReferenceMarket.Order memory o = IReferenceMarket.Order({
            maker: maker,
            tokenId: yesId,
            side: IReferenceMarket.Side.Sell,
            price: 0.5e6,
            amount: amount,
            expiry: block.timestamp + 1 days,
            salt: ++salt
        });
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(makerKey, market.hashOrder(o));
        return abi.encodeCall(market.fill, (o, abi.encodePacked(r, s, v), amount, instance.account));
    }
}
