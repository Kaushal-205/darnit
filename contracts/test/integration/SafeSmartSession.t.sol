// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {FirewallDeploy} from "../utils/FirewallDeploy.sol";
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
    ISessionValidator,
    PermissionId
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
contract SafeSmartSessionTest is RhinestoneModuleKit, FirewallDeploy {
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

        Firewall memory f = _deployFirewall(address(instance.smartSession));
        (hook, module) = (f.hook, f.module);

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

    // ================================================================ M2: firewall-built sessions

    /// The module builds and enables the session (no free-form session config is ever signed).
    function test_M2_createSessionViaModule() public {
        Session memory s = _createFirewallSession();
        assertTrue(instance.smartSession.isPermissionEnabled(instance.smartSession.getPermissionId(s), instance.account));
    }

    /// C2 from a firewall session.
    function test_M2_C2_sessionFill() public {
        Session memory s = _createFirewallSession();
        instance.useSession(s, address(market), 0, _buyCall(100e6));
        assertEq(shares.balanceOf(instance.account, yesId), 100e6);
        assertEq(module.availableBudget(instance.account), CAP - 50e6);
    }

    function test_M2_A1_sessionTransferToAttacker() public {
        Session memory s = _createFirewallSession();
        instance.expect4337Revert(abi.encodeWithSelector(FirewallErrors.UnexplainedOutflow.selector, address(usdc), 0));
        instance.useSession(s, address(usdc), 0, abi.encodeCall(usdc.transfer, (attacker, 1e6)));
    }

    function test_M2_A2_sessionApproveAttacker() public {
        Session memory s = _createFirewallSession();
        instance.expect4337Revert(abi.encodeWithSelector(FirewallErrors.UnregisteredSpender.selector, attacker));
        instance.useSession(s, address(usdc), 0, abi.encodeCall(usdc.approve, (attacker, type(uint256).max)));
    }

    function test_M2_A3_sessionSetApprovalForAllAttacker() public {
        Session memory s = _createFirewallSession();
        instance.expect4337Revert(abi.encodeWithSelector(FirewallErrors.UnregisteredSpender.selector, attacker));
        instance.useSession(s, address(shares), 0, abi.encodeCall(shares.setApprovalForAll, (attacker, true)));
    }

    /// A4: rejected at validation by FirewallActionPolicy (unknown target), before the hook is reached.
    function test_M2_A4_sessionCallsUnknownContract() public {
        Session memory s = _createFirewallSession();
        instance.expect4337Revert();
        instance.useSession(s, attacker, 0, hex"12345678");
    }

    function test_M2_A5_sessionProceedsToAttacker() public {
        Session memory s = _createFirewallSession();
        bytes memory data = _fillCallTo(IReferenceMarket.Side.Sell, 0.5e6, 100e6, attacker);
        instance.expect4337Revert(abi.encodeWithSelector(FirewallErrors.UnexplainedOutflow.selector, address(market), 0));
        instance.useSession(s, address(market), 0, data);
    }

    function test_M2_A6_sessionDumpsSharesBeyondBudget() public {
        Session memory s = _createFirewallSession();
        vm.prank(maker);
        shares.safeTransferFrom(maker, instance.account, yesId, 2_000e6, "");
        instance.exec(address(shares), abi.encodeCall(shares.setApprovalForAll, (address(market), true)));
        bytes memory data = _fillCallTo(IReferenceMarket.Side.Buy, 0.01e6, 2_000e6, instance.account);
        instance.expect4337Revert(abi.encodeWithSelector(FirewallErrors.BudgetExceeded.selector, 1_980e6, uint256(CAP)));
        instance.useSession(s, address(market), 0, data);
    }

    function test_M2_A7_sessionBuysPastCap() public {
        Session memory s = _createFirewallSession();
        for (uint256 i; i < 5; ++i) {
            instance.useSession(s, address(market), 0, _buyCall(400e6)); // $200 each
        }
        instance.expect4337Revert(abi.encodeWithSelector(FirewallErrors.BudgetExceeded.selector, 200e6, 0));
        instance.useSession(s, address(market), 0, _buyCall(400e6));
    }

    /// A9: a session cannot reach the account itself, the module, or Smart Sessions (validation rejects).
    function test_M2_A9_sessionSelfCall() public {
        Session memory s = _createFirewallSession();
        instance.expect4337Revert();
        instance.useSession(s, instance.account, 0, abi.encodeWithSignature("installModule(uint256,address,bytes)", 2, attacker, ""));
    }

    function test_M2_A9_sessionCannotQueueChanges() public {
        Session memory s = _createFirewallSession();
        instance.expect4337Revert();
        instance.useSession(
            s,
            address(module),
            0,
            abi.encodeCall(module.queue, (IFirewallModule.ChangeKind.AddDestination, abi.encode(attacker)))
        );
    }

    function test_M2_A9_sessionCannotFreezeOrRevoke() public {
        Session memory s = _createFirewallSession();
        instance.expect4337Revert();
        instance.useSession(s, address(module), 0, abi.encodeCall(module.removeDestination, (dest)));
    }

    /// A11: the session key cannot produce an account signature (no ERC-7739 content, NoSignaturePolicy).
    function test_M2_A11_sessionCannotSign() public {
        Session memory s = _createFirewallSession();
        bytes32 permissionId = PermissionId.unwrap(instance.smartSession.getPermissionId(s));
        bytes32 hash = keccak256("permit to attacker");
        bytes memory sig = abi.encodePacked(address(instance.smartSession), permissionId, bytes("anything"));
        (bool ok, bytes memory ret) =
            instance.account.staticcall(abi.encodeWithSignature("isValidSignature(bytes32,bytes)", hash, sig));
        assertTrue(!ok || bytes4(ret) != bytes4(0x1626ba7e), "session produced a valid ERC-1271 signature");
    }

    /// A12: after freeze the session is dead at validation (epoch bumped, frozen).
    function test_M2_A12_sessionAfterFreeze() public {
        Session memory s = _createFirewallSession();
        instance.exec(address(module), abi.encodeCall(module.freeze, ()));
        instance.expect4337Revert();
        instance.useSession(s, address(market), 0, _buyCall(10e6));
    }

    function test_M2_sessionAfterRevoke() public {
        Session memory s = _createFirewallSession();
        instance.exec(address(module), abi.encodeCall(module.revokeSessions, ()));
        instance.expect4337Revert();
        instance.useSession(s, address(market), 0, _buyCall(10e6));
    }

    function test_M2_sessionAfterRemove() public {
        Session memory s = _createFirewallSession();
        bytes32 permissionId = PermissionId.unwrap(instance.smartSession.getPermissionId(s));
        instance.exec(address(module), abi.encodeCall(module.removeSession, (permissionId)));
        assertFalse(instance.smartSession.isPermissionEnabled(PermissionId.wrap(permissionId), instance.account));
    }

    function test_M2_sessionExpires() public {
        Session memory s = _createFirewallSession();
        vm.warp(block.timestamp + 7 days + 1);
        instance.expect4337Revert();
        instance.useSession(s, address(market), 0, _buyCall(10e6));
    }

    /// Owner cannot enable an arbitrary session by calling Smart Sessions directly: the hook refuses.
    function test_M2_ownerCannotEnableSessionDirectly() public {
        Session[] memory sessions = new Session[](1);
        sessions[0] = _session(address(usdc), usdc.transfer.selector);
        instance.expect4337Revert(
            abi.encodeWithSelector(
                FirewallErrors.UnknownTarget.selector, address(instance.smartSession), bytes4(keccak256("enableSessions((address,bytes,bytes32,(address,bytes)[],(string[],(address,bytes)[]),(bytes4,address,(address,bytes)[])[])[])"))
            )
        );
        instance.exec(address(instance.smartSession), abi.encodeWithSignature(
            "enableSessions((address,bytes,bytes32,(address,bytes)[],(string[],(address,bytes)[]),(bytes4,address,(address,bytes)[])[])[])", sessions
        ));
    }

    // ---------------------------------------------------------------- helpers

    function _createFirewallSession() internal returns (Session memory s) {
        uint48 validUntil = uint48(block.timestamp + 7 days);
        bytes32 sessionSalt = keccak256(abi.encode("session", ++salt));
        address validator = address(instance.defaultSessionValidator);
        instance.exec(
            address(module), abi.encodeCall(module.createSession, (validator, "mockInitData", sessionSalt, validUntil))
        );
        // our SSSession and ModuleKit's Session share one ABI
        s = abi.decode(abi.encode(module.buildSession(validator, "mockInitData", sessionSalt, validUntil)), (Session));
    }

    function _fillCallTo(IReferenceMarket.Side side, uint256 price, uint256 amount, address recipient)
        internal
        returns (bytes memory)
    {
        IReferenceMarket.Order memory o = IReferenceMarket.Order({
            maker: maker,
            tokenId: yesId,
            side: side,
            price: price,
            amount: amount,
            expiry: block.timestamp + 30 days,
            salt: ++salt
        });
        (uint8 v, bytes32 r, bytes32 sg) = vm.sign(makerKey, market.hashOrder(o));
        return abi.encodeCall(market.fill, (o, abi.encodePacked(r, sg, v), amount, recipient));
    }

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
            expiry: block.timestamp + 30 days,
            salt: ++salt
        });
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(makerKey, market.hashOrder(o));
        return abi.encodeCall(market.fill, (o, abi.encodePacked(r, s, v), amount, instance.account));
    }
}
