// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {RhinestoneModuleKit, AccountInstance, AccountType, UserOpData} from "modulekit/test/RhinestoneModuleKit.sol";
import {ModuleKitHelpers} from "modulekit/test/ModuleKitHelpers.sol";
import {MockPolicy, MockValidator} from "modulekit/Mocks.sol";
import {
    Session,
    PolicyData,
    ActionData,
    ERC7739Data,
    ISessionValidator,
    PermissionId
} from "modulekit/integrations/interfaces/ISmartSession.sol";
import {Safe7579Precompiles} from "modulekit/deployment/precompiles/Safe7579Precompiles.sol";

import {FirewallDeploy} from "../utils/FirewallDeploy.sol";
import {PasskeyHelper} from "../utils/PasskeyHelper.sol";
import {FirewallOwnerValidator} from "../../src/validators/FirewallOwnerValidator.sol";
import {FirewallModule} from "../../src/FirewallModule.sol";
import {FirewallHook} from "../../src/FirewallHook.sol";
import {ReferenceMarketAdapter} from "../../src/adapters/ReferenceMarketAdapter.sol";
import {IFirewallModule} from "../../src/interfaces/IFirewallModule.sol";
import {FirewallErrors} from "../../src/interfaces/FirewallErrors.sol";
import {MODULE_TYPE_EXECUTOR, MODULE_TYPE_HOOK, MODULE_TYPE_VALIDATOR} from "../../src/interfaces/IERC7579.sol";
import {MockUSDC} from "../fixtures/MockUSDC.sol";
import {ReferenceMarket} from "../fixtures/ReferenceMarket.sol";
import {SAFE7579_HEAD_CREATION_CODE} from "../fixtures/Safe7579Head.sol";
import {MockSmartSessions} from "../mocks/MockSmartSessions.sol";

interface IERC1271Like {
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4);
}

/// @dev Like real USDC since v2.2: EIP-2612 permit that accepts ERC-1271 signatures from contract accounts.
///      The transfer then happens in the attacker's own transaction, where the hook never runs.
contract Permit1271Token is ERC20 {
    bytes32 public constant PERMIT_TYPEHASH =
        keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");
    bytes32 public immutable DOMAIN_SEPARATOR;
    mapping(address => uint256) public nonces;

    constructor() ERC20("Permit Token", "PT") {
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("Permit Token"),
                keccak256("2"),
                block.chainid,
                address(this)
            )
        );
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    function permit(address owner, address spender, uint256 value, uint256 deadline, bytes calldata signature)
        external
    {
        bytes32 digest = keccak256(
            abi.encodePacked(
                hex"1901",
                DOMAIN_SEPARATOR,
                keccak256(abi.encode(PERMIT_TYPEHASH, owner, spender, value, nonces[owner]++, deadline))
            )
        );
        require(IERC1271Like(owner).isValidSignature(digest, signature) == 0x1626ba7e, "invalid signature");
        _approve(owner, spender, value);
    }
}

/// @notice Real Safe + Safe7579 + Smart Sessions (ModuleKit 0.5.9 bytecode), with the passkey as the only
///         validator able to sign for the owner. ModuleKit's accept-everything default validator is removed,
///         because it would otherwise authorise every attack below by itself.
contract OwnerValidatorTest is RhinestoneModuleKit, FirewallDeploy, PasskeyHelper {
    using ModuleKitHelpers for AccountInstance;
    using ModuleKitHelpers for UserOpData;

    uint128 internal constant CAP = 1_000e6;
    uint256 internal constant KEY = 0xA11CE;
    uint256 internal constant NEW_KEY = 0xB0B;
    bytes4 internal constant MAGIC = 0x1626ba7e;

    AccountInstance internal instance;
    MockUSDC internal usdc;
    ReferenceMarket internal market;
    ReferenceMarketAdapter internal adapter;
    FirewallHook internal hook;
    FirewallModule internal module;
    FirewallOwnerValidator internal validator;
    MockPolicy internal allowAll;
    Permit1271Token internal token;

    address internal dest = makeAddr("destination");
    address internal attacker = makeAddr("attacker");

    function setUp() public {
        ModuleKitHelpers.setAccountType(AccountType.SAFE);
        instance = makeAccountInstance("firewalled-safe");

        usdc = new MockUSDC();
        market = new ReferenceMarket(usdc, address(this));
        adapter = new ReferenceMarketAdapter(market);
        allowAll = new MockPolicy();
        token = new Permit1271Token();

        Firewall memory f = _deployFirewall(address(instance.smartSession));
        (hook, module) = (f.hook, f.module);
        validator = new FirewallOwnerValidator(IFirewallModule(address(module)));

        (bytes32 x, bytes32 y) = _publicKey(KEY);
        string[] memory types = new string[](1);
        types[0] = BENIGN;
        instance.installModule(MODULE_TYPE_VALIDATOR, address(instance.smartSession), "");
        instance.installModule(MODULE_TYPE_VALIDATOR, address(validator), abi.encode(x, y, types));
        instance.installModule(MODULE_TYPE_EXECUTOR, address(module), _moduleInit());
        instance.uninstallModule(MODULE_TYPE_VALIDATOR, address(instance.defaultValidator), "");

        // from here on the passkey signs everything
        UserOpData memory op =
            instance.getInstallModuleOps(MODULE_TYPE_HOOK, address(hook), "", address(validator));
        op.userOp.signature = abi.encode(_assert(KEY, op.userOpHash));
        op.execUserOps();

        allowAll.setValidationData(instance.account, 0);
        usdc.mint(instance.account, 10_000e6);
        token.mint(instance.account, 10_000e6);
    }

    function test_setup_passkeyIsTheOwnerValidator() public {
        assertTrue(instance.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(validator)));
        assertFalse(instance.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(instance.defaultValidator)));
        assertTrue(instance.isModuleInstalled(MODULE_TYPE_HOOK, address(hook)));
        assertTrue(validator.isInitialized(instance.account));
    }

    // ---------------------------------------------------------------- user operations

    function test_ownerUserOpWorks() public {
        _ownerExec(KEY, address(usdc), abi.encodeCall(usdc.transfer, (dest, 1e6)));
        assertEq(usdc.balanceOf(dest), 1e6);
    }

    function test_wrongKeyUserOpFails() public {
        instance.expect4337Revert();
        _ownerExec(NEW_KEY, address(usdc), abi.encodeCall(usdc.transfer, (dest, 1e6)));
        assertEq(usdc.balanceOf(dest), 0);
    }

    function test_ownerStillBoundedByHook() public {
        instance.expect4337Revert(abi.encodeWithSelector(FirewallErrors.UnexplainedOutflow.selector, address(usdc), 0));
        _ownerExec(KEY, address(usdc), abi.encodeCall(usdc.transfer, (attacker, 1e6)));
    }

    // ---------------------------------------------------------------- R6: key change

    function test_R6_directKeyChangeBlocked() public {
        (bytes32 x, bytes32 y) = _publicKey(NEW_KEY);
        instance.expect4337Revert(
            abi.encodeWithSelector(FirewallErrors.UnknownTarget.selector, address(validator), validator.setPasskey.selector)
        );
        _ownerExec(KEY, address(validator), abi.encodeCall(validator.setPasskey, (x, y)));
    }

    function test_R6_keyChangeThroughQueue() public {
        (bytes32 x, bytes32 y) = _publicKey(NEW_KEY);
        IFirewallModule.ChangeKind kind = IFirewallModule.ChangeKind.ConfigCall;
        bytes memory change =
            abi.encode(address(validator), uint256(0), abi.encodeCall(validator.setPasskey, (x, y)));
        _ownerExec(KEY, address(module), abi.encodeCall(module.queue, (kind, change)));
        bytes32 id = keccak256(abi.encode(instance.account, uint64(0), kind, change));

        instance.expect4337Revert(abi.encodeWithSelector(FirewallErrors.TooEarly.selector, block.timestamp + 24 hours));
        _ownerExec(KEY, address(module), abi.encodeCall(module.execute, (id)));

        vm.warp(block.timestamp + 24 hours);
        _ownerExec(KEY, address(module), abi.encodeCall(module.execute, (id)));

        _ownerExec(NEW_KEY, address(usdc), abi.encodeCall(usdc.transfer, (dest, 1e6)));
        assertEq(usdc.balanceOf(dest), 1e6);
        instance.expect4337Revert();
        _ownerExec(KEY, address(usdc), abi.encodeCall(usdc.transfer, (dest, 1e6)));
    }

    // ---------------------------------------------------------------- ERC-1271 on the real account

    function test_personalSignThroughAccount() public {
        bytes memory message = "Sign in to firewall.test";
        bytes memory sig = abi.encodePacked(address(validator), _personalEnvelope(KEY, instance.account, message));
        assertTrue(_isMagic(_personalHash(message), sig));
    }

    function test_allowedTypedDataThroughAccount() public {
        bytes memory data = abi.encode(attacker, uint256(1));
        bytes memory sig = abi.encodePacked(
            address(validator), _typedEnvelope(KEY, instance.account, APP_SEPARATOR, "Mail", BENIGN, data)
        );
        assertTrue(_isMagic(_appHash(APP_SEPARATOR, BENIGN, data), sig));
    }

    function test_rawHashThroughAccountRejected() public {
        bytes32 hash = keccak256("raw digest");
        assertFalse(_isMagic(hash, abi.encodePacked(address(validator), abi.encode(_assert(KEY, hash)))));
    }

    function test_removedDefaultValidatorCannotSign() public {
        assertFalse(_isMagic(keccak256("x"), abi.encodePacked(address(instance.defaultValidator), bytes32(0))));
    }

    // ---------------------------------------------------------------- A13

    function test_A13_permitToAttackerNotMagic() public {
        bytes memory sig = _permitSignature(attacker, 1_000e6);
        assertFalse(_isMagic(_permitHash(attacker, 1_000e6), sig));
    }

    function test_A13_permitToAttackerCannotMoveFunds() public {
        bytes memory sig = _permitSignature(attacker, 1_000e6);
        vm.prank(attacker);
        vm.expectRevert("invalid signature");
        token.permit(instance.account, attacker, 1_000e6, type(uint256).max, sig);
        assertEq(token.allowance(instance.account, attacker), 0);
        assertEq(token.balanceOf(attacker), 0);
    }

    /// The same permit, disguised: wrapped as a PersonalSign and as an allowlisted type.
    function test_A13_disguisedPermitsRejected() public {
        bytes32 hash = _permitHash(attacker, 1_000e6);
        FirewallOwnerValidator.SignatureEnvelope memory env;
        env.kind = FirewallOwnerValidator.EnvelopeKind.PersonalSign;
        env.data = abi.encodePacked(hash);
        env.auth = _assert(KEY, _personalDigest(instance.account, hash));
        assertFalse(_isMagic(hash, abi.encodePacked(address(validator), abi.encode(env))));

        bytes memory data = _permitData(attacker, 1_000e6);
        bytes memory disguised = _typedEnvelope(KEY, instance.account, token.DOMAIN_SEPARATOR(), "Mail", BENIGN, data);
        assertFalse(_isMagic(hash, abi.encodePacked(address(validator), disguised)));
    }

    function test_A13_control_permitToMarketWorks() public {
        bytes memory sig = _permitSignature(address(market), 1_000e6);
        assertTrue(_isMagic(_permitHash(address(market), 1_000e6), sig));
        token.permit(instance.account, address(market), 1_000e6, type(uint256).max, sig);
        assertEq(token.allowance(instance.account, address(market)), 1_000e6);
    }

    function _permitData(address spender, uint256 value) internal view returns (bytes memory) {
        return abi.encode(instance.account, spender, value, token.nonces(instance.account), type(uint256).max);
    }

    function _permitHash(address spender, uint256 value) internal view returns (bytes32) {
        return _appHash(token.DOMAIN_SEPARATOR(), EIP2612, _permitData(spender, value));
    }

    function _permitSignature(address spender, uint256 value) internal view returns (bytes memory) {
        return abi.encodePacked(
            address(validator),
            _typedEnvelope(
                KEY, instance.account, token.DOMAIN_SEPARATOR(), "Permit", EIP2612, _permitData(spender, value)
            )
        );
    }

    // ---------------------------------------------------------------- V8: Smart Sessions enable mode

    function test_V8_enableModeWithOwnerSignatureFails() public {
        Session memory s = _permissiveSession(instance);
        UserOpData memory op = instance.getExecOps(
            address(usdc), 0, abi.encodeCall(usdc.transfer, (dest, 1e6)), address(instance.smartSession)
        );
        op.userOp.signature = instance.encodeSignatureEnableMode(op.userOp, s, _signBareDigest, address(validator));
        instance.expect4337Revert();
        op.execUserOps();
        assertFalse(instance.smartSession.isPermissionEnabled(instance.smartSession.getPermissionId(s), instance.account));
        assertEq(usdc.balanceOf(dest), 0);
    }

    function test_V8_enableModeWrappedAsPersonalSignFails() public {
        Session memory s = _permissiveSession(instance);
        UserOpData memory op = instance.getExecOps(
            address(usdc), 0, abi.encodeCall(usdc.transfer, (dest, 1e6)), address(instance.smartSession)
        );
        op.userOp.signature = instance.encodeSignatureEnableMode(op.userOp, s, _signPersonalWrap, address(validator));
        instance.expect4337Revert();
        op.execUserOps();
        assertFalse(instance.smartSession.isPermissionEnabled(instance.smartSession.getPermissionId(s), instance.account));
    }

    /// Control: the same op on an account with a validator that accepts anything enables the
    /// permissive session. This is the V8 bypass, so the two tests above fail for the right reason.
    function test_V8_control_permissiveValidatorEnables() public {
        AccountInstance memory control = makeAccountInstance("control-safe");
        allowAll.setValidationData(control.account, 0);
        control.installModule(MODULE_TYPE_VALIDATOR, address(control.smartSession), "");
        usdc.mint(control.account, 10_000e6);

        Session memory s = _permissiveSession(control);
        UserOpData memory op = control.getExecOps(
            address(usdc), 0, abi.encodeCall(usdc.transfer, (dest, 1e6)), address(control.smartSession)
        );
        op.userOp.signature =
            control.encodeSignatureEnableMode(op.userOp, s, _signBareDigest, address(control.defaultValidator));
        op.execUserOps();
        assertTrue(control.smartSession.isPermissionEnabled(control.smartSession.getPermissionId(s), control.account));
        assertEq(usdc.balanceOf(dest), 1e6);
    }

    /// @dev What an attacker wants: a session that may call usdc and can produce ERC-1271 signatures.
    function _permissiveSession(AccountInstance memory acc) internal view returns (Session memory) {
        PolicyData[] memory policies = new PolicyData[](1);
        policies[0] = PolicyData({policy: address(allowAll), initData: ""});
        ActionData[] memory actions = new ActionData[](1);
        actions[0] = ActionData({
            actionTargetSelector: usdc.transfer.selector,
            actionTarget: address(usdc),
            actionPolicies: policies
        });
        string[] memory contents = new string[](1);
        contents[0] = EIP2612;
        return Session({
            sessionValidator: ISessionValidator(address(acc.defaultSessionValidator)),
            sessionValidatorInitData: "mockInitData",
            salt: keccak256("permissive"),
            userOpPolicies: policies,
            erc7739Policies: ERC7739Data({allowedERC7739Content: contents, erc1271Policies: policies}),
            actions: actions
        });
    }

    function _signBareDigest(bytes32 hash) internal pure returns (bytes memory) {
        return abi.encode(_assert(KEY, hash));
    }

    function _signPersonalWrap(bytes32 hash) internal returns (bytes memory) {
        FirewallOwnerValidator.SignatureEnvelope memory env;
        env.kind = FirewallOwnerValidator.EnvelopeKind.PersonalSign;
        env.data = abi.encodePacked(hash);
        env.auth = _assert(KEY, _personalDigest(instance.account, hash));
        return abi.encode(env);
    }

    // ---------------------------------------------------------------- helpers

    function _ownerExec(uint256 key, address target, bytes memory data) internal {
        UserOpData memory op = instance.getExecOps(target, 0, data, address(validator));
        op.userOp.signature = abi.encode(_assert(key, op.userOpHash));
        op.execUserOps();
    }

    function _isMagic(bytes32 hash, bytes memory signature) internal view returns (bool) {
        (bool ok, bytes memory ret) = instance.account.staticcall(
            abi.encodeWithSignature("isValidSignature(bytes32,bytes)", hash, signature)
        );
        return ok && ret.length >= 32 && bytes4(ret) == MAGIC;
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
}

// ================================================================== V11

interface ISafeSetup {
    function setup(
        address[] calldata owners,
        uint256 threshold,
        address to,
        bytes calldata data,
        address fallbackHandler,
        address paymentToken,
        uint256 payment,
        address payable paymentReceiver
    ) external;
    function enableModule(address module) external;
    function domainSeparator() external view returns (bytes32);
}

struct HeadModuleInit {
    address module;
    bytes initData;
    uint256 moduleType;
}

struct HeadRegistryInit {
    address registry;
    address[] attesters;
    uint8 threshold;
}

struct EmergencyUninstall {
    address hook;
    uint256 hookType;
    bytes deInitData;
    uint256 nonce;
}

interface ISafe7579Head {
    error EmergencyUninstallSigError();

    function initializeAccount(HeadModuleInit[] calldata modules, HeadRegistryInit calldata registryInit) external;
    function emergencyUninstallHook(EmergencyUninstall calldata data, bytes calldata signature) external;
    function isModuleInstalled(uint256 moduleType, address module, bytes calldata context)
        external
        view
        returns (bool);
}

/// @notice emergencyUninstallHook needs Safe7579 at HEAD (9f507f3): ModuleKit's bytecode doesn't have it. So this
///         suite runs on a real Safe singleton with the upstream build artifact as module and fallback handler.
contract OwnerValidatorEmergencyUninstallTest is FirewallDeploy, PasskeyHelper, Safe7579Precompiles {
    uint256 internal constant KEY = 0xA11CE;
    uint256 internal constant HOOK_TYPE = 4;
    bytes32 internal constant EMERGENCY_TYPEHASH = 0xd3ddfc12654178cc44d4a7b6b969cfdce7ffe6342326ba37825314cffa0fba9c;

    address internal safe;
    FirewallHook internal hook;
    FirewallModule internal module;
    FirewallOwnerValidator internal validator;
    MockValidator internal permissive;

    function setUp() public {
        Firewall memory f = _deployFirewall(address(new MockSmartSessions()));
        (hook, module) = (f.hook, f.module);
        validator = new FirewallOwnerValidator(IFirewallModule(address(module)));
        permissive = new MockValidator();

        address head;
        bytes memory code = SAFE7579_HEAD_CREATION_CODE;
        assembly ("memory-safe") {
            head := create(0, add(code, 0x20), mload(code))
        }
        assertTrue(head != address(0), "deploy Safe7579");

        address[] memory owners = new address[](1);
        owners[0] = makeAddr("no signer");
        safe = address(
            deploySafeProxyFactory().createProxyWithNonce(
                deploySafeSingleton(),
                abi.encodeCall(
                    ISafeSetup.setup,
                    (owners, 1, address(0), "", head, address(0), 0, payable(address(0)))
                ),
                0
            )
        );
        vm.prank(safe);
        ISafeSetup(safe).enableModule(head);

        MockUSDC usdc = new MockUSDC();
        address[] memory tokens = new address[](1);
        tokens[0] = address(usdc);
        address[] memory dests = new address[](1);
        dests[0] = makeAddr("destination");
        (bytes32 x, bytes32 y) = _publicKey(KEY);
        HeadModuleInit[] memory modules = new HeadModuleInit[](4);
        modules[0] = HeadModuleInit(address(validator), abi.encode(x, y, new string[](0)), MODULE_TYPE_VALIDATOR);
        modules[1] = HeadModuleInit(address(permissive), "", MODULE_TYPE_VALIDATOR);
        modules[2] = HeadModuleInit(
            address(module),
            abi.encode(uint128(1_000e6), tokens, dests, new address[](0), new address[](0)),
            MODULE_TYPE_EXECUTOR
        );
        modules[3] = HeadModuleInit(address(hook), "", MODULE_TYPE_HOOK);
        vm.prank(safe);
        ISafe7579Head(safe).initializeAccount(modules, HeadRegistryInit(address(0), new address[](0), 0));
    }

    function _data(uint256 nonce) internal view returns (EmergencyUninstall memory) {
        return EmergencyUninstall({hook: address(hook), hookType: HOOK_TYPE, deInitData: "", nonce: nonce});
    }

    function _contents(uint256 nonce) internal view returns (bytes memory) {
        return abi.encode(address(hook), HOOK_TYPE, keccak256(""), nonce);
    }

    /// The bare EIP-712 hash Safe7579 hands the validator.
    function _hash(uint256 nonce) internal view returns (bytes32) {
        return _appHash(ISafeSetup(safe).domainSeparator(), EMERGENCY_UNINSTALL, _contents(nonce));
    }

    function _hookInstalled() internal view returns (bool) {
        return ISafe7579Head(safe).isModuleInstalled(HOOK_TYPE, address(hook), "");
    }

    function test_setup_typeStringMatchesSafe7579() public view {
        assertEq(keccak256(bytes(EMERGENCY_UNINSTALL)), EMERGENCY_TYPEHASH);
        assertTrue(_hookInstalled());
    }

    function test_V11_ownerSignatureOnBareHashFails() public {
        bytes memory sig = abi.encodePacked(address(validator), abi.encode(_assert(KEY, _hash(0))));
        vm.expectRevert(ISafe7579Head.EmergencyUninstallSigError.selector);
        ISafe7579Head(safe).emergencyUninstallHook(_data(0), sig);
    }

    /// A well-formed ERC-7739 envelope over the real EmergencyUninstall struct: the hash matches, the type is refused.
    function test_V11_ownerSignatureInTypedEnvelopeFails() public {
        bytes memory envelope = _typedEnvelope(
            KEY, safe, ISafeSetup(safe).domainSeparator(), "EmergencyUninstall", EMERGENCY_UNINSTALL, _contents(0)
        );
        vm.expectRevert(ISafe7579Head.EmergencyUninstallSigError.selector);
        ISafe7579Head(safe).emergencyUninstallHook(_data(0), abi.encodePacked(address(validator), envelope));
    }

    function test_V11_ownerSignatureWrappedAsPersonalSignFails() public {
        bytes32 hash = _hash(0);
        FirewallOwnerValidator.SignatureEnvelope memory env;
        env.kind = FirewallOwnerValidator.EnvelopeKind.PersonalSign;
        env.data = abi.encodePacked(hash);
        env.auth = _assert(KEY, _personalDigest(safe, hash));
        vm.expectRevert(ISafe7579Head.EmergencyUninstallSigError.selector);
        ISafe7579Head(safe).emergencyUninstallHook(_data(0), abi.encodePacked(address(validator), abi.encode(env)));
    }

    /// Control: through a validator with no content rules the same path removes the hook after one day.
    /// This is the V11 bypass, so the tests above fail for the right reason.
    function test_V11_control_permissiveValidatorRemovesHook() public {
        bytes memory sig = abi.encodePacked(address(permissive), bytes32(0));
        ISafe7579Head(safe).emergencyUninstallHook(_data(0), sig);
        assertTrue(_hookInstalled(), "timelock started");
        vm.warp(block.timestamp + 1 days);
        ISafe7579Head(safe).emergencyUninstallHook(_data(1), sig);
        assertFalse(_hookInstalled(), "hook removed");
    }
}
