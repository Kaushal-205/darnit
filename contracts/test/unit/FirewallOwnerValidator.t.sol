// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ERC1271 as SoladyERC1271} from "solady/accounts/ERC1271.sol";
import {EIP712 as SoladyEIP712} from "solady/utils/EIP712.sol";

import {WebAuthn} from "@openzeppelin/contracts-webauthn/utils/cryptography/WebAuthn.sol";
import {Base} from "../Base.t.sol";
import {PasskeyHelper} from "../utils/PasskeyHelper.sol";
import {FirewallOwnerValidator} from "../../src/validators/FirewallOwnerValidator.sol";
import {IFirewallModule} from "../../src/interfaces/IFirewallModule.sol";
import {FirewallErrors} from "../../src/interfaces/FirewallErrors.sol";
import {MODULE_TYPE_VALIDATOR, PackedUserOperation} from "../../src/interfaces/IERC7579.sol";

/// @notice The reference: Solady's nested EIP-712 implementation, with the validator's account domain.
contract SoladyReferenceAccount is SoladyERC1271 {
    address internal immutable SIGNER;

    constructor(address signer) {
        SIGNER = signer;
    }

    function _erc1271Signer() internal view override returns (address) {
        return SIGNER;
    }

    function _domainNameAndVersion() internal pure override returns (string memory, string memory) {
        return ("FirewallOwnerValidator", "1");
    }
}

contract FirewallOwnerValidatorTest is Base, PasskeyHelper {
    bytes4 internal constant MAGIC = 0x1626ba7e;
    bytes4 internal constant INVALID = 0xffffffff;
    uint256 internal constant KEY = 0xA11CE;
    uint256 internal constant NEW_KEY = 0xB0B;

    FirewallOwnerValidator internal validator;

    function setUp() public override {
        super.setUp();
        validator = new FirewallOwnerValidator(IFirewallModule(address(module)));
        _install(address(account), KEY);
    }

    function _install(address acc, uint256 key) internal {
        (bytes32 x, bytes32 y) = _publicKey(key);
        string[] memory types = new string[](1);
        types[0] = BENIGN;
        vm.prank(acc);
        validator.onInstall(abi.encode(x, y, types));
    }

    function _check(bytes32 hash, bytes memory signature) internal returns (bytes4) {
        vm.prank(address(account));
        return validator.isValidSignatureWithSender(address(this), hash, signature);
    }

    function _userOp(bytes memory signature) internal view returns (PackedUserOperation memory op) {
        op.sender = address(account);
        op.signature = signature;
    }

    function _validateUserOp(bytes32 hash, bytes memory signature) internal returns (uint256) {
        vm.prank(address(account));
        return validator.validateUserOp(_userOp(signature), hash);
    }

    function _typedResult(string memory name, string memory contentsType, bytes memory data) internal returns (bytes4) {
        return _check(
            _appHash(APP_SEPARATOR, contentsType, data),
            _typedEnvelope(KEY, address(account), APP_SEPARATOR, name, contentsType, data)
        );
    }

    function _permitData(address spender) internal view returns (bytes memory) {
        return abi.encode(address(account), spender, uint256(1e6), uint256(0), block.timestamp + 1 days);
    }

    /// @dev PermitSingle, PermitBatch and PermitTransferFrom-style encodeData: first field is a struct or array hash.
    function _permit2Data(address spender) internal pure returns (bytes memory) {
        return abi.encode(keccak256("details"), spender, uint256(1), uint256(2));
    }

    // ---------------------------------------------------------------- module surface

    function test_moduleSurface() public view {
        assertTrue(validator.isModuleType(MODULE_TYPE_VALIDATOR));
        assertFalse(validator.isModuleType(2));
        assertTrue(validator.isInitialized(address(account)));
        assertFalse(validator.isInitialized(attacker));
    }

    function test_installRejectsOffCurveKey() public {
        vm.prank(attacker);
        vm.expectRevert(FirewallOwnerValidator.InvalidPublicKey.selector);
        validator.onInstall(abi.encode(bytes32(uint256(1)), bytes32(uint256(1)), new string[](0)));
    }

    function test_installTwiceReverts() public {
        vm.prank(address(account));
        vm.expectRevert(abi.encodeWithSelector(FirewallOwnerValidator.AlreadyInitialized.selector, address(account)));
        validator.onInstall("");
    }

    function test_installRejectsReservedAndPermitContentTypes() public {
        (bytes32 x, bytes32 y) = _publicKey(KEY);
        string[3] memory bad = [EMERGENCY_UNINSTALL, EIP2612, "TransferWithAuthorization(address from)"];
        for (uint256 i; i < bad.length; ++i) {
            string[] memory types = new string[](1);
            types[0] = bad[i];
            vm.prank(attacker);
            vm.expectRevert(FirewallOwnerValidator.ReservedContentType.selector);
            validator.onInstall(abi.encode(x, y, types));
        }
    }

    function test_uninstallDropsKeyAndAllowlist() public {
        vm.prank(address(account));
        validator.onUninstall("");
        assertFalse(validator.isContentTypeAllowed(address(account), BENIGN));
        assertEq(_typedResult("Mail", BENIGN, abi.encode(attacker, uint256(1))), INVALID);

        // a reinstall starts with an empty allowlist
        (bytes32 x, bytes32 y) = _publicKey(KEY);
        vm.prank(address(account));
        validator.onInstall(abi.encode(x, y, new string[](0)));
        assertFalse(validator.isContentTypeAllowed(address(account), BENIGN));
    }

    // ---------------------------------------------------------------- validateUserOp

    function test_userOp_validSignature() public {
        bytes32 hash = keccak256("user op");
        assertEq(_validateUserOp(hash, abi.encode(_assert(KEY, hash))), 0);
    }

    function test_userOp_wrongKey() public {
        bytes32 hash = keccak256("user op");
        assertEq(_validateUserOp(hash, abi.encode(_assert(NEW_KEY, hash))), 1);
    }

    function test_userOp_wrongChallenge() public {
        assertEq(_validateUserOp(keccak256("user op"), abi.encode(_assert(KEY, keccak256("other")))), 1);
    }

    function test_userOp_userNotVerified() public {
        bytes32 hash = keccak256("user op");
        assertEq(_validateUserOp(hash, abi.encode(_assertWithFlags(KEY, hash, 0x01))), 1);
    }

    function test_userOp_highSRejected() public {
        bytes32 hash = keccak256("user op");
        WebAuthn.WebAuthnAuth memory auth = _assert(KEY, hash);
        auth.s = bytes32(P256_N - uint256(auth.s));
        assertEq(_validateUserOp(hash, abi.encode(auth)), 1);
    }

    function test_userOp_garbageSignature() public {
        bytes32 hash = keccak256("user op");
        assertEq(_validateUserOp(hash, ""), 1);
        assertEq(_validateUserOp(hash, hex"deadbeef"), 1);
        assertEq(_validateUserOp(hash, abi.encode(uint256(0x20), uint256(1))), 1);
        assertEq(_validateUserOp(hash, new bytes(512)), 1);
    }

    function test_userOp_uninitializedAccount() public {
        bytes32 hash = keccak256("user op");
        bytes memory sig = abi.encode(_assert(KEY, hash));
        PackedUserOperation memory op = _userOp(sig);
        vm.prank(attacker);
        assertEq(validator.validateUserOp(op, hash), 1);
    }

    // ---------------------------------------------------------------- bare hashes

    /// A passkey signing the bare hash directly, in every encoding, is never accepted.
    function test_1271_rawHashRejected() public {
        bytes32 hash = keccak256("raw digest");
        FirewallOwnerValidator.SignatureEnvelope memory env;
        env.auth = _assert(KEY, hash);

        // the bare assertion, as validateUserOp would take it
        assertEq(_check(hash, abi.encode(env.auth)), INVALID);
        // kind None
        assertEq(_check(hash, abi.encode(env)), INVALID);
        // a personal-sign envelope wrapping a hash that is not an EIP-191 hash of its message
        env.kind = FirewallOwnerValidator.EnvelopeKind.PersonalSign;
        env.data = abi.encodePacked(hash);
        env.auth = _assert(KEY, _personalDigest(address(account), hash));
        assertEq(_check(hash, abi.encode(env)), INVALID);
    }

    /// Plain ERC-7739 PersonalSign wraps any hash, which would let a permit through. Ours needs the plaintext.
    function test_1271_personalSignCannotWrapPermit() public {
        bytes memory data = _permitData(attacker);
        bytes32 permitHash = _appHash(APP_SEPARATOR, EIP2612, data);
        FirewallOwnerValidator.SignatureEnvelope memory env;
        env.kind = FirewallOwnerValidator.EnvelopeKind.PersonalSign;
        env.data = data;
        env.auth = _assert(KEY, _personalDigest(address(account), permitHash));
        assertEq(_check(permitHash, abi.encode(env)), INVALID);
    }

    function test_1271_erc7739Detection() public {
        bytes32 detect = 0x7739773977397739773977397739773977397739773977397739773977397739;
        assertEq(_check(detect, ""), bytes4(0x77390001));
    }

    // ---------------------------------------------------------------- PersonalSign

    function test_1271_personalSignAccepted() public {
        bytes memory message = "Sign in to firewall.test";
        bytes32 hash = _personalHash(message);
        assertEq(_check(hash, _personalEnvelope(KEY, address(account), message)), MAGIC);
    }

    function test_1271_personalSignWrongKey() public {
        bytes memory message = "Sign in to firewall.test";
        bytes32 hash = _personalHash(message);
        assertEq(_check(hash, _personalEnvelope(NEW_KEY, address(account), message)), INVALID);
    }

    function test_1271_personalSignBoundToAccount() public {
        bytes memory message = "Sign in to firewall.test";
        bytes32 hash = _personalHash(message);
        assertEq(_check(hash, _personalEnvelope(KEY, attacker, message)), INVALID);
    }

    function test_1271_personalSignWrongMessage() public {
        bytes memory sig = _personalEnvelope(KEY, address(account), "message A");
        assertEq(_check(_personalHash("message B"), sig), INVALID);
    }

    // ---------------------------------------------------------------- TypedDataSign, allowlist

    function test_1271_allowlistedTypeAccepted() public {
        assertEq(_typedResult("Mail", BENIGN, abi.encode(attacker, uint256(1))), MAGIC);
    }

    function test_1271_unlistedTypeRejected() public {
        string memory other = "Order(address maker,uint256 amount)";
        assertEq(_typedResult("Order", other, abi.encode(attacker, uint256(1))), INVALID);
    }

    function test_1271_typedDataBoundToAccount() public {
        bytes memory data = abi.encode(attacker, uint256(1));
        bytes memory sig = _typedEnvelope(KEY, attacker, APP_SEPARATOR, "Mail", BENIGN, data);
        assertEq(_check(_appHash(APP_SEPARATOR, BENIGN, data), sig), INVALID);
    }

    function test_1271_typedDataWrongKey() public {
        bytes memory data = abi.encode(attacker, uint256(1));
        bytes memory sig = _typedEnvelope(NEW_KEY, address(account), APP_SEPARATOR, "Mail", BENIGN, data);
        assertEq(_check(_appHash(APP_SEPARATOR, BENIGN, data), sig), INVALID);
    }

    /// A real permit hash presented under an allowlisted type name: the recomputed contents hash won't match.
    function test_1271_permitDisguisedAsAllowedType() public {
        bytes memory data = _permitData(attacker);
        bytes32 permitHash = _appHash(APP_SEPARATOR, EIP2612, data);
        assertEq(_check(permitHash, _typedEnvelope(KEY, address(account), APP_SEPARATOR, "Mail", BENIGN, data)), INVALID);
    }

    function test_1271_envelopeHashMismatch() public {
        bytes memory sig =
            _typedEnvelope(KEY, address(account), APP_SEPARATOR, "Mail", BENIGN, abi.encode(attacker, uint256(1)));
        assertEq(_check(keccak256("different"), sig), INVALID);
    }

    function test_1271_frozenAccountSignsNoTypedData() public {
        bytes memory mail = abi.encode(attacker, uint256(1));
        _moduleCall(abi.encodeCall(module.freeze, ()));
        assertEq(_typedResult("Mail", BENIGN, mail), INVALID);
        assertEq(_typedResult("Permit", EIP2612, _permitData(address(market))), INVALID);
        // login still works
        bytes memory message = "login";
        assertEq(_check(_personalHash(message), _personalEnvelope(KEY, address(account), message)), MAGIC);
    }

    // ---------------------------------------------------------------- permits (A13)

    function test_A13_permitToAttackerRejected() public {
        assertEq(_typedResult("Permit", EIP2612, _permitData(attacker)), INVALID);
    }

    function test_A13_permitToMarketAccepted() public {
        assertEq(_typedResult("Permit", EIP2612, _permitData(address(market))), MAGIC);
    }

    function test_A13_permitToRemovedMarketRejected() public {
        _moduleCall(abi.encodeCall(module.removeMarket, (address(market))));
        assertEq(_typedResult("Permit", EIP2612, _permitData(address(market))), INVALID);
    }

    function test_A13_permit2Attacker() public {
        bytes memory data = _permit2Data(attacker);
        assertEq(_typedResult("PermitSingle", PERMIT_SINGLE, data), INVALID);
        assertEq(_typedResult("PermitBatch", PERMIT_BATCH, data), INVALID);
        assertEq(_typedResult("PermitTransferFrom", PERMIT_TRANSFER, data), INVALID);
        assertEq(_typedResult("PermitBatchTransferFrom", PERMIT_BATCH_TRANSFER, data), INVALID);
        assertEq(_typedResult("PermitWitnessTransferFrom", PERMIT_WITNESS, data), INVALID);
        assertEq(_typedResult("PermitBatchWitnessTransferFrom", PERMIT_BATCH_WITNESS, data), INVALID);
    }

    function test_A13_permit2Market() public {
        bytes memory data = _permit2Data(address(market));
        assertEq(_typedResult("PermitSingle", PERMIT_SINGLE, data), MAGIC);
        assertEq(_typedResult("PermitBatch", PERMIT_BATCH, data), MAGIC);
        assertEq(_typedResult("PermitTransferFrom", PERMIT_TRANSFER, data), MAGIC);
        assertEq(_typedResult("PermitBatchTransferFrom", PERMIT_BATCH_TRANSFER, data), MAGIC);
        assertEq(_typedResult("PermitWitnessTransferFrom", PERMIT_WITNESS, data), MAGIC);
        assertEq(_typedResult("PermitBatchWitnessTransferFrom", PERMIT_BATCH_WITNESS, data), MAGIC);
    }

    /// DAI's layout has a different first field name. We don't read layouts we don't know.
    function test_A13_unknownPermitLayoutRejected() public {
        string memory dai = "Permit(address holder,address spender,uint256 nonce,uint256 expiry,bool allowed)";
        bytes memory data = abi.encode(address(account), address(market), uint256(0), uint256(1), true);
        assertEq(_typedResult("Permit", dai, data), INVALID);
    }

    function test_A13_dirtySpenderRejected() public {
        bytes memory data = abi.encode(
            address(account), uint256(uint160(address(market))) | (uint256(1) << 200), uint256(1), uint256(0), uint256(1)
        );
        assertEq(_typedResult("Permit", EIP2612, data), INVALID);
    }

    function test_A13_shortPermitRejected() public {
        assertEq(_typedResult("Permit", "Permit(address owner,address spender,)", abi.encode(address(account))), INVALID);
    }

    /// USDC moves funds directly on an EIP-3009 signature, and there is no spender to check.
    function test_A13_eip3009Rejected() public {
        string memory t =
            "TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)";
        bytes memory data = abi.encode(address(account), attacker, uint256(1), uint256(0), uint256(1), bytes32(0));
        assertEq(_typedResult("TransferWithAuthorization", t, data), INVALID);
    }

    // ---------------------------------------------------------------- account control

    function test_1271_emergencyUninstallRejected() public {
        bytes memory data = abi.encode(address(hook), uint256(4), keccak256(""), uint256(0));
        assertEq(_typedResult("EmergencyUninstall", EMERGENCY_UNINSTALL, data), INVALID);
    }

    function test_1271_enableSessionRejected() public {
        string memory t = "MultiChainSession(ChainSession[] sessionsAndChainIds)ChainSession(uint64 chainId)";
        assertEq(_typedResult("MultiChainSession", t, abi.encode(keccak256("sessions"))), INVALID);
    }

    function test_1271_nestedEnvelopeRejected() public {
        string memory t = "TypedDataSign(Mail contents)Mail(address to,uint256 id)";
        assertEq(_typedResult("TypedDataSign", t, abi.encode(keccak256("nested"))), INVALID);
    }

    // ---------------------------------------------------------------- malformed envelopes

    function test_1271_malformedBytesRejected() public {
        bytes32 hash = keccak256("x");
        assertEq(_check(hash, ""), INVALID);
        assertEq(_check(hash, hex"deadbeef"), INVALID);
        assertEq(_check(hash, new bytes(31)), INVALID);
        assertEq(_check(hash, new bytes(600)), INVALID);
        assertEq(_check(hash, abi.encode(uint256(0x20), uint256(9), bytes32(0))), INVALID);
        assertEq(_check(hash, abi.encode(type(uint256).max)), INVALID);
    }

    function test_1271_badContentTypesRejected() public {
        bytes memory data = abi.encode(uint256(1));
        string[6] memory bad = [
            "",
            "(uint256 a)", // no name
            "Mail", // no fields
            "mail(uint256 a)", // leading lower case
            "Ma il(uint256 a)", // space in the name
            "Mail(uint256 a)Mail" // ERC-7739 explicit mode is not supported
        ];
        for (uint256 i; i < bad.length; ++i) {
            bytes32 hash = _appHash(APP_SEPARATOR, bad[i], data);
            bytes memory sig = _typedEnvelope(KEY, address(account), APP_SEPARATOR, "Mail", bad[i], data);
            assertEq(_check(hash, sig), INVALID);
        }
    }

    function test_1271_unalignedDataRejected() public {
        bytes memory data = abi.encodePacked(abi.encode(attacker, uint256(1)), bytes1(0x01));
        assertEq(_typedResult("Mail", BENIGN, data), INVALID);
        assertEq(_typedResult("Mail", BENIGN, ""), INVALID);
    }

    function test_1271_uninitializedAccount() public {
        bytes memory message = "login";
        bytes memory sig = _personalEnvelope(KEY, attacker, message);
        vm.prank(attacker);
        assertEq(validator.isValidSignatureWithSender(address(this), _personalHash(message), sig), INVALID);
    }

    // ---------------------------------------------------------------- ERC-7739 exactness

    /// The digest our validator requires is the one Solady's nested EIP-712 implementation requires.
    function test_erc7739_typedDigestMatchesSolady() public {
        (address signer, uint256 ecdsaKey) = makeAddrAndKey("solady signer");
        SoladyReferenceAccount ref = new SoladyReferenceAccount(signer);
        bytes memory data = abi.encode(attacker, uint256(1));
        bytes32 appHash = _appHash(APP_SEPARATOR, BENIGN, data);
        bytes32 digest = _typedDigest(address(ref), APP_SEPARATOR, "Mail", BENIGN, data);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ecdsaKey, digest);
        bytes32 contents = keccak256(abi.encodePacked(keccak256(bytes(BENIGN)), data));
        bytes memory standard = abi.encodePacked(
            r, s, v, APP_SEPARATOR, contents, bytes(BENIGN), uint16(bytes(BENIGN).length)
        );
        vm.txGasPrice(1); // Solady's RPC-only path stays off
        assertEq(ref.isValidSignature(appHash, standard), MAGIC);

        // and our validator accepts a passkey over the same digest for the same account address
        _install(address(ref), KEY);
        bytes memory envelope = _typedEnvelope(KEY, address(ref), APP_SEPARATOR, "Mail", BENIGN, data);
        vm.prank(address(ref));
        assertEq(validator.isValidSignatureWithSender(address(this), appHash, envelope), MAGIC);
    }

    function test_erc7739_personalDigestMatchesSolady() public {
        (address signer, uint256 ecdsaKey) = makeAddrAndKey("solady signer");
        SoladyReferenceAccount ref = new SoladyReferenceAccount(signer);
        bytes memory message = "Sign in to firewall.test";
        bytes32 hash = _personalHash(message);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ecdsaKey, _personalDigest(address(ref), hash));
        vm.txGasPrice(1);
        assertEq(ref.isValidSignature(hash, abi.encodePacked(r, s, v)), MAGIC);

        (,,, , , bytes32 refSalt,) = ref.eip712Domain();
        assertEq(refSalt, bytes32(0));
        (,, uint256 chainId, address verifying, bytes32 salt) = validator.eip712Domain(address(ref));
        assertEq(chainId, block.chainid);
        assertEq(verifying, address(ref));
        assertEq(salt, bytes32(0));
        assertEq(validator.domainSeparator(address(ref)), _accountSeparator(address(ref)));
    }

    // ---------------------------------------------------------------- changes go through the queue (R6)

    function test_R6_directKeyChangeBlockedByHook() public {
        (bytes32 x, bytes32 y) = _publicKey(NEW_KEY);
        vm.expectRevert(
            abi.encodeWithSelector(FirewallErrors.UnknownTarget.selector, address(validator), validator.setPasskey.selector)
        );
        _exec(address(validator), 0, abi.encodeCall(validator.setPasskey, (x, y)));
    }

    function test_R6_directContentTypeChangeBlockedByHook() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                FirewallErrors.UnknownTarget.selector, address(validator), validator.setContentType.selector
            )
        );
        _exec(address(validator), 0, abi.encodeCall(validator.setContentType, ("Order(uint256 id)", true)));
    }

    function test_R6_keyChangeThroughQueue() public {
        (bytes32 x, bytes32 y) = _publicKey(NEW_KEY);
        bytes32 id = _queue(
            IFirewallModule.ChangeKind.ConfigCall,
            abi.encode(address(validator), uint256(0), abi.encodeCall(validator.setPasskey, (x, y)))
        );

        vm.expectRevert(abi.encodeWithSelector(FirewallErrors.TooEarly.selector, block.timestamp + 24 hours));
        _moduleCall(abi.encodeCall(module.execute, (id)));

        bytes32 hash = keccak256("user op");
        assertEq(_validateUserOp(hash, abi.encode(_assert(KEY, hash))), 0, "old key works during the delay");

        vm.warp(block.timestamp + 24 hours);
        _moduleCall(abi.encodeCall(module.execute, (id)));

        (bytes32 storedX, bytes32 storedY) = validator.passkey(address(account));
        assertEq(storedX, x);
        assertEq(storedY, y);
        assertEq(_validateUserOp(hash, abi.encode(_assert(NEW_KEY, hash))), 0, "new key works");
        assertEq(_validateUserOp(hash, abi.encode(_assert(KEY, hash))), 1, "old key is dead");
    }

    function test_R6_queuedKeyChangeCanBeCancelled() public {
        (bytes32 x, bytes32 y) = _publicKey(NEW_KEY);
        bytes32 id = _queue(
            IFirewallModule.ChangeKind.ConfigCall,
            abi.encode(address(validator), uint256(0), abi.encodeCall(validator.setPasskey, (x, y)))
        );
        _moduleCall(abi.encodeCall(module.cancel, (id)));
        vm.warp(block.timestamp + 24 hours);
        vm.expectRevert(abi.encodeWithSelector(FirewallErrors.UnknownChange.selector, id));
        _moduleCall(abi.encodeCall(module.execute, (id)));
    }

    function test_R6_contentTypeThroughQueue() public {
        string memory order = "Order(address maker,uint256 amount)";
        bytes memory data = abi.encode(attacker, uint256(1));
        assertEq(_typedResult("Order", order, data), INVALID);

        bytes32 id = _queue(
            IFirewallModule.ChangeKind.ConfigCall,
            abi.encode(address(validator), uint256(0), abi.encodeCall(validator.setContentType, (order, true)))
        );
        vm.warp(block.timestamp + 24 hours);
        _moduleCall(abi.encodeCall(module.execute, (id)));
        assertEq(_typedResult("Order", order, data), MAGIC);

        id = _queue(
            IFirewallModule.ChangeKind.ConfigCall,
            abi.encode(address(validator), uint256(0), abi.encodeCall(validator.setContentType, (order, false)))
        );
        vm.warp(block.timestamp + 24 hours);
        _moduleCall(abi.encodeCall(module.execute, (id)));
        assertEq(_typedResult("Order", order, data), INVALID);
    }

    /// Even a matured queue item can't list a reserved or permit-family type.
    function test_R6_reservedTypeCannotBeListed() public {
        vm.startPrank(address(account));
        vm.expectRevert(FirewallOwnerValidator.ReservedContentType.selector);
        validator.setContentType(EMERGENCY_UNINSTALL, true);
        vm.expectRevert(FirewallOwnerValidator.ReservedContentType.selector);
        validator.setContentType(EIP2612, true);
        vm.expectRevert(FirewallOwnerValidator.InvalidContentType.selector);
        validator.setContentType("not a type", true);
        vm.stopPrank();
    }

    function test_configFunctionsNeedInstall() public {
        vm.startPrank(attacker);
        vm.expectRevert(abi.encodeWithSelector(FirewallOwnerValidator.NotInitialized.selector, attacker));
        validator.setPasskey(bytes32(0), bytes32(0));
        vm.expectRevert(abi.encodeWithSelector(FirewallOwnerValidator.NotInitialized.selector, attacker));
        validator.setContentType(BENIGN, true);
        vm.stopPrank();
    }
}
