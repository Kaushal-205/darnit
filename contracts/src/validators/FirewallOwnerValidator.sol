// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {P256} from "@openzeppelin/contracts-webauthn/utils/cryptography/P256.sol";
import {WebAuthn} from "@openzeppelin/contracts-webauthn/utils/cryptography/WebAuthn.sol";
import {MessageHashUtils} from "@openzeppelin/contracts-webauthn/utils/cryptography/MessageHashUtils.sol";
import {IValidator, PackedUserOperation, MODULE_TYPE_VALIDATOR} from "../interfaces/IERC7579.sol";
import {IFirewallModule} from "../interfaces/IFirewallModule.sol";

/// @title FirewallOwnerValidator
/// @notice The account's owner validator: one P-256 passkey per account, verified as a WebAuthn assertion.
///         User operations are checked directly, because the hook bounds every execution. ERC-1271 signatures
///         settle where the hook never runs, so they are accepted only when their contents are visible and
///         on an allowlist (docs/decisions.md D12).
/// @dev What the ERC-1271 path accepts:
///      - PersonalSign, with the plaintext message. `hash` must be the EIP-191 hash of that message, so it can
///        never be an EIP-712 digest (permit, enable mode, emergency uninstall). Plain ERC-7739 cannot give
///        this guarantee: it would wrap any 32-byte hash.
///      - TypedDataSign, with the contents' encodeData. Recomputing the contents hash from the claimed type
///        and fields stops a permit being passed off under a benign type name. Then:
///        reserved type names are always refused; permit-family types need a registered market as spender;
///        anything else needs its exact type string on this account's allowlist.
///      The signed digest is exactly ERC-7739's (cross-checked against Solady in the tests). Only the transport
///      differs: an ABI-encoded SignatureEnvelope instead of appended bytes, because of the extra fields.
///
///      No admin, no upgrades, no delegatecall. All state is keyed by account (ERC-7562 associated storage).
///      Config functions key on msg.sender. The hook refuses direct account calls to this contract
///      (UnknownTarget), so an account reaches them only through a matured ConfigCall (R6).
contract FirewallOwnerValidator is IValidator {
    enum EnvelopeKind {
        None,
        TypedDataSign,
        PersonalSign
    }

    struct SignatureEnvelope {
        EnvelopeKind kind;
        bytes32 appDomainSeparator; // TypedDataSign only
        string contentsType; // TypedDataSign only: full EIP-712 encodeType, contents' own type first
        bytes data; // TypedDataSign: EIP-712 encodeData of the contents. PersonalSign: the plaintext message
        WebAuthn.WebAuthnAuth auth;
    }

    struct Owner {
        bytes32 x;
        bytes32 y;
        uint64 epoch; // bumped on install, so an uninstall discards the old allowlist
        bool initialized;
    }

    string public constant NAME = "FirewallOwnerValidator";
    string public constant VERSION = "1";

    uint256 internal constant VALIDATION_SUCCESS = 0;
    uint256 internal constant VALIDATION_FAILED = 1;
    bytes4 internal constant ERC1271_MAGIC = 0x1626ba7e;
    bytes4 internal constant ERC1271_INVALID = 0xffffffff;
    bytes4 internal constant ERC7739_SUPPORT = 0x77390001;
    bytes32 internal constant ERC7739_DETECTION_HASH =
        0x7739773977397739773977397739773977397739773977397739773977397739;

    bytes32 internal constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 internal constant PERSONAL_SIGN_TYPEHASH = keccak256("PersonalSign(bytes prefixed)");

    IFirewallModule public immutable MODULE;

    mapping(address account => Owner) internal _owners;
    /// @dev Keyed type-first so the account is the inner key (associated storage). Value: the epoch it was set in.
    mapping(bytes32 typeHash => mapping(address account => uint64)) internal _allowedContent;

    event PasskeySet(address indexed account, bytes32 x, bytes32 y);
    event ContentTypeSet(address indexed account, bytes32 indexed typeHash, string contentsType, bool allowed);

    error ZeroModule();
    error NotInitialized(address account);
    error AlreadyInitialized(address account);
    error InvalidPublicKey();
    error InvalidContentType();
    error ReservedContentType();

    constructor(IFirewallModule module) {
        if (address(module) == address(0)) revert ZeroModule();
        MODULE = module;
    }

    // ---------------------------------------------------------------- ERC-7579 module

    /// @param data abi.encode(bytes32 x, bytes32 y, string[] allowedContentTypes). Types are active at once,
    ///             like destinations passed to FirewallModule.onInstall. Later additions wait 24 hours.
    function onInstall(bytes calldata data) external override {
        Owner storage o = _owners[msg.sender];
        if (o.initialized) revert AlreadyInitialized(msg.sender);
        (bytes32 x, bytes32 y, string[] memory contentTypes) = abi.decode(data, (bytes32, bytes32, string[]));
        o.initialized = true;
        o.epoch++;
        _setPasskey(o, x, y);
        for (uint256 i; i < contentTypes.length; ++i) {
            _setContentType(o, contentTypes[i], true);
        }
    }

    /// @dev Reachable only through a matured ConfigCall (the hook forbids uninstallModule otherwise).
    function onUninstall(bytes calldata) external override {
        Owner storage o = _owners[msg.sender];
        o.x = 0;
        o.y = 0;
        o.initialized = false;
    }

    function isModuleType(uint256 moduleTypeId) external pure override returns (bool) {
        return moduleTypeId == MODULE_TYPE_VALIDATOR;
    }

    function isInitialized(address account) external view override returns (bool) {
        return _owners[account].initialized;
    }

    // ---------------------------------------------------------------- config (ConfigCall only, see above)

    function setPasskey(bytes32 x, bytes32 y) external {
        Owner storage o = _owners[msg.sender];
        if (!o.initialized) revert NotInitialized(msg.sender);
        _setPasskey(o, x, y);
    }

    function setContentType(string calldata contentsType, bool allowed) external {
        Owner storage o = _owners[msg.sender];
        if (!o.initialized) revert NotInitialized(msg.sender);
        _setContentType(o, contentsType, allowed);
    }

    // ---------------------------------------------------------------- reads

    function passkey(address account) external view returns (bytes32 x, bytes32 y) {
        Owner storage o = _owners[account];
        return (o.x, o.y);
    }

    function isContentTypeAllowed(address account, string calldata contentsType) external view returns (bool) {
        return _isAllowed(account, keccak256(bytes(contentsType)));
    }

    /// @notice The ERC-7739 "account domain". Safe does not implement ERC-5267, so the validator defines it:
    ///         name and version above, this chain, verifyingContract = the account, zero salt. The SDK uses
    ///         these values when it builds the digest to sign.
    function eip712Domain(address account)
        external
        view
        returns (string memory name, string memory version, uint256 chainId, address verifyingContract, bytes32 salt)
    {
        return (NAME, VERSION, block.chainid, account, bytes32(0));
    }

    function domainSeparator(address account) public view returns (bytes32) {
        return keccak256(
            abi.encode(DOMAIN_TYPEHASH, keccak256(bytes(NAME)), keccak256(bytes(VERSION)), block.chainid, account)
        );
    }

    // ---------------------------------------------------------------- user operations

    /// @param userOp its signature is abi.encode(WebAuthn.WebAuthnAuth), with the userOpHash as challenge.
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        view
        override
        returns (uint256)
    {
        Owner storage o = _owners[msg.sender];
        if (!o.initialized) return VALIDATION_FAILED;
        (bool ok, WebAuthn.WebAuthnAuth calldata auth) = _tryDecodeAuth(userOp.signature);
        if (!ok) return VALIDATION_FAILED;
        return WebAuthn.verify(abi.encodePacked(userOpHash), auth, o.x, o.y) ? VALIDATION_SUCCESS : VALIDATION_FAILED;
    }

    // ---------------------------------------------------------------- ERC-1271

    /// @param signature abi.encode(SignatureEnvelope). Anything else, including a raw hash signature, is invalid.
    function isValidSignatureWithSender(address, bytes32 hash, bytes calldata signature)
        external
        view
        override
        returns (bytes4)
    {
        if (hash == ERC7739_DETECTION_HASH && signature.length == 0) return ERC7739_SUPPORT;

        Owner storage o = _owners[msg.sender];
        if (!o.initialized) return ERC1271_INVALID;

        // Malformed bytes read as "invalid", not a revert, so every caller sees one clean failure value.
        try this.decodeEnvelope(signature) returns (SignatureEnvelope memory env) {
            bytes32 digest;
            if (env.kind == EnvelopeKind.TypedDataSign) digest = _typedDataSignDigest(msg.sender, hash, env);
            else if (env.kind == EnvelopeKind.PersonalSign) digest = _personalSignDigest(msg.sender, hash, env);
            if (digest == 0) return ERC1271_INVALID;
            return WebAuthn.verify(abi.encodePacked(digest), env.auth, o.x, o.y) ? ERC1271_MAGIC : ERC1271_INVALID;
        } catch {
            return ERC1271_INVALID;
        }
    }

    /// @dev External only so a malformed signature can be caught with try/catch.
    function decodeEnvelope(bytes calldata signature) external pure returns (SignatureEnvelope memory) {
        return abi.decode(signature, (SignatureEnvelope));
    }

    /// @return The digest the passkey must have signed, or 0 if the content rules refuse this signature.
    function _personalSignDigest(address account, bytes32 hash, SignatureEnvelope memory env)
        internal
        view
        returns (bytes32)
    {
        if (MessageHashUtils.toEthSignedMessageHash(env.data) != hash) return 0;
        return MessageHashUtils.toTypedDataHash(
            domainSeparator(account), keccak256(abi.encode(PERSONAL_SIGN_TYPEHASH, hash))
        );
    }

    /// @return The digest the passkey must have signed, or 0 if the content rules refuse this signature.
    function _typedDataSignDigest(address account, bytes32 hash, SignatureEnvelope memory env)
        internal
        view
        returns (bytes32)
    {
        if (env.data.length == 0 || env.data.length % 32 != 0) return 0;
        (bool ok, bytes memory name) = _parseContentsName(env.contentsType);
        if (!ok) return 0;

        // Bind the claimed type and fields to the hash the app actually asked about.
        bytes32 typeHash = keccak256(bytes(env.contentsType));
        bytes32 contents = keccak256(abi.encodePacked(typeHash, env.data));
        if (MessageHashUtils.toTypedDataHash(env.appDomainSeparator, contents) != hash) return 0;

        if (!_contentAllowed(account, name, env.contentsType, typeHash, env.data)) return 0;

        bytes32 typedDataSignTypeHash = keccak256(
            abi.encodePacked(
                "TypedDataSign(",
                name,
                " contents,string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)",
                env.contentsType
            )
        );
        bytes32 structHash = keccak256(
            abi.encode(
                typedDataSignTypeHash,
                contents,
                keccak256(bytes(NAME)),
                keccak256(bytes(VERSION)),
                block.chainid,
                account,
                bytes32(0)
            )
        );
        return MessageHashUtils.toTypedDataHash(env.appDomainSeparator, structHash);
    }

    function _contentAllowed(
        address account,
        bytes memory name,
        string memory contentsType,
        bytes32 typeHash,
        bytes memory data
    ) internal view returns (bool) {
        bytes32 nameHash = keccak256(name);
        if (_isReserved(nameHash)) return false;
        // R8: after a freeze the owner signs no typed data until the queued unfreeze has run.
        if (MODULE.config(account).frozen) return false;

        bytes memory permitPrefix = _permitPrefix(nameHash);
        if (permitPrefix.length != 0) {
            // A layout we don't know (e.g. DAI's Permit) can't be read safely, so it is refused.
            if (!_startsWith(bytes(contentsType), permitPrefix) || data.length < 64) return false;
            // Every known layout has the spender as the second field, one word in.
            uint256 word;
            assembly ("memory-safe") {
                word := mload(add(data, 0x40))
            }
            if (word > type(uint160).max) return false;
            return MODULE.marketAdapter(account, address(uint160(word))) != address(0);
        }
        return _isAllowed(account, typeHash);
    }

    // ---------------------------------------------------------------- content rules

    /// @dev Never signable, whatever the allowlist says: account control, session enable, nested envelopes,
    ///      and EIP-3009 transfers (USDC moves funds directly on these, with no spender to check).
    function _isReserved(bytes32 nameHash) internal pure returns (bool) {
        return nameHash == keccak256("EmergencyUninstall") || nameHash == keccak256("MultiChainSession")
            || nameHash == keccak256("ChainSession") || nameHash == keccak256("SignedSession")
            || nameHash == keccak256("SafeTx") || nameHash == keccak256("SafeMessage")
            || nameHash == keccak256("SafeOp") || nameHash == keccak256("TypedDataSign")
            || nameHash == keccak256("PersonalSign") || nameHash == keccak256("TransferWithAuthorization")
            || nameHash == keccak256("ReceiveWithAuthorization");
    }

    /// @return The type string up to the spender field, or empty if this name is not in the permit family.
    function _permitPrefix(bytes32 nameHash) internal pure returns (bytes memory) {
        if (nameHash == keccak256("Permit")) return "Permit(address owner,address spender,";
        if (nameHash == keccak256("PermitSingle")) return "PermitSingle(PermitDetails details,address spender,";
        if (nameHash == keccak256("PermitBatch")) return "PermitBatch(PermitDetails[] details,address spender,";
        if (nameHash == keccak256("PermitTransferFrom")) {
            return "PermitTransferFrom(TokenPermissions permitted,address spender,";
        }
        if (nameHash == keccak256("PermitBatchTransferFrom")) {
            return "PermitBatchTransferFrom(TokenPermissions[] permitted,address spender,";
        }
        if (nameHash == keccak256("PermitWitnessTransferFrom")) {
            return "PermitWitnessTransferFrom(TokenPermissions permitted,address spender,";
        }
        if (nameHash == keccak256("PermitBatchWitnessTransferFrom")) {
            return "PermitBatchWitnessTransferFrom(TokenPermissions[] permitted,address spender,";
        }
        return "";
    }

    /// @dev ERC-7739 implicit mode only: the type string must begin with the contents' own type, so its hash
    ///      is the EIP-712 typehash. Name rules follow ERC-7739: non-empty, no leading a-z, none of ", )\x00".
    function _parseContentsName(string memory contentsType) internal pure returns (bool, bytes memory) {
        bytes memory t = bytes(contentsType);
        if (t.length < 3 || t[t.length - 1] != ")") return (false, "");
        if (t[0] >= "a" && t[0] <= "z") return (false, "");
        for (uint256 i; i < t.length; ++i) {
            bytes1 c = t[i];
            if (c == "(") {
                if (i == 0) return (false, "");
                bytes memory name = new bytes(i);
                for (uint256 j; j < i; ++j) {
                    name[j] = t[j];
                }
                return (true, name);
            }
            if (c == 0x00 || c == " " || c == "," || c == ")") return (false, "");
        }
        return (false, "");
    }

    function _startsWith(bytes memory value, bytes memory prefix) internal pure returns (bool) {
        if (value.length < prefix.length) return false;
        for (uint256 i; i < prefix.length; ++i) {
            if (value[i] != prefix[i]) return false;
        }
        return true;
    }

    function _isAllowed(address account, bytes32 typeHash) internal view returns (bool) {
        Owner storage o = _owners[account];
        return o.initialized && _allowedContent[typeHash][account] == o.epoch;
    }

    // ---------------------------------------------------------------- internals

    function _setPasskey(Owner storage o, bytes32 x, bytes32 y) internal {
        if (!P256.isValidPublicKey(x, y)) revert InvalidPublicKey();
        o.x = x;
        o.y = y;
        emit PasskeySet(msg.sender, x, y);
    }

    /// @dev Permit-family types have their own rule and reserved types no rule, so neither can be listed.
    function _setContentType(Owner storage o, string memory contentsType, bool allowed) internal {
        (bool ok, bytes memory name) = _parseContentsName(contentsType);
        if (!ok) revert InvalidContentType();
        bytes32 nameHash = keccak256(name);
        if (_isReserved(nameHash) || _permitPrefix(nameHash).length != 0) revert ReservedContentType();
        bytes32 typeHash = keccak256(bytes(contentsType));
        _allowedContent[typeHash][msg.sender] = allowed ? o.epoch : 0;
        emit ContentTypeSet(msg.sender, typeHash, contentsType, allowed);
    }

    /// @dev OpenZeppelin's checked decoder expects the bare tuple; abi.encode(auth) adds one leading offset word.
    function _tryDecodeAuth(bytes calldata signature)
        internal
        pure
        returns (bool, WebAuthn.WebAuthnAuth calldata auth)
    {
        if (signature.length < 0x20 || uint256(bytes32(signature[:0x20])) != 0x20) {
            assembly ("memory-safe") {
                auth := signature.offset
            }
            return (false, auth);
        }
        return WebAuthn.tryDecodeAuth(signature[0x20:]);
    }
}
