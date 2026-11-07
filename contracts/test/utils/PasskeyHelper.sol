// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {Base64} from "@openzeppelin/contracts-webauthn/utils/Base64.sol";
import {WebAuthn} from "@openzeppelin/contracts-webauthn/utils/cryptography/WebAuthn.sol";
import {FirewallOwnerValidator} from "../../src/validators/FirewallOwnerValidator.sol";

/// @notice Builds what a browser passkey produces (WebAuthn assertions) and the ERC-7739 digests, computed
///         independently of the validator so a validator hashing bug can't hide behind shared code.
abstract contract PasskeyHelper is Test {
    uint256 internal constant P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551;

    string internal constant EIP2612 =
        "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)";
    string internal constant PERMIT_SINGLE =
        "PermitSingle(PermitDetails details,address spender,uint256 sigDeadline)PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)";
    string internal constant PERMIT_BATCH =
        "PermitBatch(PermitDetails[] details,address spender,uint256 sigDeadline)PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)";
    string internal constant PERMIT_TRANSFER =
        "PermitTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline)TokenPermissions(address token,uint256 amount)";
    string internal constant PERMIT_BATCH_TRANSFER =
        "PermitBatchTransferFrom(TokenPermissions[] permitted,address spender,uint256 nonce,uint256 deadline)TokenPermissions(address token,uint256 amount)";
    string internal constant PERMIT_WITNESS =
        "PermitWitnessTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline,Order witness)Order(uint256 id)TokenPermissions(address token,uint256 amount)";
    string internal constant PERMIT_BATCH_WITNESS =
        "PermitBatchWitnessTransferFrom(TokenPermissions[] permitted,address spender,uint256 nonce,uint256 deadline,Order witness)Order(uint256 id)TokenPermissions(address token,uint256 amount)";
    string internal constant BENIGN = "Mail(address to,uint256 id)";
    string internal constant EMERGENCY_UNINSTALL =
        "EmergencyUninstall(address hook,uint256 hookType,bytes deInitData,uint256 nonce)";

    bytes32 internal constant APP_SEPARATOR = keccak256("some app domain");

    function _publicKey(uint256 key) internal pure returns (bytes32, bytes32) {
        (uint256 x, uint256 y) = vm.publicKeyP256(key);
        return (bytes32(x), bytes32(y));
    }

    /// @dev Flags 0x05: user present and user verified. Low-s, as P256.verify requires.
    function _assert(uint256 key, bytes32 challenge) internal pure returns (WebAuthn.WebAuthnAuth memory auth) {
        return _assertWithFlags(key, challenge, 0x05);
    }

    function _assertWithFlags(uint256 key, bytes32 challenge, bytes1 flags)
        internal
        pure
        returns (WebAuthn.WebAuthnAuth memory auth)
    {
        auth.authenticatorData = abi.encodePacked(sha256("firewall.test"), flags, uint32(1));
        auth.clientDataJSON = string.concat(
            '{"type":"webauthn.get","challenge":"',
            Base64.encodeURL(abi.encodePacked(challenge)),
            '","origin":"https://firewall.test","crossOrigin":false}'
        );
        auth.typeIndex = 1;
        auth.challengeIndex = 23;
        (bytes32 r, bytes32 s) =
            vm.signP256(key, sha256(abi.encodePacked(auth.authenticatorData, sha256(bytes(auth.clientDataJSON)))));
        if (uint256(s) > P256_N / 2) s = bytes32(P256_N - uint256(s));
        auth.r = r;
        auth.s = s;
    }

    // ---------------------------------------------------------------- ERC-7739 digests

    function _accountSeparator(address account) internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("FirewallOwnerValidator"),
                keccak256("1"),
                block.chainid,
                account
            )
        );
    }

    function _appHash(bytes32 appSeparator, string memory contentsType, bytes memory data)
        internal
        pure
        returns (bytes32)
    {
        bytes32 contents = keccak256(abi.encodePacked(keccak256(bytes(contentsType)), data));
        return keccak256(abi.encodePacked(hex"1901", appSeparator, contents));
    }

    function _typedDigest(
        address account,
        bytes32 appSeparator,
        string memory name,
        string memory contentsType,
        bytes memory data
    ) internal view returns (bytes32) {
        bytes32 typeHash = keccak256(
            abi.encodePacked(
                "TypedDataSign(",
                name,
                " contents,string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)",
                contentsType
            )
        );
        bytes32 structHash = keccak256(
            abi.encode(
                typeHash,
                keccak256(abi.encodePacked(keccak256(bytes(contentsType)), data)),
                keccak256("FirewallOwnerValidator"),
                keccak256("1"),
                block.chainid,
                account,
                bytes32(0)
            )
        );
        return keccak256(abi.encodePacked(hex"1901", appSeparator, structHash));
    }

    function _personalHash(bytes memory message) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", vm.toString(message.length), message));
    }

    function _personalDigest(address account, bytes32 hash) internal view returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                hex"1901",
                _accountSeparator(account),
                keccak256(abi.encode(keccak256("PersonalSign(bytes prefixed)"), hash))
            )
        );
    }

    // ---------------------------------------------------------------- envelopes

    function _typedEnvelope(
        uint256 key,
        address account,
        bytes32 appSeparator,
        string memory name,
        string memory contentsType,
        bytes memory data
    ) internal view returns (bytes memory) {
        return abi.encode(
            FirewallOwnerValidator.SignatureEnvelope({
                kind: FirewallOwnerValidator.EnvelopeKind.TypedDataSign,
                appDomainSeparator: appSeparator,
                contentsType: contentsType,
                data: data,
                auth: _assert(key, _typedDigest(account, appSeparator, name, contentsType, data))
            })
        );
    }

    function _personalEnvelope(uint256 key, address account, bytes memory message)
        internal
        view
        returns (bytes memory)
    {
        return abi.encode(
            FirewallOwnerValidator.SignatureEnvelope({
                kind: FirewallOwnerValidator.EnvelopeKind.PersonalSign,
                appDomainSeparator: bytes32(0),
                contentsType: "",
                data: message,
                auth: _assert(key, _personalDigest(account, _personalHash(message)))
            })
        );
    }
}
