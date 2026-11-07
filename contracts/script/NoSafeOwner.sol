// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title NoSafeOwner
/// @notice The only Safe owner of a firewall account (docs/decisions.md V7). It rejects every ERC-1271
///         signature, so Safe-native paths (`execTransaction`, Safe-signature fallbacks in Safe7579's
///         `validateUserOp` / `isValidSignature`) can never be authorised. All control goes through
///         ERC-7579 validators, and therefore through the firewall hook.
contract NoSafeOwner {
    bytes4 internal constant INVALID = 0xffffffff;

    /// @dev Legacy ERC-1271 used by Safe <= 1.4.1 `checkSignatures` for contract owners.
    function isValidSignature(bytes calldata, bytes calldata) external pure returns (bytes4) {
        return INVALID;
    }

    /// @dev Current ERC-1271.
    function isValidSignature(bytes32, bytes calldata) external pure returns (bytes4) {
        return INVALID;
    }
}
