// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Describes what a market call can move, so the hook can snapshot it and bound it.
interface IMarketAdapter {
    struct Touched {
        // false: the adapter does not recognise the call; the hook rejects it with UnknownTarget
        bool supported;
        // ERC-20s the call may move into or out of the account
        address[] erc20s;
        // ERC-1155 ids on shareToken() the call may move
        uint256[] shareIds;
        // every address that receives proceeds of the call; each must be the account or a destination
        address[] recipients;
    }

    function market() external view returns (address);
    function shareToken() external view returns (address);
    function touched(address account, bytes calldata callData) external view returns (Touched memory);
}
