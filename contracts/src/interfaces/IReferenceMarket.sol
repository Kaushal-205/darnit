// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface IReferenceMarket {
    enum Side {
        Buy, // maker buys shares, taker sells
        Sell // maker sells shares, taker buys
    }

    struct Order {
        address maker;
        uint256 tokenId;
        Side side;
        uint256 price; // USDC base units per whole share (1e6 = $1)
        uint256 amount; // shares, 6 decimals
        uint256 expiry;
        uint256 salt;
    }

    function collateral() external view returns (address);
    function outcomeIds(uint256 marketId) external pure returns (uint256 yesId, uint256 noId);
    function shares() external view returns (address);

    function fill(Order calldata order, bytes calldata signature, uint256 fillAmount, address recipient)
        external
        returns (uint256 usdcAmount);
    function split(uint256 marketId, uint256 amount) external;
    function merge(uint256 marketId, uint256 amount) external;
    function redeem(uint256 marketId) external;
    function cancel(Order calldata order) external;
}
