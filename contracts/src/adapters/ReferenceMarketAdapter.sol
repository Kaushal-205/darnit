// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IMarketAdapter} from "../interfaces/IMarketAdapter.sol";
import {IReferenceMarket} from "../interfaces/IReferenceMarket.sol";

/// @title ReferenceMarketAdapter
/// @notice Tells the hook what each ReferenceMarket call can move and where proceeds go.
///         Unknown selectors are reported unsupported, so the hook rejects them.
contract ReferenceMarketAdapter is IMarketAdapter {
    address public immutable override market;
    address public immutable override shareToken;
    address public immutable collateral;

    constructor(IReferenceMarket market_) {
        market = address(market_);
        shareToken = market_.shares();
        collateral = market_.collateral();
    }

    function touched(address, bytes calldata callData) external view override returns (Touched memory t) {
        if (callData.length < 4) return t;
        bytes4 sel = bytes4(callData[0:4]);

        if (sel == IReferenceMarket.fill.selector) {
            (IReferenceMarket.Order memory o,,, address recipient) =
                abi.decode(callData[4:], (IReferenceMarket.Order, bytes, uint256, address));
            t.supported = true;
            t.erc20s = _one(collateral);
            t.shareIds = new uint256[](1);
            t.shareIds[0] = o.tokenId;
            t.recipients = _one(recipient);
        } else if (
            sel == IReferenceMarket.split.selector || sel == IReferenceMarket.merge.selector
                || sel == IReferenceMarket.redeem.selector
        ) {
            // all three pay and mint to msg.sender only
            uint256 marketId = abi.decode(callData[4:36], (uint256));
            (uint256 yesId, uint256 noId) = IReferenceMarket(market).outcomeIds(marketId);
            t.supported = true;
            t.erc20s = _one(collateral);
            t.shareIds = new uint256[](2);
            t.shareIds[0] = yesId;
            t.shareIds[1] = noId;
        } else if (sel == IReferenceMarket.cancel.selector) {
            t.supported = true;
        }
    }

    function _one(address a) private pure returns (address[] memory out) {
        out = new address[](1);
        out[0] = a;
    }
}
