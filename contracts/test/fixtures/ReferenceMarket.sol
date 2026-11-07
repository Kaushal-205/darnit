// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ERC1155} from "@openzeppelin/contracts/token/ERC1155/ERC1155.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {IReferenceMarket} from "../../src/interfaces/IReferenceMarket.sol";

/// @notice ERC-1155 outcome shares. Only the market mints and burns; transfers follow normal approvals.
contract OutcomeShares is ERC1155 {
    address public immutable market;

    error OnlyMarket();

    constructor() ERC1155("") {
        market = msg.sender;
    }

    function mint(address to, uint256 id, uint256 amount) external {
        if (msg.sender != market) revert OnlyMarket();
        _mint(to, id, amount, "");
    }

    function burn(address from, uint256 id, uint256 amount) external {
        if (msg.sender != market) revert OnlyMarket();
        _burn(from, id, amount);
    }
}

/// @title ReferenceMarket
/// @notice Testnet-only binary prediction market. USDC collateral, ERC-1155 shares (1e6 units = 1 share,
///         paying at most $1), EIP-712 maker orders filled by takers. Maker signatures go through
///         SignatureChecker, so smart accounts make orders via ERC-1271.
contract ReferenceMarket is IReferenceMarket, EIP712 {
    using SafeERC20 for IERC20;

    uint256 public constant ONE = 1e6;
    bytes32 public constant ORDER_TYPEHASH = keccak256(
        "Order(address maker,uint256 tokenId,uint8 side,uint256 price,uint256 amount,uint256 expiry,uint256 salt)"
    );

    struct MarketInfo {
        bool exists;
        bool resolved;
        bool yesWins;
    }

    IERC20 internal immutable _collateral;
    OutcomeShares internal immutable _shares;
    address public immutable resolver;

    uint256 public nextMarketId = 1;
    mapping(uint256 marketId => MarketInfo) public markets;
    mapping(bytes32 orderHash => uint256) public filled;
    mapping(bytes32 orderHash => bool) public cancelled;

    event MarketCreated(uint256 indexed marketId, string question);
    event MarketResolved(uint256 indexed marketId, bool yesWins);
    event OrderFilled(
        bytes32 indexed orderHash, address indexed taker, uint256 fillAmount, uint256 usdcAmount
    );
    event OrderCancelled(bytes32 indexed orderHash);

    error OnlyResolver();
    error UnknownMarket();
    error AlreadyResolved();
    error NotResolved();
    error BadOrder();
    error BadSignature();
    error Overfill();

    constructor(IERC20 collateral_, address resolver_) EIP712("ReferenceMarket", "1") {
        _collateral = collateral_;
        _shares = new OutcomeShares();
        resolver = resolver_;
    }

    function collateral() external view override returns (address) {
        return address(_collateral);
    }

    function shares() external view override returns (address) {
        return address(_shares);
    }

    function outcomeIds(uint256 marketId) public pure override returns (uint256 yesId, uint256 noId) {
        yesId = marketId << 1;
        noId = (marketId << 1) | 1;
    }

    function marketOf(uint256 tokenId) public pure returns (uint256) {
        return tokenId >> 1;
    }

    // ---------------------------------------------------------------- lifecycle

    function createMarket(string calldata question) external returns (uint256 marketId) {
        if (msg.sender != resolver) revert OnlyResolver();
        marketId = nextMarketId++;
        markets[marketId].exists = true;
        emit MarketCreated(marketId, question);
    }

    function resolve(uint256 marketId, bool yesWins) external {
        if (msg.sender != resolver) revert OnlyResolver();
        MarketInfo storage m = markets[marketId];
        if (!m.exists) revert UnknownMarket();
        if (m.resolved) revert AlreadyResolved();
        m.resolved = true;
        m.yesWins = yesWins;
        emit MarketResolved(marketId, yesWins);
    }

    /// @notice Lock `amount` USDC, receive `amount` YES and `amount` NO shares.
    function split(uint256 marketId, uint256 amount) external override {
        MarketInfo storage m = markets[marketId];
        if (!m.exists || m.resolved) revert UnknownMarket();
        _collateral.safeTransferFrom(msg.sender, address(this), amount);
        (uint256 yesId, uint256 noId) = outcomeIds(marketId);
        _shares.mint(msg.sender, yesId, amount);
        _shares.mint(msg.sender, noId, amount);
    }

    /// @notice Burn `amount` YES and NO shares, get `amount` USDC back.
    function merge(uint256 marketId, uint256 amount) external override {
        if (!markets[marketId].exists) revert UnknownMarket();
        (uint256 yesId, uint256 noId) = outcomeIds(marketId);
        _shares.burn(msg.sender, yesId, amount);
        _shares.burn(msg.sender, noId, amount);
        _collateral.safeTransfer(msg.sender, amount);
    }

    /// @notice Burn all winning shares for USDC 1:1. Losing shares stay in the wallet, worthless.
    function redeem(uint256 marketId) external override {
        MarketInfo storage m = markets[marketId];
        if (!m.resolved) revert NotResolved();
        (uint256 yesId, uint256 noId) = outcomeIds(marketId);
        uint256 winner = m.yesWins ? yesId : noId;
        uint256 amount = _shares.balanceOf(msg.sender, winner);
        _shares.burn(msg.sender, winner, amount);
        _collateral.safeTransfer(msg.sender, amount);
    }

    // ---------------------------------------------------------------- orders

    function hashOrder(Order calldata o) public view returns (bytes32) {
        return _hashTypedDataV4(
            keccak256(
                abi.encode(ORDER_TYPEHASH, o.maker, o.tokenId, o.side, o.price, o.amount, o.expiry, o.salt)
            )
        );
    }

    /// @notice Taker fills `fillAmount` shares of a signed maker order. Taker proceeds (shares when buying,
    ///         USDC when selling) go to `recipient`; taker payment always comes from msg.sender.
    function fill(Order calldata o, bytes calldata signature, uint256 fillAmount, address recipient)
        external
        override
        returns (uint256 usdcAmount)
    {
        if (fillAmount == 0 || recipient == address(0) || o.price == 0 || o.price >= ONE) {
            revert BadOrder();
        }
        if (block.timestamp > o.expiry || !markets[marketOf(o.tokenId)].exists) revert BadOrder();
        if (markets[marketOf(o.tokenId)].resolved) revert AlreadyResolved();

        bytes32 h = hashOrder(o);
        if (cancelled[h]) revert BadOrder();
        if (filled[h] + fillAmount > o.amount) revert Overfill();
        if (!SignatureChecker.isValidSignatureNow(o.maker, h, signature)) revert BadSignature();
        filled[h] += fillAmount;

        if (o.side == Side.Sell) {
            // taker buys: pays USDC (rounded up) to maker, gets shares
            usdcAmount = Math.mulDiv(fillAmount, o.price, ONE, Math.Rounding.Ceil);
            _collateral.safeTransferFrom(msg.sender, o.maker, usdcAmount);
            _shares.safeTransferFrom(o.maker, recipient, o.tokenId, fillAmount, "");
        } else {
            // taker sells: sends shares to maker, gets USDC (rounded down)
            usdcAmount = Math.mulDiv(fillAmount, o.price, ONE, Math.Rounding.Floor);
            _shares.safeTransferFrom(msg.sender, o.maker, o.tokenId, fillAmount, "");
            _collateral.safeTransferFrom(o.maker, recipient, usdcAmount);
        }
        emit OrderFilled(h, msg.sender, fillAmount, usdcAmount);
    }

    function cancel(Order calldata o) external override {
        if (msg.sender != o.maker) revert BadOrder();
        bytes32 h = hashOrder(o);
        cancelled[h] = true;
        emit OrderCancelled(h);
    }
}
