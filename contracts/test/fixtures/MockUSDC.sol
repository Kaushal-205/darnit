// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";

/// @notice Testnet-only 6-decimal stablecoin with an open faucet and EIP-2612 permits.
contract MockUSDC is ERC20, ERC20Permit {
    uint256 public constant FAUCET_LIMIT = 10_000e6;

    error FaucetLimit();

    constructor() ERC20("Mock USD Coin", "mUSDC") ERC20Permit("Mock USD Coin") {}

    function decimals() public pure override returns (uint8) {
        return 6;
    }

    function faucet(address to, uint256 amount) external {
        if (amount > FAUCET_LIMIT) revert FaucetLimit();
        _mint(to, amount);
    }

    /// @dev Unlimited mint for tests and local scripts.
    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}
