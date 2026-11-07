// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title RiskBudget
/// @notice Token bucket: capacity = cap, refilling at cap / 3600 per second. Refill rounds down,
///         so the bucket can only ever under-report what is available (INV2).
library RiskBudget {
    uint256 internal constant WINDOW = 3600;

    struct Bucket {
        uint128 level;
        uint64 updatedAt;
    }

    function available(Bucket memory b, uint128 cap, uint256 timestamp) internal pure returns (uint256) {
        uint256 elapsed = timestamp > b.updatedAt ? timestamp - b.updatedAt : 0;
        // elapsed < 2^64 and cap < 2^128, so the product fits in 256 bits
        uint256 level = uint256(b.level) + (elapsed * cap) / WINDOW;
        return level > cap ? cap : level;
    }

    /// @dev Brings the stored level up to date. Must run before any cap change.
    function settle(Bucket storage b, uint128 cap) internal {
        b.level = uint128(available(b, cap, block.timestamp));
        b.updatedAt = uint64(block.timestamp);
    }

    /// @return ok false if the bucket holds less than amount (state untouched)
    /// @return remaining the level after consumption, or the available level if not ok
    function tryConsume(Bucket storage b, uint128 cap, uint256 amount)
        internal
        returns (bool ok, uint256 remaining)
    {
        uint256 avail = available(b, cap, block.timestamp);
        if (amount > avail) return (false, avail);
        remaining = avail - amount;
        b.level = uint128(remaining);
        b.updatedAt = uint64(block.timestamp);
        return (true, remaining);
    }

    /// @dev Clamp the level to a new, lower cap. Settles with the old cap first.
    function lower(Bucket storage b, uint128 oldCap, uint128 newCap) internal {
        settle(b, oldCap);
        if (b.level > newCap) b.level = newCap;
    }

    function empty(Bucket storage b) internal {
        b.level = 0;
        b.updatedAt = uint64(block.timestamp);
    }
}
