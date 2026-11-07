// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {RiskBudget} from "../../src/lib/RiskBudget.sol";

contract BucketHarness {
    using RiskBudget for RiskBudget.Bucket;

    RiskBudget.Bucket public b;
    uint128 public cap;

    constructor(uint128 cap_, uint128 level) {
        cap = cap_;
        b = RiskBudget.Bucket({level: level, updatedAt: uint64(block.timestamp)});
    }

    function available() external view returns (uint256) {
        return b.available(cap, block.timestamp);
    }

    function consume(uint256 amount) external returns (bool ok, uint256 remaining) {
        return b.tryConsume(cap, amount);
    }

    function lower(uint128 newCap) external {
        b.lower(cap, newCap);
        cap = newCap;
    }

    function raise(uint128 newCap) external {
        b.settle(cap);
        cap = newCap;
    }
}

/// @notice R4: token bucket with capacity = cap, refill cap / 3600 per second.
contract RiskBudgetTest is Test {
    uint128 constant CAP = 3_600e6;

    function test_R4_startsAtGivenLevel() public {
        BucketHarness h = new BucketHarness(CAP, CAP);
        assertEq(h.available(), CAP);
    }

    function test_R4_refillsLinearly() public {
        BucketHarness h = new BucketHarness(CAP, 0);
        vm.warp(block.timestamp + 60);
        assertEq(h.available(), 60e6); // $1 per second
        vm.warp(block.timestamp + 3_600);
        assertEq(h.available(), CAP); // clamped at capacity
    }

    function test_R4_consumeReducesLevel() public {
        BucketHarness h = new BucketHarness(CAP, CAP);
        (bool ok, uint256 remaining) = h.consume(1_000e6);
        assertTrue(ok);
        assertEq(remaining, 2_600e6);
        assertEq(h.available(), 2_600e6);
    }

    function test_R4_overConsumeLeavesStateUntouched() public {
        BucketHarness h = new BucketHarness(CAP, 100e6);
        (bool ok, uint256 avail) = h.consume(100e6 + 1);
        assertFalse(ok);
        assertEq(avail, 100e6);
        assertEq(h.available(), 100e6);
    }

    function test_R4_lowerClampsLevel() public {
        BucketHarness h = new BucketHarness(CAP, CAP);
        h.lower(500e6);
        assertEq(h.available(), 500e6);
    }

    function test_R4_raiseDoesNotRefillInstantly() public {
        BucketHarness h = new BucketHarness(CAP, 0);
        h.raise(2 * CAP);
        assertEq(h.available(), 0);
        vm.warp(block.timestamp + 1);
        assertEq(h.available(), 2e6);
    }

    /// INV2 at library level: over any one-hour window, total consumed <= cap + starting level.
    function testFuzz_R4_windowBound(uint128 cap, uint256[8] memory amounts, uint16[8] memory gaps) public {
        cap = uint128(bound(cap, 1, 1e18));
        BucketHarness h = new BucketHarness(cap, cap);
        uint256 start = block.timestamp;
        uint256 total;
        for (uint256 i; i < 8; ++i) {
            uint256 t = block.timestamp + (gaps[i] % 600);
            if (t > start + 3_600) break;
            vm.warp(t);
            (bool ok,) = h.consume(bound(amounts[i], 0, uint256(cap)));
            if (ok) total += bound(amounts[i], 0, uint256(cap));
        }
        assertLe(total, uint256(cap) * 2);
    }
}
