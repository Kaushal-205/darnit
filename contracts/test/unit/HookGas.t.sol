// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {console} from "forge-std/console.sol";
import {Base} from "../Base.t.sol";
import {IReferenceMarket} from "../../src/interfaces/IReferenceMarket.sol";
import {Execution} from "../../src/interfaces/IERC7579.sol";
import {MockAccount} from "../mocks/MockAccount.sol";

/// @notice V6: hook overhead = gas(hooked account) - gas(same execution on an unhooked account).
///         The plain run goes first, so shared market/token slots are warm for the hooked run and the
///         figure is a lower bound; swapping the order gives the upper bound (see docs/decisions.md).
contract HookGasTest is Base {
    MockAccount internal plain;

    function setUp() public override {
        super.setUp();
        plain = new MockAccount(entryPoint);
        usdc.mint(address(plain), START_USDC);
        vm.startPrank(entryPoint);
        plain.execute(
            MODE_SINGLE,
            abi.encodePacked(
                address(usdc), uint256(0), abi.encodeCall(usdc.approve, (address(market), type(uint256).max))
            )
        );
        vm.stopPrank();
    }

    function _gas(MockAccount acc, bytes32 mode, bytes memory ec) internal returns (uint256 used) {
        vm.prank(entryPoint);
        uint256 g = gasleft();
        acc.execute(mode, ec);
        used = g - gasleft();
    }

    function _fill(address recipient) internal returns (bytes memory) {
        return _fillCall(IReferenceMarket.Side.Sell, yesId, 0.5e6, 100e6, recipient);
    }

    function test_gas_singleFill() public {
        uint256 without =
            _gas(plain, MODE_SINGLE, abi.encodePacked(address(market), uint256(0), _fill(address(plain))));
        uint256 withHook = _gas(
            account, MODE_SINGLE, abi.encodePacked(address(market), uint256(0), _fill(address(account)))
        );
        console.log("single fill  hooked %d  plain %d  overhead %d", withHook, without, withHook - without);
    }

    function test_gas_batchOfFourFills() public {
        Execution[] memory a = new Execution[](4);
        Execution[] memory b = new Execution[](4);
        for (uint256 i; i < 4; ++i) {
            a[i] = Execution(address(market), 0, _fill(address(account)));
            b[i] = Execution(address(market), 0, _fill(address(plain)));
        }
        uint256 without = _gas(plain, MODE_BATCH, abi.encode(b));
        uint256 withHook = _gas(account, MODE_BATCH, abi.encode(a));
        console.log("4-fill batch hooked %d  plain %d  overhead %d", withHook, without, withHook - without);
    }

    function test_gas_exitTransfer() public {
        bytes memory t = abi.encodeCall(usdc.transfer, (dest, 1e6));
        uint256 without = _gas(plain, MODE_SINGLE, abi.encodePacked(address(usdc), uint256(0), t));
        uint256 withHook = _gas(account, MODE_SINGLE, abi.encodePacked(address(usdc), uint256(0), t));
        console.log("exit transfer hooked %d  plain %d  overhead %d", withHook, without, withHook - without);
    }
}
