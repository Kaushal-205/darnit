// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console2} from "forge-std/Script.sol";
import {MockUSDC} from "../test/fixtures/MockUSDC.sol";
import {ReferenceMarket, OutcomeShares} from "../test/fixtures/ReferenceMarket.sol";
import {ReferenceMarketAdapter} from "../src/adapters/ReferenceMarketAdapter.sol";
import {IReferenceMarket} from "../src/interfaces/IReferenceMarket.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/// @title DeployFixtures (testnet / local only)
/// @notice MockUSDC, ReferenceMarket (+ its OutcomeShares), ReferenceMarketAdapter, one demo market, and
///         maker liquidity: the maker splits USDC into YES/NO shares so takers can buy either side.
///         Deterministic (CREATE2) for a given broadcaster, which is also the market resolver. Idempotent.
///
///   MAKER_PRIVATE_KEY=0x... forge script script/DeployFixtures.s.sol --rpc-url $RPC --broadcast --private-key $KEY
///
/// Env: MAKER_PRIVATE_KEY (required), SEED_USDC (optional, default 100,000 USDC split into shares).
/// Output: deployments/<chainId>.fixtures.json
contract DeployFixtures is Script {
    bytes32 internal constant SALT = keccak256("session-firewall.fixtures.v1");
    string internal constant QUESTION = "Will it rain tomorrow?";

    struct Fixtures {
        address usdc;
        address market;
        address shares;
        address adapter;
        address resolver;
        address maker;
        uint256 marketId;
        uint256 yesId;
        uint256 noId;
    }

    function run() external returns (Fixtures memory f) {
        uint256 makerKey = vm.envUint("MAKER_PRIVATE_KEY");
        uint256 seed = vm.envOr("SEED_USDC", uint256(100_000e6));
        f.maker = vm.addr(makerKey);

        vm.startBroadcast();
        (, f.resolver,) = vm.readCallers();
        f.usdc = _create2(type(MockUSDC).creationCode);
        f.market = _create2(abi.encodePacked(type(ReferenceMarket).creationCode, abi.encode(f.usdc, f.resolver)));
        f.shares = ReferenceMarket(f.market).shares();
        f.adapter = _create2(
            abi.encodePacked(type(ReferenceMarketAdapter).creationCode, abi.encode(IReferenceMarket(f.market)))
        );
        ReferenceMarket market = ReferenceMarket(f.market);
        f.marketId = market.nextMarketId() == 1 ? market.createMarket(QUESTION) : 1;
        vm.stopBroadcast();

        (f.yesId, f.noId) = market.outcomeIds(f.marketId);
        OutcomeShares shares = OutcomeShares(f.shares);
        if (shares.balanceOf(f.maker, f.yesId) < seed / 2) {
            vm.startBroadcast(makerKey);
            MockUSDC(f.usdc).mint(f.maker, seed * 2);
            IERC20(f.usdc).approve(f.market, type(uint256).max);
            shares.setApprovalForAll(f.market, true);
            market.split(f.marketId, seed);
            vm.stopBroadcast();
            console2.log("seeded maker", f.maker);
        }

        _write(f);
    }

    function _create2(bytes memory initCode) internal returns (address addr) {
        addr = vm.computeCreate2Address(SALT, keccak256(initCode));
        if (addr.code.length > 0) return addr;
        (bool ok,) = CREATE2_FACTORY.call(abi.encodePacked(SALT, initCode));
        require(ok && addr.code.length > 0, "CREATE2 deployment failed");
        console2.log("deployed", addr);
    }

    function _write(Fixtures memory f) internal {
        string memory k = "fixtures";
        vm.serializeUint(k, "chainId", block.chainid);
        vm.serializeAddress(k, "usdc", f.usdc);
        vm.serializeAddress(k, "market", f.market);
        vm.serializeAddress(k, "shares", f.shares);
        vm.serializeAddress(k, "adapter", f.adapter);
        vm.serializeAddress(k, "resolver", f.resolver);
        vm.serializeAddress(k, "maker", f.maker);
        vm.serializeUint(k, "marketId", f.marketId);
        vm.serializeUint(k, "yesId", f.yesId);
        string memory json = vm.serializeUint(k, "noId", f.noId);
        string memory path =
            string.concat(vm.projectRoot(), "/deployments/", vm.toString(block.chainid), ".fixtures.json");
        vm.writeJson(json, path);
        console2.log("wrote", path);
    }
}
