// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console2} from "forge-std/Script.sol";

interface IRegistryLike {
    struct AttestationRequest {
        address moduleAddress;
        uint48 expirationTime;
        bytes data;
        uint256[] moduleTypes;
    }

    struct ModuleRecord {
        bytes32 resolverUID;
        address sender;
        bytes metadata;
    }

    struct AttestationRecord {
        uint48 time;
        uint48 expirationTime;
        uint48 revocationTime;
        uint256 moduleTypes;
        address moduleAddress;
        address attester;
        address dataPointer;
        bytes32 schemaUID;
    }

    function registerResolver(address resolver) external returns (bytes32 uid);
    function registerSchema(string calldata schema, address validator) external returns (bytes32 uid);
    function registerModule(bytes32 resolverUID, address module, bytes calldata metadata, bytes calldata ctx) external;
    function attest(bytes32 schemaUID, AttestationRequest calldata request) external;
    function findModule(address module) external view returns (ModuleRecord memory);
    function findAttestation(address module, address attester) external view returns (AttestationRecord memory);
}

/// @notice Registry resolver that accepts everything: every call (supportsInterface and the
///         resolve* callbacks) returns true. Local fixture for the attestations below.
contract OpenResolver {
    fallback() external payable {
        assembly {
            mstore(0, 1)
            return(0, 32)
        }
    }

    receive() external payable {}
}

/// @title DeployLocalAttestations (LOCAL ONLY)
/// @notice The ModuleKit 0.5.9 Smart Sessions build calls `registry.checkForAccount(account, module)` on the
///         Rhinestone ERC-7484 registry for every policy and session validator it enables. (ModuleKit tests
///         etch a mock registry there; a fork has the real one.) The broadcaster registers and attests our two
///         policies and the session validator; accounts then trust it as their attester at creation.
///         The canonical Smart Sessions has no such check, so this goes away with the V13 ABI migration.
///
///   REGISTRY=0x... MODULES=0xA,0xB,0xC forge script script/DeployLocalAttestations.s.sol --broadcast ...
///
/// Output: deployments/<chainId>.attester.json
contract DeployLocalAttestations is Script {
    bytes32 internal constant SALT = keccak256("session-firewall.local-attestations.v1");

    function run() external returns (address attester) {
        require(block.chainid == 31337, "local Anvil only: chain id must be 31337");
        IRegistryLike registry = IRegistryLike(vm.envAddress("REGISTRY"));
        address[] memory modules = vm.envAddress("MODULES", ",");
        // Smart Sessions checks session validators with type 7 (stateless validator), policies with no type
        uint256[] memory moduleTypes = new uint256[](1);
        moduleTypes[0] = 7;

        vm.startBroadcast();
        (, attester,) = vm.readCallers();

        bool pending;
        for (uint256 i; i < modules.length; ++i) {
            if (registry.findAttestation(modules[i], attester).time == 0) pending = true;
        }
        if (pending) {
            bytes memory initCode = type(OpenResolver).creationCode;
            address resolver = vm.computeCreate2Address(SALT, keccak256(initCode));
            if (resolver.code.length == 0) {
                (bool ok,) = CREATE2_FACTORY.call(abi.encodePacked(SALT, initCode));
                require(ok && resolver.code.length > 0, "resolver deployment failed");
            }
            // unique per run: the registry refuses duplicate resolver owners and schemas
            bytes32 resolverUID = registry.registerResolver(resolver);
            bytes32 schemaUID =
                registry.registerSchema(string.concat("session-firewall local ", vm.toString(attester)), address(0));
            for (uint256 i; i < modules.length; ++i) {
                if (registry.findAttestation(modules[i], attester).time != 0) continue;
                if (registry.findModule(modules[i]).resolverUID == bytes32(0)) {
                    registry.registerModule(resolverUID, modules[i], "", "");
                }
                registry.attest(
                    schemaUID,
                    IRegistryLike.AttestationRequest({
                        moduleAddress: modules[i],
                        expirationTime: 0,
                        data: "",
                        moduleTypes: moduleTypes
                    })
                );
                console2.log("attested", modules[i]);
            }
        }
        vm.stopBroadcast();

        string memory json = vm.serializeAddress("attester", "attester", attester);
        vm.writeJson(
            json, string.concat(vm.projectRoot(), "/deployments/", vm.toString(block.chainid), ".attester.json")
        );
    }
}
