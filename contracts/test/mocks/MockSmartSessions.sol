// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ISmartSessions, SSSession, IPolicy} from "../../src/interfaces/ISmartSessions.sol";

/// @notice Records what the module enables, and initialises policies the way Smart Sessions does.
///         The real contract is exercised in test/integration.
contract MockSmartSessions is ISmartSessions {
    mapping(bytes32 => mapping(address => bool)) public enabled;
    SSSession internal _last;
    uint256 public enableCalls;

    function enableSessions(SSSession[] calldata sessions) external returns (bytes32[] memory ids) {
        ids = new bytes32[](sessions.length);
        for (uint256 i; i < sessions.length; ++i) {
            SSSession calldata s = sessions[i];
            bytes32 id = keccak256(abi.encode(s.sessionValidator, s.sessionValidatorInitData, s.salt));
            ids[i] = id;
            enabled[id][msg.sender] = true;
            for (uint256 a; a < s.actions.length; ++a) {
                for (uint256 p; p < s.actions[a].actionPolicies.length; ++p) {
                    IPolicy(s.actions[a].actionPolicies[p].policy).initializeWithMultiplexer(
                        msg.sender, configId(id, a), s.actions[a].actionPolicies[p].initData
                    );
                }
            }
            _last = s;
        }
        enableCalls++;
    }

    function removeSession(bytes32 permissionId) external {
        enabled[permissionId][msg.sender] = false;
    }

    function isPermissionEnabled(bytes32 permissionId, address account) external view returns (bool) {
        return enabled[permissionId][account];
    }

    function last() external view returns (SSSession memory) {
        return _last;
    }

    function configId(bytes32 permissionId, uint256 actionIndex) public pure returns (bytes32) {
        return keccak256(abi.encode(permissionId, actionIndex));
    }
}
