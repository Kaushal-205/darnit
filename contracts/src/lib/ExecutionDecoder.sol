// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {
    Execution,
    CALLTYPE_SINGLE,
    CALLTYPE_BATCH,
    EXECTYPE_DEFAULT,
    EXECTYPE_TRY
} from "../interfaces/IERC7579.sol";

/// @title ExecutionDecoder
/// @notice Decodes ERC-7579 execute / executeFromExecutor calldata and the argument words of token calls.
///         Everything is bounds-checked; malformed input reverts with Malformed().
library ExecutionDecoder {
    error Malformed();

    /// @param params msgData without its 4-byte selector, ABI-encoded (bytes32 mode, bytes executionCalldata)
    function decodeExecute(bytes calldata params)
        internal
        pure
        returns (bytes1 callType, bytes1 execType, bytes calldata executionCalldata)
    {
        if (params.length < 64) revert Malformed();
        bytes32 mode = bytes32(params[0:32]);
        callType = mode[0];
        execType = mode[1];
        uint256 offset = uint256(bytes32(params[32:64]));
        if (offset > params.length || params.length - offset < 32) revert Malformed();
        uint256 len = uint256(bytes32(params[offset:offset + 32]));
        if (len > params.length - offset - 32) revert Malformed();
        executionCalldata = params[offset + 32:offset + 32 + len];
    }

    function isSupportedExecType(bytes1 execType) internal pure returns (bool) {
        return execType == EXECTYPE_DEFAULT || execType == EXECTYPE_TRY;
    }

    /// @notice Decode single or batch executions into memory. Reverts for any other call type.
    function decodeExecutions(bytes1 callType, bytes calldata executionCalldata)
        internal
        pure
        returns (Execution[] memory executions)
    {
        if (callType == CALLTYPE_SINGLE) {
            if (executionCalldata.length < 52) revert Malformed();
            executions = new Execution[](1);
            executions[0] = Execution({
                target: address(bytes20(executionCalldata[0:20])),
                value: uint256(bytes32(executionCalldata[20:52])),
                callData: executionCalldata[52:]
            });
        } else if (callType == CALLTYPE_BATCH) {
            executions = abi.decode(executionCalldata, (Execution[]));
        } else {
            revert Malformed();
        }
    }

    function selector(bytes memory data) internal pure returns (bytes4 sel) {
        if (data.length < 4) return bytes4(0);
        assembly ("memory-safe") {
            sel := mload(add(data, 32))
        }
    }

    /// @notice The i-th static 32-byte argument after the selector.
    function word(bytes memory data, uint256 i) internal pure returns (bytes32 w) {
        uint256 end = 4 + 32 * (i + 1);
        if (data.length < end) revert Malformed();
        assembly ("memory-safe") {
            w := mload(add(add(data, 36), mul(i, 32)))
        }
    }

    /// @notice The i-th argument as an address; rejects dirty upper bits like the ABI decoder would.
    function addr(bytes memory data, uint256 i) internal pure returns (address) {
        uint256 w = uint256(word(data, i));
        if (w > type(uint160).max) revert Malformed();
        return address(uint160(w));
    }

    function uintArg(bytes memory data, uint256 i) internal pure returns (uint256) {
        return uint256(word(data, i));
    }

    /// @notice Copy of data without its 4-byte selector, for abi.decode of dynamic arguments.
    function args(bytes memory data) internal pure returns (bytes memory out) {
        if (data.length < 4) revert Malformed();
        out = new bytes(data.length - 4);
        for (uint256 i; i < out.length; ++i) {
            out[i] = data[i + 4];
        }
    }
}
