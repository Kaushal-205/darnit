// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {
    IHook,
    IERC7579Account,
    IAccountExecute,
    Execution,
    MODULE_TYPE_HOOK,
    CALLTYPE_SINGLE,
    CALLTYPE_BATCH
} from "./interfaces/IERC7579.sol";
import {IFirewallModule} from "./interfaces/IFirewallModule.sol";
import {IMarketAdapter} from "./interfaces/IMarketAdapter.sol";
import {FirewallErrors} from "./interfaces/FirewallErrors.sol";
import {ExecutionDecoder} from "./lib/ExecutionDecoder.sol";

interface IERC20Like {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
    function approve(address, uint256) external returns (bool);
    function increaseAllowance(address, uint256) external returns (bool);
    function decreaseAllowance(address, uint256) external returns (bool);
    function permit(address, address, uint256, uint256, uint8, bytes32, bytes32) external;
}

interface IERC1155Like {
    function balanceOf(address, uint256) external view returns (uint256);
    function safeTransferFrom(address, address, uint256, uint256, bytes calldata) external;
    function safeBatchTransferFrom(address, address, uint256[] calldata, uint256[] calldata, bytes calldata)
        external;
    function setApprovalForAll(address, bool) external;
}

/// @title FirewallHook
/// @notice ERC-7579 hook enforcing R1-R5 on every execution, whoever signed it.
///         preCheck: allowlisted targets and selectors, approvals only to markets, recipients only to
///         the account or destinations; then snapshots balances. postCheck: conservation and budget.
/// @dev Stateless apart from the install flag. Only external calls: the module (config, consume),
///      market adapters (view) and token balanceOf. No delegatecall, no upgradeability.
contract FirewallHook is IHook, FirewallErrors {
    using ExecutionDecoder for bytes;

    uint256 public constant MAX_SHARE_IDS = 16;

    IFirewallModule public immutable MODULE;

    mapping(address account => bool) internal _installed;

    struct Asset {
        address token;
        uint256 id;
        bool isShare;
        bool marketTouched;
    }

    struct Ctx {
        address account;
        IFirewallModule.AccountView v;
        Asset[] assets;
        uint256 nAssets;
        uint256 nShares;
        bool hasMarketCall;
    }

    constructor(IFirewallModule module) {
        if (address(module) == address(0)) revert ZeroAddress();
        MODULE = module;
    }

    // ---------------------------------------------------------------- ERC-7579 module

    function onInstall(bytes calldata) external override {
        _installed[msg.sender] = true;
    }

    function onUninstall(bytes calldata) external override {
        _installed[msg.sender] = false;
    }

    function isModuleType(uint256 moduleTypeId) external pure override returns (bool) {
        return moduleTypeId == MODULE_TYPE_HOOK;
    }

    function isInitialized(address account) external view override returns (bool) {
        return _installed[account];
    }

    // ---------------------------------------------------------------- preCheck

    function preCheck(address, uint256, bytes calldata msgData) external override returns (bytes memory) {
        address account = msg.sender;
        // A matured, owner-queued change (R6) is running: it was approved 24h ago, let it through.
        if (MODULE.configCallActive(account)) return "";
        if (msgData.length < 4) return "";

        bytes4 sel = bytes4(msgData[0:4]);
        if (sel == IERC7579Account.execute.selector || sel == IERC7579Account.executeFromExecutor.selector) {
            return _checkExecution(account, msgData[4:]);
        }
        if (
            sel == IERC7579Account.installModule.selector || sel == IERC7579Account.uninstallModule.selector
                || sel == IAccountExecute.executeUserOp.selector
        ) {
            revert ForbiddenExecution();
        }
        // Anything else is a fallback call into the account (e.g. ERC-1155 receiver callbacks). It runs no
        // account execution; fallback handlers can only be added through the queue.
        return "";
    }

    function _checkExecution(address account, bytes calldata args) internal view returns (bytes memory) {
        (bytes1 callType, bytes1 execType, bytes calldata ec) = ExecutionDecoder.decodeExecute(args);
        if (callType != CALLTYPE_SINGLE && callType != CALLTYPE_BATCH) revert ForbiddenExecution();
        if (!ExecutionDecoder.isSupportedExecType(execType)) revert ForbiddenExecution();
        Execution[] memory execs = ExecutionDecoder.decodeExecutions(callType, ec);

        Ctx memory c;
        c.account = account;
        c.v = MODULE.accountView(account);
        c.assets = new Asset[](c.v.tokens.length + MAX_SHARE_IDS);
        for (uint256 i; i < c.v.tokens.length; ++i) {
            c.assets[c.nAssets++] = Asset({token: c.v.tokens[i], id: 0, isShare: false, marketTouched: false});
        }

        for (uint256 i; i < execs.length; ++i) {
            Execution memory e = execs[i];
            if (e.target == address(MODULE) && e.callData.selector() == IFirewallModule.execute.selector) {
                // Running a matured queue item must be the only call, so nothing rides along unchecked.
                if (execs.length != 1 || e.value != 0) revert ForbiddenExecution();
                return "";
            }
            _checkCall(c, e);
        }

        Asset[] memory assets = new Asset[](c.nAssets);
        for (uint256 i; i < c.nAssets; ++i) {
            assets[i] = c.assets[i];
        }
        return abi.encode(
            account, c.v.destinations, assets, _snapshot(account, c.v.destinations, assets), c.hasMarketCall
        );
    }

    function _checkCall(Ctx memory c, Execution memory e) internal view {
        address t = e.target;
        bytes memory data = e.callData;
        bytes4 sel = data.selector();

        if (t == c.account || t == address(this)) revert ForbiddenExecution();

        if (_isDestination(c, t)) {
            // plain value transfer only
            if (data.length != 0) revert UnknownTarget(t, sel);
            return;
        }
        if (e.value != 0) revert UnknownTarget(t, sel);
        if (t == address(MODULE)) return _checkModuleCall(sel);

        if (_contains(c.v.tokens, t)) return _checkErc20Call(c, t, sel, data);
        (bool isShareToken,) = _indexOf(c.v.shareTokens, t);
        if (isShareToken) return _checkShareCall(c, t, sel, data);
        (bool isMarket, uint256 m) = _indexOf(c.v.markets, t);
        if (isMarket) return _checkMarketCall(c, m, data);

        revert UnknownTarget(t, sel);
    }

    /// @dev Only the owner-facing config surface. onInstall / onUninstall must never be reachable
    ///      from an execution: a reinstall would register new destinations instantly (bypassing R6).
    function _checkModuleCall(bytes4 sel) internal view {
        if (
            sel == IFirewallModule.queue.selector || sel == IFirewallModule.cancel.selector
                || sel == IFirewallModule.removeDestination.selector
                || sel == IFirewallModule.removeMarket.selector || sel == IFirewallModule.lowerCap.selector
                || sel == IFirewallModule.revokeSessions.selector || sel == IFirewallModule.freeze.selector
        ) return;
        revert UnknownTarget(address(MODULE), sel);
    }

    function _checkErc20Call(Ctx memory c, address t, bytes4 sel, bytes memory data) internal pure {
        if (sel == IERC20Like.transfer.selector) {
            _checkRecipient(c, data.addr(0), t, 0);
        } else if (sel == IERC20Like.transferFrom.selector) {
            _checkRecipient(c, data.addr(1), t, 0);
        } else if (sel == IERC20Like.approve.selector) {
            // approve(x, 0) only revokes, which is always allowed
            if (data.uintArg(1) != 0) _checkSpender(c, data.addr(0));
        } else if (sel == IERC20Like.increaseAllowance.selector) {
            _checkSpender(c, data.addr(0));
        } else if (sel == IERC20Like.decreaseAllowance.selector) {
            data.addr(0);
        } else if (sel == IERC20Like.permit.selector) {
            _checkSpender(c, data.addr(1));
        } else {
            revert UnknownTarget(t, sel);
        }
    }

    function _checkShareCall(Ctx memory c, address t, bytes4 sel, bytes memory data) internal pure {
        if (sel == IERC1155Like.safeTransferFrom.selector) {
            uint256 id = data.uintArg(2);
            _checkRecipient(c, data.addr(1), t, id);
            _addShare(c, t, id, false);
        } else if (sel == IERC1155Like.safeBatchTransferFrom.selector) {
            (, address to, uint256[] memory ids,,) =
                abi.decode(data.args(), (address, address, uint256[], uint256[], bytes));
            for (uint256 i; i < ids.length; ++i) {
                _checkRecipient(c, to, t, ids[i]);
                _addShare(c, t, ids[i], false);
            }
        } else if (sel == IERC1155Like.setApprovalForAll.selector) {
            uint256 approved = data.uintArg(1);
            if (approved > 1) revert ExecutionDecoder.Malformed();
            address operator = data.addr(0);
            if (approved == 1) _checkShareOperator(c, t, operator);
        } else {
            revert UnknownTarget(t, sel);
        }
    }

    function _checkMarketCall(Ctx memory c, uint256 m, bytes memory data) internal view {
        if (c.v.config.frozen) revert Frozen();
        address market = c.v.markets[m];
        IMarketAdapter.Touched memory touched = IMarketAdapter(c.v.adapters[m]).touched(c.account, data);
        if (!touched.supported) revert UnknownTarget(market, data.selector());

        for (uint256 i; i < touched.recipients.length; ++i) {
            address r = touched.recipients[i];
            if (r != c.account && !_isDestination(c, r)) revert UnexplainedOutflow(market, 0);
        }
        for (uint256 i; i < touched.erc20s.length; ++i) {
            (bool tracked, uint256 j) = _indexOfAsset(c, touched.erc20s[i], 0, false);
            if (!tracked) revert UnknownTarget(touched.erc20s[i], bytes4(0));
            c.assets[j].marketTouched = true;
        }
        for (uint256 i; i < touched.shareIds.length; ++i) {
            _addShare(c, c.v.shareTokens[m], touched.shareIds[i], true);
        }
        c.hasMarketCall = true;
    }

    function _checkRecipient(Ctx memory c, address to, address asset, uint256 id) internal pure {
        if (to != c.account && !_isDestination(c, to)) revert UnexplainedOutflow(asset, id);
    }

    function _checkSpender(Ctx memory c, address spender) internal pure {
        if (!_contains(c.v.markets, spender)) revert UnregisteredSpender(spender);
        if (c.v.config.frozen) revert Frozen();
    }

    /// @dev A share token may only be approved to the market that settles it.
    function _checkShareOperator(Ctx memory c, address shareToken, address operator) internal pure {
        for (uint256 i; i < c.v.markets.length; ++i) {
            if (c.v.markets[i] == operator && c.v.shareTokens[i] == shareToken) {
                if (c.v.config.frozen) revert Frozen();
                return;
            }
        }
        revert UnregisteredSpender(operator);
    }

    function _addShare(Ctx memory c, address token, uint256 id, bool marketTouched) internal pure {
        (bool found, uint256 j) = _indexOfAsset(c, token, id, true);
        if (found) {
            if (marketTouched) c.assets[j].marketTouched = true;
            return;
        }
        if (c.nShares == MAX_SHARE_IDS) revert TooMany();
        c.nShares++;
        c.assets[c.nAssets++] = Asset({token: token, id: id, isShare: true, marketTouched: marketTouched});
    }

    // ---------------------------------------------------------------- postCheck

    function postCheck(bytes calldata hookData) external override {
        if (hookData.length == 0) return;
        (
            address account,
            address[] memory destinations,
            Asset[] memory assets,
            uint256[] memory before,
            bool hasMarketCall
        ) = abi.decode(hookData, (address, address[], Asset[], uint256[], bool));
        if (account != msg.sender) revert ForbiddenExecution();

        uint256[] memory afterBal = _snapshot(account, destinations, assets);
        uint256 parties = destinations.length + 1;
        uint256 usdcOut;
        uint256 usdcIn;
        uint256 sharesOut;

        for (uint256 i; i < assets.length; ++i) {
            // Account and destinations form one trust zone: moving value between them is neutral (R5).
            uint256 sumBefore;
            uint256 sumAfter;
            for (uint256 j; j < parties; ++j) {
                sumBefore += before[i * parties + j];
                sumAfter += afterBal[i * parties + j];
            }
            Asset memory a = assets[i];
            if (sumAfter < sumBefore) {
                // R3: value left the trust zone. Only a market call may explain it, and only for assets
                // that market declared; everything else is unexplained.
                if (!hasMarketCall || !a.marketTouched) revert UnexplainedOutflow(a.token, a.id);
                if (a.isShare) sharesOut += sumBefore - sumAfter;
                else usdcOut += sumBefore - sumAfter;
            } else if (!a.isShare) {
                usdcIn += sumAfter - sumBefore;
            }
        }

        // R4: worst-case value out = USDC out + shares out x $1 - USDC in, floored at zero.
        // Shares received are never credited. Executions without market calls never touch the budget (R5).
        if (hasMarketCall) {
            uint256 gross = usdcOut + sharesOut;
            if (gross > usdcIn) MODULE.consume(account, gross - usdcIn);
        }
    }

    // ---------------------------------------------------------------- helpers

    function _snapshot(address account, address[] memory destinations, Asset[] memory assets)
        internal
        view
        returns (uint256[] memory bal)
    {
        uint256 parties = destinations.length + 1;
        bal = new uint256[](assets.length * parties);
        for (uint256 i; i < assets.length; ++i) {
            for (uint256 j; j < parties; ++j) {
                address who = j == 0 ? account : destinations[j - 1];
                bal[i * parties + j] = assets[i].isShare
                    ? IERC1155Like(assets[i].token).balanceOf(who, assets[i].id)
                    : IERC20Like(assets[i].token).balanceOf(who);
            }
        }
    }

    function _isDestination(Ctx memory c, address a) internal pure returns (bool) {
        return _contains(c.v.destinations, a);
    }

    function _contains(address[] memory list, address a) internal pure returns (bool found) {
        (found,) = _indexOf(list, a);
    }

    function _indexOf(address[] memory list, address a) internal pure returns (bool, uint256) {
        for (uint256 i; i < list.length; ++i) {
            if (list[i] == a) return (true, i);
        }
        return (false, 0);
    }

    function _indexOfAsset(Ctx memory c, address token, uint256 id, bool isShare)
        internal
        pure
        returns (bool, uint256)
    {
        for (uint256 i; i < c.nAssets; ++i) {
            Asset memory a = c.assets[i];
            if (a.token == token && a.id == id && a.isShare == isShare) return (true, i);
        }
        return (false, 0);
    }
}
