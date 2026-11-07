// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IFirewallModule} from "./interfaces/IFirewallModule.sol";
import {IMarketAdapter} from "./interfaces/IMarketAdapter.sol";
import {IERC7579Account, IModule, MODULE_TYPE_EXECUTOR, CALLTYPE_SINGLE} from "./interfaces/IERC7579.sol";
import {RiskBudget} from "./lib/RiskBudget.sol";

/// @title FirewallModule
/// @notice ERC-7579 executor holding each account's firewall config, the 24-hour change queue,
///         the risk-budget bucket, and the freeze / revoke switches. No owner, no admin, no upgrades.
/// @dev All per-account state sits in one struct at keccak(account . slot) using fixed-size arrays,
///      so every slot is ERC-7562 "associated storage" and policies may read it during validation.
contract FirewallModule is IFirewallModule, IModule {
    using RiskBudget for RiskBudget.Bucket;

    uint32 public constant MIN_DELAY = 24 hours;
    uint256 public constant MAX_TOKENS = 4;
    uint256 public constant MAX_DESTINATIONS = 8;
    uint256 public constant MAX_MARKETS = 4;

    struct AccountState {
        Config config;
        RiskBudget.Bucket bucket;
        uint64 sessionEpoch;
        uint64 nonce;
        bool initialized;
        uint8 nTokens;
        uint8 nDestinations;
        uint8 nMarkets;
        address[MAX_TOKENS] tokens;
        address[MAX_DESTINATIONS] destinations;
        address[MAX_MARKETS] markets;
        address[MAX_MARKETS] adapters;
        address[MAX_MARKETS] shareTokens;
    }

    address public immutable HOOK;

    mapping(address account => AccountState) internal _state;
    // keyed id-first so the account is the inner key (associated storage)
    mapping(bytes32 id => mapping(address account => Change)) internal _changes;

    /// @dev Set only while execute() runs a matured ConfigCall for this account.
    address internal transient _configCallAccount;

    constructor(address hook) {
        if (hook == address(0)) revert ZeroAddress();
        HOOK = hook;
    }

    modifier onlyInitialized() {
        if (!_state[msg.sender].initialized) revert NotInitialized(msg.sender);
        _;
    }

    // ---------------------------------------------------------------- ERC-7579 module

    /// @param data abi.encode(uint128 hourlyCap, address[] tokens, address[] destinations,
    ///             address[] markets, address[] adapters). Entries passed here are active at once.
    function onInstall(bytes calldata data) external override {
        AccountState storage s = _state[msg.sender];
        if (s.initialized) revert AlreadyInitialized(msg.sender);
        (
            uint128 cap,
            address[] memory tokens,
            address[] memory destinations,
            address[] memory markets,
            address[] memory adapters
        ) = abi.decode(data, (uint128, address[], address[], address[], address[]));
        if (markets.length != adapters.length) revert InvalidEntry(address(0));

        s.initialized = true;
        s.config = Config({hourlyCap: cap, delay: MIN_DELAY, frozen: false});
        s.bucket = RiskBudget.Bucket({level: cap, updatedAt: uint64(block.timestamp)});
        for (uint256 i; i < tokens.length; ++i) {
            _addToken(msg.sender, s, tokens[i]);
        }
        for (uint256 i; i < destinations.length; ++i) {
            _addDestination(msg.sender, s, destinations[i]);
        }
        for (uint256 i; i < markets.length; ++i) {
            _addMarket(msg.sender, s, markets[i], adapters[i]);
        }
        emit Installed(msg.sender, cap);
    }

    /// @dev Reachable only through a matured ConfigCall (the hook forbids uninstallModule otherwise).
    ///      Nonce and session epoch survive so stale queue ids and revoked sessions stay dead.
    function onUninstall(bytes calldata) external override {
        AccountState storage s = _state[msg.sender];
        uint64 nonce = s.nonce;
        uint64 epoch = s.sessionEpoch;
        delete _state[msg.sender];
        _state[msg.sender].nonce = nonce;
        _state[msg.sender].sessionEpoch = epoch + 1;
        emit Uninstalled(msg.sender);
    }

    function isModuleType(uint256 moduleTypeId) external pure override returns (bool) {
        return moduleTypeId == MODULE_TYPE_EXECUTOR;
    }

    function isInitialized(address account) external view override returns (bool) {
        return _state[account].initialized;
    }

    // ---------------------------------------------------------------- reads

    function isDestination(address account, address dest) public view override returns (bool) {
        AccountState storage s = _state[account];
        for (uint256 i; i < s.nDestinations; ++i) {
            if (s.destinations[i] == dest) return true;
        }
        return false;
    }

    function marketAdapter(address account, address market) external view override returns (address) {
        AccountState storage s = _state[account];
        for (uint256 i; i < s.nMarkets; ++i) {
            if (s.markets[i] == market) return s.adapters[i];
        }
        return address(0);
    }

    function trackedTokens(address account) external view override returns (address[] memory out) {
        AccountState storage s = _state[account];
        out = new address[](s.nTokens);
        for (uint256 i; i < out.length; ++i) {
            out[i] = s.tokens[i];
        }
    }

    function config(address account) external view override returns (Config memory) {
        return _state[account].config;
    }

    function accountView(address account) external view override returns (AccountView memory v) {
        AccountState storage s = _state[account];
        if (!s.initialized) revert NotInitialized(account);
        v.config = s.config;
        v.tokens = new address[](s.nTokens);
        for (uint256 i; i < s.nTokens; ++i) {
            v.tokens[i] = s.tokens[i];
        }
        v.destinations = new address[](s.nDestinations);
        for (uint256 i; i < s.nDestinations; ++i) {
            v.destinations[i] = s.destinations[i];
        }
        v.markets = new address[](s.nMarkets);
        v.adapters = new address[](s.nMarkets);
        v.shareTokens = new address[](s.nMarkets);
        for (uint256 i; i < s.nMarkets; ++i) {
            v.markets[i] = s.markets[i];
            v.adapters[i] = s.adapters[i];
            v.shareTokens[i] = s.shareTokens[i];
        }
    }

    function sessionEpoch(address account) external view override returns (uint64) {
        return _state[account].sessionEpoch;
    }

    function configCallActive(address account) external view override returns (bool) {
        return account != address(0) && _configCallAccount == account;
    }

    function availableBudget(address account) external view override returns (uint256) {
        AccountState storage s = _state[account];
        return s.bucket.available(s.config.hourlyCap, block.timestamp);
    }

    function pendingChange(address account, bytes32 id) external view returns (Change memory) {
        return _changes[id][account];
    }

    // ---------------------------------------------------------------- budget (R4)

    function consume(address account, uint256 worstCaseOut) external override {
        if (msg.sender != HOOK) revert OnlyHook();
        AccountState storage s = _state[account];
        if (!s.initialized) revert NotInitialized(account);
        if (s.config.frozen) revert Frozen();
        (bool ok, uint256 remaining) = s.bucket.tryConsume(s.config.hourlyCap, worstCaseOut);
        if (!ok) revert BudgetExceeded(worstCaseOut, remaining);
        emit BudgetConsumed(account, worstCaseOut, remaining);
    }

    // ---------------------------------------------------------------- loosening: queued (R6)

    function queue(ChangeKind kind, bytes calldata data)
        external
        override
        onlyInitialized
        returns (bytes32 id)
    {
        AccountState storage s = _state[msg.sender];
        _precheckChange(s, kind, data);
        id = keccak256(abi.encode(msg.sender, s.nonce++, kind, data));
        uint64 eta = uint64(block.timestamp) + s.config.delay;
        _changes[id][msg.sender] = Change({kind: kind, eta: eta, data: data});
        emit ChangeQueued(msg.sender, id, kind, data, eta);
    }

    function execute(bytes32 id) external override onlyInitialized {
        Change memory c = _changes[id][msg.sender];
        if (c.eta == 0) revert UnknownChange(id);
        if (block.timestamp < c.eta) revert TooEarly(c.eta);
        delete _changes[id][msg.sender];

        AccountState storage s = _state[msg.sender];
        if (c.kind == ChangeKind.AddDestination) {
            _addDestination(msg.sender, s, abi.decode(c.data, (address)));
        } else if (c.kind == ChangeKind.AddMarket) {
            (address market, address adapter) = abi.decode(c.data, (address, address));
            _addMarket(msg.sender, s, market, adapter);
        } else if (c.kind == ChangeKind.AddToken) {
            _addToken(msg.sender, s, abi.decode(c.data, (address)));
        } else if (c.kind == ChangeKind.RaiseCap) {
            s.bucket.settle(s.config.hourlyCap);
            s.config.hourlyCap = abi.decode(c.data, (uint128));
        } else if (c.kind == ChangeKind.Unfreeze) {
            s.config.frozen = false;
        } else {
            (address target, uint256 value, bytes memory callData) =
                abi.decode(c.data, (address, uint256, bytes));
            address previous = _configCallAccount;
            _configCallAccount = msg.sender;
            IERC7579Account(msg.sender)
                .executeFromExecutor(bytes32(CALLTYPE_SINGLE), abi.encodePacked(target, value, callData));
            _configCallAccount = previous;
        }
        emit ChangeExecuted(msg.sender, id);
    }

    function cancel(bytes32 id) external override onlyInitialized {
        if (_changes[id][msg.sender].eta == 0) revert UnknownChange(id);
        delete _changes[id][msg.sender];
        emit ChangeCancelled(msg.sender, id);
    }

    // ---------------------------------------------------------------- tightening: instant

    function removeDestination(address dest) external override onlyInitialized {
        AccountState storage s = _state[msg.sender];
        uint256 n = s.nDestinations;
        for (uint256 i; i < n; ++i) {
            if (s.destinations[i] == dest) {
                s.destinations[i] = s.destinations[n - 1];
                s.destinations[n - 1] = address(0);
                s.nDestinations = uint8(n - 1);
                emit DestinationRemoved(msg.sender, dest);
                return;
            }
        }
        revert InvalidEntry(dest);
    }

    function removeMarket(address market) external override onlyInitialized {
        AccountState storage s = _state[msg.sender];
        uint256 n = s.nMarkets;
        for (uint256 i; i < n; ++i) {
            if (s.markets[i] == market) {
                s.markets[i] = s.markets[n - 1];
                s.adapters[i] = s.adapters[n - 1];
                s.shareTokens[i] = s.shareTokens[n - 1];
                s.markets[n - 1] = address(0);
                s.adapters[n - 1] = address(0);
                s.shareTokens[n - 1] = address(0);
                s.nMarkets = uint8(n - 1);
                emit MarketRemoved(msg.sender, market);
                return;
            }
        }
        revert InvalidEntry(market);
    }

    function lowerCap(uint128 newCap) external override onlyInitialized {
        AccountState storage s = _state[msg.sender];
        if (newCap > s.config.hourlyCap) revert NotTightening();
        s.bucket.lower(s.config.hourlyCap, newCap);
        s.config.hourlyCap = newCap;
        emit CapLowered(msg.sender, newCap);
    }

    function revokeSessions() public override onlyInitialized {
        AccountState storage s = _state[msg.sender];
        emit SessionsRevoked(msg.sender, ++s.sessionEpoch);
    }

    /// @notice R8: one instant call revokes every session and drops the budget to zero.
    function freeze() external override onlyInitialized {
        AccountState storage s = _state[msg.sender];
        s.config.frozen = true;
        s.config.hourlyCap = 0;
        s.bucket.empty();
        revokeSessions();
        emit CapLowered(msg.sender, 0);
        emit FreezeActivated(msg.sender);
    }

    // ---------------------------------------------------------------- internals

    function _precheckChange(AccountState storage s, ChangeKind kind, bytes calldata data) internal view {
        if (kind == ChangeKind.AddDestination || kind == ChangeKind.AddToken) {
            _checkNew(msg.sender, s, abi.decode(data, (address)));
        } else if (kind == ChangeKind.AddMarket) {
            (address market, address adapter) = abi.decode(data, (address, address));
            _checkNew(msg.sender, s, market);
            if (adapter == address(0)) revert ZeroAddress();
        } else if (kind == ChangeKind.RaiseCap) {
            if (abi.decode(data, (uint128)) <= s.config.hourlyCap) revert NotLoosening();
        } else if (kind == ChangeKind.Unfreeze) {
            if (!s.config.frozen) revert NotLoosening();
        } else {
            abi.decode(data, (address, uint256, bytes));
        }
    }

    function _addToken(address account, AccountState storage s, address token) internal {
        _checkNew(account, s, token);
        if (s.nTokens == MAX_TOKENS) revert TooMany();
        s.tokens[s.nTokens++] = token;
    }

    function _addDestination(address account, AccountState storage s, address dest) internal {
        _checkNew(account, s, dest);
        if (s.nDestinations == MAX_DESTINATIONS) revert TooMany();
        s.destinations[s.nDestinations++] = dest;
    }

    function _addMarket(address account, AccountState storage s, address market, address adapter) internal {
        _checkNew(account, s, market);
        if (adapter == address(0)) revert ZeroAddress();
        if (IMarketAdapter(adapter).market() != market) revert InvalidEntry(adapter);
        address shareToken = IMarketAdapter(adapter).shareToken();
        // a share token may be shared by several markets, but must not collide with anything else
        if (
            shareToken == address(0) || shareToken == account || shareToken == address(this)
                || shareToken == HOOK
        ) {
            revert InvalidEntry(shareToken);
        }
        if (_inTokens(s, shareToken) || _inDestinations(s, shareToken) || _inMarkets(s, shareToken)) {
            revert InvalidEntry(shareToken);
        }
        if (s.nMarkets == MAX_MARKETS) revert TooMany();
        uint256 i = s.nMarkets++;
        s.markets[i] = market;
        s.adapters[i] = adapter;
        s.shareTokens[i] = shareToken;
    }

    /// @dev Tokens, destinations, markets and share tokens are disjoint sets, none is the account
    ///      or a firewall contract. This keeps the hook's classification of every target unambiguous.
    function _checkNew(address account, AccountState storage s, address entry) internal view {
        if (entry == address(0)) revert ZeroAddress();
        if (entry == account || entry == address(this) || entry == HOOK) revert InvalidEntry(entry);
        if (_inTokens(s, entry) || _inDestinations(s, entry) || _inMarkets(s, entry)) {
            revert InvalidEntry(entry);
        }
        for (uint256 i; i < s.nMarkets; ++i) {
            if (s.shareTokens[i] == entry) revert InvalidEntry(entry);
        }
    }

    function _inTokens(AccountState storage s, address a) internal view returns (bool) {
        for (uint256 i; i < s.nTokens; ++i) {
            if (s.tokens[i] == a) return true;
        }
        return false;
    }

    function _inDestinations(AccountState storage s, address a) internal view returns (bool) {
        for (uint256 i; i < s.nDestinations; ++i) {
            if (s.destinations[i] == a) return true;
        }
        return false;
    }

    function _inMarkets(AccountState storage s, address a) internal view returns (bool) {
        for (uint256 i; i < s.nMarkets; ++i) {
            if (s.markets[i] == a) return true;
        }
        return false;
    }
}
