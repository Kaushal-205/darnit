// Hand-written minimal ABIs for the third-party contracts the SDK talks to.
// Versions: Safe 1.4.1, Safe7579 v1.0.0 + Safe7579Launchpad v1.0.0, Smart Sessions (ModuleKit 0.5.9 ABI),
// Rhinestone OwnableValidator. Selectors were checked against Ethereum Sepolia bytecode (docs/decisions.md V14).

const moduleInit = {
  type: "tuple[]",
  components: [
    { name: "module", type: "address" },
    { name: "initData", type: "bytes" },
  ],
} as const;

export const safe7579Abi = [
  {
    type: "function",
    name: "execute",
    stateMutability: "payable",
    inputs: [
      { name: "mode", type: "bytes32" },
      { name: "executionCalldata", type: "bytes" },
    ],
    outputs: [],
  },
  {
    type: "function",
    name: "installModule",
    stateMutability: "nonpayable",
    inputs: [
      { name: "moduleType", type: "uint256" },
      { name: "module", type: "address" },
      { name: "initData", type: "bytes" },
    ],
    outputs: [],
  },
  {
    type: "function",
    name: "setRegistry",
    stateMutability: "nonpayable",
    inputs: [
      { name: "registry", type: "address" },
      { name: "attesters", type: "address[]" },
      { name: "threshold", type: "uint8" },
    ],
    outputs: [],
  },
  {
    type: "function",
    name: "isModuleInstalled",
    stateMutability: "view",
    inputs: [
      { name: "moduleType", type: "uint256" },
      { name: "module", type: "address" },
      { name: "additionalContext", type: "bytes" },
    ],
    outputs: [{ type: "bool" }],
  },
  {
    type: "function",
    name: "getActiveHook",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "hook", type: "address" }],
  },
  { type: "error", name: "ExecutionFailed", inputs: [] },
] as const;

const launchpadInitData = {
  name: "initData",
  type: "tuple",
  components: [
    { name: "singleton", type: "address" },
    { name: "owners", type: "address[]" },
    { name: "threshold", type: "uint256" },
    { name: "setupTo", type: "address" },
    { name: "setupData", type: "bytes" },
    { name: "safe7579", type: "address" },
    { name: "validators", ...moduleInit },
    { name: "callData", type: "bytes" },
  ],
} as const;

export const safe7579LaunchpadAbi = [
  {
    type: "function",
    name: "initSafe7579",
    stateMutability: "nonpayable",
    inputs: [
      { name: "safe7579", type: "address" },
      { name: "executors", ...moduleInit },
      { name: "fallbacks", ...moduleInit },
      { name: "hooks", ...moduleInit },
      { name: "attesters", type: "address[]" },
      { name: "threshold", type: "uint8" },
    ],
    outputs: [],
  },
  {
    type: "function",
    name: "setupSafe",
    stateMutability: "nonpayable",
    inputs: [launchpadInitData],
    outputs: [],
  },
  {
    type: "function",
    name: "preValidationSetup",
    stateMutability: "nonpayable",
    inputs: [
      { name: "initHash", type: "bytes32" },
      { name: "to", type: "address" },
      { name: "preInit", type: "bytes" },
    ],
    outputs: [],
  },
  {
    type: "function",
    name: "hash",
    stateMutability: "pure",
    inputs: [launchpadInitData],
    outputs: [{ type: "bytes32" }],
  },
] as const;

export const safeProxyFactoryAbi = [
  {
    type: "function",
    name: "createProxyWithNonce",
    stateMutability: "nonpayable",
    inputs: [
      { name: "_singleton", type: "address" },
      { name: "initializer", type: "bytes" },
      { name: "saltNonce", type: "uint256" },
    ],
    outputs: [{ name: "proxy", type: "address" }],
  },
  {
    type: "function",
    name: "proxyCreationCode",
    stateMutability: "pure",
    inputs: [],
    outputs: [{ type: "bytes" }],
  },
] as const;

export const safeAbi = [
  {
    type: "function",
    name: "getOwners",
    stateMutability: "view",
    inputs: [],
    outputs: [{ type: "address[]" }],
  },
  {
    type: "function",
    name: "getThreshold",
    stateMutability: "view",
    inputs: [],
    outputs: [{ type: "uint256" }],
  },
] as const;

export const smartSessionsAbi = [
  {
    type: "function",
    name: "isPermissionEnabled",
    stateMutability: "view",
    inputs: [
      { name: "permissionId", type: "bytes32" },
      { name: "account", type: "address" },
    ],
    outputs: [{ type: "bool" }],
  },
] as const;

export const erc20Abi = [
  {
    type: "function",
    name: "transfer",
    stateMutability: "nonpayable",
    inputs: [
      { name: "to", type: "address" },
      { name: "amount", type: "uint256" },
    ],
    outputs: [{ type: "bool" }],
  },
  {
    type: "function",
    name: "approve",
    stateMutability: "nonpayable",
    inputs: [
      { name: "spender", type: "address" },
      { name: "amount", type: "uint256" },
    ],
    outputs: [{ type: "bool" }],
  },
  {
    type: "function",
    name: "balanceOf",
    stateMutability: "view",
    inputs: [{ name: "owner", type: "address" }],
    outputs: [{ type: "uint256" }],
  },
] as const;

/** EntryPoint v0.7 errors and events the SDK decodes (viem's entryPoint07Abi has them too). */
export const entryPointErrorsAbi = [
  {
    type: "error",
    name: "FailedOp",
    inputs: [
      { name: "opIndex", type: "uint256" },
      { name: "reason", type: "string" },
    ],
  },
  {
    type: "error",
    name: "FailedOpWithRevert",
    inputs: [
      { name: "opIndex", type: "uint256" },
      { name: "reason", type: "string" },
      { name: "inner", type: "bytes" },
    ],
  },
] as const;
