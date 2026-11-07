import type { Address } from "viem";

/**
 * Third-party contracts on Base Sepolia (chain 84532), verified 2026-11-07 with `cast code` against
 * https://sepolia.base.org and selector checks (docs/decisions.md V14). The same addresses exist on an
 * Anvil fork of Base Sepolia (`local`).
 */
export const BASE_SEPOLIA = {
  chainId: 84532,
  /** ERC-4337 EntryPoint v0.7 */
  entryPoint: "0x0000000071727De22E5E9d8BAf0edAc6f37da032",
  /** Safe 1.4.1 singleton (non-L2, the build the ModuleKit integration tests use) */
  safeSingleton: "0x41675C099F32341bf84BFc5382aF534df5C7461a",
  /** SafeL2 1.4.1 singleton */
  safeL2Singleton: "0x29fcB43b46531BcA003ddC8FCB67FFE91900C762",
  /** SafeProxyFactory 1.4.1 */
  safeProxyFactory: "0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67",
  /** Rhinestone Safe7579 adapter v1.0.0 (ModuleInit = (module, initData); reverts ExecutionFailed()) */
  safe7579: "0x7579EE8307284F293B1927136486880611F20002",
  /** Rhinestone Safe7579Launchpad v1.0.0 (REGISTRY = Rhinestone registry below) */
  safe7579Launchpad: "0x7579011aB74c46090561ea277Ba79D510c6C00ff",
  /** Rhinestone ERC-7484 module registry, wired into the launchpad */
  registry: "0x000000000069E2a187AEFFb852bF3cCdC95151B2",
  /**
   * Canonical Smart Sessions (v1.0.x). Its `Session` ABI uses `ERC7739Context[]` plus a
   * `permitERC4337Paymaster` flag, so it does NOT match contracts/src/interfaces/ISmartSessions.sol (V13).
   * Listed for reference; a firewall deployment must point at a Smart Sessions with the matching ABI.
   */
  smartSessionsCanonical: "0x00000000002B0eCfbD0496EE71e01257dA0E37DE",
  /** Older Smart Sessions deployment; same newer ABI as the canonical one (also does NOT match V13). */
  smartSessionsLegacy: "0x00000000008bDABA73cD9815d79069c247Eb4bDA",
  /**
   * Rhinestone OwnableValidator (ECDSA, k-of-n). Used as the ECDSA owner validator and, through its
   * stateless `validateSignatureWithData`, as the Smart Sessions session-key validator.
   */
  ownableValidator: "0x2483DA3A338895199E5e538530213157e931Bf06",
  /** Standard CREATE2 factory used by contracts/script/*.s.sol */
  create2Factory: "0x4e59b44847b379578588920cA78FbF26c0B4956C",
} as const satisfies Record<string, Address | number>;

/** Everything the SDK needs to know about one deployment. */
export type FirewallAddresses = {
  entryPoint: Address;
  safeSingleton: Address;
  safeProxyFactory: Address;
  safe7579: Address;
  safe7579Launchpad: Address;
  smartSessions: Address;
  ownableValidator: Address;
  /** Our contracts (contracts/script/Deploy.s.sol output) */
  module: Address;
  hook: Address;
  actionPolicy: Address;
  signaturePolicy: Address;
  noSafeOwner: Address;
  /**
   * ERC-7484 attester the account trusts at creation. Needed only with the ModuleKit 0.5.9 Smart Sessions build
   * (`local`), which checks the registry for every policy and session validator it enables.
   * Unset: a placeholder is trusted, which is harmless because the account's own registry check is switched off.
   */
  attester?: Address;
};

/** Output of contracts/script/Deploy.s.sol (deployments/<chainId>.json). */
export type FirewallDeploymentJson = {
  smartSessions: Address;
  module: Address;
  hook: Address;
  actionPolicy: Address;
  signaturePolicy: Address;
  noSafeOwner: Address;
};

/** Combine Base Sepolia infrastructure with a firewall deployment. */
export function baseSepoliaAddresses(
  deployment: FirewallDeploymentJson,
  opts: { attester?: Address } = {},
): FirewallAddresses {
  return {
    attester: opts.attester,
    entryPoint: BASE_SEPOLIA.entryPoint,
    safeSingleton: BASE_SEPOLIA.safeSingleton,
    safeProxyFactory: BASE_SEPOLIA.safeProxyFactory,
    safe7579: BASE_SEPOLIA.safe7579,
    safe7579Launchpad: BASE_SEPOLIA.safe7579Launchpad,
    ownableValidator: BASE_SEPOLIA.ownableValidator,
    smartSessions: deployment.smartSessions,
    module: deployment.module,
    hook: deployment.hook,
    actionPolicy: deployment.actionPolicy,
    signaturePolicy: deployment.signaturePolicy,
    noSafeOwner: deployment.noSafeOwner,
  };
}
