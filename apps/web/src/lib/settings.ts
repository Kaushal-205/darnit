import { type RuntimeConfig, isHttpUrl } from "./config";

/** User-editable network endpoints. Saved only in this browser (localStorage). */
export type NetworkSettings = {
  rpcUrl: string;
  bundlerUrl: string;
  paymasterUrl: string;
};

const KEY = (chainId: number) => `session-firewall:network:${chainId}`;

type KV = Pick<Storage, "getItem" | "setItem" | "removeItem">;

function storage(): KV | undefined {
  try {
    return globalThis.localStorage;
  } catch {
    return undefined;
  }
}

/** Values from the runtime config, used until the user saves their own. */
export function defaultSettings(config: RuntimeConfig): NetworkSettings {
  return {
    rpcUrl: config.network.rpcUrl,
    bundlerUrl: config.network.bundlerUrl ?? "",
    paymasterUrl: config.network.paymasterUrl ?? "",
  };
}

export function loadSettings(config: RuntimeConfig, kv: KV | undefined = storage()): NetworkSettings {
  const defaults = defaultSettings(config);
  const raw = kv?.getItem(KEY(config.network.chainId));
  if (!raw) return defaults;
  try {
    const saved = JSON.parse(raw) as Partial<NetworkSettings>;
    const errors = validateSettings({ ...defaults, ...saved });
    return errors.length ? defaults : { ...defaults, ...saved };
  } catch {
    return defaults;
  }
}

export function saveSettings(
  config: RuntimeConfig,
  s: NetworkSettings,
  kv: KV | undefined = storage(),
): void {
  const errors = validateSettings(s);
  if (errors.length) throw new Error(errors.join(" "));
  kv?.setItem(KEY(config.network.chainId), JSON.stringify(s));
}

export function resetSettings(config: RuntimeConfig, kv: KV | undefined = storage()): void {
  kv?.removeItem(KEY(config.network.chainId));
}

/** Plain-language problems with the settings, empty when they are fine. */
export function validateSettings(s: NetworkSettings): string[] {
  const errors: string[] = [];
  if (!isHttpUrl(s.rpcUrl)) errors.push("The RPC address must start with https:// or http://.");
  if (s.bundlerUrl && !isHttpUrl(s.bundlerUrl))
    errors.push("The bundler address must start with https:// or http://.");
  if (s.paymasterUrl && !isHttpUrl(s.paymasterUrl))
    errors.push("The paymaster address must start with https:// or http://.");
  if (s.paymasterUrl && !s.bundlerUrl)
    errors.push("A paymaster only works together with a bundler address.");
  return errors;
}
