import type { FirewallSession } from "@session-firewall/sdk";
import type { Address, Hex } from "viem";
import type { StoredPasskey } from "./passkey";

/**
 * What this browser remembers. Nothing here is sent anywhere.
 *
 * - The account record (address, passkey id and public key) is public information: localStorage.
 * - Session keys are private keys, kept in IndexedDB on this device. That is acceptable because a session
 *   key can only do what the onchain firewall allows: trade on registered markets, never send funds to a
 *   new address, never approve a new spender, never change settings, and never lose more than the hourly
 *   limit. It expires on its own, and "Pause trading" or "End session" cancels it instantly. The passkey,
 *   which controls the account, never leaves the authenticator.
 */
export type AccountRecord = {
  chainId: number;
  address: Address;
  passkey: StoredPasskey;
  ownerValidator: Address;
  createdAt: number;
};

const accountKey = (chainId: number, module: Address) =>
  `session-firewall:account:${chainId}:${module.toLowerCase()}`;

export function loadAccount(
  chainId: number,
  module: Address,
): AccountRecord | undefined {
  try {
    const raw = localStorage.getItem(accountKey(chainId, module));
    return raw ? (JSON.parse(raw) as AccountRecord) : undefined;
  } catch {
    return undefined;
  }
}

export function saveAccount(module: Address, a: AccountRecord): void {
  localStorage.setItem(accountKey(a.chainId, module), JSON.stringify(a));
}

export function forgetAccount(chainId: number, module: Address): void {
  localStorage.removeItem(accountKey(chainId, module));
}

/** Passkey made but account not deployed yet (so a reload does not lose it). */
const pendingKey = "session-firewall:pending-passkey";
export function loadPendingPasskey(): StoredPasskey | undefined {
  try {
    const raw = localStorage.getItem(pendingKey);
    return raw ? (JSON.parse(raw) as StoredPasskey) : undefined;
  } catch {
    return undefined;
  }
}
export function savePendingPasskey(p: StoredPasskey | undefined): void {
  if (p) localStorage.setItem(pendingKey, JSON.stringify(p));
  else localStorage.removeItem(pendingKey);
}

// ------------------------------------------------------------------ sessions (IndexedDB)

export type StoredSession = FirewallSession & {
  chainId: number;
  /** FirewallModule.sessionEpoch when the session was made; a later revoke-all bumps it. */
  epoch: string;
  createdAt: number;
};

const DB_NAME = "session-firewall";
const STORE = "sessions";

function openDb(idb: IDBFactory = indexedDB): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = idb.open(DB_NAME, 1);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE)) {
        const s = db.createObjectStore(STORE, { keyPath: "permissionId" });
        s.createIndex("account", "account");
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

function tx<T>(
  mode: IDBTransactionMode,
  fn: (s: IDBObjectStore) => IDBRequest<T>,
  idb?: IDBFactory,
): Promise<T> {
  return openDb(idb).then(
    (db) =>
      new Promise<T>((resolve, reject) => {
        const t = db.transaction(STORE, mode);
        const req = fn(t.objectStore(STORE));
        t.oncomplete = () => {
          db.close();
          resolve(req.result);
        };
        t.onerror = () => reject(t.error);
      }),
  );
}

export function putSession(
  s: StoredSession,
  idb?: IDBFactory,
): Promise<IDBValidKey> {
  return tx("readwrite", (store) => store.put(s), idb);
}

export async function listSessions(
  account: Address,
  idb?: IDBFactory,
): Promise<StoredSession[]> {
  const all = await tx<StoredSession[]>(
    "readonly",
    (store) =>
      store.index("account").getAll(account) as IDBRequest<StoredSession[]>,
    idb,
  );
  return all.sort((a, b) => b.createdAt - a.createdAt);
}

export function deleteSession(
  permissionId: Hex,
  idb?: IDBFactory,
): Promise<undefined> {
  return tx("readwrite", (store) => store.delete(permissionId), idb);
}
